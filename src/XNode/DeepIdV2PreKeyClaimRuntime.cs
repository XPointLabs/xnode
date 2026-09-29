using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode;

public sealed class DeepIdV2PreKeyClaimOptions
{
    public bool Enabled { get; set; }
    internal bool Validate(bool stageEnabled, bool hasObserver, bool v1Enabled, bool developmentOrUat)
    {
        if (Enabled && (!stageEnabled || !hasObserver || v1Enabled || !developmentOrUat))
            throw new InvalidOperationException("DID2 claim needs independent UAT placement, observer and publication custody.");
        return Enabled;
    }
}

/// <summary>
/// DID2-only, fixed selected-coordinator prepare/complete runtime. Pending
/// uncertainty never releases keys or changes selection. Placement handover,
/// protected whole-state rollback detection and release activation are separate.
/// </summary>
internal sealed class DeepIdV2PreKeyClaimRuntime(
    RouterNodeOptions node, IDeepIdV2PreKeyClaimPlacementSource placements,
    DeepIdV2PublicationCandidateAuthority candidates, IContactReplicaPeerClient peers,
    IOnionMonotonicClock monotonic, IClock wallClock,
    IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability) : IContactReplicaCommandReceiver
{
    private readonly SemaphoreSlim gate = new(1, 1);

    internal async ValueTask<ReadOnlyMemory<byte>> ReceiveTerminalAsync(
        ReadOnlyMemory<byte> exactRequest, CancellationToken cancellationToken)
    {
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exactRequest.Span);
        try
        {
            var current = await CurrentPlacementAsync(request, cancellationToken).ConfigureAwait(false);
            if (!IsCoordinator(current))
            {
                var forwarded = await SendAsync(current, ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim,
                    request.CanonicalBytes, cancellationToken).ConfigureAwait(false);
                current.VerifiedPlacement.Network.EnsureCurrent();
                var result = DeepIdV2PreKeyClaimResultCodec.Decode(forwarded.Span, request.CanonicalBytes.Span);
                if (result.Status is Xpc1V2Status.Claimed or Xpc1V2Status.Replay)
                    _ = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, result, current.VerifiedPlacement);
                return forwarded;
            }
            return await CoordinateAsync(request, current, cancellationToken).ConfigureAwait(false);
        }
        catch (DeepIdV2ClaimConflictException conflict)
        {
            return Failure(request, Xpc1V2Status.Conflict, Xpc1V2MutationOutcome.None, 0, [conflict.EvidenceHash]);
        }
        catch (IOException)
        {
            return Failure(request, Xpc1V2Status.OutcomeUnknown, Xpc1V2MutationOutcome.OutcomeUnknown, 1, []);
        }
    }

    public async ValueTask<ContactReplicaRpcResponse> ReceiveAsync(ContactReplicaRpcCommand command,
        RouterId authenticatedSender, CancellationToken cancellationToken)
    {
        if (command.Operation is not (ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim or
                ContactReplicaRpcOperation.PrepareDid2PreKeyClaim or ContactReplicaRpcOperation.CompleteDid2PreKeyClaim or
                ContactReplicaRpcOperation.ReadDid2PreKeyInventoryCommit) ||
            command.Placement.RequestKind != ContactServiceRequestKind.ClaimPreKey)
            throw new InvalidDataException("DID2 claim receiver rejects unrelated replica operations.");
        var local = node.GetRouterId().ToBytes();
        if (!command.Placement.ContainsReplica(local) ||
            !Fixed(command.Placement.OtherReplica(local), authenticatedSender.ToBytes()))
            throw new UnauthorizedAccessException("DID2 claim peer is outside the projected placement.");
        DeepIdV2ClaimPreparePayload? prepare = null;
        DeepIdV2ClaimCompletePayload? complete = null;
        ParsedXpk1V2 request;
        if (command.Operation == ContactReplicaRpcOperation.PrepareDid2PreKeyClaim)
        { prepare = DeepIdV2ClaimPeerPayloadCodec.DecodePrepare(command.Payload.Span); request = prepare.Proposal.Request; }
        else if (command.Operation == ContactReplicaRpcOperation.CompleteDid2PreKeyClaim)
        { complete = DeepIdV2ClaimPeerPayloadCodec.DecodeComplete(command.Payload.Span); request = complete.Request; }
        else request = DeepIdV2PreKeyClaimRequestCodec.Decode(command.Payload.Span);
        var current = await CurrentPlacementAsync(request, cancellationToken).ConfigureAwait(false);
        ContactReplicaRequestReceiver.EnsureExactPlacement(command.Placement, current);
        if (!Fixed(current.OtherReplica(local), authenticatedSender.ToBytes()) ||
            command.Operation == ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim && !IsCoordinator(current) ||
            command.Operation is ContactReplicaRpcOperation.PrepareDid2PreKeyClaim or ContactReplicaRpcOperation.CompleteDid2PreKeyClaim &&
                (IsCoordinator(current) || !Fixed(current.ReplicaIds[0].Span, authenticatedSender.ToBytes())))
            throw new UnauthorizedAccessException("DID2 claim peer has no current coordinator role.");
        ReadOnlyMemory<byte> result;
        if (command.Operation == ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim)
            result = await ReceiveTerminalAsync(request.CanonicalBytes, cancellationToken).ConfigureAwait(false);
        else
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var context = await VerifyContextAsync(request, current, cancellationToken).ConfigureAwait(false);
                var now = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
                using var store = OpenStore(request, current);
                EnsureSameInventory(store, context);
                if (prepare is not null)
                {
                    VerifyPublicationPair(context, prepare.FirstPublicationReceipt, prepare.SecondPublicationReceipt);
                    var proposal = prepare.Proposal;
                    if (!Fixed(proposal.Manifest.CanonicalBytes.Span, context.Publication.Manifest.CanonicalBytes.Span))
                        throw new UnauthorizedAccessException("DID2 proposal is not the current retained inventory.");
                    var input = SigningInput(proposal);
                    var coordinatorKey = current.VerifiedPlacement.Network.ResolveNodeIdentityPublicKey(current.ReplicaIds[0]);
                    if (!PublicKeyAuth.VerifyDetached(prepare.CoordinatorSignature.ToArray(), input, coordinatorKey.ToArray()))
                        throw new CryptographicException("DID2 claim coordinator signature is invalid.");
                    _ = store.ReserveClaimProposal(request, proposal.Offering, proposal.Manifest,
                        proposal.Generation, proposal.Counter, now.TrustedLowerUnixSeconds, now.TrustedUpperUnixSeconds,
                        Sign);
                    _ = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
                    result = Sign(input);
                }
                else if (complete is not null)
                {
                    VerifyPublicationPair(context, complete.FirstPublicationReceipt, complete.SecondPublicationReceipt);
                    if (!Fixed(complete.Result.Field(26).Span, context.Publication.Manifest.CanonicalBytes.Span))
                        throw new UnauthorizedAccessException("DID2 completion is not the current retained inventory.");
                    var verified = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, complete.Result, current.VerifiedPlacement);
                    result = store.CompleteClaimLocally(verified, Sign);
                    _ = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
                }
                else result = context.Receipt.CanonicalBytes;
            }
            finally { gate.Release(); }
        }
        return new(command.Operation, command.CorrelationId.ToArray(), local, result.ToArray());
    }

    private async ValueTask<ReadOnlyMemory<byte>> CoordinateAsync(ParsedXpk1V2 request,
        ContactServicePlacementCapability current, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var context = await VerifyContextAsync(request, current, cancellationToken).ConfigureAwait(false);
            var remoteReceipt = DeepIdV2PreKeyCommitReceiptCodec.Decode((await SendAsync(current,
                ContactReplicaRpcOperation.ReadDid2PreKeyInventoryCommit, request.CanonicalBytes, cancellationToken)
                .ConfigureAwait(false)).Span);
            VerifyPublicationPair(context, context.Receipt, remoteReceipt);
            var now = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
            using var store = OpenStore(request, current);
            EnsureSameInventory(store, context);
            DeepIdV2ClaimProposal proposal;
            try
            {
                proposal = store.PrepareNextClaim(request, now.TrustedLowerUnixSeconds,
                    now.TrustedUpperUnixSeconds, Sign);
                var localSignature = Sign(SigningInput(proposal));
                var remoteSignature = await SendAsync(current, ContactReplicaRpcOperation.PrepareDid2PreKeyClaim,
                    DeepIdV2ClaimPeerPayloadCodec.EncodePrepare(proposal, context.Receipt, remoteReceipt, localSignature),
                    cancellationToken).ConfigureAwait(false);
                _ = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
                var result = proposal.CompletedResult.IsEmpty
                    ? DeepIdV2ClaimResultAuthor.Create(proposal, context.Publication, current,
                        node.GetRouterId().ToBytes(), localSignature, remoteSignature, now.TrustedLowerUnixSeconds)
                    : DeepIdV2PreKeyClaimResultCodec.Decode(proposal.CompletedResult.Span, request.CanonicalBytes.Span);
                _ = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, result, current.VerifiedPlacement);
                var remoteCompletion = await SendAsync(current, ContactReplicaRpcOperation.CompleteDid2PreKeyClaim,
                    DeepIdV2ClaimPeerPayloadCodec.EncodeComplete(request, result, context.Receipt, remoteReceipt),
                    cancellationToken).ConfigureAwait(false);
                var reread = DeepIdV2PreKeyClaimResultCodec.Decode(remoteCompletion.Span, request.CanonicalBytes.Span);
                var verified = DeepIdV2PreKeyClaimReplicaSignatureVerifier.Verify(request, reread, current.VerifiedPlacement);
                _ = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
                var localCompletion = store.CompleteClaimLocally(verified, Sign);
                if (!Fixed(localCompletion.Span, remoteCompletion.Span))
                    store.LatchClaimCompletionFork();
                _ = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
                return localCompletion;
            }
            catch (DeepIdV2ClaimConflictException) { throw; }
            catch (Exception exception) when (exception is IOException or InvalidDataException or
                CryptographicException or FormatException or InvalidOperationException or OperationCanceledException)
            {
                throw new IOException("DID2 claim reservation/completion outcome requires exact-operation reconciliation.", exception);
            }
        }
        finally { gate.Release(); }
    }

    private async ValueTask<ContactServicePlacementCapability> CurrentPlacementAsync(ParsedXpk1V2 request,
        CancellationToken cancellationToken)
    {
        var current = await placements.MintPreKeyClaimAsync(request.Field(16), cancellationToken).ConfigureAwait(false);
        current.VerifiedPlacement.Network.EnsureCurrent();
        if (current.RequestKind != ContactServiceRequestKind.ClaimPreKey ||
            !current.VerifiedPlacement.Binds(ContactServiceRequestKind.ClaimPreKey, request.Field(16)) ||
            !current.ContainsReplica(node.GetRouterId().ToBytes()) ||
            !Fixed(request.Field(1).Span, current.NetworkId.Span) ||
            !Fixed(request.Field(3).Span, current.ViewHash.Span) ||
            !Fixed(request.Field(4).Span, current.PlacementHash.Span))
            throw new UnauthorizedAccessException("DID2 claim is outside independently verified current placement.");
        return current;
    }

    private async ValueTask<ClaimContext> VerifyContextAsync(ParsedXpk1V2 request,
        ContactServicePlacementCapability current, CancellationToken cancellationToken)
    {
        ParsedXpp1V2 publication; ParsedXic1V2 receipt;
        using (var store = OpenStore(request, current))
        {
            publication = store.ReadCurrentPublication() ?? throw new InvalidOperationException("DID2 inventory is absent.");
            receipt = store.ReadCurrentCommitReceipt() ?? throw new InvalidOperationException("DID2 publication receipt is absent.");
        }
        if (!Fixed(request.Field(18).Span, publication.Manifest.Field(6).Span[6..]) ||
            !Fixed(request.Field(19).Span, publication.Manifest.Field(3).Span))
            throw new UnauthorizedAccessException("DID2 claim does not bind the retained service/device.");
        var directory = Path.Combine(Path.GetFullPath(node.DataDirectory), "did2-prekey-stage",
            Convert.ToHexString(publication.NetworkId.Span), Convert.ToHexString(publication.PublicationOperationId.Span));
        var path = Path.Combine(directory, "manifest.xpp1");
        RejectLinks(path);
        if (!File.Exists(path)) throw new InvalidDataException("DID2 claim lost its public publication support.");
        security.ValidateSecureFile(path);
        using var support = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (support.Length is < 325 or > DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes)
            throw new InvalidDataException("DID2 public support exceeds its bound.");
        var bytes = new byte[checked((int)support.Length)];
        support.ReadExactly(bytes);
        if (support.ReadByte() != -1) throw new InvalidDataException("DID2 public support changed while reading.");
        var manifest = DeepIdV2BoundedPreKeyPublicationCodec.Decode(bytes);
        if (manifest.Phase != Xpp1V2FragmentPhase.Manifest ||
            !Fixed(manifest.PublicationOperationId.Span, publication.PublicationOperationId.Span) ||
            !Fixed(manifest.NetworkId.Span, publication.NetworkId.Span))
            throw new InvalidDataException("DID2 public support belongs to another publication.");
        using var journal = new DeepIdV2PublicationJournal(directory, publication.NetworkId.Span,
            publication.PublicationOperationId.Span, manifest.ViewHash.Span, manifest.PlacementHash.Span,
            request.Field(16).Span, security, durability);
        var candidate = await candidates.VerifyCommittedCandidateAsync(journal, cancellationToken).ConfigureAwait(false);
        if (!Fixed(candidate.Publication.CanonicalBytes.Span, publication.CanonicalBytes.Span))
            throw new UnauthorizedAccessException("DID2 current publication support differs from retained inventory.");
        var publicationPlacement = ContactServicePlacementFactory.Create(current.VerifiedPlacement.Network,
            ContactServiceRequestKind.PublishPreKeyInventory, request.Field(16));
        var context = new ClaimContext(request, publication, receipt, candidate, current, publicationPlacement);
        _ = await EnsureFreshAsync(context, cancellationToken).ConfigureAwait(false);
        return context;
    }

    private async ValueTask<DeepIdV2CurrentContactAuthorization> EnsureFreshAsync(ClaimContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = await monotonic.ReadAsync(cancellationToken).ConfigureAwait(false);
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            context.Candidate.CurrentAuthorization.Freshness, context.Candidate.CurrentAuthorization.Authorization,
            now.BootId.Span, now.SampleSeconds);
        context.Placement.VerifiedPlacement.Network.EnsureCurrent();
        context.Placement.EnsureUsable(current.TrustedUpperUnixSeconds);
        // Complete signatures/member closure were checked from immutable public
        // support by the candidate authority. Recheck its current lease and exact
        // signed intervals after every await, without repeating all member crypto.
        if (current.TrustedLowerUnixSeconds < U64(context.Request.Field(5).Span) ||
            current.TrustedUpperUnixSeconds >= U64(context.Request.Field(6).Span) ||
            current.TrustedLowerUnixSeconds < U64(context.Publication.Manifest.Field(14).Span) ||
            current.TrustedUpperUnixSeconds >= U64(context.Publication.Manifest.Field(15).Span))
            throw new CryptographicException("DID2 claim is outside the exact request/inventory interval.");
        return current;
    }

    private void VerifyPublicationPair(ClaimContext context, ParsedXic1V2 first, ParsedXic1V2 second)
    {
        DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(context.Publication, context.PublicationPlacement, first, second);
        var own = Fixed(first.Field(5).Span, node.GetRouterId().ToBytes()) ? first : second;
        if (!Fixed(own.CanonicalBytes.Span, context.Receipt.CanonicalBytes.Span))
            throw new UnauthorizedAccessException("DID2 receipt pair does not contain the local durable publication receipt.");
    }

    private static void EnsureSameInventory(DeepIdV2InventoryCommitStore store, ClaimContext context)
    {
        if (store.ReadCurrentPublication() is not { } publication ||
            !Fixed(publication.CanonicalBytes.Span, context.Publication.CanonicalBytes.Span) ||
            store.ReadCurrentCommitReceipt() is not { } receipt ||
            !Fixed(receipt.CanonicalBytes.Span, context.Receipt.CanonicalBytes.Span))
            throw new IOException("DID2 inventory changed before claim custody.");
    }

    private DeepIdV2InventoryCommitStore OpenStore(ParsedXpk1V2 request, ContactServicePlacementCapability current) =>
        DeepIdV2InventoryCommitStore.OpenExisting(node.DataDirectory, current.NetworkId.Span, request.Field(16).Span,
            node.GetRouterId().ToBytes(), security, durability);
    private bool IsCoordinator(ContactServicePlacementCapability placement) => Fixed(placement.ReplicaIds[0].Span, node.GetRouterId().ToBytes());

    private byte[] Sign(byte[] input)
    {
        var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
        try
        {
            var key = PublicKeyAuth.GenerateKeyPair(seed);
            try
            {
                if (!Fixed(key.PublicKey, node.GetRouterId().ToBytes()))
                    throw new CryptographicException("DID2 claim signer is not the local node.");
                return PublicKeyAuth.SignDetached(input, key.PrivateKey);
            }
            finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    private async ValueTask<ReadOnlyMemory<byte>> SendAsync(ContactServicePlacementCapability placement,
        ContactReplicaRpcOperation operation, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        placement.VerifiedPlacement.Network.EnsureCurrent();
        var correlation = RandomNumberGenerator.GetBytes(32);
        var response = await peers.SendAsync(new(placement, operation, correlation, payload), cancellationToken).ConfigureAwait(false);
        if (response.Operation != operation || !Fixed(response.CorrelationId.Span, correlation) ||
            !Fixed(response.ReplicaId.Span, placement.OtherReplica(node.GetRouterId().ToBytes())))
            throw new IOException("DID2 claim peer response is not the exact authenticated operation.");
        return response.Payload.ToArray();
    }

    private ReadOnlyMemory<byte> Failure(ParsedXpk1V2 request, Xpc1V2Status status,
        Xpc1V2MutationOutcome outcome, uint retry, IReadOnlyList<ReadOnlyMemory<byte>> payload) =>
        DeepIdV2PreKeyClaimResultCodec.Encode(request.CanonicalBytes.Span, status, outcome,
            checked((ulong)wallClock.UtcNow.ToUnixTimeSeconds()), retry, payload);
    private static byte[] SigningInput(DeepIdV2ClaimProposal proposal) =>
        DeepIdV2PreKeyClaimCommitment.CreateReplicaSignatureInput(proposal.Request.CanonicalBytes.Span,
            proposal.Offering.CanonicalBytes.Span, proposal.Manifest.CanonicalBytes.Span, proposal.Generation, proposal.Counter);
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private static void RejectLinks(string path)
    {
        var full = Path.GetFullPath(path); var root = Path.GetPathRoot(full)!; var current = root;
        foreach (var part in Path.GetRelativePath(root, full).Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException("DID2 claim custody path contains a link.");
        }
    }

    private sealed record ClaimContext(ParsedXpk1V2 Request, ParsedXpp1V2 Publication, ParsedXic1V2 Receipt,
        DeepIdV2VerifiedPublicationCandidate Candidate, ContactServicePlacementCapability Placement,
        VerifiedContactServicePlacement PublicationPlacement);
}
