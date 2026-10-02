using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode;

public sealed class DeepIdV2ReplicaStageOptions
{
    public bool Enabled { get; set; }

    internal bool Validate(bool placementEnabled, bool developmentOrUat)
    {
        if (Enabled && (!placementEnabled ||
                !developmentOrUat))
            throw new InvalidOperationException(
                "DID2 replica staging requires an independent UAT V2 placement boundary.");
        return Enabled;
    }
}

/// <summary>
/// DID2 fragment staging shared by the authenticated peer RPC and the
/// selected ONION terminal. CandidateReady means only that exact XPP1 bytes
/// survived durable reassembly; final commit has a separate authority gate.
/// </summary>
internal sealed class DeepIdV2ReplicaStageReceiver : IContactReplicaCommandReceiver
{
    private const int MaximumOperationsPerNetwork = 64;
    private readonly RouterNodeOptions node;
    private readonly IDeepIdV2PreKeyPlacementSource placements;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly DeepIdV2PublicationFinalCommitter? finalCommitter;
    private readonly DeepIdV2PreKeyClaimRuntime? claims;
    private readonly string root;
    private readonly SemaphoreSlim stageGate = new(1, 1);

    public DeepIdV2ReplicaStageReceiver(RouterNodeOptions node,
        IDeepIdV2PreKeyPlacementSource placements,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability,
        DeepIdV2PublicationFinalCommitter? finalCommitter = null,
        DeepIdV2PreKeyClaimRuntime? claims = null)
    {
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.placements = placements ?? throw new ArgumentNullException(nameof(placements));
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        this.finalCommitter = finalCommitter;
        this.claims = claims;
        root = Path.Combine(Path.GetFullPath(node.DataDirectory),
            "did2-prekey-stage");
        RejectExistingLinks(root);
        security.SecureDirectory(root);
        RejectExistingLinks(root);
    }

    public async ValueTask<ContactReplicaRpcResponse> ReceiveAsync(
        ContactReplicaRpcCommand command, RouterId authenticatedSender,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Operation is ContactReplicaRpcOperation.CoordinateDid2PreKeyClaim or
            ContactReplicaRpcOperation.PrepareDid2PreKeyClaim or ContactReplicaRpcOperation.CompleteDid2PreKeyClaim or
            ContactReplicaRpcOperation.ReadDid2PreKeyInventoryCommit)
            return await (claims ?? throw new InvalidOperationException("DID2 claim runtime is not enabled."))
                .ReceiveAsync(command, authenticatedSender, cancellationToken).ConfigureAwait(false);
        if (command.Operation is not
                (ContactReplicaRpcOperation.StageDid2PreKeyPublication or
                 ContactReplicaRpcOperation.CommitDid2PreKeyPublication) ||
            command.Placement.RequestKind !=
                ContactServiceRequestKind.PublishPreKeyInventory)
            throw new InvalidDataException(
                "DID2 stage receiver rejects all non-V2 replica operations.");
        var decoded = DeepIdV2ReplicaStagePayloadCodec.Decode(
            command.Payload.Span);
        if (command.Operation ==
                ContactReplicaRpcOperation.CommitDid2PreKeyPublication &&
            decoded.Fragment.Phase != Xpp1V2FragmentPhase.Commit)
            throw new InvalidDataException(
                "DID2 final commit requires the exact staged commit fragment.");
        var localId = node.GetRouterId().ToBytes();
        // The caller-supplied projection can only reject, never authorize.
        // Avoid an authority fetch for an obviously unrelated authenticated peer.
        if (!command.Placement.ContainsReplica(localId) ||
            !Fixed(command.Placement.OtherReplica(localId),
                authenticatedSender.ToBytes()))
            throw new UnauthorizedAccessException(
                "DID2 fragment peer is outside the claimed placement.");
        var current = await placements.MintPreKeyPublicationAsync(
            decoded.Publisher, command.Placement.ShardKey,
            cancellationToken).ConfigureAwait(false);
        ContactReplicaRequestReceiver.EnsureExactPlacement(
            command.Placement, current);
        if (!Fixed(current.OtherReplica(localId),
                authenticatedSender.ToBytes()) ||
            !Fixed(decoded.Fragment.NetworkId.Span, current.NetworkId.Span) ||
            !Fixed(decoded.Fragment.ViewHash.Span, current.ViewHash.Span) ||
            !Fixed(decoded.Fragment.PlacementHash.Span,
                current.PlacementHash.Span))
            throw new UnauthorizedAccessException(
                "DID2 fragment is outside the authenticated current placement.");

        var result = await StageVerifiedAsync(decoded.Fragment,
            decoded.Publisher, current, command.Placement,
            finalCommit: command.Operation ==
                ContactReplicaRpcOperation.CommitDid2PreKeyPublication,
            requireExactCommitReplay: true, authenticatedSender,
            cancellationToken).ConfigureAwait(false);
        return new ContactReplicaRpcResponse(command.Operation,
            command.CorrelationId.ToArray(), localId, result);
    }

    internal async ValueTask<ReadOnlyMemory<byte>> ReceiveTerminalAsync(
        ReadOnlyMemory<byte> exactFragment,
        CancellationToken cancellationToken)
    {
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
            exactFragment.Span);
        var stagedManifest = fragment.Phase == Xpp1V2FragmentPhase.Manifest
            ? fragment
            : ReadStagedManifest(fragment);
        var publisher = DeepIdV2Codec.DecodeDid2(
            stagedManifest.PublisherDid2.Span);
        var exactXpi1 = stagedManifest.Body.Span.Slice(
            DeepIdV2BoundedPreKeyPublicationCodec.ManifestSupportLength,
            DeepIdV2PreKeyManifestCodec.CanonicalLength);
        var serviceCapability = DeepIdV2PreKeyManifestCodec.Decode(exactXpi1)
            .Field(2);
        var current = await placements.MintPreKeyPublicationAsync(
            publisher, serviceCapability, cancellationToken)
            .ConfigureAwait(false);
        // Unlike an authenticated peer request, this anonymous ONION exit has
        // no caller-provided placement. Only the locally minted proof selects
        // its terminal node and authorizes staging.
        current.VerifiedPlacement.Network.EnsureCurrent();
        var localId = node.GetRouterId().ToBytes();
        if (current.RequestKind !=
                ContactServiceRequestKind.PublishPreKeyInventory ||
            !current.VerifiedPlacement.Binds(
                ContactServiceRequestKind.PublishPreKeyInventory,
                serviceCapability) ||
            !current.ContainsReplica(localId) ||
            !Fixed(fragment.NetworkId.Span, current.NetworkId.Span) ||
            !Fixed(fragment.ViewHash.Span, current.ViewHash.Span) ||
            !Fixed(fragment.PlacementHash.Span, current.PlacementHash.Span) ||
            !Fixed(fragment.NetworkId.Span,
                stagedManifest.NetworkId.Span) ||
            !Fixed(fragment.PublicationOperationId.Span,
                stagedManifest.PublicationOperationId.Span) ||
            !Fixed(fragment.ExactAggregateHash.Span,
                stagedManifest.ExactAggregateHash.Span) ||
            !Fixed(fragment.PublisherDescriptorCommitment.Span,
                stagedManifest.PublisherDescriptorCommitment.Span))
            throw new UnauthorizedAccessException(
                "DID2 ONION fragment is outside the selected current placement.");
        return await StageVerifiedAsync(fragment, publisher, current, current,
            finalCommit: fragment.Phase ==
                Xpp1V2FragmentPhase.Commit,
            requireExactCommitReplay: false, authenticatedSender: null,
            cancellationToken).ConfigureAwait(false);
    }

    internal ValueTask<ReadOnlyMemory<byte>> ReceiveClaimTerminalAsync(ReadOnlyMemory<byte> exactRequest,
        CancellationToken cancellationToken) => (claims ?? throw new ContactServiceUnavailableException(
            "DID2 claim runtime is not enabled.")).ReceiveTerminalAsync(exactRequest, cancellationToken);

    private async ValueTask<byte[]> StageVerifiedAsync(
        ParsedXpp1V2Fragment fragment, ParsedDid2 publisher,
        ContactServicePlacementCapability current,
        ContactServicePlacementCapability claimedPlacement,
        bool finalCommit, bool requireExactCommitReplay,
        RouterId? authenticatedSender, CancellationToken cancellationToken)
    {

        await stageGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var networkRoot = Path.Combine(root,
                Convert.ToHexString(current.NetworkId.Span));
            var operationPath = Path.Combine(networkRoot,
                Convert.ToHexString(fragment.PublicationOperationId.Span));
            if (fragment.Phase != Xpp1V2FragmentPhase.Manifest &&
                !Directory.Exists(operationPath))
            {
                if (finalCommit)
                    throw new InvalidDataException(
                        "DID2 final commit has no staged operation.");
                if (authenticatedSender is null)
                    throw new InvalidDataException(
                        "DID2 ONION fragment lost its staged manifest.");
                return DeepIdV2ReplicaStagePayloadCodec.EncodeStatus(
                    PublicationStageDisposition.Incomplete);
            }

            RejectExistingLinks(networkRoot);
            security.SecureDirectory(networkRoot);
            RejectExistingLinks(networkRoot);
            using var rootLease = new FileStream(Path.Combine(root,
                "stage.lock"), new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough
            });
            security.SecureFile(rootLease.Name);
            if (!Directory.Exists(operationPath) &&
                Directory.EnumerateDirectories(networkRoot).Take(
                    MaximumOperationsPerNetwork + 1).Count() >=
                MaximumOperationsPerNetwork)
                throw new InvalidOperationException(
                    "DID2 pre-key staging has reached its operation limit.");
            RejectExistingLinks(operationPath);
            using var journal = new DeepIdV2PublicationJournal(operationPath,
                current.NetworkId.Span,
                fragment.PublicationOperationId.Span,
                current.ViewHash.Span, current.PlacementHash.Span,
                current.ShardKey.Span, security, durability);
            if (finalCommit)
            {
                if (requireExactCommitReplay &&
                    journal.ReadCommitted()?.Candidate is null)
                    throw new InvalidDataException(
                        "DID2 final commit has no exact durable staged candidate.");
                var finalStage = journal.Stage(fragment.CanonicalBytes.Span,
                    publisher);
                if (finalStage.Disposition is not
                    (PublicationStageDisposition.CandidateReady or
                     PublicationStageDisposition.ExactReplay) ||
                    (requireExactCommitReplay && finalStage.Disposition !=
                        PublicationStageDisposition.ExactReplay) ||
                    journal.ReadCommitted()?.Candidate is null)
                    throw new InvalidDataException(
                        "DID2 final commit has no exact durable staged candidate.");
                var committer = finalCommitter ??
                    throw new InvalidOperationException(
                        "DID2 final commit authority is not configured.");
                var receipt = await committer.CommitAsync(journal,
                    claimedPlacement, authenticatedSender,
                    cancellationToken).ConfigureAwait(false);
                return receipt.CanonicalBytes.ToArray();
            }
            var staged = journal.Stage(fragment.CanonicalBytes.Span,
                publisher);
            if (staged.Disposition is PublicationStageDisposition.WrongScope
                or PublicationStageDisposition.ForkLatched)
                throw new InvalidDataException(
                    "DID2 publication fragment conflicts with durable scope.");
            if (authenticatedSender is null && staged.Disposition is not
                (PublicationStageDisposition.Staged or
                 PublicationStageDisposition.CandidateReady or
                 PublicationStageDisposition.ExactReplay))
                throw new InvalidDataException(
                    "DID2 ONION staging has no successful durable result.");
            if (staged.Disposition == PublicationStageDisposition.CandidateReady)
            {
                var committed = journal.ReadCommitted();
                if (committed?.Candidate is null ||
                    !Fixed(committed.Candidate.CanonicalBytes.Span,
                        staged.Candidate!.CanonicalBytes.Span))
                    throw new InvalidDataException(
                        "DID2 publication candidate is not durably complete.");
            }
            return authenticatedSender is null
                ? DeepIdV2ReplicaStagePayloadCodec.EncodeTerminalStageStatus(
                    staged.Disposition)
                : DeepIdV2ReplicaStagePayloadCodec.EncodeStatus(
                    staged.Disposition);
        }
        finally { stageGate.Release(); }
    }

    private ParsedXpp1V2Fragment ReadStagedManifest(
        ParsedXpp1V2Fragment fragment)
    {
        var manifestPath = Path.Combine(root,
            Convert.ToHexString(fragment.NetworkId.Span),
            Convert.ToHexString(fragment.PublicationOperationId.Span),
            "manifest.xpp1");
        RejectExistingLinks(manifestPath);
        if (!File.Exists(manifestPath))
            throw new InvalidDataException(
                "DID2 ONION fragment has no staged manifest.");
        security.ValidateSecureFile(manifestPath);
        var length = new FileInfo(manifestPath).Length;
        if (length is < 325 or >
            DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes)
            throw new InvalidDataException(
                "DID2 staged manifest exceeds its closed bound.");
        var manifest = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
            File.ReadAllBytes(manifestPath));
        if (manifest.Phase != Xpp1V2FragmentPhase.Manifest)
            throw new InvalidDataException(
                "DID2 staged publication has no exact manifest.");
        return manifest;
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void RejectExistingLinks(string path)
    {
        var full = Path.GetFullPath(path);
        var basePath = Path.GetPathRoot(full) ??
            throw new InvalidDataException("DID2 stage path has no root.");
        var current = basePath;
        foreach (var part in Path.GetRelativePath(basePath, full).Split(
                     [Path.DirectorySeparatorChar,
                      Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException(
                    "DID2 stage custody path contains a link.");
        }
    }
}

internal sealed record DeepIdV2ReplicaStagePayload(
    ParsedDid2 Publisher, ParsedXpp1V2Fragment Fragment);

internal static class DeepIdV2ReplicaStagePayloadCodec
{
    internal static byte[] Encode(ParsedDid2 publisher,
        ReadOnlySpan<byte> exactFragment)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
            exactFragment);
        if (fragment.Phase == Xpp1V2FragmentPhase.Manifest &&
            !CryptographicOperations.FixedTimeEquals(
                fragment.PublisherDid2.Span,
                publisher.CanonicalBytes.Span))
            throw new InvalidDataException(
                "DID2 replica manifest publisher hint is inconsistent.");
        var output = new byte[DeepIdV2Codec.Did2Length + exactFragment.Length];
        publisher.CanonicalBytes.Span.CopyTo(output);
        exactFragment.CopyTo(output.AsSpan(DeepIdV2Codec.Did2Length));
        return output;
    }

    internal static DeepIdV2ReplicaStagePayload Decode(ReadOnlySpan<byte> body)
    {
        if (body.Length is < DeepIdV2Codec.Did2Length + 325 or
            > DeepIdV2Codec.Did2Length +
                DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes)
            throw new InvalidDataException(
                "DID2 replica fragment payload is outside its closed bound.");
        var publisher = DeepIdV2Codec.DecodeDid2(
            body[..DeepIdV2Codec.Did2Length]);
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
            body[DeepIdV2Codec.Did2Length..]);
        if (fragment.Phase == Xpp1V2FragmentPhase.Manifest &&
            !CryptographicOperations.FixedTimeEquals(
                publisher.CanonicalBytes.Span,
                fragment.PublisherDid2.Span))
            throw new InvalidDataException(
                "DID2 replica manifest publisher hint is inconsistent.");
        return new DeepIdV2ReplicaStagePayload(publisher, fragment);
    }

    internal static byte[] EncodeStatus(
        PublicationStageDisposition disposition) =>
        disposition switch
        {
            PublicationStageDisposition.Staged => [1],
            PublicationStageDisposition.Incomplete => [2],
            PublicationStageDisposition.ExactReplay => [3],
            PublicationStageDisposition.CandidateReady => [4],
            _ => throw new InvalidDataException(
                "DID2 replica stage has no admissible result.")
        };

    internal static byte[] EncodeTerminalStageStatus(
        PublicationStageDisposition disposition) =>
        disposition switch
        {
            PublicationStageDisposition.Staged or
                PublicationStageDisposition.CandidateReady => [1],
            PublicationStageDisposition.ExactReplay => [3],
            _ => throw new InvalidDataException(
                "DID2 ONION stage has no admissible result.")
        };
}

/// <summary>
/// DID2-only ONION terminal adapter. The anonymous exit may stage public
/// bounded bytes or use the opt-in V2 claim owner on a freshly selected local
/// replica. Other ContactResolve operations remain unavailable here.
/// </summary>
internal sealed class DeepIdV2ContactOnionDispatcher(
    DeepIdV2ReplicaStageReceiver receiver, Did2ContactResolverDispatcher? contacts = null) : IContactServiceOpaqueDispatcher
{
    public ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        ContactServiceOperation operation,
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        if (operation == ContactServiceOperation.ClaimPreKey)
            return receiver.ReceiveClaimTerminalAsync(canonicalRequest, cancellationToken);
        if (operation is ContactServiceOperation.PublishDcr or ContactServiceOperation.ResolveDcr or ContactServiceOperation.AcquireMailboxGrant)
            return (contacts ?? throw new ContactServiceUnavailableException("DID2 contact resolver is not enabled."))
                .DispatchAsync(operation, canonicalRequest, cancellationToken);
        if (operation != ContactServiceOperation.PublishPreKeyInventory)
            throw new ContactServiceUnavailableException(
                "Only DID2 V2 pre-key publication is enabled at this ONION exit.");
        return receiver.ReceiveTerminalAsync(canonicalRequest,
            cancellationToken);
    }
}
