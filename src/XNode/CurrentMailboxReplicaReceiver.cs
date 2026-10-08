using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

/// <summary>Current DR-0081 peer proof -> native replay -> guarded durable
/// mutation -> descriptor-key receipt. No P04, raw policy/time, or UTC fallback.</summary>
internal sealed partial class CurrentMailboxReplicaReceiver(CurrentMailboxAdmission admission,
    MailboxPeerMutationStore mutations, DurableMailboxPeerReplayJournal replay,
    ReadOnlyMemory<byte> localSigningSeed, MailboxClientOperationLedger operations) : IDisposable
{
    private readonly MailboxClientOperationLedger operationLedger = operations ?? throw new ArgumentNullException(nameof(operations));
    internal MailboxClientOperationLedger OperationLedger => operationLedger;
    private readonly byte[] seed = CaptureSeed(localSigningSeed);
    private readonly SodiumMailboxPeerReplicationCrypto crypto = new();
    private readonly Dictionary<string, (ulong Start, int Count)> rates = new(StringComparer.Ordinal);
    private int disposed;
    private MailboxPeerMutationStore Mutations => mutations;
    private DurableMailboxPeerReplayJournal Replay => replay;
    private CurrentMailboxAdmission Admission => admission;
    internal ReadOnlyMemory<byte> LocalNodeId => admission.LocalNodeId;

    internal ValueTask EnrollNewHostAsync(ReadOnlyMemory<byte> depositInitialSnapshot,
        ReadOnlyMemory<byte> retrieveInitialSnapshot, CancellationToken token = default) =>
        admission.EnrollNewHostAsync(this, depositInitialSnapshot, retrieveInitialSnapshot, token);

    internal async ValueTask ValidateEnrollmentSigningCustodyAsync(CurrentMailboxAdmission owner,
        VerifiedMailboxHostAuthorityV2 host, CancellationToken token)
    {
        if (!ReferenceEquals(owner, admission))
            throw new InvalidOperationException("Enrollment must use the receiver's native admission owner.");
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var local = await host.ResolveReplicaAsync(LocalNodeId, token).ConfigureAwait(false);
        await host.EnsureCurrentAsync(token).ConfigureAwait(false);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        token.ThrowIfCancellationRequested();
        if (!Fixed(crypto.GetPublicKey(seed), local.SigningPublicKey.Span))
            throw new CryptographicException("Enrollment signing custody differs from the current descriptor.");
    }

    // A real host recovery operation, not admission for a synthetic client
    // request. Both MGR owners remain held through key and exact-document checks.
    internal async ValueTask InitializeHostAsync(CancellationToken token = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        _ = await admission.WithHostAsync(async (scope, ct) =>
        {
            if (!ReferenceEquals(scope.Owner, admission))
                throw new CryptographicException("Current host recovery belongs to another admission owner.");
            var local = await scope.Host.ResolveReplicaAsync(LocalNodeId, ct).ConfigureAwait(false);
            void RequireKey()
            {
                scope.Lease.RequireActive();
                ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
                if (!Fixed(crypto.GetPublicKey(seed), local.SigningPublicKey.Span))
                    throw new CryptographicException("Current host signing custody differs from its descriptor.");
            }
            RequireKey();
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            RequireKey();
            await operationLedger.InitializeCurrentAsync(LocalNodeId, scope.Host, scope.Lease, ct).ConfigureAwait(false);
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            RequireKey();
            return true;
        }, token).ConfigureAwait(false);
    }

    internal ValueTask<T> WithClientRequestAsync<T>(ReadOnlyMemory<byte> exactRequest, MailboxAuthenticatedOperation operation,
        Func<CurrentMailboxAdmission.Request, CancellationToken, ValueTask<T>> action, CancellationToken token,
        XNode.Core.Mailbox.Client.MailboxClientOperationLedger? storeLedger = null)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (storeLedger is not null && !ReferenceEquals(storeLedger, operationLedger))
            throw new InvalidOperationException("Current client work must use this receiver's operation owner.");
        return admission.WithRequestAsync(exactRequest, operation, action, token, operationLedger,
            storeLedger is null ? null : mutations, RequireSigningCustody);
    }

    private void RequireSigningCustody(CurrentMailboxAdmission.GrantScope scope)
    {
        scope.Lease.RequireActive();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (!ReferenceEquals(scope.Owner, admission))
            throw new CryptographicException("Current signing custody belongs to another admission owner.");
        var local = scope.Replicas.Single(replica => Fixed(replica.NodeId.Span, LocalNodeId.Span));
        if (!Fixed(crypto.GetPublicKey(seed), local.SigningPublicKey.Span))
            throw new CryptographicException("Current signing custody differs from its descriptor.");
    }

    private async ValueTask RequireOperationCustodyAsync(CurrentMailboxAdmission.GrantScope scope, CancellationToken token)
    {
        RequireSigningCustody(scope);
        await operationLedger.InitializeCurrentAsync(LocalNodeId, scope.Host, scope.Lease, token).ConfigureAwait(false);
    }

    internal Task<bool> HasStoreCustodyAsync(CurrentMailboxAdmission.GrantScope scope,
        MailboxEncryptedEnvelope envelope, CancellationToken token)
    {
        scope.Lease.RequireActive();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (!ReferenceEquals(scope.Owner, admission))
            throw new CryptographicException("Current Store lookup belongs to another native admission owner.");
        return mutations.HasCurrentStoreCustodyAsync(envelope, scope.Lease, token);
    }

    internal ReadOnlyMemory<byte> AuthorStoreRequest(CurrentMailboxAdmission.GrantScope scope,
        ReadOnlyMemory<byte> canonicalEnvelope, ulong cursor, ulong createdAt)
    {
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(canonicalEnvelope.Span);
        return AuthorRequest(scope, MailboxPeerReplicationOperation.Store, envelope.Epoch,
            envelope.OperationId, envelope.MailboxId.Bytes, canonicalEnvelope, cursor, createdAt, envelope.ExpiresAtUnixSeconds);
    }

    internal ReadOnlyMemory<byte> AuthorTombstoneRequest(CurrentMailboxAdmission.GrantScope scope,
        MailboxAuthenticatedAckBody body, MailboxCurrentAckTarget target, ulong createdAt) =>
        AuthorRequest(scope, MailboxPeerReplicationOperation.Tombstone, body.Epoch,
            body.OperationId, body.MailboxId.Bytes, target.EnvelopeDigest, target.Cursor, createdAt, target.ExpiresAtUnixSeconds);

    internal Task<IReadOnlyList<MailboxCurrentAckTarget>> ReadAckTargetsAsync(CurrentMailboxAdmission.GrantScope scope,
        MailboxAuthenticatedAckBody body, CancellationToken token)
    {
        scope.Lease.RequireActive();
        if (!ReferenceEquals(scope.Owner, admission)) throw new CryptographicException("Current ACK belongs to another native owner.");
        return mutations.ReadCurrentAckTargetsAsync(body, scope.Grant.MembershipCommitment, scope.Lease, token);
    }

    private ReadOnlyMemory<byte> AuthorRequest(CurrentMailboxAdmission.GrantScope scope,
        MailboxPeerReplicationOperation operation, ulong epoch, ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> mailbox, ReadOnlyMemory<byte> payload, ulong cursor, ulong createdAt, ulong expiresAt)
    {
        scope.Lease.RequireActive();
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (!ReferenceEquals(scope.Owner, admission))
            throw new CryptographicException("Current peer producer belongs to another native admission owner.");
        var local = scope.Replicas.Single(replica => Fixed(replica.NodeId.Span, admission.LocalNodeId.Span));
        var remote = scope.Replicas.Single(replica => !Fixed(replica.NodeId.Span, local.NodeId.Span));
        if (operation == MailboxPeerReplicationOperation.Store && !Fixed(local.NodeId.Span, scope.Replicas[0].NodeId.Span))
            throw new CryptographicException("Store intent must be authored by the authenticated PMS2 writer.");
        if (!Fixed(crypto.GetPublicKey(seed), local.SigningPublicKey.Span))
            throw new CryptographicException("Current Store producer signing custody differs from its descriptor.");
        var proof = new byte[342];
        scope.ProjectionReference.Span.CopyTo(proof);
        MailboxAuthenticatedCapabilityCodec.EncodeGrant(scope.Grant).CopyTo(proof, 38);
        MailboxReplicaMembershipProof Membership(VerifiedMailboxReplicaV2 replica) => new()
        {
            ReplicaId = replica.NodeId,
            SigningPublicKey = replica.SigningPublicKey,
            Epoch = scope.Grant.Epoch,
            MembershipCommitment = scope.Grant.MembershipCommitment,
            CanonicalInclusionProof = proof
        };
        return MailboxPeerWireV2Codec.Encode(crypto.SignRequest(new MailboxPeerWireRequestV2
        {
            Operation = operation,
            Epoch = epoch,
            OperationId = operationId,
            SenderRouterId = local.NodeId,
            RecipientRouterId = remote.NodeId,
            MembershipCommitment = scope.Grant.MembershipCommitment,
            PlacementCommitment = scope.Grant.PlacementCommitment,
            BlindedMailboxId = mailbox,
            Cursor = cursor,
            CreatedAtUnixSeconds = createdAt,
            ExpiresAtUnixSeconds = expiresAt,
            ReplayNonce = RandomNumberGenerator.GetBytes(32),
            PayloadDigest = SHA256.HashData(payload.Span),
            Payload = payload,
            SenderMembershipProof = Membership(local),
            RecipientMembershipProof = Membership(remote),
            Signature = ReadOnlyMemory<byte>.Empty
        }, seed));
    }

    internal ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(ReadOnlyMemory<byte> canonicalRequest,
        MailboxPeerReplicationOperation expectedOperation, CancellationToken token = default) =>
        WithPeerAsync(canonicalRequest, expectedOperation, MailboxPeerWireResponseReplicaV2.Recipient,
            async (operation, ct) =>
            {
                if (operation.Verified.ReplayDisposition == MailboxPeerReplayDisposition.IdempotentCompleted)
                    return operation.Verified.CachedResponse.ToArray();
                var response = await operation.ApplyAndSignLocalAsync(ct).ConfigureAwait(false);
                await operation.CommitRecipientAsync(response, ct).ConfigureAwait(false);
                return response;
            }, token);

    internal async ValueTask<T> WithPeerAsync<T>(ReadOnlyMemory<byte> canonicalRequest,
        MailboxPeerReplicationOperation expectedOperation, MailboxPeerWireResponseReplicaV2 localRole,
        Func<PeerOperation, CancellationToken, ValueTask<T>> action, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (localRole is not (MailboxPeerWireResponseReplicaV2.Sender or MailboxPeerWireResponseReplicaV2.Recipient))
            throw new ArgumentOutOfRangeException(nameof(localRole));
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        // Capture before the authority callback. The scoped overload below is
        // also used by admitted client work without reacquiring native floors.
        var decoded = MailboxPeerWireV2Codec.Decode(canonicalRequest.Span);
        var owned = MailboxPeerWireV2Codec.Encode(decoded);
        var localProof = localRole == MailboxPeerWireResponseReplicaV2.Sender ? decoded.SenderMembershipProof : decoded.RecipientMembershipProof;
        if (decoded.Operation != expectedOperation || !Fixed(localProof.ReplicaId.Span, admission.LocalNodeId.Span))
            throw new CryptographicException("Current peer operation or local replica differs.");
        var first = decoded.SenderMembershipProof.CanonicalInclusionProof;
        var second = decoded.RecipientMembershipProof.CanonicalInclusionProof;
        if (first.Length != 342 || !Fixed(first.Span, second.Span))
            throw new CryptographicException("Current peer proofs must name one exact projection and grant.");
        var role = expectedOperation == MailboxPeerReplicationOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve;
        return await admission.WithGrantAsync(first[38..].ToArray(), role,
            (scope, ct) => WithAdmittedPeerAsync(owned, expectedOperation, localRole, scope, action, ct), token).ConfigureAwait(false);
    }

    internal async ValueTask<T> WithAdmittedPeerAsync<T>(ReadOnlyMemory<byte> canonicalRequest,
        MailboxPeerReplicationOperation expectedOperation, MailboxPeerWireResponseReplicaV2 localRole,
        CurrentMailboxAdmission.GrantScope scope,
        Func<PeerOperation, CancellationToken, ValueTask<T>> action, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(action);
        scope.Lease.RequireActive();
        if (!ReferenceEquals(scope.Owner, admission))
            throw new CryptographicException("Current peer scope belongs to another native admission owner.");
        if (localRole is not (MailboxPeerWireResponseReplicaV2.Sender or MailboxPeerWireResponseReplicaV2.Recipient))
            throw new ArgumentOutOfRangeException(nameof(localRole));
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var decoded = MailboxPeerWireV2Codec.Decode(canonicalRequest.Span);
        var owned = MailboxPeerWireV2Codec.Encode(decoded);
        var localProof = localRole == MailboxPeerWireResponseReplicaV2.Sender ? decoded.SenderMembershipProof : decoded.RecipientMembershipProof;
        if (decoded.Operation != expectedOperation || !Fixed(localProof.ReplicaId.Span, admission.LocalNodeId.Span))
            throw new CryptographicException("Current peer operation or local replica differs.");
        var first = decoded.SenderMembershipProof.CanonicalInclusionProof;
        var second = decoded.RecipientMembershipProof.CanonicalInclusionProof;
        if (first.Length != 342 || !Fixed(first.Span, second.Span))
            throw new CryptographicException("Current peer proofs must name one exact projection and grant.");
        if (!Fixed(first.Span[38..], MailboxAuthenticatedCapabilityCodec.EncodeGrant(scope.Grant)) ||
            scope.Grant.Domain != (expectedOperation == MailboxPeerReplicationOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve))
            throw new CryptographicException("Current peer grant differs from the admitted client scope.");
        var ct = token;
        if (!Fixed(first.Span[..38], scope.ProjectionReference.Span))
            throw new CryptographicException("Peer projection differs from the exact host-verified grant selection.");
        if (expectedOperation == MailboxPeerReplicationOperation.Store &&
            !Fixed(decoded.SenderRouterId.Span, scope.Replicas[0].NodeId.Span))
            throw new CryptographicException("Peer Store sender must be the authenticated PMS2 writer.");
        var proofs = new CurrentProofs(scope, first.ToArray());
        var upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
        if (!proofs.VerifyStorageReplica(decoded.SenderMembershipProof, upper) ||
            !proofs.VerifyStorageReplica(decoded.RecipientMembershipProof, upper) ||
            !Fixed(crypto.GetPublicKey(seed), localProof.SigningPublicKey.Span))
            throw new CryptographicException("Current peer descriptor keys or local signing custody differ.");
        if (!crypto.Verify(decoded.SenderMembershipProof.SigningPublicKey.Span,
            MailboxPeerWireV2Codec.GetSigningDigest(decoded), decoded.Signature.Span))
            throw new CryptographicException("Current peer sender signature is invalid.");

        BlindedPlacementId placement;
        if (expectedOperation == MailboxPeerReplicationOperation.Store)
            placement = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(decoded.Payload.Span).PlacementId;
        else if (!mutations.TryResolveTombstonePlacement(decoded, out placement))
            throw new CryptographicException("Current peer tombstone has no matching durable target.");
        if (!Fixed(MailboxPlacementCommitment.Compute(placement), scope.Grant.PlacementCommitment.Span) ||
            decoded.Epoch != scope.Grant.Epoch ||
            !Fixed(decoded.MembershipCommitment.Span, scope.Grant.MembershipCommitment.Span) ||
            !Fixed(decoded.PlacementCommitment.Span, scope.Grant.PlacementCommitment.Span))
            throw new CryptographicException("Current peer body/placement differs from its signed grant.");
        upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
        var policy = new MailboxPeerWireVerificationPolicyV2
        {
            ExpectedOperation = expectedOperation,
            Epoch = scope.Grant.Epoch,
            OperationId = decoded.OperationId,
            SenderRouterId = decoded.SenderRouterId,
            RecipientRouterId = decoded.RecipientRouterId,
            MembershipCommitment = scope.Grant.MembershipCommitment,
            PlacementCommitment = scope.Grant.PlacementCommitment,
            PlacementId = placement,
            NowUnixSeconds = upper,
            // Canonical object retention must be identical for Store and ACK
            // after network renewal. Independent current host/MGR/grant leases
            // above and around every effect remain the admission authority.
            EpochExpiresAtUnixSeconds = decoded.ExpiresAtUnixSeconds
        };
        _ = MailboxPeerWireV2Codec.VerifyReplayCandidate(owned, policy, crypto, proofs);
        // Authenticate the complete candidate before recovery; even a completed
        // replay cannot bypass this owner. The SAME role leases remain held
        // before rate/replay/mutation, without a synthetic client request.
        await RequireOperationCustodyAsync(scope, ct).ConfigureAwait(false);
        upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
        policy = policy with { NowUnixSeconds = upper };
        _ = MailboxPeerWireV2Codec.VerifyReplayCandidate(owned, policy, crypto, proofs);
        RequireRate(decoded.SenderRouterId.Span, upper);
        var verified = MailboxPeerWireV2Codec.VerifyAndReserve(owned, policy, crypto, proofs, replay);
        _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
        var result = await action(new PeerOperation(this, scope, verified, owned, localRole), ct).ConfigureAwait(false);
        _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
        await RequireOperationCustodyAsync(scope, ct).ConfigureAwait(false);
        return result;
    }

    internal sealed class PeerOperation(CurrentMailboxReplicaReceiver owner, CurrentMailboxAdmission.GrantScope scope,
        VerifiedMailboxPeerWireRequestV2 verified, byte[] exact, MailboxPeerWireResponseReplicaV2 localRole)
    {
        internal VerifiedMailboxPeerWireRequestV2 Verified => verified;
        internal ReadOnlyMemory<byte> CanonicalRequest => exact.ToArray();
        internal VerifiedOnionNextHopTransport RecipientTransport => scope.Replicas.Single(
            replica => Fixed(replica.NodeId.Span, verified.Request.RecipientRouterId.Span)).Transport;
        internal async ValueTask EnsureCurrentAsync(CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref owner.disposed) != 0, owner);
            _ = await scope.Lease.CheckAsync(token).ConfigureAwait(false);
            await owner.RequireOperationCustodyAsync(scope, token).ConfigureAwait(false);
            ObjectDisposedException.ThrowIf(Volatile.Read(ref owner.disposed) != 0, owner);
        }
        internal async ValueTask<ReadOnlyMemory<byte>> ApplyAndSignLocalAsync(CancellationToken token)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var mutation = await owner.Mutations.ApplyCurrentAsync(verified, scope.Lease, token).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(mutation.Error)) throw new InvalidDataException("Current peer durable mutation was rejected.");
            var durableAt = await scope.Lease.CheckAsync(token).ConfigureAwait(false);
            var receipt = MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(verified,
                localRole, mutation.Disposition, verified.ReplayClaim.ReservedAtUnixSeconds, durableAt);
            var result = MailboxReceiptV2Codec.EncodeReplica(owner.crypto.SignReplicaResponse(receipt, owner.seed));
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
        internal async ValueTask CommitRecipientAsync(ReadOnlyMemory<byte> response, CancellationToken token)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            _ = MailboxPeerWireV2Codec.VerifyReplicaResponse(response.Span, verified, owner.crypto);
            owner.Replay.CompleteAtomically(verified.ReplayClaim, response);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
        }
        internal async ValueTask<ReadOnlyMemory<byte>> CreateQuorumAsync(ReadOnlyMemory<byte> local,
            ReadOnlyMemory<byte> remote, CancellationToken token)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var unsigned = MailboxPeerWireV2Codec.CreateUnsignedDurableQuorumResponse(verified, local.Span,
                remote.Span, owner.Admission.LocalNodeId, owner.crypto);
            var result = MailboxReceiptV3Codec.EncodeDurableQuorum(owner.crypto.SignQuorumResponse(unsigned, owner.seed));
            _ = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(result, verified, owner.crypto);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
        internal async ValueTask ValidateQuorumAsync(ReadOnlyMemory<byte> quorum, CancellationToken token)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            _ = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(quorum.Span, verified, owner.crypto);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
        }
    }

    private sealed class CurrentProofs(CurrentMailboxAdmission.GrantScope scope, byte[] exactProof)
        : IMailboxReplicaMembershipProofVerifier
    {
        public bool VerifyStorageReplica(MailboxReplicaMembershipProof proof, ulong verificationTimeUnixSeconds)
        {
            scope.Lease.RequireActive();
            var replica = scope.Replicas.SingleOrDefault(fact => Fixed(fact.NodeId.Span, proof.ReplicaId.Span));
            return replica is not null && proof.Epoch == scope.Grant.Epoch &&
                Fixed(proof.MembershipCommitment.Span, scope.Grant.MembershipCommitment.Span) &&
                Fixed(proof.SigningPublicKey.Span, replica.SigningPublicKey.Span) &&
                Fixed(proof.CanonicalInclusionProof.Span, exactProof);
        }
    }
    private void RequireRate(ReadOnlySpan<byte> sender, ulong now)
    {
        var key = Convert.ToHexString(SHA256.HashData(sender));
        if (!rates.TryGetValue(key, out var window) || now >= checked(window.Start + 60))
        {
            foreach (var expired in rates.Where(pair => now >= checked(pair.Value.Start + 60)).Select(pair => pair.Key).ToArray())
                rates.Remove(expired);
            if (rates.Count >= 4096) throw new InvalidOperationException("Current peer ingress partitions are full.");
            window = (now, 0);
        }
        if (window.Count >= 120) throw new InvalidOperationException("Current peer ingress rate is exceeded.");
        rates[key] = (window.Start, window.Count + 1);
    }
    public void Dispose()
    { if (Interlocked.Exchange(ref disposed, 1) == 0) CryptographicOperations.ZeroMemory(seed); }
    private static byte[] CaptureSeed(ReadOnlyMemory<byte> value) => value.Length == 32
        ? value.ToArray() : throw new ArgumentException("Current node signing seed must be 32 bytes.", nameof(value));
    private static bool Fixed(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) =>
        first.Length == second.Length && CryptographicOperations.FixedTimeEquals(first, second);
}
