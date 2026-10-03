using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>Current DR-0081 peer proof -> native replay -> guarded durable
/// mutation -> descriptor-key receipt. No P04, raw policy/time, or UTC fallback.</summary>
internal sealed class CurrentMailboxReplicaReceiver(CurrentMailboxAdmission admission,
    MailboxPeerMutationStore mutations, DurableMailboxPeerReplayJournal replay,
    ReadOnlyMemory<byte> localSigningSeed) : IDisposable
{
    private readonly byte[] seed = CaptureSeed(localSigningSeed);
    private readonly SodiumMailboxPeerReplicationCrypto crypto = new();
    private readonly Dictionary<string, (ulong Start, int Count)> rates = new(StringComparer.Ordinal);
    private int disposed;

    internal async ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(ReadOnlyMemory<byte> canonicalRequest,
        MailboxPeerReplicationOperation expectedOperation, CancellationToken token = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        var decoded = MailboxPeerWireV2Codec.Decode(canonicalRequest.Span);
        var owned = MailboxPeerWireV2Codec.Encode(decoded);
        if (decoded.Operation != expectedOperation || !Fixed(decoded.RecipientRouterId.Span, admission.LocalNodeId.Span))
            throw new CryptographicException("Current peer operation or local recipient differs.");
        var first = decoded.SenderMembershipProof.CanonicalInclusionProof;
        var second = decoded.RecipientMembershipProof.CanonicalInclusionProof;
        if (first.Length != 342 || !Fixed(first.Span, second.Span))
            throw new CryptographicException("Current peer proofs must name one exact projection and grant.");
        var exactGrant = first[38..].ToArray();
        var role = expectedOperation == MailboxPeerReplicationOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve;
        return await admission.WithGrantAsync(exactGrant, role, async (scope, ct) =>
        {
            if (!Fixed(first.Span[..38], scope.Host.ProjectionReference.Span))
                throw new CryptographicException("Current peer projection differs from the signed host.");
            var proofs = new CurrentProofs(scope, first.ToArray());
            var upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            if (!proofs.VerifyStorageReplica(decoded.SenderMembershipProof, upper) ||
                !proofs.VerifyStorageReplica(decoded.RecipientMembershipProof, upper) ||
                !Fixed(crypto.GetPublicKey(seed), decoded.RecipientMembershipProof.SigningPublicKey.Span))
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
                decoded.Epoch != scope.Host.SelectionEpoch ||
                !Fixed(decoded.MembershipCommitment.Span, scope.Host.MembershipCommitment.Span) ||
                !Fixed(decoded.PlacementCommitment.Span, scope.Grant.PlacementCommitment.Span))
                throw new CryptographicException("Current peer body/placement differs from its signed grant.");
            upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            var policy = new MailboxPeerWireVerificationPolicyV2
            {
                ExpectedOperation = expectedOperation, Epoch = scope.Host.SelectionEpoch,
                OperationId = decoded.OperationId, SenderRouterId = decoded.SenderRouterId,
                RecipientRouterId = admission.LocalNodeId, MembershipCommitment = scope.Host.MembershipCommitment,
                PlacementCommitment = scope.Grant.PlacementCommitment, PlacementId = placement,
                NowUnixSeconds = upper, EpochExpiresAtUnixSeconds = scope.Authority.Network.MaximumRecordExpiryUnixSeconds
            };
            _ = MailboxPeerWireV2Codec.VerifyReplayCandidate(owned, policy, crypto, proofs);
            RequireRate(decoded.SenderRouterId.Span, upper);
            var verified = MailboxPeerWireV2Codec.VerifyAndReserve(owned, policy, crypto, proofs, replay);
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            if (verified.ReplayDisposition == MailboxPeerReplayDisposition.IdempotentCompleted)
                return verified.CachedResponse.ToArray();

            var mutation = await mutations.ApplyCurrentAsync(verified, scope.Lease, ct).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(mutation.Error))
                throw new InvalidDataException("Current peer durable mutation was rejected.");
            var durableAt = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            var receipt = MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(verified,
                mutation.Disposition, verified.ReplayClaim.ReservedAtUnixSeconds, durableAt);
            var response = MailboxReceiptV2Codec.EncodeReplica(crypto.SignReplicaResponse(receipt, seed));
            _ = MailboxPeerWireV2Codec.VerifyReplicaResponse(response, verified, crypto);
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            replay.CompleteAtomically(verified.ReplayClaim, response);
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            return response;
        }, token).ConfigureAwait(false);
    }

    private sealed class CurrentProofs(CurrentMailboxAdmission.GrantScope scope, byte[] exactProof)
        : IMailboxReplicaMembershipProofVerifier
    {
        public bool VerifyStorageReplica(MailboxReplicaMembershipProof proof, ulong verificationTimeUnixSeconds)
        {
            scope.Lease.RequireActive();
            var replica = scope.Replicas.SingleOrDefault(fact => Fixed(fact.NodeId.Span, proof.ReplicaId.Span));
            return replica is not null && proof.Epoch == scope.Host.SelectionEpoch &&
                Fixed(proof.MembershipCommitment.Span, scope.Host.MembershipCommitment.Span) &&
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
