using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

/// <summary>Current-only native admission owner. Endpoint activation and peer
/// quorum remain separate: neither copied replica facts nor a recovered outcome
/// authorize a receipt outside this bounded, protected operation.</summary>
internal sealed class CurrentMailboxAdmission(
    IDeepIdV2ContactStoreAuthoritySource source, IOnionMonotonicClock clock, ReadOnlyMemory<byte> localNodeId,
    FileMailboxGrantRevocationStore deposit, FileMailboxGrantRevocationStore retrieve,
    MailboxAuthenticatedCapabilityRuntime runtime)
{
    private readonly byte[] node = CaptureNode(localNodeId);
    internal ReadOnlyMemory<byte> LocalNodeId => node.ToArray();

    internal async ValueTask<T> WithRequestAsync<T>(ReadOnlyMemory<byte> exactRequest,
        MailboxAuthenticatedOperation operation,
        Func<Request, CancellationToken, ValueTask<T>> action, CancellationToken token = default,
        MailboxClientOperationLedger? storeLedger = null)
    {
        ArgumentNullException.ThrowIfNull(action);
        // The decoder bounds and owns request bytes before any external callback.
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(exactRequest.Span);
        var owned = MailboxAuthenticatedClientRequestCodec.Encode(decoded);
        if (decoded.Binding.Operation != operation)
            throw new CryptographicException("Mailbox outer operation differs from the authenticated body.");
        var grant = decoded.Presentation.Grant;
        var exactGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
        var role = operation == MailboxAuthenticatedOperation.Store ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve;
        return await WithGrantAsync(exactGrant, role, async (scope, ct) =>
        {
            MailboxAuthenticatedRuntimeReservation? reservation = null;
            try
            {
                if (operation == MailboxAuthenticatedOperation.Store && !Fixed(scope.Replicas[0].NodeId.Span, node))
                    throw new CryptographicException("Client Store requires the authenticated PMS2 writer.");
                if (storeLedger is not null)
                {
                    runtime.RequireCurrentStoreHolder(owned, scope.Lease.RequireActive);
                    await storeLedger.EnsureCurrentStorePrefixAsync(
                        MailboxAuthenticatedRequestTranscript.DecodeStoreBody(decoded.Binding.CanonicalRequest.Span),
                        scope.Host, scope.Lease, ct).ConfigureAwait(false);
                }
                var upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
                var policy = new MailboxAuthenticatedVerificationPolicy
                {
                    NetworkId = scope.Host.NetworkId, Epoch = scope.Host.SelectionEpoch,
                    MembershipCommitment = scope.Host.MembershipCommitment,
                    PlacementCommitment = grant.PlacementCommitment,
                    MinimumGeneration = scope.Authority.MailboxAuthority.MinimumGrantGeneration,
                    NowUnixSeconds = upper,
                    TrustedIssuers = [scope.Authority.MailboxAuthority.ResolveIssuer(grant.Domain)]
                };
                reservation = runtime.VerifyCurrent(owned, policy, upper,
                    new CheckedRevocation(grant, scope.Lease.RequireActive), scope.Lease.RequireActive);
                var request = new Request(runtime, reservation, scope, scope.Lease.CheckAsync, scope.Lease.RequireActive);
                await request.EnsureCurrentAsync(ct).ConfigureAwait(false);
                var result = await action(request, ct).ConfigureAwait(false);
                await request.EnsureCurrentAsync(ct).ConfigureAwait(false);
                return result;
            }
            finally { if (reservation is not null) runtime.CleanupRequest(reservation); }
        }, token).ConfigureAwait(false);
    }

    internal async ValueTask<T> WithGrantAsync<T>(ReadOnlyMemory<byte> canonicalGrant, MailboxCapabilityDomain role,
        Func<GrantScope, CancellationToken, ValueTask<T>> action, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(canonicalGrant.Span);
        var exactGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(grant);
        if (grant.Domain != role) throw new CryptographicException("Current grant role differs from the operation.");
        var authority = await source.ReadPublicationAuthorityAsync(token).ConfigureAwait(false);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(authority.Network, authority.Authority,
            authority.MailboxAuthority.ExactPma2, authority.TrustedTime, token).ConfigureAwait(false);
        var replicas = await host.ResolveGrantReplicasAsync(exactGrant, token).ConfigureAwait(false);
        var protectedHistory = OnionNetworkProtectedHistoryCodec.Encode(authority.Network);
        if (replicas.Count != 2 || !replicas.Any(replica => Fixed(replica.NodeId.Span, node)))
            throw new CryptographicException("The local node is not a selected mailbox replica.");
        byte[] policyReference = [.. "PMA2"u8, 0, 1, .. authority.MailboxAuthority.CoreHash.Span];
        deposit.RequireScope(node, host.NetworkId.Span, policyReference, MailboxCapabilityDomain.Deposit);
        retrieve.RequireScope(node, host.NetworkId.Span, policyReference, MailboxCapabilityDomain.Retrieve);

        // All consumers take the two protected owners in this order. A successor
        // cannot commit between a revocation check and a mailbox/outcome effect.
        return await deposit.WithCurrentAsync(host, (depositLease, ct) =>
            retrieve.WithCurrentAsync(host, async (retrieveLease, innerToken) =>
            {
                var active = true;
                void RequireActive()
                {
                    if (!Volatile.Read(ref active)) throw new InvalidOperationException("Current mailbox operation is closed.");
                    depositLease.RequireActive(); retrieveLease.RequireActive();
                }
                var roleLease = grant.Domain == MailboxCapabilityDomain.Deposit ? depositLease : retrieveLease;
                async ValueTask<ulong> CheckAsync(CancellationToken checkToken)
                {
                    RequireActive(); checkToken.ThrowIfCancellationRequested();
                    var current = await source.ReadPublicationAuthorityAsync(checkToken).ConfigureAwait(false);
                    RequireActive();
                    if (!Fixed(current.Network.NetworkId.Span, host.NetworkId.Span) ||
                        !current.Network.BindsProjection(host.ProjectionReference) ||
                        !Fixed(OnionNetworkProtectedHistoryCodec.Encode(current.Network), protectedHistory) ||
                        !Fixed(current.Authority.AuthorityCoreReference.Span, authority.Authority.AuthorityCoreReference.Span) ||
                        !Fixed(current.MailboxAuthority.CoreHash.Span, authority.MailboxAuthority.CoreHash.Span))
                        throw new CryptographicException("Current mailbox authority changed during the operation.");
                    var currentHost = await MailboxHostAuthorityV2Verifier.VerifyAsync(current.Network, current.Authority,
                        current.MailboxAuthority.ExactPma2, current.TrustedTime, checkToken).ConfigureAwait(false);
                    RequireActive();
                    await currentHost.EnsureGrantCurrentAsync(exactGrant, checkToken).ConfigureAwait(false);
                    RequireActive();
                    await depositLease.EnsureCurrentAsync(checkToken).ConfigureAwait(false);
                    RequireActive();
                    await retrieveLease.EnsureCurrentAsync(checkToken).ConfigureAwait(false);
                    RequireActive();
                    await roleLease.EnsureGrantNotRevokedAsync(exactGrant, checkToken).ConfigureAwait(false);
                    RequireActive();
                    var reading = await clock.ReadAsync(checkToken).ConfigureAwait(false);
                    RequireActive(); checkToken.ThrowIfCancellationRequested();
                    var freshness = current.Freshness;
                    if (!Fixed(freshness.NetworkId.Span, host.NetworkId.Span) ||
                        !freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
                        throw new CryptographicException("Current mailbox trusted interval is unavailable.");
                    var elapsed = checked(reading.SampleSeconds - freshness.MonotonicSample);
                    var lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
                    var upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
                    if (lower < grant.NotBeforeUnixSeconds || upper >= grant.ExpiresAtUnixSeconds)
                        throw new CryptographicException("Current mailbox grant does not cover the full trusted interval.");
                    // Recheck the same closed host after the final clock callback.
                    await host.EnsureGrantCurrentAsync(exactGrant, checkToken).ConfigureAwait(false);
                    RequireActive(); checkToken.ThrowIfCancellationRequested();
                    return upper;
                }

                try
                {
                    var scope = new GrantScope(this, authority, host, replicas, grant,
                        new MailboxCurrentOperationLease(CheckAsync, RequireActive));
                    _ = await scope.Lease.CheckAsync(innerToken).ConfigureAwait(false);
                    var result = await action(scope, innerToken).ConfigureAwait(false);
                    _ = await scope.Lease.CheckAsync(innerToken).ConfigureAwait(false);
                    return result;
                }
                finally { Volatile.Write(ref active, false); }
            }, ct), token).ConfigureAwait(false);
    }

    internal sealed record GrantScope(CurrentMailboxAdmission Owner, DeepIdV2ContactStoreAuthority Authority,
        VerifiedMailboxHostAuthorityV2 Host, IReadOnlyList<VerifiedMailboxReplicaV2> Replicas,
        MailboxAuthenticatedGrant Grant, MailboxCurrentOperationLease Lease);

    internal sealed class Request(MailboxAuthenticatedCapabilityRuntime runtime,
        MailboxAuthenticatedRuntimeReservation reservation,
        GrantScope scope,
        Func<CancellationToken, ValueTask<ulong>> check, Action requireActive)
    {
        internal GrantScope Scope { get { requireActive(); return scope; } }
        internal MailboxAuthenticatedReplayDisposition ReplayDisposition
        { get { requireActive(); return reservation.ReplayDisposition; } }
        internal MailboxClientCanonicalOutcome? RecoveredOutcome
        { get { requireActive(); return reservation.RecoveredOutcome; } }
        internal async ValueTask EnsureCurrentAsync(CancellationToken token = default) =>
            _ = await check(token).ConfigureAwait(false);
        internal async ValueTask<bool> TryAcquireExecutionAsync(CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return runtime.TryAcquireExecution(reservation);
        }
        internal async ValueTask ReserveOutcomeCapacityAsync(int maximumBytes, CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            runtime.ReserveOutcomeCapacity(reservation, maximumBytes);
        }
        internal async ValueTask<MailboxClientCanonicalOutcome> PersistTerminalAsync(
            MailboxClientTerminalOutcome terminal, CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var result = runtime.PersistTerminal(reservation, terminal);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
        internal async ValueTask<MailboxClientCanonicalOutcome> PersistSuccessAsync(
            ReadOnlyMemory<byte> exactOutcome, int maximumBytes, CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var result = runtime.PersistSuccess(reservation, exactOutcome, maximumBytes);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
        internal async ValueTask<MailboxClientCanonicalOutcome> CompleteRecoveredAsync(CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var result = runtime.CompletePersistedOutcome(reservation);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
    }

    // This answers only the exact query already checked against the actual native
    // floor under both live leases. Absence, a candidate, or configuration can
    // never manufacture negative revocation authority.
    private sealed class CheckedRevocation(MailboxAuthenticatedGrant grant, Action requireActive)
        : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query)
        {
            requireActive();
            return query.Domain != grant.Domain || query.Generation != grant.Generation || query.Epoch != grant.Epoch ||
                !Fixed(query.IssuerPublicKey.Span, grant.IssuerPublicKey.Span) || !Fixed(query.Serial.Span, grant.Serial.Span) ||
                !Fixed(query.MembershipCommitment.Span, grant.MembershipCommitment.Span);
        }
    }
    private static byte[] CaptureNode(ReadOnlyMemory<byte> id) => id.Length == 32 && id.Span.IndexOfAnyExcept((byte)0) >= 0
        ? id.ToArray() : throw new ArgumentException("Local canonical node ID must be nonzero 32 bytes.", nameof(id));
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
