using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

/// <summary>Current authority native admission owner. Store requires current
/// selection; Retrieve/ACK require the exact verified retained selection.
/// Endpoint activation and peer
/// quorum remain separate: neither copied replica facts nor a recovered outcome
/// authorize a receipt outside this bounded, protected operation.</summary>
internal sealed partial class CurrentMailboxAdmission(
    IDeepIdV2ContactStoreAuthoritySource source, IOnionMonotonicClock clock, ReadOnlyMemory<byte> localNodeId,
    FileMailboxGrantRevocationStore deposit, FileMailboxGrantRevocationStore retrieve,
    MailboxAuthenticatedCapabilityRuntime runtime)
{
    private readonly byte[] node = CaptureNode(localNodeId);
    private readonly MailboxClientVerifiedHolderLimiter holderLimiter = new();
    internal ReadOnlyMemory<byte> LocalNodeId => node.ToArray();

    internal void ValidateNewNativeScope(CancellationToken token) => runtime.ValidateNewNativeScope(token);

    internal void ValidateNativeRecovery(HostScope scope, CancellationToken token)
    {
        if (!ReferenceEquals(scope.Owner, this))
            throw new InvalidOperationException("Native recovery requires this admission owner.");
        scope.Lease.RequireActive();
        runtime.ValidateNativeRecovery(token);
        scope.Lease.RequireActive();
    }

    internal async ValueTask<T> WithRequestAsync<T>(ReadOnlyMemory<byte> exactRequest,
        MailboxAuthenticatedOperation operation,
        Func<Request, CancellationToken, ValueTask<T>> action, CancellationToken token = default,
        MailboxClientOperationLedger? operationLedger = null, MailboxPeerMutationStore? storeMutations = null,
        Action<GrantScope>? requireSigningCustody = null,
        Func<IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor>, MailboxCurrentOperationLease,
            CancellationToken, Task>? validatePeerCustody = null)
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
                runtime.RequireCurrentHolder(owned, scope.Lease.RequireActive);
                requireSigningCustody?.Invoke(scope);
                // The host already authenticated the grant-selected pair and
                // issuer; holder authentication precedes this memory-only budget.
                // No host UTC, caller time or durable replay floor is involved.
                if (!holderLimiter.TryAccept(grant.HolderPublicKey.Span, operation,
                    checked((ulong)(Stopwatch.GetTimestamp() / Stopwatch.Frequency))))
                    throw new CurrentMailboxHolderRateLimitException();
                if (operationLedger is not null)
                {
                    if (operation == MailboxAuthenticatedOperation.Store && storeMutations is not null)
                    {
                        await operationLedger.EnsureCurrentStorePrefixAsync(
                            MailboxAuthenticatedRequestTranscript.DecodeStoreBody(decoded.Binding.CanonicalRequest.Span),
                            scope.Host, scope.Lease, storeMutations, ct).ConfigureAwait(false);
                    }
                    // Prefix inspection is denial-only: no mutation, replay,
                    // receipt or HTTP. Join a fresh authenticated snapshot AFTER
                    // its callbacks and BEFORE the first client reservation.
                    await operationLedger.InitializeCurrentAsync(node, scope.Host, scope.Lease, ct,
                        runtime.ValidateCurrentNativeRecovery, validatePeerCustody is null ? null :
                            (floors, peerToken) => validatePeerCustody(floors, scope.Lease, peerToken)).ConfigureAwait(false);
                }
                var upper = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
                var policy = new MailboxAuthenticatedVerificationPolicy
                {
                    NetworkId = scope.Host.NetworkId, Epoch = scope.Grant.Epoch,
                    MembershipCommitment = scope.Grant.MembershipCommitment,
                    PlacementCommitment = grant.PlacementCommitment,
                    MinimumGeneration = scope.Authority.MailboxAuthority.MinimumGrantGeneration,
                    NowUnixSeconds = upper,
                    TrustedIssuers = [scope.Authority.MailboxAuthority.ResolveIssuer(grant.Domain)]
                };
                reservation = runtime.VerifyCurrent(owned, policy, upper,
                    new CheckedRevocation(grant, scope.Lease.RequireActive), scope.Lease.RequireActive);
                if (operationLedger is not null)
                    await operationLedger.RecordCurrentClientReplayAsync(reservation.Verified.Capability.ReplayClaim,
                        null, scope.Lease, ct).ConfigureAwait(false);
                async ValueTask<ulong> CheckRequestAsync(CancellationToken checkToken)
                {
                    requireSigningCustody?.Invoke(scope);
                    var now = operationLedger is null
                        ? await scope.Lease.CheckAsync(checkToken).ConfigureAwait(false)
                        : await operationLedger.InitializeCurrentAsync(node, scope.Host, scope.Lease, checkToken,
                            runtime.ValidateCurrentNativeRecovery, validatePeerCustody is null ? null :
                                (floors, peerToken) => validatePeerCustody(floors, scope.Lease, peerToken)).ConfigureAwait(false);
                    requireSigningCustody?.Invoke(scope);
                    return now;
                }
                async ValueTask RecordCompletionAsync(ReadOnlyMemory<byte> outcome, CancellationToken completionToken)
                {
                    if (operationLedger is not null)
                        await operationLedger.RecordCurrentClientReplayAsync(reservation.Verified.Capability.ReplayClaim,
                            outcome, scope.Lease, completionToken).ConfigureAwait(false);
                }
                var request = new Request(runtime, reservation, scope, CheckRequestAsync, scope.Lease.RequireActive,
                    RecordCompletionAsync);
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
        return await WithAuthorityAsync(exactGrant, grant, (scope, ct) => action(new GrantScope(this,
            scope.Authority, scope.Host, scope.Replicas, grant, scope.Lease), ct), token).ConfigureAwait(false);
    }

    // Native startup/recovery needs independently current host authority, not a
    // synthetic client grant. Both role owners are still held for the callback.
    internal ValueTask<T> WithHostAsync<T>(Func<HostScope, CancellationToken, ValueTask<T>> action,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(action);
        return WithAuthorityAsync(null, null, (scope, ct) => action(new HostScope(this,
            scope.Authority, scope.Host, scope.Lease), ct), token);
    }

    internal ValueTask<bool> InitializeOperationsAsync(MailboxClientOperationLedger ledger, CancellationToken token = default) =>
        WithHostAsync(async (scope, ct) =>
        {
            await ledger.InitializeCurrentAsync(node, scope.Host, scope.Lease, ct,
                runtime.ValidateCurrentNativeRecovery).ConfigureAwait(false);
            return true;
        }, token);

    internal Task InitializeHostOperationsAsync(MailboxClientOperationLedger ledger, HostScope scope, CancellationToken token,
        Func<IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor>, CancellationToken, Task>? validatePeer = null)
    {
        if (!ReferenceEquals(scope.Owner, this)) throw new InvalidOperationException("Recovery scope differs.");
        return ledger.InitializeCurrentAsync(node, scope.Host, scope.Lease, token, runtime.ValidateCurrentNativeRecovery, validatePeer);
    }

    internal Task<ulong> InitializeGrantOperationsAsync(MailboxClientOperationLedger ledger, GrantScope scope, CancellationToken token,
        Func<IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor>, CancellationToken, Task>? validatePeer = null)
    {
        if (!ReferenceEquals(scope.Owner, this)) throw new InvalidOperationException("Operation scope differs.");
        return ledger.InitializeCurrentAsync(node, scope.Host, scope.Lease, token, runtime.ValidateCurrentNativeRecovery, validatePeer);
    }

    internal ValueTask<bool> EnrollNewOperationsAsync(MailboxClientOperationLedger ledger, CancellationToken token = default) =>
        WithHostAsync(async (scope, ct) =>
        {
            await ledger.EnrollNewCurrentAsync(node, scope.Host, scope.Lease, ct).ConfigureAwait(false);
            return true;
        }, token);

    private async ValueTask<T> WithAuthorityAsync<T>(byte[]? exactGrant, MailboxAuthenticatedGrant? grant,
        Func<AuthorityScope, CancellationToken, ValueTask<T>> action, CancellationToken token)
    {
        var authority = await source.ReadPublicationAuthorityAsync(token).ConfigureAwait(false);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(authority.Network, authority.Authority,
            authority.MailboxAuthority.ExactPma2, authority.TrustedTime, token).ConfigureAwait(false);
        _ = await host.ResolveReplicaAsync(node, token).ConfigureAwait(false);
        IReadOnlyList<VerifiedMailboxReplicaV2> replicas = exactGrant is null ? [] :
            grant!.Domain == MailboxCapabilityDomain.Retrieve
                ? await host.GetSelectedRetainedReadReplicasAsync(exactGrant, token).ConfigureAwait(false)
                : await host.ResolveGrantReplicasAsync(exactGrant, token).ConfigureAwait(false);
        var protectedHistory = OnionNetworkProtectedHistoryCodec.Encode(authority.Network);
        if (exactGrant is not null && (replicas.Count != 2 || !replicas.Any(replica => Fixed(replica.NodeId.Span, node))))
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
                var roleLease = grant?.Domain == MailboxCapabilityDomain.Deposit ? depositLease : retrieveLease;
                async ValueTask<ulong> CheckAsync(CancellationToken checkToken)
                {
                    using var measurement = CurrentMailboxDiagnostics.Measure("lease-check");
                    RequireActive(); checkToken.ThrowIfCancellationRequested();
                    DeepIdV2ContactStoreAuthority current;
                    using (CurrentMailboxDiagnostics.Measure("authority-source"))
                        current = await source.ReadPublicationAuthorityAsync(checkToken).ConfigureAwait(false);
                    RequireActive();
                    if (!Fixed(current.Network.NetworkId.Span, host.NetworkId.Span) ||
                        !current.Network.BindsProjection(host.ProjectionReference) ||
                        !Fixed(OnionNetworkProtectedHistoryCodec.Encode(current.Network), protectedHistory) ||
                        !Fixed(current.Authority.AuthorityCoreReference.Span, authority.Authority.AuthorityCoreReference.Span) ||
                        !Fixed(current.MailboxAuthority.CoreHash.Span, authority.MailboxAuthority.CoreHash.Span))
                        throw new CryptographicException("Current mailbox authority changed during the operation.");
                    VerifiedMailboxHostAuthorityV2 currentHost;
                    using (CurrentMailboxDiagnostics.Measure("host-verify"))
                        currentHost = await MailboxHostAuthorityV2Verifier.VerifyAsync(current.Network, current.Authority,
                            current.MailboxAuthority.ExactPma2, current.TrustedTime, checkToken).ConfigureAwait(false);
                    RequireActive();
                    await RequireGrantCurrentAsync(currentHost, checkToken).ConfigureAwait(false);
                    RequireActive();
                    // The grant-specific Protocol method checks its role's
                    // actual protected floor before AND after serial validation.
                    // Check the other role separately; do not read the grant
                    // role a third time immediately before that same boundary.
                    if (grant?.Domain != MailboxCapabilityDomain.Deposit)
                        await depositLease.EnsureCurrentAsync(checkToken).ConfigureAwait(false);
                    RequireActive();
                    if (grant?.Domain != MailboxCapabilityDomain.Retrieve)
                        await retrieveLease.EnsureCurrentAsync(checkToken).ConfigureAwait(false);
                    RequireActive();
                    if (exactGrant is not null)
                    {
                        if (grant!.Domain == MailboxCapabilityDomain.Retrieve)
                            await roleLease.EnsureRetainedReadGrantNotRevokedAsync(exactGrant, checkToken).ConfigureAwait(false);
                        else await roleLease.EnsureGrantNotRevokedAsync(exactGrant, checkToken).ConfigureAwait(false);
                    }
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
                    if (grant is not null && (lower < grant.NotBeforeUnixSeconds || upper >= grant.ExpiresAtUnixSeconds))
                        throw new CryptographicException("Current mailbox grant does not cover the full trusted interval.");
                    // Recheck the same closed host after the final clock callback.
                    await RequireGrantCurrentAsync(host, checkToken).ConfigureAwait(false);
                    RequireActive(); checkToken.ThrowIfCancellationRequested();
                    return upper;
                }

                async ValueTask RequireGrantCurrentAsync(VerifiedMailboxHostAuthorityV2 actualHost, CancellationToken checkToken)
                {
                    if (exactGrant is null) await actualHost.EnsureCurrentAsync(checkToken).ConfigureAwait(false);
                    else if (grant!.Domain == MailboxCapabilityDomain.Retrieve)
                    {
                        var selected = await actualHost.GetSelectedRetainedReadReplicasAsync(exactGrant, checkToken).ConfigureAwait(false);
                        if (selected.Count != replicas.Count || selected.Where((fact, index) =>
                            !Fixed(fact.NodeId.Span, replicas[index].NodeId.Span) ||
                            !Fixed(fact.SigningPublicKey.Span, replicas[index].SigningPublicKey.Span)).Any())
                            throw new CryptographicException("Retained read changed its selected current descriptor custody.");
                    }
                    else await actualHost.EnsureGrantCurrentAsync(exactGrant, checkToken).ConfigureAwait(false);
                }

                try
                {
                    var scope = new AuthorityScope(authority, host, replicas,
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
        MailboxAuthenticatedGrant Grant, MailboxCurrentOperationLease Lease)
    {
        // This scope is created only after current host selection/issuer checks
        // and both protected MGR1 owners. These are exact grant-selected facts,
        // never a caller-supplied historical projection authority.
        internal ReadOnlyMemory<byte> ProjectionReference =>
            ContactCodec.DecodeArtifactReference(
                [.. "PMT2"u8, 0, 1, .. Grant.MembershipCommitment.Span], ProtocolMagic.PMT2).CanonicalBytes;
    }

    internal sealed record HostScope(CurrentMailboxAdmission Owner, DeepIdV2ContactStoreAuthority Authority,
        VerifiedMailboxHostAuthorityV2 Host, MailboxCurrentOperationLease Lease);
    private sealed record AuthorityScope(DeepIdV2ContactStoreAuthority Authority,
        VerifiedMailboxHostAuthorityV2 Host, IReadOnlyList<VerifiedMailboxReplicaV2> Replicas,
        MailboxCurrentOperationLease Lease);

    internal sealed class Request(MailboxAuthenticatedCapabilityRuntime runtime,
        MailboxAuthenticatedRuntimeReservation reservation,
        GrantScope scope,
        Func<CancellationToken, ValueTask<ulong>> check, Action requireActive,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> recordCompletion)
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
            await recordCompletion(result.CanonicalBytes, token).ConfigureAwait(false);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
        internal async ValueTask<MailboxClientCanonicalOutcome> PersistSuccessAsync(
            ReadOnlyMemory<byte> exactOutcome, int maximumBytes, CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var result = runtime.PersistSuccess(reservation, exactOutcome, maximumBytes);
            await recordCompletion(result.CanonicalBytes, token).ConfigureAwait(false);
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            return result;
        }
        internal async ValueTask<MailboxClientCanonicalOutcome> CompleteRecoveredAsync(CancellationToken token = default)
        {
            await EnsureCurrentAsync(token).ConfigureAwait(false);
            var result = runtime.CompletePersistedOutcome(reservation);
            await recordCompletion(result.CanonicalBytes, token).ConfigureAwait(false);
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
