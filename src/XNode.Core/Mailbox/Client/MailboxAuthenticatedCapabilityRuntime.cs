using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed record MailboxCapabilityAuthorityQuery(
    MailboxAuthenticatedOperation Operation,
    MailboxCapabilityDomain Domain,
    ulong Epoch,
    ulong Generation,
    MailboxCapabilityLifecycle Lifecycle,
    ReadOnlyMemory<byte> NetworkId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    ReadOnlyMemory<byte> IssuerPublicKey);

/// <summary>
/// Resolves only externally trusted issuer and epoch policy. Implementations must never derive
/// trust from values merely because they appeared in an untrusted MCG2 grant.
/// </summary>
public interface IMailboxCapabilityAuthoritySource
{
    bool IsConfigured { get; }

    bool TryResolve(
        MailboxCapabilityAuthorityQuery query,
        out MailboxAuthenticatedVerificationPolicy? policy);

    ulong ReplayValidityEndsAt(
        MailboxCapabilityAuthorityQuery query,
        MailboxAuthenticatedGrant grant) =>
        grant.ExpiresAtUnixSeconds;
}

public interface IMailboxCapabilityRevocationPolicy : IMailboxCapabilityRevocationSource
{
    bool IsConfigured { get; }
}

public sealed class RejectAllMailboxCapabilityAuthoritySource
    : IMailboxCapabilityAuthoritySource
{
    public bool IsConfigured => false;

    public bool TryResolve(
        MailboxCapabilityAuthorityQuery query,
        out MailboxAuthenticatedVerificationPolicy? policy)
    {
        policy = null;
        return false;
    }
}

public sealed class RejectAllMailboxCapabilityRevocationPolicy
    : IMailboxCapabilityRevocationPolicy
{
    public bool IsConfigured => false;

    public bool IsRevoked(MailboxCapabilityRevocationQuery query) => true;
}

public sealed record MailboxAuthenticatedRuntimeStatus(
    bool StrictMau2Decoder,
    bool Ed25519Verifier,
    bool DurableAtomicReplay,
    bool DurableCanonicalOutcomes,
    bool AuthorityConfigured,
    bool RevocationPolicyConfigured,
    bool Ready,
    string Reason);

public sealed class MailboxAuthenticatedRuntimeReservation
{
    private int _sideEffectsStarted;
    private int _executionOwned;
    private int _requestCleanupStarted;
    private MailboxClientCanonicalOutcomeReservation? _outcomeReservation;

    internal MailboxAuthenticatedRuntimeReservation(
        MailboxAuthenticatedCapabilityRuntime owner,
        VerifiedMailboxAuthenticatedClientRequest verified,
        ulong retainUntilUnixSeconds,
        MailboxClientCanonicalOutcomeKey outcomeKey,
        MailboxClientCanonicalOutcome? recoveredOutcome)
    {
        Owner = owner;
        Verified = verified;
        RetainUntilUnixSeconds = retainUntilUnixSeconds;
        OutcomeKey = outcomeKey;
        RecoveredOutcome = recoveredOutcome;
    }

    internal MailboxAuthenticatedCapabilityRuntime Owner { get; }

    public VerifiedMailboxAuthenticatedClientRequest Verified { get; }

    public MailboxAuthenticatedReplayDisposition ReplayDisposition =>
        Verified.Capability.ReplayDisposition;

    public ulong RetainUntilUnixSeconds { get; }

    public MailboxClientCanonicalOutcomeKey OutcomeKey { get; }

    public MailboxClientCanonicalOutcome? RecoveredOutcome { get; }

    public bool SideEffectsStarted => Volatile.Read(ref _sideEffectsStarted) != 0;

    public void MarkSideEffectsStarted() =>
        Interlocked.Exchange(ref _sideEffectsStarted, 1);

    internal void AttachOutcomeReservation(
        MailboxClientCanonicalOutcomeReservation reservation)
    {
        ArgumentNullException.ThrowIfNull(reservation);
        if (Interlocked.CompareExchange(
                ref _outcomeReservation,
                reservation,
                null) is not null)
        {
            reservation.Dispose();
            throw new InvalidOperationException(
                "Canonical outcome capacity is already reserved.");
        }
    }

    internal MailboxClientCanonicalOutcomeReservation RequireOutcomeReservation() =>
        Volatile.Read(ref _outcomeReservation)
        ?? throw new InvalidOperationException(
            "Canonical outcome capacity was not reserved before mailbox work.");

    internal void ConsumeOutcomeReservation(
        MailboxClientCanonicalOutcomeReservation reservation)
    {
        if (!ReferenceEquals(
                Interlocked.CompareExchange(
                    ref _outcomeReservation,
                    null,
                    reservation),
                reservation))
        {
            throw new InvalidOperationException(
                "Canonical outcome reservation ownership is invalid.");
        }
    }

    internal void ReleaseOutcomeReservation() =>
        Interlocked.Exchange(ref _outcomeReservation, null)?.Dispose();

    internal bool TryOwnExecution() =>
        Interlocked.CompareExchange(ref _executionOwned, 1, 0) == 0;

    internal bool ReleaseExecutionOwnership() =>
        Interlocked.Exchange(ref _executionOwned, 0) != 0;

    internal bool OwnsExecution =>
        Volatile.Read(ref _executionOwned) != 0;

    internal bool TryBeginRequestCleanup() =>
        Interlocked.CompareExchange(ref _requestCleanupStarted, 1, 0) == 0;

    internal void ResetRequestCleanup() =>
        Interlocked.Exchange(ref _requestCleanupStarted, 0);
}

/// <summary>
/// Native MAU2 verification and durable replay reservation boundary. This type performs no
/// mailbox storage or replica fanout. Completed replay records contain only a digest; the exact
/// canonical response is recovered from the separate durable outcome store.
/// </summary>
public sealed class MailboxAuthenticatedCapabilityRuntime
{
    private readonly IMailboxCapabilityAuthoritySource _authority;
    private readonly IMailboxCapabilityRevocationPolicy _revocations;
    private readonly DurableMailboxCapabilityReplayJournal _replay;
    private readonly MailboxClientCanonicalOutcomeStore _outcomes;
    private readonly IMailboxAuthenticatedCapabilityCrypto _crypto;
    private readonly IClock _clock;
    private readonly object _activeGate = new();
    private readonly HashSet<string> _activeExecutions =
        new(StringComparer.Ordinal);

    public MailboxAuthenticatedCapabilityRuntime(
        IMailboxCapabilityAuthoritySource authority,
        IMailboxCapabilityRevocationPolicy revocations,
        DurableMailboxCapabilityReplayJournal replay,
        MailboxClientCanonicalOutcomeStore outcomes,
        IClock? clock = null,
        IMailboxAuthenticatedCapabilityCrypto? crypto = null)
    {
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _revocations = revocations ?? throw new ArgumentNullException(nameof(revocations));
        _replay = replay ?? throw new ArgumentNullException(nameof(replay));
        _outcomes = outcomes ?? throw new ArgumentNullException(nameof(outcomes));
        _clock = clock ?? new SystemClock();
        _crypto = crypto ?? new SodiumMailboxCapabilityCrypto();
    }

    public MailboxAuthenticatedRuntimeStatus Status
    {
        get
        {
            var ready = _authority.IsConfigured && _revocations.IsConfigured;
            return new(
                StrictMau2Decoder: true,
                Ed25519Verifier: true,
                DurableAtomicReplay: true,
                DurableCanonicalOutcomes: true,
                AuthorityConfigured: _authority.IsConfigured,
                RevocationPolicyConfigured: _revocations.IsConfigured,
                Ready: ready,
                Reason: ready ? "" : "issuer-or-revocation-authority-unconfigured");
        }
    }

    public MailboxAuthenticatedRuntimeReservation Verify(
        ReadOnlyMemory<byte> canonicalMau2)
    {
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(canonicalMau2.Span);
        var grant = decoded.Presentation.Grant;
        var query = new MailboxCapabilityAuthorityQuery(
            decoded.Binding.Operation,
            grant.Domain,
            grant.Epoch,
            grant.Generation,
            grant.Lifecycle,
            grant.NetworkId.ToArray(),
            grant.PlacementCommitment.ToArray(),
            grant.MembershipCommitment.ToArray(),
            grant.IssuerPublicKey.ToArray());
        if (!_authority.TryResolve(query, out var configured) || configured is null)
        {
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.UntrustedIssuer,
                "Mailbox capability issuer authority is unavailable.");
        }

        var body = decoded.Binding.CanonicalRequest.Span;
        var bodyEpoch = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(8, 8));
        if (bodyEpoch != grant.Epoch)
        {
            throw new MailboxAuthenticatedCapabilityException(
                MailboxAuthenticatedCapabilityError.BindingMismatch,
                "Mailbox capability epoch binding failed.");
        }

        var observedNow = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
        var retainUntil = _replay.RetainUntilUnixSeconds(
            Math.Max(
                grant.ExpiresAtUnixSeconds,
                _authority.ReplayValidityEndsAt(query, grant)));
        var replayScope = _replay.CreateEvaluationScope(
            observedNow,
            retainUntil);
        var policy = configured with
        {
            NowUnixSeconds = replayScope.EffectiveNowUnixSeconds
        };
        var verified = MailboxAuthenticatedClientRequestCodec.Verify(
            canonicalMau2.Span,
            policy,
            _crypto,
            _revocations,
            replayScope);
        var claim = verified.Capability.ReplayClaim;
        var outcomeKey = MailboxClientCanonicalOutcomeKey.Create(
            MailboxCapabilityReplayStateMachine.ComputeScopeKey(claim),
            claim.ReplayCounter,
            claim.ClaimDigest.Span);
        MailboxClientCanonicalOutcome? recoveredOutcome = null;
        if (verified.Capability.ReplayDisposition
            == MailboxAuthenticatedReplayDisposition.IdempotentCompleted)
        {
            recoveredOutcome = _outcomes.ReadRequired(
                outcomeKey,
                verified.Binding.Operation);
            var recoveredDigest = SHA256.HashData(recoveredOutcome.CanonicalBytes.Span);
            if (!CryptographicOperations.FixedTimeEquals(
                    recoveredDigest,
                    verified.Capability.CachedOutcome.Span))
            {
                throw new InvalidDataException(
                    "The durable mailbox outcome does not match its replay digest.");
            }
        }
        else if (verified.Capability.ReplayDisposition
                     == MailboxAuthenticatedReplayDisposition.InFlight
                 && _outcomes.TryRead(
                     outcomeKey,
                     verified.Binding.Operation,
                     out recoveredOutcome))
        {
            var recoveredDigest = SHA256.HashData(
                recoveredOutcome!.CanonicalBytes.Span);
            _replay.CompleteAtomically(claim, recoveredDigest);
        }

        return new(
            this,
            verified,
            retainUntil,
            outcomeKey,
            recoveredOutcome);
    }

    public MailboxClientCanonicalOutcome CompletePersistedOutcome(
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        RequireOwned(reservation);
        var persisted = _outcomes.ReadRequired(
            reservation.OutcomeKey,
            reservation.Verified.Binding.Operation);
        var digest = SHA256.HashData(persisted.CanonicalBytes.Span);
        if (reservation.ReplayDisposition
            == MailboxAuthenticatedReplayDisposition.IdempotentCompleted)
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    reservation.Verified.Capability.CachedOutcome.Span,
                    digest))
            {
                throw new InvalidOperationException(
                    "The completed mailbox replay outcome digest conflicts.");
            }

            ReleaseExecution(reservation);
            return persisted;
        }

        _replay.CompleteAtomically(
            reservation.Verified.Capability.ReplayClaim,
            digest);
        ReleaseExecution(reservation);
        return persisted;
    }

    public MailboxClientCanonicalOutcome PersistSuccess(
        MailboxAuthenticatedRuntimeReservation reservation,
        ReadOnlyMemory<byte> canonicalOutcome,
        int maximumCanonicalBytes)
    {
        RequireOwned(reservation);
        reservation.MarkSideEffectsStarted();
        var outcomeReservation = reservation.RequireOutcomeReservation();
        if (outcomeReservation.MaximumCanonicalBytes != maximumCanonicalBytes)
        {
            throw new InvalidOperationException(
                "Canonical outcome capacity does not match the endpoint contract.");
        }

        _outcomes.PutSuccess(outcomeReservation, canonicalOutcome);
        reservation.ConsumeOutcomeReservation(outcomeReservation);
        return CompletePersistedOutcome(reservation);
    }

    public MailboxClientCanonicalOutcome PersistTerminal(
        MailboxAuthenticatedRuntimeReservation reservation,
        MailboxClientTerminalOutcome terminal)
    {
        RequireOwned(reservation);
        reservation.MarkSideEffectsStarted();
        var outcomeReservation = reservation.RequireOutcomeReservation();
        _outcomes.PutTerminal(outcomeReservation, terminal);
        reservation.ConsumeOutcomeReservation(outcomeReservation);
        return CompletePersistedOutcome(reservation);
    }

    public void ReserveOutcomeCapacity(
        MailboxAuthenticatedRuntimeReservation reservation,
        int maximumCanonicalBytes)
    {
        RequireOwned(reservation);
        reservation.AttachOutcomeReservation(
            _outcomes.Reserve(
                reservation.OutcomeKey,
                reservation.Verified.Binding.Operation,
                reservation.RetainUntilUnixSeconds,
                maximumCanonicalBytes));
    }

    public bool TryAcquireExecution(
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        RequireOwned(reservation);
        if (reservation.RecoveredOutcome is not null
            || reservation.ReplayDisposition
                == MailboxAuthenticatedReplayDisposition.IdempotentCompleted
            || !reservation.TryOwnExecution())
        {
            return false;
        }

        var key = Convert.ToHexString(reservation.OutcomeKey.Digest);
        lock (_activeGate)
        {
            if (!_replay.IsExactPending(
                    reservation.Verified.Capability.ReplayClaim))
            {
                reservation.ReleaseExecutionOwnership();
                return false;
            }

            if (_activeExecutions.Add(key))
            {
                return true;
            }
        }

        reservation.ReleaseExecutionOwnership();
        return false;
    }

    internal void ReleaseOutcomeCapacity(
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        RequireOwned(reservation);
        reservation.ReleaseOutcomeReservation();
    }

    internal void EndExecution(
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        RequireOwned(reservation);
        reservation.ReleaseOutcomeReservation();
        ReleaseExecution(reservation);
    }

    internal void AbortIfNew(MailboxAuthenticatedRuntimeReservation reservation)
    {
        RequireOwned(reservation);
        reservation.ReleaseOutcomeReservation();
        if (reservation.ReplayDisposition
                == MailboxAuthenticatedReplayDisposition.NewReserved
            && !reservation.SideEffectsStarted)
        {
            _replay.AbortAtomically(reservation.Verified.Capability.ReplayClaim);
        }

        ReleaseExecution(reservation);
    }

    /// <summary>
    /// Unconditionally closes the HTTP request lifecycle. Cleanup is idempotent and aware of
    /// exact-claim execution ownership: a losing New reservation cannot release a Pending record
    /// that another exact reservation is actively executing.
    /// </summary>
    public void CleanupRequest(
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        RequireOwned(reservation);
        if (!reservation.TryBeginRequestCleanup())
        {
            return;
        }

        try
        {
            reservation.ReleaseOutcomeReservation();
            var abortNew =
                reservation.ReplayDisposition
                    == MailboxAuthenticatedReplayDisposition.NewReserved
                && !reservation.SideEffectsStarted;
            var key = Convert.ToHexString(reservation.OutcomeKey.Digest);
            lock (_activeGate)
            {
                var ownsExecution = reservation.OwnsExecution;
                try
                {
                    if (abortNew
                        && (ownsExecution
                            || !_activeExecutions.Contains(key))
                        && _replay.IsExactPending(
                            reservation.Verified.Capability.ReplayClaim))
                    {
                        _replay.AbortAtomically(
                            reservation.Verified.Capability.ReplayClaim);
                    }
                }
                finally
                {
                    if (ownsExecution
                        && reservation.ReleaseExecutionOwnership())
                    {
                        _activeExecutions.Remove(key);
                    }
                }
            }
        }
        catch
        {
            reservation.ResetRequestCleanup();
            throw;
        }
    }

    /// <summary>
    /// Collects one bounded expiry batch. Replay records are durably marked expired first,
    /// then only their exact canonical outcomes are deleted, and finally the replay markers
    /// are removed. An interrupted batch remains retryable after restart.
    /// </summary>
    public int CollectExpired(
        ulong nowUnixSeconds,
        int maximumEntries)
    {
        if (maximumEntries is < 1 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        lock (_activeGate)
        {
            var collected = _replay.PrepareExpiredCollection(
                nowUnixSeconds,
                maximumEntries,
                _activeExecutions);
            foreach (var item in collected)
            {
                _outcomes.DeleteExpired(
                    item.OutcomeKey,
                    item.EffectiveNowUnixSeconds);
            }

            _replay.CompleteExpiredCollection(collected);
            return collected.Count;
        }
    }

    private void ReleaseExecution(
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        if (!reservation.ReleaseExecutionOwnership())
        {
            return;
        }

        var key = Convert.ToHexString(reservation.OutcomeKey.Digest);
        lock (_activeGate)
        {
            if (!_activeExecutions.Remove(key))
            {
                throw new InvalidOperationException(
                    "Authenticated mailbox execution ownership is corrupt.");
            }
        }
    }

    private void RequireOwned(MailboxAuthenticatedRuntimeReservation reservation)
    {
        ArgumentNullException.ThrowIfNull(reservation);
        if (!ReferenceEquals(reservation.Owner, this))
        {
            throw new ArgumentException(
                "The authenticated mailbox reservation belongs to another runtime.",
                nameof(reservation));
        }
    }
}
