using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;

namespace XNode.Core.Mailbox;

public sealed class MailboxPeerAuthorityOptions
{
    public ulong CurrentEpoch { get; set; }
    public string CurrentMembershipCommitment { get; set; } = "";
    public ulong CurrentEpochExpiresAtUnixSeconds { get; set; }
    public ulong NextEpoch { get; set; }
    public string NextMembershipCommitment { get; set; } = "";
    public ulong NextEpochExpiresAtUnixSeconds { get; set; }
    public List<MailboxPeerPlacementSelection> PlacementSelections { get; set; } = [];

    public void Validate(bool required)
    {
        if (!required
            && CurrentEpoch == 0
            && NextEpoch == 0
            && string.IsNullOrEmpty(CurrentMembershipCommitment)
            && string.IsNullOrEmpty(NextMembershipCommitment)
            && PlacementSelections.Count == 0)
        {
            return;
        }

        if (CurrentEpoch == 0
            || CurrentEpochExpiresAtUnixSeconds == 0
            || !TryCommitment(CurrentMembershipCommitment, out var current)
            || NextEpoch == 0
                && (NextEpochExpiresAtUnixSeconds != 0
                    || !string.IsNullOrEmpty(NextMembershipCommitment))
            || NextEpoch != 0
                && (NextEpoch != CurrentEpoch + 1
                    || NextEpochExpiresAtUnixSeconds == 0
                    || !TryCommitment(NextMembershipCommitment, out var next)
                    || CryptographicOperations.FixedTimeEquals(current, next))
            || PlacementSelections.Count == 0
            || PlacementSelections.Any(selection =>
                !selection.IsValidFor(CurrentEpoch, NextEpoch))
            || PlacementSelections
                .GroupBy(
                    selection => $"{selection.Epoch}:{selection.PlacementCommitment}",
                    StringComparer.Ordinal)
                .Any(group => group.Count() != 1))
        {
            throw new InvalidOperationException(
                "MailboxPeerAuthority must pin the current membership epoch and an optional " +
                "cryptographically distinct E+1 commitment.");
        }
    }

    public bool IsSelectedReplicaPair(
        ulong epoch,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> senderRouterId,
        ReadOnlySpan<byte> recipientRouterId)
    {
        foreach (var selection in PlacementSelections)
        {
            if (selection.Epoch != epoch
                || !FixedHex(selection.PlacementCommitment, placementCommitment))
            {
                continue;
            }

            var first = Convert.FromHexString(selection.FirstRouterId);
            var second = Convert.FromHexString(selection.SecondRouterId);
            return Fixed(first, senderRouterId) && Fixed(second, recipientRouterId)
                || Fixed(first, recipientRouterId) && Fixed(second, senderRouterId);
        }

        return false;
    }

    public bool TryGetEpoch(
        ulong epoch,
        out byte[] membershipCommitment,
        out ulong expiresAtUnixSeconds)
    {
        membershipCommitment = [];
        var encoded = epoch == CurrentEpoch
            ? CurrentMembershipCommitment
            : epoch == NextEpoch
                ? NextMembershipCommitment
                : "";
        expiresAtUnixSeconds = epoch == CurrentEpoch
            ? CurrentEpochExpiresAtUnixSeconds
            : epoch == NextEpoch
                ? NextEpochExpiresAtUnixSeconds
                : 0;
        return expiresAtUnixSeconds != 0
            && TryCommitment(encoded, out membershipCommitment);
    }

    private static bool TryCommitment(string? encoded, out byte[] value)
    {
        value = [];
        if (encoded is null
            || encoded.Length != 64
            || encoded.Any(character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            return false;
        }

        value = Convert.FromHexString(encoded);
        return value.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
    }

    private static bool FixedHex(string encoded, ReadOnlySpan<byte> expected)
    {
        try
        {
            return Fixed(Convert.FromHexString(encoded), expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed class MailboxPeerPlacementSelection
{
    public ulong Epoch { get; set; }
    public string PlacementCommitment { get; set; } = "";
    public string FirstRouterId { get; set; } = "";
    public string SecondRouterId { get; set; } = "";

    internal bool IsValidFor(ulong currentEpoch, ulong nextEpoch)
    {
        if (Epoch == 0
            || Epoch != currentEpoch && (nextEpoch == 0 || Epoch != nextEpoch)
            || !IsNonZeroLowerHex(PlacementCommitment, 32)
            || !IsNonZeroLowerHex(FirstRouterId, 32)
            || !IsNonZeroLowerHex(SecondRouterId, 32))
        {
            return false;
        }

        var first = Convert.FromHexString(FirstRouterId);
        var second = Convert.FromHexString(SecondRouterId);
        return !CryptographicOperations.FixedTimeEquals(first, second);
    }

    private static bool IsNonZeroLowerHex(string? value, int bytes) =>
        value is not null
        && value.Length == bytes * 2
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f')
        && Convert.FromHexString(value).AsSpan().IndexOfAnyExcept((byte)0) >= 0;
}

public interface IMailboxPeerRequestPolicyResolver
{
    MailboxPeerWireVerificationPolicyV2? Resolve(
        MailboxPeerWireRequestV2 request,
        MailboxPeerReplicationOperation expectedOperation,
        ulong nowUnixSeconds);
}

public sealed class MailboxPeerRequestPolicyResolver : IMailboxPeerRequestPolicyResolver
{
    private readonly byte[] _localRouterId;
    private readonly byte[] _localSigningPublicKey;
    private readonly MailboxPeerAuthorityOptions _authority;
    private readonly MailboxPeerMutationStore _mutations;

    public MailboxPeerRequestPolicyResolver(
        RouterId localRouterId,
        string privateKeySeedHex,
        MailboxPeerAuthorityOptions authority,
        MailboxPeerMutationStore mutations)
    {
        _localRouterId = localRouterId.ToBytes();
        _authority = authority;
        _mutations = mutations;
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        _localSigningPublicKey = crypto.GetPublicKey(DecodeSeed(privateKeySeedHex));
    }

    public MailboxPeerWireVerificationPolicyV2? Resolve(
        MailboxPeerWireRequestV2 request,
        MailboxPeerReplicationOperation expectedOperation,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Operation != expectedOperation
            || !Fixed(request.RecipientRouterId.Span, _localRouterId)
            || Fixed(request.SenderRouterId.Span, request.RecipientRouterId.Span)
            || Fixed(
                request.SenderMembershipProof.SigningPublicKey.Span,
                request.RecipientMembershipProof.SigningPublicKey.Span)
            || !Fixed(
                request.RecipientMembershipProof.SigningPublicKey.Span,
                _localSigningPublicKey)
            || !_authority.TryGetEpoch(
                request.Epoch,
                out var authoritativeMembership,
                out var epochExpiresAt)
            || !Fixed(request.MembershipCommitment.Span, authoritativeMembership))
        {
            return null;
        }

        MembershipRouteDescriptor sender;
        MembershipRouteDescriptor recipient;
        try
        {
            sender = MailboxReplicaRouteProofCodec.Decode(
                request.SenderMembershipProof.CanonicalInclusionProof.Span).Descriptor;
            recipient = MailboxReplicaRouteProofCodec.Decode(
                request.RecipientMembershipProof.CanonicalInclusionProof.Span).Descriptor;
        }
        catch (MembershipRouteDescriptorException)
        {
            return null;
        }

        if (!Fixed(request.SenderMembershipProof.ReplicaId.Span, request.SenderRouterId.Span)
            || !Fixed(
                request.RecipientMembershipProof.ReplicaId.Span,
                request.RecipientRouterId.Span)
            || !Fixed(sender.RouterId.Span, request.SenderRouterId.Span)
            || !Fixed(recipient.RouterId.Span, request.RecipientRouterId.Span)
            || !Fixed(
                sender.Ed25519PublicKey.Span,
                request.SenderMembershipProof.SigningPublicKey.Span)
            || !Fixed(
                recipient.Ed25519PublicKey.Span,
                request.RecipientMembershipProof.SigningPublicKey.Span))
        {
            return null;
        }

        epochExpiresAt = Math.Min(
            epochExpiresAt,
            Math.Min(sender.ValidUntilUnixSeconds, recipient.ValidUntilUnixSeconds));
        BlindedPlacementId placementId;
        if (request.Operation == MailboxPeerReplicationOperation.Store)
        {
            if (request.Payload.Length < 80
                || !request.Payload.Span[..4].SequenceEqual("MEO1"u8))
            {
                return null;
            }

            placementId = new BlindedPlacementId(request.Payload.Span.Slice(48, 32));
        }
        else if (!_mutations.TryResolveTombstonePlacement(request, out placementId))
        {
            return null;
        }

        if (!_authority.IsSelectedReplicaPair(
                request.Epoch,
                request.PlacementCommitment.Span,
                request.SenderRouterId.Span,
                request.RecipientRouterId.Span))
        {
            return null;
        }

        return new MailboxPeerWireVerificationPolicyV2
        {
            ExpectedOperation = expectedOperation,
            Epoch = request.Epoch,
            OperationId = request.OperationId.ToArray(),
            SenderRouterId = request.SenderRouterId.ToArray(),
            RecipientRouterId = _localRouterId.ToArray(),
            MembershipCommitment = authoritativeMembership,
            PlacementCommitment = request.PlacementCommitment.ToArray(),
            PlacementId = placementId,
            NowUnixSeconds = nowUnixSeconds,
            EpochExpiresAtUnixSeconds = epochExpiresAt
        };
    }

    private static byte[] DecodeSeed(string value)
    {
        if (value.Length != 64 || !value.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException("The local Ed25519 seed is invalid.");
        }

        return Convert.FromHexString(value);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

public enum MailboxPeerReceiveStatus
{
    Accepted,
    Disabled,
    Malformed,
    AuthenticationFailed,
    AuthorizationFailed,
    Conflict,
    RateLimited,
    DependencyUnavailable
}

public sealed record MailboxPeerReceiveResult(
    MailboxPeerReceiveStatus Status,
    ReadOnlyMemory<byte> CanonicalResponse,
    bool WasCached = false);

public sealed record MailboxPeerReceiverMetricsSnapshot(
    long Accepted,
    long Stored,
    long Duplicates,
    long Tombstones,
    long IdempotentReplays,
    long AuthenticationFailures,
    long AuthorizationFailures,
    long Conflicts,
    long RateLimited,
    long Rejected,
    long DependencyFailures);

public sealed class MailboxReplicaReceiver
{
    private readonly byte[] _privateKeySeed;
    private readonly ReplicatedMailboxOptions _options;
    private readonly MailboxPeerMutationStore _mutations;
    private readonly IMailboxPeerRequestPolicyResolver _policyResolver;
    private readonly IMailboxReplicaMembershipProofVerifier _membershipVerifier;
    private readonly IMailboxPeerReplayJournal _replayJournal;
    private readonly SodiumMailboxPeerReplicationCrypto _crypto = new();
    private readonly IClock _clock;
    private readonly MailboxPeerRateLimiter _rateLimiter = new();
    private readonly SemaphoreSlim[] _executionGates =
        Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();
    private long _accepted;
    private long _stored;
    private long _duplicates;
    private long _tombstones;
    private long _idempotentReplays;
    private long _authenticationFailures;
    private long _authorizationFailures;
    private long _conflicts;
    private long _rateLimited;
    private long _rejected;
    private long _dependencyFailures;

    public MailboxReplicaReceiver(
        string privateKeySeedHex,
        ReplicatedMailboxOptions options,
        MailboxPeerMutationStore mutations,
        IMailboxPeerRequestPolicyResolver policyResolver,
        IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal replayJournal,
        IClock? clock = null)
    {
        options.Validate();
        _privateKeySeed = Convert.FromHexString(privateKeySeedHex);
        if (_privateKeySeed.Length != 32)
        {
            throw new InvalidOperationException("The mailbox peer Ed25519 seed is invalid.");
        }

        _options = options;
        _mutations = mutations;
        _policyResolver = policyResolver;
        _membershipVerifier = membershipVerifier;
        _replayJournal = replayJournal;
        _clock = clock ?? new SystemClock();
    }

    public MailboxPeerReceiverMetricsSnapshot Metrics => new(
        Interlocked.Read(ref _accepted),
        Interlocked.Read(ref _stored),
        Interlocked.Read(ref _duplicates),
        Interlocked.Read(ref _tombstones),
        Interlocked.Read(ref _idempotentReplays),
        Interlocked.Read(ref _authenticationFailures),
        Interlocked.Read(ref _authorizationFailures),
        Interlocked.Read(ref _conflicts),
        Interlocked.Read(ref _rateLimited),
        Interlocked.Read(ref _rejected),
        Interlocked.Read(ref _dependencyFailures));

    public async Task<MailboxPeerReceiveResult> ReceiveAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        MailboxPeerReplicationOperation expectedOperation,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return Failure(MailboxPeerReceiveStatus.Disabled);
        }

        MailboxPeerWireRequestV2 decoded;
        try
        {
            decoded = MailboxPeerWireV2Codec.Decode(canonicalRequest.Span);
        }
        catch (MailboxPeerReplicationException)
        {
            Interlocked.Increment(ref _rejected);
            return Failure(MailboxPeerReceiveStatus.Malformed);
        }

        var scope = MailboxPeerReplayStateMachine.ComputeScopeKey(
            decoded.SenderRouterId.Span,
            decoded.RecipientRouterId.Span,
            decoded.Epoch,
            decoded.ReplayNonce.Span);
        var executionGate = _executionGates[scope[0] % _executionGates.Length];
        await executionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
            var policy = _policyResolver.Resolve(decoded, expectedOperation, now);
            if (policy is null)
            {
                Interlocked.Increment(ref _authorizationFailures);
                return Failure(MailboxPeerReceiveStatus.AuthorizationFailed);
            }

            VerifiedMailboxPeerWireRequestV2 verified;
            try
            {
                _ = _replayJournal.CollectExpired(now, _options.MaxPeerReplayGcBatch);
                // Authenticate the sender and both MIP1 proofs before using the sender id as a
                // rate-limit partition. This validation journal has no durable side effects.
                _ = MailboxPeerWireV2Codec.VerifyAndReserve(
                    canonicalRequest.Span,
                    policy,
                    _crypto,
                    _membershipVerifier,
                    ValidationOnlyReplayJournal.Instance);
                if (!_rateLimiter.TryAcquire(decoded.SenderRouterId.Span, now))
                {
                    Interlocked.Increment(ref _rateLimited);
                    return Failure(MailboxPeerReceiveStatus.RateLimited);
                }

                verified = MailboxPeerWireV2Codec.VerifyAndReserve(
                    canonicalRequest.Span,
                    policy,
                    _crypto,
                    _membershipVerifier,
                    _replayJournal);
            }
            catch (MailboxPeerReplayCapacityException)
            {
                Interlocked.Increment(ref _rateLimited);
                return Failure(MailboxPeerReceiveStatus.RateLimited);
            }
            catch (MailboxPeerReplicationException exception)
            {
                return ProtocolFailure(exception.Error);
            }
            catch (MailboxReceiptException)
            {
                Interlocked.Increment(ref _dependencyFailures);
                return Failure(MailboxPeerReceiveStatus.DependencyUnavailable);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException
                    or InvalidDataException or InvalidOperationException)
            {
                Interlocked.Increment(ref _dependencyFailures);
                return Failure(MailboxPeerReceiveStatus.DependencyUnavailable);
            }

            if (verified.ReplayDisposition == MailboxPeerReplayDisposition.IdempotentCompleted)
            {
                Interlocked.Increment(ref _accepted);
                Interlocked.Increment(ref _idempotentReplays);
                return new(
                    MailboxPeerReceiveStatus.Accepted,
                    verified.CachedResponse.ToArray(),
                    WasCached: true);
            }

            MailboxPeerMutationResult mutation;
            try
            {
                mutation = await _mutations.ApplyAsync(
                    verified,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException
                    or InvalidDataException or MailboxPeerMutationCapacityException)
            {
                Interlocked.Increment(ref _dependencyFailures);
                return Failure(MailboxPeerReceiveStatus.DependencyUnavailable);
            }

            if (!string.IsNullOrEmpty(mutation.Error))
            {
                var contextRejected = mutation.Error.Contains(
                        "context",
                        StringComparison.Ordinal)
                    || string.Equals(
                        mutation.Error,
                        "mailbox-peer-tombstone-target-missing",
                        StringComparison.Ordinal);
                if (contextRejected)
                {
                    Interlocked.Increment(ref _authorizationFailures);
                }
                else
                {
                    Interlocked.Increment(ref _dependencyFailures);
                }
                return Failure(contextRejected
                    ? MailboxPeerReceiveStatus.AuthorizationFailed
                    : MailboxPeerReceiveStatus.DependencyUnavailable);
            }

            var acceptedAt = verified.ReplayClaim.ReservedAtUnixSeconds;
            var unsigned =
                MailboxPeerWireV2Codec.CreateUnsignedDurableResponseAfterPersistence(
                    verified,
                    mutation.Disposition,
                    acceptedAt,
                    acceptedAt);
            var signed = _crypto.SignReplicaResponse(unsigned, _privateKeySeed);
            var canonicalResponse = MailboxReceiptV2Codec.EncodeReplica(signed);
            _ = MailboxPeerWireV2Codec.VerifyReplicaResponse(
                canonicalResponse,
                verified,
                _crypto);

            try
            {
                if (verified.ReplayDisposition == MailboxPeerReplayDisposition.NewReserved)
                {
                    MailboxPeerWireV2Codec.CompleteAtomically(
                        verified,
                        canonicalResponse,
                        _crypto,
                        _replayJournal);
                }
                else
                {
                    // A persisted pending claim has no in-memory owner after restart. The
                    // mutation is idempotently recovered above and the exact response completes it.
                    _replayJournal.CompleteAtomically(
                        verified.ReplayClaim,
                        canonicalResponse);
                }

                _ = _replayJournal.CollectExpired(now, _options.MaxPeerReplayGcBatch);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException
                    or InvalidDataException)
            {
                Interlocked.Increment(ref _dependencyFailures);
                return Failure(MailboxPeerReceiveStatus.DependencyUnavailable);
            }

            Interlocked.Increment(ref _accepted);
            switch (mutation.Disposition)
            {
                case MailboxReplicaDisposition.Stored:
                    Interlocked.Increment(ref _stored);
                    break;
                case MailboxReplicaDisposition.Duplicate:
                    Interlocked.Increment(ref _duplicates);
                    break;
                case MailboxReplicaDisposition.Tombstone:
                    Interlocked.Increment(ref _tombstones);
                    break;
            }

            return new(MailboxPeerReceiveStatus.Accepted, canonicalResponse);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Interlocked.Increment(ref _dependencyFailures);
            return Failure(MailboxPeerReceiveStatus.DependencyUnavailable);
        }
        finally
        {
            executionGate.Release();
        }
    }

    private MailboxPeerReceiveResult ProtocolFailure(MailboxPeerReplicationError error)
    {
        var status = error switch
        {
            MailboxPeerReplicationError.InvalidSignature =>
                MailboxPeerReceiveStatus.AuthenticationFailed,
            MailboxPeerReplicationError.InvalidMembershipProof
                or MailboxPeerReplicationError.BindingMismatch =>
                MailboxPeerReceiveStatus.AuthorizationFailed,
            MailboxPeerReplicationError.ReplayConflict
                or MailboxPeerReplicationError.ExpiredOrStale =>
                MailboxPeerReceiveStatus.Conflict,
            _ => MailboxPeerReceiveStatus.Malformed
        };
        switch (status)
        {
            case MailboxPeerReceiveStatus.AuthenticationFailed:
                Interlocked.Increment(ref _authenticationFailures);
                break;
            case MailboxPeerReceiveStatus.AuthorizationFailed:
                Interlocked.Increment(ref _authorizationFailures);
                break;
            case MailboxPeerReceiveStatus.Conflict:
                Interlocked.Increment(ref _conflicts);
                break;
            default:
                Interlocked.Increment(ref _rejected);
                break;
        }

        return Failure(status);
    }

    private static MailboxPeerReceiveResult Failure(MailboxPeerReceiveStatus status) =>
        new(status, ReadOnlyMemory<byte>.Empty);

    private sealed class MailboxPeerRateLimiter
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, Window> _windows = new(StringComparer.Ordinal);

        public bool TryAcquire(ReadOnlySpan<byte> senderRouterId, ulong nowUnixSeconds)
        {
            var key = Convert.ToHexString(SHA256.HashData(senderRouterId));
            lock (_gate)
            {
                if (_windows.Count >= 4096)
                {
                    foreach (var expired in _windows
                                 .Where(pair =>
                                     nowUnixSeconds >= pair.Value.StartedAt + 60)
                                 .Select(pair => pair.Key)
                                 .ToArray())
                    {
                        _windows.Remove(expired);
                    }
                }

                if (!_windows.TryGetValue(key, out var window))
                {
                    if (_windows.Count >= 4096)
                    {
                        return false;
                    }

                    window = new Window(nowUnixSeconds, 0);
                }
                else if (nowUnixSeconds >= window.StartedAt + 60)
                {
                    window = new Window(nowUnixSeconds, 0);
                }

                if (window.Count >= MailboxWireHttpContract.PeerStore.RequestsPerMinute)
                {
                    return false;
                }

                _windows[key] = window with { Count = window.Count + 1 };
                return true;
            }
        }

        private sealed record Window(ulong StartedAt, int Count);
    }

    private sealed class ValidationOnlyReplayJournal : IMailboxPeerReplayJournal
    {
        public static ValidationOnlyReplayJournal Instance { get; } = new();

        public MailboxPeerReplayEvaluation EvaluateAndReserve(MailboxPeerReplayClaim claim) =>
            new()
            {
                State = MailboxPeerReplayState.NewReserved,
                CachedResponse = ReadOnlyMemory<byte>.Empty
            };

        public void CompleteAtomically(
            MailboxPeerReplayClaim claim,
            ReadOnlyMemory<byte> canonicalMrr2Response) =>
            throw new NotSupportedException();

        public int CollectExpired(ulong nowUnixSeconds, int maximumRecords) =>
            throw new NotSupportedException();
    }
}
