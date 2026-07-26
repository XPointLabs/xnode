namespace XNode.Core.Mailbox;

public interface IMailboxPeerAuthorizer
{
    bool IsAuthorized(RouterId routerId, DateTimeOffset now);
}

public enum MailboxReplicaReceiveStatus
{
    Accepted,
    Disabled,
    Unauthorized,
    Replay,
    RateLimited,
    Rejected
}

public sealed record MailboxReplicaReceiveResult(
    MailboxReplicaReceiveStatus Status,
    MailboxWriteReceipt? Receipt = null,
    string Error = "");

public sealed record MailboxReplicaReceiverMetricsSnapshot(
    long Accepted,
    long Stored,
    long Duplicates,
    long IdempotentReplays,
    long Unauthorized,
    long Replays,
    long RateLimited,
    long Rejected);

public sealed class MailboxReplicaReceiver
{
    private readonly RouterId _localRouterId;
    private readonly string _privateKeySeedHex;
    private readonly ReplicatedMailboxOptions _options;
    private readonly ReplicatedMailboxStore _store;
    private readonly IMailboxPeerAuthorizer _authorizer;
    private readonly MailboxReplicaReplayGuard _replayGuard;
    private readonly IClock _clock;
    private long _accepted;
    private long _stored;
    private long _duplicates;
    private long _idempotentReplays;
    private long _unauthorized;
    private long _replays;
    private long _rateLimited;
    private long _rejected;

    public MailboxReplicaReceiver(
        RouterId localRouterId,
        string privateKeySeedHex,
        ReplicatedMailboxOptions options,
        ReplicatedMailboxStore store,
        IMailboxPeerAuthorizer authorizer,
        MailboxReplicaReplayGuard replayGuard,
        IClock? clock = null)
    {
        options.Validate();
        _localRouterId = localRouterId;
        _privateKeySeedHex = privateKeySeedHex;
        _options = options;
        _store = store;
        _authorizer = authorizer;
        _replayGuard = replayGuard;
        _clock = clock ?? new SystemClock();
    }

    public MailboxReplicaReceiverMetricsSnapshot Metrics => new(
        Interlocked.Read(ref _accepted),
        Interlocked.Read(ref _stored),
        Interlocked.Read(ref _duplicates),
        Interlocked.Read(ref _idempotentReplays),
        Interlocked.Read(ref _unauthorized),
        Interlocked.Read(ref _replays),
        Interlocked.Read(ref _rateLimited),
        Interlocked.Read(ref _rejected));

    public async Task<MailboxReplicaReceiveResult> ReceiveAsync(
        SignedMailboxReplicaRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return new MailboxReplicaReceiveResult(MailboxReplicaReceiveStatus.Disabled);
        }

        var now = _clock.UtcNow;
        if (!RouterId.TryParse(request.SenderRouterId, out var sender)
            || !RouterId.TryParse(request.RecipientRouterId, out var recipient)
            || recipient != _localRouterId
            || !MailboxReplicationProtocol.VerifyRequest(request, now)
            || !_authorizer.IsAuthorized(sender, now))
        {
            Interlocked.Increment(ref _unauthorized);
            return new MailboxReplicaReceiveResult(MailboxReplicaReceiveStatus.Unauthorized);
        }

        if (!EncryptedMailboxBlobValidator.TryValidate(
                request.Blob,
                now,
                _options,
                out _,
                out var validationError))
        {
            Interlocked.Increment(ref _rejected);
            return new MailboxReplicaReceiveResult(
                MailboxReplicaReceiveStatus.Rejected,
                Error: validationError);
        }

        MailboxReplayExecutionResult execution;
        try
        {
            execution = await _replayGuard.ExecuteAsync(
                sender,
                request,
                async token =>
                {
                    var result = await _store.PutAsync(request.Blob, token).ConfigureAwait(false);
                    if (result.Disposition == MailboxPutDisposition.Rejected)
                    {
                        throw new MailboxReplicaRejectedException(result.Error);
                    }

                    Interlocked.Increment(ref result.Disposition == MailboxPutDisposition.Stored
                        ? ref _stored
                        : ref _duplicates);
                    return MailboxReplicationProtocol.SignReceipt(
                        _localRouterId,
                        _privateKeySeedHex,
                        request.Blob,
                        now,
                        result.Disposition);
                },
                now,
                cancellationToken).ConfigureAwait(false);
        }
        catch (MailboxReplicaRejectedException exception)
        {
            Interlocked.Increment(ref _rejected);
            return new MailboxReplicaReceiveResult(
                MailboxReplicaReceiveStatus.Rejected,
                Error: exception.Message);
        }

        switch (execution.Status)
        {
            case MailboxReplayExecutionStatus.Completed:
                Interlocked.Increment(ref _accepted);
                if (execution.WasCached)
                {
                    Interlocked.Increment(ref _idempotentReplays);
                }

                return new MailboxReplicaReceiveResult(
                    MailboxReplicaReceiveStatus.Accepted,
                    execution.Receipt);
            case MailboxReplayExecutionStatus.RateLimited:
                Interlocked.Increment(ref _rateLimited);
                return new MailboxReplicaReceiveResult(
                    MailboxReplicaReceiveStatus.RateLimited,
                    Error: "mailbox-peer-rate-limited");
            default:
                Interlocked.Increment(ref _replays);
                return new MailboxReplicaReceiveResult(MailboxReplicaReceiveStatus.Replay);
        }
    }

    private sealed class MailboxReplicaRejectedException : Exception
    {
        public MailboxReplicaRejectedException(string message)
            : base(message)
        {
        }
    }
}

public enum MailboxReplayExecutionStatus
{
    Completed,
    Conflict,
    RateLimited
}

public sealed record MailboxReplayExecutionResult(
    MailboxReplayExecutionStatus Status,
    MailboxWriteReceipt? Receipt = null,
    bool WasCached = false);

public sealed class MailboxReplicaReplayGuard
{
    private readonly object _gate = new();
    private readonly Dictionary<RouterId, SenderReplayState> _senders = [];
    private readonly int _maximumEntriesPerSender;
    private readonly int _maximumReservationsPerWindow;
    private readonly int _maximumSenderStates;
    private readonly TimeSpan _retention;
    private readonly TimeSpan _reservationTimeout;
    private readonly TimeSpan _rateWindow;

    public MailboxReplicaReplayGuard(
        int maximumEntriesPerSender = 2048,
        int maximumReservationsPerWindow = 240,
        int maximumSenderStates = 4096,
        TimeSpan? retention = null,
        TimeSpan? reservationTimeout = null,
        TimeSpan? rateWindow = null)
    {
        var normalizedRetention = retention ?? TimeSpan.FromMinutes(5);
        var normalizedReservationTimeout = reservationTimeout ?? TimeSpan.FromMinutes(2);
        var normalizedRateWindow = rateWindow ?? TimeSpan.FromMinutes(1);
        if (maximumEntriesPerSender <= 0
            || maximumReservationsPerWindow <= 0
            || maximumSenderStates <= 0
            || normalizedRetention <= TimeSpan.Zero
            || normalizedReservationTimeout <= TimeSpan.Zero
            || normalizedReservationTimeout > normalizedRetention
            || normalizedRateWindow <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntriesPerSender));
        }

        _maximumEntriesPerSender = maximumEntriesPerSender;
        _maximumReservationsPerWindow = maximumReservationsPerWindow;
        _maximumSenderStates = maximumSenderStates;
        _retention = normalizedRetention;
        _reservationTimeout = normalizedReservationTimeout;
        _rateWindow = normalizedRateWindow;
    }

    public async Task<MailboxReplayExecutionResult> ExecuteAsync(
        RouterId sender,
        SignedMailboxReplicaRequest request,
        Func<CancellationToken, Task<MailboxWriteReceipt>> operation,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var fingerprint = MailboxReplicationProtocol.ComputeRequestFingerprint(request);
        while (true)
        {
            ReplayEntry? ownerEntry = null;
            Task<MailboxWriteReceipt?>? existing = null;
            lock (_gate)
            {
                var state = GetOrCreateSenderState(sender, now);
                if (state is null)
                {
                    return new MailboxReplayExecutionResult(MailboxReplayExecutionStatus.RateLimited);
                }

                Prune(state, now);
                state.LastAccess = now;
                if (state.Entries.TryGetValue(request.Nonce, out var entry))
                {
                    if (!string.Equals(entry.Fingerprint, fingerprint, StringComparison.Ordinal))
                    {
                        return new MailboxReplayExecutionResult(MailboxReplayExecutionStatus.Conflict);
                    }

                    existing = entry.Completion.Task;
                }
                else
                {
                    ResetRateWindowIfNeeded(state, now);
                    if (state.ReservationsInWindow >= _maximumReservationsPerWindow
                        || !EnsureSenderCapacity(state))
                    {
                        return new MailboxReplayExecutionResult(MailboxReplayExecutionStatus.RateLimited);
                    }

                    ownerEntry = new ReplayEntry(fingerprint, now, state.RateWindowStartedAt);
                    state.Entries.Add(request.Nonce, ownerEntry);
                    state.ReservationsInWindow++;
                }
            }

            if (existing is not null)
            {
                var cached = await existing.WaitAsync(cancellationToken).ConfigureAwait(false);
                if (cached is not null)
                {
                    return new MailboxReplayExecutionResult(
                        MailboxReplayExecutionStatus.Completed,
                        cached,
                        WasCached: true);
                }

                // The prior durable write failed or was cancelled and released its reservation.
                continue;
            }

            try
            {
                var receipt = await operation(cancellationToken).ConfigureAwait(false);
                lock (_gate)
                {
                    ownerEntry!.CompletedAt = now;
                    ownerEntry.Completion.TrySetResult(receipt);
                }

                return new MailboxReplayExecutionResult(
                    MailboxReplayExecutionStatus.Completed,
                    receipt);
            }
            catch
            {
                lock (_gate)
                {
                    if (_senders.TryGetValue(sender, out var state)
                        && state.Entries.TryGetValue(request.Nonce, out var current)
                        && ReferenceEquals(current, ownerEntry))
                    {
                        state.Entries.Remove(request.Nonce);
                        if (state.RateWindowStartedAt == ownerEntry!.RateWindowStartedAt
                            && state.ReservationsInWindow > 0)
                        {
                            state.ReservationsInWindow--;
                        }
                    }

                    ownerEntry!.Completion.TrySetResult(null);
                }

                throw;
            }
        }
    }

    private SenderReplayState? GetOrCreateSenderState(RouterId sender, DateTimeOffset now)
    {
        if (_senders.TryGetValue(sender, out var existing))
        {
            return existing;
        }

        if (_senders.Count >= _maximumSenderStates)
        {
            foreach (var state in _senders.Values)
            {
                Prune(state, now);
            }

            var evictable = _senders
                .Where(pair => pair.Value.Entries.Values.All(entry => entry.Completion.Task.IsCompleted))
                .OrderBy(pair => pair.Value.LastAccess)
                .FirstOrDefault();
            if (evictable.Value is null)
            {
                return null;
            }

            _senders.Remove(evictable.Key);
        }

        var newState = new SenderReplayState(now);
        _senders.Add(sender, newState);
        return newState;
    }

    private void Prune(SenderReplayState state, DateTimeOffset now)
    {
        foreach (var pair in state.Entries.ToArray())
        {
            var entry = pair.Value;
            var expired = entry.Completion.Task.IsCompleted
                ? now - (entry.CompletedAt ?? entry.CreatedAt) >= _retention
                : now - entry.CreatedAt >= _reservationTimeout;
            if (!expired)
            {
                continue;
            }

            state.Entries.Remove(pair.Key);
            entry.Completion.TrySetResult(null);
        }
    }

    private bool EnsureSenderCapacity(SenderReplayState state)
    {
        return state.Entries.Count < _maximumEntriesPerSender;
    }

    private void ResetRateWindowIfNeeded(SenderReplayState state, DateTimeOffset now)
    {
        if (now - state.RateWindowStartedAt >= _rateWindow)
        {
            state.RateWindowStartedAt = now;
            state.ReservationsInWindow = 0;
        }
    }

    private sealed class SenderReplayState
    {
        public SenderReplayState(DateTimeOffset now)
        {
            LastAccess = now;
            RateWindowStartedAt = now;
        }

        public Dictionary<string, ReplayEntry> Entries { get; } = new(StringComparer.Ordinal);

        public DateTimeOffset LastAccess { get; set; }

        public DateTimeOffset RateWindowStartedAt { get; set; }

        public int ReservationsInWindow { get; set; }
    }

    private sealed class ReplayEntry
    {
        public ReplayEntry(
            string fingerprint,
            DateTimeOffset createdAt,
            DateTimeOffset rateWindowStartedAt)
        {
            Fingerprint = fingerprint;
            CreatedAt = createdAt;
            RateWindowStartedAt = rateWindowStartedAt;
        }

        public string Fingerprint { get; }

        public DateTimeOffset CreatedAt { get; }

        public DateTimeOffset RateWindowStartedAt { get; }

        public DateTimeOffset? CompletedAt { get; set; }

        public TaskCompletionSource<MailboxWriteReceipt?> Completion { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}
