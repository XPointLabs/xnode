using System.Collections.Concurrent;

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
    long Unauthorized,
    long Replays,
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
    private long _unauthorized;
    private long _replays;
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
        Interlocked.Read(ref _unauthorized),
        Interlocked.Read(ref _replays),
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

        if (!_replayGuard.TryAccept(sender, request.Nonce, request.TimestampUnixMs, now))
        {
            Interlocked.Increment(ref _replays);
            return new MailboxReplicaReceiveResult(MailboxReplicaReceiveStatus.Replay);
        }

        var result = await _store.PutAsync(request.Blob, cancellationToken).ConfigureAwait(false);
        if (result.Disposition == MailboxPutDisposition.Rejected)
        {
            Interlocked.Increment(ref _rejected);
            return new MailboxReplicaReceiveResult(
                MailboxReplicaReceiveStatus.Rejected,
                Error: result.Error);
        }

        Interlocked.Increment(ref _accepted);
        Interlocked.Increment(ref result.Disposition == MailboxPutDisposition.Stored
            ? ref _stored
            : ref _duplicates);
        return new MailboxReplicaReceiveResult(
            MailboxReplicaReceiveStatus.Accepted,
            MailboxReplicationProtocol.SignReceipt(
                _localRouterId,
                _privateKeySeedHex,
                request.Blob,
                now,
                result.Disposition));
    }
}

public sealed class MailboxReplicaReplayGuard
{
    private const int MaximumEntries = 100_000;
    private readonly ConcurrentDictionary<string, long> _accepted = new(StringComparer.Ordinal);
    private long _lastPrunedAtUnixMs;

    public bool TryAccept(RouterId sender, string nonce, long timestampUnixMs, DateTimeOffset now)
    {
        PruneIfDue(now);
        if (_accepted.Count >= MaximumEntries)
        {
            return false;
        }

        return _accepted.TryAdd($"{sender.Value}:{nonce}", timestampUnixMs);
    }

    private void PruneIfDue(DateTimeOffset now)
    {
        var nowUnixMs = now.ToUnixTimeMilliseconds();
        var previous = Interlocked.Read(ref _lastPrunedAtUnixMs);
        if (nowUnixMs - previous < TimeSpan.FromMinutes(1).TotalMilliseconds
            || Interlocked.CompareExchange(ref _lastPrunedAtUnixMs, nowUnixMs, previous) != previous)
        {
            return;
        }

        var cutoff = now.Subtract(TimeSpan.FromMinutes(5)).ToUnixTimeMilliseconds();
        foreach (var accepted in _accepted)
        {
            if (accepted.Value < cutoff)
            {
                _accepted.TryRemove(accepted.Key, out _);
            }
        }
    }
}
