using System.Collections.Concurrent;

namespace XNode;

public sealed class OnionPeerReplayGuard
{
    private readonly ConcurrentDictionary<string, long> _accepted = new(StringComparer.Ordinal);
    private long _lastPrunedAtUnixMs;

    public bool TryAccept(string senderRouterId, string nonce, long timestampUnixMs, DateTimeOffset now)
    {
        PruneIfDue(now);
        var key = $"{senderRouterId.Trim().ToLowerInvariant()}:{nonce.Trim().ToLowerInvariant()}";
        return _accepted.TryAdd(key, timestampUnixMs);
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
        foreach (var entry in _accepted)
        {
            if (entry.Value < cutoff)
            {
                _accepted.TryRemove(entry.Key, out _);
            }
        }
    }
}
