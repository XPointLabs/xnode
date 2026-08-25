using System.Collections.Concurrent;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace XNode;

public sealed class PrivacyRoutingReplayGuard
{
    private readonly ConcurrentDictionary<string, long> _accepted =
        new(StringComparer.Ordinal);
    private readonly PrivacyRoutingConfiguration _configuration;
    private long _lastPrunedAtUnixMilliseconds;

    public PrivacyRoutingReplayGuard(PrivacyRoutingConfiguration configuration)
    {
        _configuration = configuration;
    }

    public PrivacyRoutingReplayResult TryAccept(
        ReadOnlySpan<byte> replayId,
        DateTimeOffset now)
    {
        if (replayId.Length != PrivacyRoutingLimits.HopReplayIdBytes
            || replayId.ToArray().All(static value => value == 0))
        {
            throw new PrivacyRoutingProtocolException(
                PrivacyRoutingProtocolError.InvalidIdentifier,
                "A hop replay id must be a nonzero 32-byte value.");
        }

        Prune(now);
        var key = Convert.ToHexString(replayId);
        if (_accepted.ContainsKey(key))
        {
            return PrivacyRoutingReplayResult.Replayed;
        }

        if (_accepted.Count >= _configuration.ReplayCapacity)
        {
            return PrivacyRoutingReplayResult.Saturated;
        }

        return _accepted.TryAdd(key, now.ToUnixTimeMilliseconds())
            ? PrivacyRoutingReplayResult.Accepted
            : PrivacyRoutingReplayResult.Replayed;
    }

    private void Prune(DateTimeOffset now)
    {
        var nowMilliseconds = now.ToUnixTimeMilliseconds();
        var previous = Interlocked.Read(ref _lastPrunedAtUnixMilliseconds);
        if (nowMilliseconds - previous < TimeSpan.FromMinutes(1).TotalMilliseconds
            || Interlocked.CompareExchange(
                ref _lastPrunedAtUnixMilliseconds,
                nowMilliseconds,
                previous) != previous)
        {
            return;
        }

        var cutoff = now.Subtract(_configuration.ReplayTtl).ToUnixTimeMilliseconds();
        foreach (var entry in _accepted)
        {
            if (entry.Value < cutoff)
            {
                _accepted.TryRemove(entry.Key, out _);
            }
        }
    }
}
