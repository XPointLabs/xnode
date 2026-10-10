using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

// Denial/recovery metadata in the existing protected document, not another
// request journal or caller-supplied admission authority.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record MailboxCurrentPeerReplayFloor([property: JsonRequired] string ReplayDigest,
    [property: JsonRequired] string TargetKey, [property: JsonRequired] string StoreDigest,
    [property: JsonRequired] string TombstoneDigest, [property: JsonRequired] bool MutationCompleted,
    [property: JsonRequired] string ResponseDigest, [property: JsonRequired] ulong RetainUntilUnixSeconds)
{
    internal static string Digest(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    internal static string ReplayIdentity(MailboxPeerReplaySnapshot snapshot) => Digest(
        JsonSerializer.SerializeToUtf8Bytes(snapshot with
        { Status = MailboxPeerReplayRecordStatus.Pending, CanonicalResponse = ReadOnlyMemory<byte>.Empty }));
}

public sealed partial class MailboxClientOperationLedger
{
    internal async Task RequireCurrentPeerFloorCapacityAsync(ReadOnlyMemory<byte> scopeKey,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        var key = ToLowerHex(scopeKey.Span, 32, nameof(scopeKey));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            if (!document.PeerReplayFloors.ContainsKey(key) && document.PeerReplayFloors.Count >= _maxEntries)
                throw new InvalidOperationException("Current peer custody capacity is exhausted.");
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task<ulong> RecordCurrentPeerFloorAsync(ReadOnlyMemory<byte> scopeKey,
        MailboxCurrentPeerReplayFloor candidate, bool requireExisting,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        var key = ToLowerHex(scopeKey.Span, 32, nameof(scopeKey));
        ValidatePeerFloor(candidate);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            if (document.PeerReplayFloors.TryGetValue(key, out var prior))
            {
                if (prior.ReplayDigest != candidate.ReplayDigest || prior.TargetKey != candidate.TargetKey ||
                    prior.StoreDigest != candidate.StoreDigest || prior.TombstoneDigest != candidate.TombstoneDigest ||
                    prior.RetainUntilUnixSeconds != candidate.RetainUntilUnixSeconds ||
                    prior.ResponseDigest.Length != 0 && candidate.ResponseDigest.Length != 0 &&
                    prior.ResponseDigest != candidate.ResponseDigest)
                    throw new InvalidDataException("Current peer replay differs from independent custody.");
                candidate = candidate with
                {
                    MutationCompleted = prior.MutationCompleted || candidate.MutationCompleted,
                    ResponseDigest = candidate.ResponseDigest.Length == 0 ? prior.ResponseDigest : candidate.ResponseDigest
                };
                if (candidate == prior) return await lease.CheckAsync(token).ConfigureAwait(false);
            }
            else if (requireExisting)
                throw new InvalidDataException("Known current peer replay has lost independent custody.");
            else if (document.PeerReplayFloors.Count >= _maxEntries)
                throw new InvalidOperationException("Current peer custody capacity is exhausted.");
            document.PeerReplayFloors[key] = candidate;
            await SaveAsync(document, token, lease).ConfigureAwait(false);
            return await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static void ValidatePeerFloor(MailboxCurrentPeerReplayFloor floor)
    {
        _ = DecodeLowerHex(floor.ReplayDigest, 32); _ = DecodeLowerHex(floor.TargetKey, 32);
        _ = DecodeLowerHex(floor.StoreDigest, 32);
        if (floor.TombstoneDigest is null || floor.ResponseDigest is null || floor.RetainUntilUnixSeconds == 0 ||
            floor.ResponseDigest.Length != 0 && !floor.MutationCompleted)
            throw new InvalidDataException("Current peer custody fact is malformed.");
        if (floor.TombstoneDigest.Length != 0) _ = DecodeLowerHex(floor.TombstoneDigest, 32);
        if (floor.ResponseDigest.Length != 0) _ = DecodeLowerHex(floor.ResponseDigest, 32);
    }
}
