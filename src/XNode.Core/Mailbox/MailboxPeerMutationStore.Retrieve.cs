using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

internal sealed record MailboxCurrentRetrieveWindow(ulong SnapshotHighWater,
    IReadOnlyList<MailboxRetrievedEnvelope> Items);

public sealed partial class MailboxPeerMutationStore
{
    // Derivable from the same bounded native mutation files. Never a second
    // journal or evidence that a Store reached two-replica quorum.
    private readonly Dictionary<string, SortedDictionary<ulong, HashSet<string>>> _retrieveIndex = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (string Scope, ulong Cursor)> _retrievePaths = new(StringComparer.Ordinal);

    internal async Task<MailboxCurrentRetrieveWindow> ReadCurrentWindowAsync(
        MailboxAuthenticatedRetrieveBody request, ReadOnlyMemory<byte> membership,
        ulong snapshotHighWater, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var placement = MailboxPlacementCommitment.Compute(request.PlacementId);
            var scope = RetrieveScope(request.Epoch, Hex(request.MailboxId.Bytes.Span), Hex(placement), Hex(membership.Span));
            _retrieveIndex.TryGetValue(scope, out var index);
            var maximum = index is null || index.Count == 0 ? 0 : index.Keys.Last();
            var highWater = snapshotHighWater == 0 ? maximum : snapshotHighWater;
            if (highWater > maximum || request.AfterCursor > highWater)
                throw new InvalidDataException("Current retrieve snapshot is unavailable.");
            if (index is not null && index.Any(pair => pair.Key <= highWater && pair.Value.Count != 1))
                throw new InvalidDataException("Current mailbox cursor has ambiguous mutation custody.");
            var items = new List<MailboxRetrievedEnvelope>(request.MaximumItems + 1);
            if (index is not null)
            {
                foreach (var pair in index)
                {
                    if (pair.Key > highWater) break;
                    var upper = await lease.CheckAsync(token).ConfigureAwait(false);
                    var path = pair.Value.Single(); var record = Read(path);
                    if (record.Cursor != pair.Key || RetrieveScope(record) != scope ||
                        Path.GetFileNameWithoutExtension(path) != RecordKey(record.Epoch, record.MailboxId, record.EnvelopeDigest))
                        throw new InvalidDataException("Current retrieve index differs from native custody.");
                    if (record.ExpiresAtUnixSeconds <= upper || record.State is "tombstone-pending" or "tombstoned") continue;
                    if (record.State != "completed")
                        throw new InvalidDataException("Current retrieve has unresolved native Store custody.");
                    // A continuation issued by the other replica may already
                    // be beyond a locally reserved Store. Do not silently skip
                    // that live Pending custody: it can complete below the
                    // snapshot cursor. Consumed completed records need no blob
                    // reread, but their native state must be checked first.
                    if (pair.Key <= request.AfterCursor) continue;
                    var blob = await _blobStore.ReadExactCurrentAsync(record.MailboxId, record.BlobId, lease, token).ConfigureAwait(false)
                        ?? throw new InvalidDataException("Current retrieve blob is unavailable.");
                    _faults?.Inject(MailboxPeerMutationFaultPoint.RetrieveBlobRead);
                    _ = await lease.CheckAsync(token).ConfigureAwait(false);
                    if (blob.Ciphertext.Length > ((MailboxClientLimits.MaximumEncryptedEnvelopeLength + 2) / 3) * 4)
                        throw new InvalidDataException("Current retrieve blob exceeds its bound.");
                    var bytes = Convert.FromBase64String(blob.Ciphertext);
                    var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(bytes);
                    if (!FixedHex(record.BlobId, SHA256.HashData(bytes)) || envelope.Epoch != request.Epoch ||
                        !FixedHex(record.OperationId, envelope.OperationId.Span) ||
                        !FixedHex(record.MailboxId, envelope.MailboxId.Bytes.Span) ||
                        !FixedHex(record.PlacementId, envelope.PlacementId.Bytes.Span) ||
                        !FixedHex(record.EnvelopeDigest, envelope.DeduplicationDigest.Span) ||
                        envelope.ExpiresAtUnixSeconds != record.ExpiresAtUnixSeconds ||
                        blob.ExpiresAtUnixMs != checked((long)record.ExpiresAtUnixSeconds * 1000))
                        throw new InvalidDataException("Current retrieve blob differs from mutation custody.");
                    items.Add(new() { Cursor = pair.Key, Envelope = envelope });
                    if (items.Count == request.MaximumItems + 1) break;
                }
            }
            var finalUpper = await lease.CheckAsync(token).ConfigureAwait(false);
            if (items.Any(item => item.Envelope.ExpiresAtUnixSeconds <= finalUpper))
                throw new InvalidDataException("Current retrieve object expired during read.");
            return new(highWater, items);
        }
        finally { _gate.Release(); }
    }

    private void IndexForRetrieve(string path, PersistedMutation record)
    {
        var first = !_retrievePaths.ContainsKey(path);
        RemoveRetrieveIndex(path); var scope = RetrieveScope(record);
        if (!_retrieveIndex.TryGetValue(scope, out var cursors)) _retrieveIndex.Add(scope, cursors = new());
        if (!cursors.TryGetValue(record.Cursor, out var paths)) cursors.Add(record.Cursor, paths = new(StringComparer.Ordinal));
        paths.Add(path); _retrievePaths.Add(path, (scope, record.Cursor));
        _recordCount = _retrievePaths.Count;
        if (first) _collectionQueue.Enqueue(path, record.RetainUntilUnixSeconds);
    }
    private void RemoveRetrieveIndex(string path)
    {
        if (!_retrievePaths.Remove(path, out var prior)) return;
        var cursors = _retrieveIndex[prior.Scope]; var paths = cursors[prior.Cursor]; paths.Remove(path);
        if (paths.Count == 0) cursors.Remove(prior.Cursor);
        if (cursors.Count == 0) _retrieveIndex.Remove(prior.Scope);
        _recordCount = _retrievePaths.Count;
    }
    private static string RetrieveScope(PersistedMutation record) =>
        RetrieveScope(record.Epoch, record.MailboxId, record.PlacementCommitment, record.MembershipCommitment);
    private static string RetrieveScope(ulong epoch, string mailbox, string placement, string membership) =>
        $"{epoch:x16}/{mailbox}/{placement}/{membership}";
}
