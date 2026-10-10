using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode.Core.Mailbox;

public sealed partial class DurableMailboxPeerReplayJournal
{
    internal MailboxPeerReplaySnapshot CaptureCurrentSnapshot(MailboxPeerReplayClaim claim)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var snapshot = Read(RecordPath(Hex(claim.ScopeKey.Span))).Snapshot();
            if (!snapshot.ScopeKey.Span.SequenceEqual(claim.ScopeKey.Span) ||
                !snapshot.RequestDigest.Span.SequenceEqual(claim.RequestDigest.Span))
                throw new InvalidDataException("Current peer replay snapshot differs from its verified claim.");
            return snapshot;
        }
    }

    internal void ValidateCurrentFloors(IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor> floors,
        CancellationToken token)
    {
        lock (_gate)
        {
            ValidateNativeRecovery(token);
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                token.ThrowIfCancellationRequested();
                if (!floors.ContainsKey(Path.GetFileNameWithoutExtension(path)))
                    throw new InvalidDataException("Current native peer replay has no independent fact.");
            }
            foreach (var (key, floor) in floors)
            {
                token.ThrowIfCancellationRequested();
                var path = RecordPath(key);
                if (!File.Exists(path)) throw new InvalidDataException("Current peer replay has lost independent history.");
                var snapshot = Read(path).Snapshot();
                if (Hex(snapshot.ScopeKey.Span) != key ||
                    MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot) != floor.ReplayDigest ||
                    snapshot.RetainUntilUnixSeconds != floor.RetainUntilUnixSeconds ||
                    floor.ResponseDigest.Length != 0 && (snapshot.Status != MailboxPeerReplayRecordStatus.Completed ||
                    MailboxCurrentPeerReplayFloor.Digest(snapshot.CanonicalResponse.Span) != floor.ResponseDigest))
                    throw new InvalidDataException("Current peer replay rolled back its independent fact.");
            }
        }
    }

    internal void ValidateNewNativeScope(CancellationToken token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_recordCount != 0 || _partitionCounts.Count != 0 || _collectionQueue.Count != 0)
                throw new InvalidDataException("New mailbox enrollment cannot adopt native peer replay.");
            MailboxNativeRecovery.RequireNewDirectory(_directory, ".lease", token);
        }
    }

    internal void ValidateNativeRecovery(CancellationToken token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            MailboxNativeRecovery.RequireDirectory(_directory, token);
            var partitions = new Dictionary<string, int>(StringComparer.Ordinal);
            var count = 0;
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                if (++count > checked(_options.MaxPeerReplayRecords + _options.MaxPeerReplayGcBatch))
                    throw new InvalidDataException("Mailbox recovery peer replay exceeds its bound.");
                MailboxNativeRecovery.RequireFile(path, token);
                var record = Read(path);
                if (Path.GetFileNameWithoutExtension(path) != Hex(record.Snapshot().ScopeKey.Span))
                    throw new InvalidDataException("Mailbox recovery peer replay differs from its native key.");
                partitions[record.PartitionKey] = partitions.GetValueOrDefault(record.PartitionKey) + 1;
            }
            if (count != _recordCount || partitions.Count != _partitionCounts.Count ||
                partitions.Any(pair => _partitionCounts.GetValueOrDefault(pair.Key) != pair.Value))
                throw new InvalidDataException("Mailbox recovery peer replay custody is missing.");
        }
    }
}
