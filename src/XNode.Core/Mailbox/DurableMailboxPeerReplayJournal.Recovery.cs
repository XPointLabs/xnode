namespace XNode.Core.Mailbox;

public sealed partial class DurableMailboxPeerReplayJournal
{
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
