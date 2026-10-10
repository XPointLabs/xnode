using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed partial class DurableMailboxCapabilityReplayJournal
{
    internal void ValidateNativeRecovery(IReadOnlyDictionary<string, string> outcomes, CancellationToken token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            MailboxNativeRecovery.RequireDirectory(_directory, token);
            if (File.Exists(_path)) MailboxNativeRecovery.RequireFile(_path, token);
            else if (_document.AcceptedTimeHighWatermarkUnixSeconds != 0 || outcomes.Count != 0)
                throw new InvalidDataException("Mailbox recovery replay document is missing.");
            var actual = Load();
            if (actual.AcceptedTimeHighWatermarkUnixSeconds != _document.AcceptedTimeHighWatermarkUnixSeconds ||
                actual.Records.Count != _document.Records.Count)
                throw new InvalidDataException("Mailbox recovery replay differs from its native custody.");
            foreach (var pair in actual.Records)
            {
                token.ThrowIfCancellationRequested();
                var record = pair.Value;
                if (!_document.Records.TryGetValue(pair.Key, out var indexed) ||
                    record.HighestCounter != indexed.HighestCounter || record.ClaimDigest != indexed.ClaimDigest ||
                    record.Status != indexed.Status || record.CanonicalOutcome != indexed.CanonicalOutcome ||
                    record.RetainUntilUnixSeconds != indexed.RetainUntilUnixSeconds)
                    throw new InvalidDataException("Mailbox recovery replay record differs from native custody.");
                if (record.Status != nameof(MailboxCapabilityReplayRecordStatus.Completed)) continue;
                var key = MailboxClientCanonicalOutcomeKey.Create(Convert.FromHexString(pair.Key),
                    record.HighestCounter, Convert.FromHexString(record.ClaimDigest));
                var digest = Convert.FromBase64String(record.CanonicalOutcome);
                if (digest.Length != 32 || !outcomes.TryGetValue(Convert.ToHexString(key.Digest).ToLowerInvariant(), out var outcome) ||
                    Convert.ToHexString(digest).ToLowerInvariant() != outcome)
                    throw new InvalidDataException("Mailbox recovery completed replay has lost its exact outcome.");
            }
        }
    }
}
