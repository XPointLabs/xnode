namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientCanonicalOutcomeStore
{
    // Key/digest metadata only, owned by this native store. This is not an
    // outcome delivery API and cannot complete replay or grant admission.
    internal IReadOnlyDictionary<string, string> ValidateNativeRecovery(CancellationToken token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            MailboxNativeRecovery.RequireDirectory(_directory, token);
            var digests = new Dictionary<string, string>(StringComparer.Ordinal);
            long canonicalBytes = 0, fileBytes = 0;
            foreach (var path in Directory.EnumerateFiles(_directory, $"*{Extension}"))
            {
                if (digests.Count >= _maximumEntries) throw Corrupt();
                MailboxNativeRecovery.RequireFile(path, token);
                var key = Path.GetFileNameWithoutExtension(path);
                if (!IsLowerHex(key, 32) || !_entries.TryGetValue(key, out var indexed)) throw Corrupt();
                var actual = ToEntry(ReadFile(path, Convert.FromHexString(key)));
                if (actual != indexed || !digests.TryAdd(key, actual.CanonicalDigest)) throw Corrupt();
                canonicalBytes = checked(canonicalBytes + actual.CanonicalLength);
                fileBytes = checked(fileBytes + actual.FileLength);
                if (fileBytes > _maximumBytes) throw Corrupt();
            }
            if (digests.Count != _entries.Count || canonicalBytes != _canonicalBytes || fileBytes != _fileBytes)
                throw Corrupt();
            return digests;
        }
    }
}
