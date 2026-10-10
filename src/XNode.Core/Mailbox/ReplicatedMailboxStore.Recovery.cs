using System.Text.Json;

namespace XNode.Core.Mailbox;

public sealed partial class ReplicatedMailboxStore
{
    // Expiry does not make persisted corruption valid. The callback joins every
    // extant blob to its mutation; it does not admit expired objects for reads.
    internal async Task ValidateCurrentRecoveryAsync(Action<EncryptedMailboxBlob> requireMutation,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            try { MailboxNativeRecovery.RequireDirectory(_rootDirectory, token); }
            catch (FileNotFoundException) { return; } // new, still-empty blob owner
            catch (DirectoryNotFoundException) { return; }
            var scanned = 0;
            var blobs = 0;
            foreach (var directory in Directory.EnumerateFileSystemEntries(_rootDirectory))
            {
                if (++scanned > _options.MaxRecoveryScanFiles)
                    throw new InvalidDataException("Mailbox recovery scan exceeds its bound.");
                MailboxNativeRecovery.RequireDirectory(directory, token);
                var mailbox = Path.GetFileName(directory);
                if (!EncryptedMailboxBlobValidator.IsCanonicalId(mailbox))
                    throw new InvalidDataException("Mailbox recovery directory is not canonical.");
                foreach (var path in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (++scanned > _options.MaxRecoveryScanFiles)
                        throw new InvalidDataException("Mailbox recovery scan exceeds its bound.");
                    MailboxNativeRecovery.RequireFile(path, token);
                    if (path.EndsWith(".tmp", StringComparison.Ordinal)) continue; // no purge/repair
                    if (!path.EndsWith(".json", StringComparison.Ordinal) || ++blobs > _options.MaxStoredBlobs)
                        throw new InvalidDataException("Mailbox recovery blob inventory is invalid.");
                    var id = Path.GetFileNameWithoutExtension(path);
                    var length = new FileInfo(path).Length;
                    if (!EncryptedMailboxBlobValidator.IsCanonicalId(id) || length <= 0 ||
                        length > checked((long)_options.MaxBlobBytes * 8 + 1024))
                        throw new InvalidDataException("Mailbox recovery blob framing is invalid.");
                    await using var stream = File.OpenRead(path);
                    var blob = await JsonSerializer.DeserializeAsync<EncryptedMailboxBlob>(stream, JsonOptions, token)
                        .ConfigureAwait(false);
                    if (blob is null || blob.MailboxId != mailbox || blob.BlobId != id || !IsStoredBlobValid(blob, 0))
                        throw new InvalidDataException("Mailbox recovery blob differs from its native key.");
                    requireMutation(blob);
                }
            }
            if (_storedBlobCount >= 0 && _storedBlobCount != blobs)
                throw new InvalidDataException("Mailbox recovery blob count differs from native custody.");
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Mailbox recovery blob JSON is corrupt.", error);
        }
        finally { _gate.Release(); }
    }
}
