using System.Text.Json;

namespace XNode.Core.Mailbox;

public sealed partial class ReplicatedMailboxStore
{
    internal async Task ValidateNewNativeScopeAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (_storedBlobCount > 0)
                throw new InvalidDataException("New mailbox enrollment cannot adopt stored blobs.");
            MailboxNativeRecovery.RequireNewDirectory(_rootDirectory, null, token);
        }
        finally { _gate.Release(); }
    }

    // Expiry does not make persisted corruption valid. The callback joins every
    // extant blob to its mutation; it does not admit expired objects for reads.
    // This is an internal read-only subscan of the mutation owner's recovery
    // join. That owner brackets the complete scan/callbacks with live checks
    // before returning any recovered authority. No blob/state mutation, public
    // response or independently usable capability is released by this helper.
    internal async Task ValidateCurrentRecoveryAsync(Action<EncryptedMailboxBlob> requireMutation,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            lease.RequireActive(); token.ThrowIfCancellationRequested();
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
            lease.RequireActive(); token.ThrowIfCancellationRequested();
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("Mailbox recovery blob JSON is corrupt.", error);
        }
        finally { _gate.Release(); }
    }
}
