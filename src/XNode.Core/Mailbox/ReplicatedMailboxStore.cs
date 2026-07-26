using System.Text.Json;

namespace XNode.Core.Mailbox;

public enum MailboxPutDisposition
{
    Stored,
    Duplicate,
    Rejected
}

public sealed record MailboxPutResult(MailboxPutDisposition Disposition, string Error = "");

public sealed class ReplicatedMailboxStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _rootDirectory;
    private readonly ReplicatedMailboxOptions _options;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private int _storedBlobCount = -1;

    public ReplicatedMailboxStore(
        string dataDirectory,
        ReplicatedMailboxOptions options,
        IClock? clock = null)
    {
        options.Validate();
        _options = options;
        _clock = clock ?? new SystemClock();
        _rootDirectory = Path.Combine(dataDirectory, options.DirectoryName);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(_rootDirectory);
        RestrictDirectoryPermissions(_rootDirectory);
        await PurgeExpiredAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<MailboxPutResult> PutAsync(
        EncryptedMailboxBlob blob,
        CancellationToken cancellationToken = default)
    {
        if (!EncryptedMailboxBlobValidator.TryValidate(
                blob,
                _clock.UtcNow,
                _options,
                out _,
                out var validationError))
        {
            return new MailboxPutResult(MailboxPutDisposition.Rejected, validationError);
        }

        Directory.CreateDirectory(_rootDirectory);
        RestrictDirectoryPermissions(_rootDirectory);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureStoredBlobCount();
            var mailboxDirectory = Path.Combine(_rootDirectory, blob.MailboxId);
            var finalPath = Path.Combine(mailboxDirectory, $"{blob.BlobId}.json");
            if (File.Exists(finalPath))
            {
                try
                {
                    await using var existingStream = File.OpenRead(finalPath);
                    var existing = await JsonSerializer.DeserializeAsync<EncryptedMailboxBlob>(
                        existingStream,
                        JsonOptions,
                        cancellationToken).ConfigureAwait(false);
                    return existing == blob
                        ? new MailboxPutResult(MailboxPutDisposition.Duplicate)
                        : new MailboxPutResult(MailboxPutDisposition.Rejected, "mailbox-blob-id-conflict");
                }
                catch (Exception exception) when (exception is IOException or JsonException)
                {
                    return new MailboxPutResult(MailboxPutDisposition.Rejected, "mailbox-storage-corrupt");
                }
            }

            if (_storedBlobCount >= _options.MaxStoredBlobs)
            {
                await PurgeExpiredUnderGateAsync(cancellationToken).ConfigureAwait(false);
                if (_storedBlobCount >= _options.MaxStoredBlobs)
                {
                    return new MailboxPutResult(MailboxPutDisposition.Rejected, "mailbox-capacity-exhausted");
                }
            }

            Directory.CreateDirectory(mailboxDirectory);
            RestrictDirectoryPermissions(mailboxDirectory);
            var temporaryPath = $"{finalPath}.{Guid.NewGuid():N}.tmp";
            try
            {
                await using (var stream = new FileStream(
                                 temporaryPath,
                                 FileMode.CreateNew,
                                 FileAccess.Write,
                                 FileShare.None,
                                 8192,
                                 FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await JsonSerializer.SerializeAsync(stream, blob, JsonOptions, cancellationToken)
                        .ConfigureAwait(false);
                    await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }

                File.Move(temporaryPath, finalPath, overwrite: false);
                RestrictFilePermissions(finalPath);
                _storedBlobCount++;
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }

            return new MailboxPutResult(MailboxPutDisposition.Stored);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<EncryptedMailboxBlob>> ReadAsync(
        string mailboxId,
        int maximumCount,
        CancellationToken cancellationToken = default)
    {
        if (!EncryptedMailboxBlobValidator.IsCanonicalId(mailboxId)
            || maximumCount is < 1 or > 1000)
        {
            return [];
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.Combine(_rootDirectory, mailboxId);
            if (!Directory.Exists(directory))
            {
                return [];
            }

            var nowUnixMs = _clock.UtcNow.ToUnixTimeMilliseconds();
            var result = new List<EncryptedMailboxBlob>(Math.Min(maximumCount, 100));
            foreach (var path in Directory.EnumerateFiles(directory, "*.json")
                         .Order(StringComparer.Ordinal))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await using var stream = File.OpenRead(path);
                    var blob = await JsonSerializer.DeserializeAsync<EncryptedMailboxBlob>(
                        stream,
                        JsonOptions,
                        cancellationToken).ConfigureAwait(false);
                    if (blob is not null
                        && blob.MailboxId == mailboxId
                        && Path.GetFileNameWithoutExtension(path) == blob.BlobId
                        && IsStoredBlobValid(blob, nowUnixMs))
                    {
                        result.Add(blob);
                        if (result.Count == maximumCount)
                        {
                            break;
                        }
                    }
                }
                catch (Exception exception) when (exception is IOException or JsonException)
                {
                    // Corrupt entries are never returned as valid encrypted messages.
                }
            }

            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await PurgeExpiredUnderGateAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<int> PurgeExpiredUnderGateAsync(CancellationToken cancellationToken)
    {
        if (!Directory.Exists(_rootDirectory))
        {
            _storedBlobCount = 0;
            return 0;
        }

        var removed = 0;
        EnsureStoredBlobCount();
        var nowUnixMs = _clock.UtcNow.ToUnixTimeMilliseconds();
        foreach (var path in Directory.EnumerateFiles(_rootDirectory, "*.json", SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var keep = false;
            try
            {
                await using (var stream = File.OpenRead(path))
                {
                    var blob = await JsonSerializer.DeserializeAsync<EncryptedMailboxBlob>(
                        stream,
                        JsonOptions,
                        cancellationToken).ConfigureAwait(false);
                    keep = blob is not null
                        && string.Equals(
                            blob.MailboxId,
                            Directory.GetParent(path)?.Name,
                            StringComparison.Ordinal)
                        && string.Equals(
                            blob.BlobId,
                            Path.GetFileNameWithoutExtension(path),
                            StringComparison.Ordinal)
                        && IsStoredBlobValid(blob, nowUnixMs);
                }
            }
            catch (Exception exception) when (exception is IOException or JsonException)
            {
                // Invalid storage is quarantined by deletion, never served.
            }

            if (keep)
            {
                continue;
            }

            File.Delete(path);
            removed++;
        }

        _storedBlobCount = Math.Max(0, _storedBlobCount - removed);
        return removed;
    }

    private void EnsureStoredBlobCount()
    {
        if (_storedBlobCount < 0)
        {
            _storedBlobCount = Directory.Exists(_rootDirectory)
                ? Directory.EnumerateFiles(_rootDirectory, "*.json", SearchOption.AllDirectories).Count()
                : 0;
        }
    }

    private bool IsStoredBlobValid(EncryptedMailboxBlob blob, long nowUnixMs)
    {
        if (!EncryptedMailboxBlobValidator.IsCanonicalId(blob.MailboxId)
            || !EncryptedMailboxBlobValidator.IsCanonicalId(blob.BlobId)
            || blob.ExpiresAtUnixMs <= nowUnixMs)
        {
            return false;
        }

        try
        {
            var ciphertext = Convert.FromBase64String(blob.Ciphertext);
            return ciphertext.Length is > 0
                && ciphertext.Length <= _options.MaxBlobBytes
                && string.Equals(Convert.ToBase64String(ciphertext), blob.Ciphertext, StringComparison.Ordinal)
                && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Security.Cryptography.SHA256.HashData(ciphertext),
                    Convert.FromHexString(blob.BlobId));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static void RestrictDirectoryPermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private static void RestrictFilePermissions(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
