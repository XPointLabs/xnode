using System.Security.Cryptography;
using XNode.Core.Mailbox;

namespace XNode.Core.Blob;

internal enum BlobChunkWriteResult { Committed, ExactReplay, QuotaExceeded }

// Ciphertext-only storage primitive. No route, capability, retention or receipt
// authority: the eventual authenticated BLOB service must enforce those first.
internal sealed class DurableBlobChunkStore : IDisposable
{
    internal const int MaximumChunkBytes = 262160;
    private const string LeaseName = "owner.lock";
    private readonly object gate = new();
    private readonly string directory;
    private readonly int maximumChunks;
    private readonly long maximumBytes;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lifetimeLease;
    private int count;
    private long bytes;
    private bool disposed, faulted;

    internal DurableBlobChunkStore(string directory, int maximumChunks, long maximumBytes,
        IMailboxStorageSecurity? security = null, IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        if (maximumChunks is < 1 or > 16384 || maximumBytes < 1 || maximumBytes > (long)maximumChunks * MaximumChunkBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumChunks));
        this.directory = Path.GetFullPath(directory);
        this.maximumChunks = maximumChunks; this.maximumBytes = maximumBytes;
        this.security = security ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();
        _ = ExistsRegular(this.directory, true);
        this.security.SecureDirectory(this.directory); RequireRegular(this.directory, true);
        var leasePath = Path.Combine(this.directory, LeaseName);
        _ = ExistsRegular(leasePath, false);
        lifetimeLease = new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
            FileShare.None, 1, FileOptions.WriteThrough);
        try
        {
            this.security.SecureFile(leasePath);
            Scan();
        }
        catch { lifetimeLease.Dispose(); throw; }
    }

    internal BlobChunkWriteResult Put(ReadOnlySpan<byte> expectedHash, ReadOnlySpan<byte> ciphertext,
        CancellationToken ct = default)
    {
        var name = ChunkName(expectedHash);
        if (ciphertext.Length is < 1 or > MaximumChunkBytes)
            throw new ArgumentOutOfRangeException(nameof(ciphertext));
        var digest = SHA256.HashData(ciphertext);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(digest, expectedHash))
                throw new CryptographicException("Blob ciphertext does not match its commitment.");
        }
        finally { CryptographicOperations.ZeroMemory(digest); }
        lock (gate)
        {
            RequireAlive(); ct.ThrowIfCancellationRequested();
            var final = Path.Combine(directory, name);
            if (ExistsRegular(final, false))
            {
                byte[] retained;
                try { retained = ReadExact(final, expectedHash); }
                catch { faulted = true; throw; }
                try
                {
                    if (!retained.AsSpan().SequenceEqual(ciphertext))
                        throw new CryptographicException("A retained blob commitment changed bytes.");
                    return BlobChunkWriteResult.ExactReplay;
                }
                finally { CryptographicOperations.ZeroMemory(retained); }
            }
            if (count == maximumChunks || ciphertext.Length > maximumBytes - bytes)
                return BlobChunkWriteResult.QuotaExceeded;
            var pending = Path.Combine(directory, name[..64] + "." + Guid.NewGuid().ToString("N") + ".pending");
            try
            {
                using (var stream = new FileStream(pending, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    security.SecureFile(pending);
                    stream.Write(ciphertext); stream.Flush(flushToDisk: true);
                }
                durability.FlushFileAndParentDirectory(pending);
                ct.ThrowIfCancellationRequested();
                // The lifetime lease gives one writer. Never overwrite a
                // committed chunk; a failed barrier has outcome-unknown state.
                if (ExistsRegular(final, false)) throw new IOException("Blob storage changed outside its owner.");
                durability.ReplaceFile(pending, final);
                security.SecureFile(final); durability.FlushFileAndParentDirectory(final);
                count++; bytes += ciphertext.Length;
                ct.ThrowIfCancellationRequested();
                return BlobChunkWriteResult.Committed;
            }
            catch (OperationCanceledException) { throw; }
            catch { faulted = true; throw; }
            finally
            {
                if (File.Exists(pending))
                {
                    try { RequireRegular(pending, false); durability.DeleteFile(pending); }
                    catch { faulted = true; }
                }
            }
        }
    }

    internal byte[]? Read(ReadOnlySpan<byte> expectedHash, CancellationToken ct = default)
    {
        var name = ChunkName(expectedHash);
        lock (gate)
        {
            RequireAlive(); ct.ThrowIfCancellationRequested();
            var path = Path.Combine(directory, name);
            if (!ExistsRegular(path, false)) return null;
            byte[] result;
            try { result = ReadExact(path, expectedHash); }
            catch { faulted = true; throw; }
            try { ct.ThrowIfCancellationRequested(); return result; }
            catch { CryptographicOperations.ZeroMemory(result); throw; }
        }
    }

    private void Scan()
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(directory))
        {
            var name = Path.GetFileName(path);
            if (name == LeaseName) continue;
            RequireRegular(path, false);
            if (IsPending(name))
            {
                // Only this store's closed random staging filename is eligible.
                // Unpublished ciphertext has no commit/receipt and may be retried.
                durability.DeleteFile(path); continue;
            }
            if (name.Length != 70 || !name.EndsWith(".chunk", StringComparison.Ordinal) || !IsHash(name.AsSpan(0, 64)))
                throw new InvalidDataException("Blob storage contains an unknown entry.");
            if (++count > maximumChunks) throw new InvalidDataException("Blob count exceeds its configured quota.");
            var hash = Convert.FromHexString(name[..64]);
            var chunk = ReadExact(path, hash);
            try
            {
                bytes = checked(bytes + chunk.Length);
                if (bytes > maximumBytes) throw new InvalidDataException("Blob bytes exceed their configured quota.");
            }
            finally { CryptographicOperations.ZeroMemory(chunk); }
        }
    }

    private byte[] ReadExact(string path, ReadOnlySpan<byte> expectedHash)
    {
        RequireRegular(path, false); security.ValidateSecureFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length is < 1 or > MaximumChunkBytes)
            throw new InvalidDataException("Stored blob chunk exceeds its closed bound.");
        var result = new byte[checked((int)stream.Length)];
        byte[] digest = [];
        try
        {
            stream.ReadExactly(result);
            if (stream.ReadByte() != -1) throw new InvalidDataException("Stored blob chunk changed length.");
            digest = SHA256.HashData(result);
            if (!CryptographicOperations.FixedTimeEquals(digest, expectedHash))
                throw new CryptographicException("Stored blob chunk failed integrity verification.");
            return result;
        }
        catch { CryptographicOperations.ZeroMemory(result); throw; }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }

    private static string ChunkName(ReadOnlySpan<byte> hash)
    {
        if (hash.Length != 32) throw new ArgumentException("Blob commitment must be exactly 32 bytes.", nameof(hash));
        return Convert.ToHexStringLower(hash) + ".chunk";
    }
    private static bool IsHash(ReadOnlySpan<char> value) => value.Length == 64 && value.IndexOfAnyExcept("0123456789abcdef") < 0;
    private static bool IsPending(string name) => name.Length == 105 && IsHash(name.AsSpan(0, 64)) &&
        name[64] == '.' && name.AsSpan(65, 32).IndexOfAnyExcept("0123456789abcdef") < 0 &&
        name.EndsWith(".pending", StringComparison.Ordinal);
    private static void RequireRegular(string path, bool directory)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 || ((attributes & FileAttributes.Directory) != 0) != directory)
            throw new UnauthorizedAccessException("Blob storage requires a regular owned filesystem entry.");
    }
    private static bool ExistsRegular(string path, bool directory)
    {
        try { RequireRegular(path, directory); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
    private void RequireAlive()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted) throw new IOException("Blob storage requires reopen after an uncertain persistence failure.");
    }
    public void Dispose()
    {
        lock (gate) { if (disposed) return; disposed = true; lifetimeLease.Dispose(); }
    }
}
