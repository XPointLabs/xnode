using System.Security.Cryptography;
using Deep.Protocol.BlobV1;
using XNode.Core.Mailbox;

namespace XNode.Core.Blob;

/// <summary>Immutable public object commitments plus ciphertext. No account, object key or raw capability is persisted.</summary>
internal sealed class DurableBlobObjectStore : IDisposable
{
    private readonly string directory;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly DurableBlobChunkStore chunks;
    private readonly FileStream lease;
    private readonly object gate = new();
    private readonly int maximumObjects;
    private int objects;
    private bool disposed, faulted;

    internal DurableBlobObjectStore(string root, int maximumObjects, int maximumChunks, long maximumBytes,
        IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability)
    {
        if (maximumObjects is < 1 or > 16384) throw new ArgumentOutOfRangeException(nameof(maximumObjects));
        this.maximumObjects = maximumObjects; this.security = security; this.durability = durability;
        directory = Path.GetFullPath(Path.Combine(root, "objects"));
        RequireNoLinks(directory); security.SecureDirectory(directory); RequireNoLinks(directory);
        var lockPath = Path.Combine(directory, "owner.lock"); RequireNoLinks(lockPath);
        lease = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        try
        {
            security.SecureFile(lockPath);
            foreach (var file in Directory.EnumerateFileSystemEntries(directory))
            {
                RequireNoLinks(file);
                if (Path.GetFileName(file) == "owner.lock") continue;
                if (IsPending(Path.GetFileName(file)))
                {
                    security.ValidateSecureFile(file);
                    durability.DeleteFile(file); // Never published, therefore no Stored authority.
                    continue;
                }
                if (!Path.GetFileName(file).EndsWith(".object", StringComparison.Ordinal) || ++objects > maximumObjects)
                    throw new InvalidDataException("Blob object custody has an unknown entry or exceeded quota.");
                var descriptor = Read(file);
                if (Path.GetFileName(file) != Name(descriptor)) throw new InvalidDataException("Blob descriptor has a different object scope.");
            }
            chunks = new(Path.Combine(root, "chunks"), maximumChunks, maximumBytes, security, durability);
        }
        catch { lease.Dispose(); throw; }
    }

    internal (BlobChunkStatus Status, byte[] Ciphertext) Execute(BlobChunkRequest request, ulong trustedLower, ulong trustedUpper, CancellationToken ct)
    {
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if (faulted) throw new IOException("Blob object owner requires a verified restart.");
            ct.ThrowIfCancellationRequested();
            var descriptor = request.Descriptor;
            if (trustedUpper >= descriptor.ExpiresAtUnixSeconds) return (BlobChunkStatus.Expired, []);
            var path = Path.Combine(directory, Name(descriptor)); RequireNoLinks(path);
            if (File.Exists(path))
            {
                if (!Read(path).CanonicalBytes.Span.SequenceEqual(descriptor.CanonicalBytes.Span)) return (BlobChunkStatus.Conflict, []);
            }
            else
            {
                if (request.Operation == BlobChunkOperation.Get) return (BlobChunkStatus.Missing, []);
                if (descriptor.ExpiresAtUnixSeconds > checked(trustedLower + BlobChunkCodec.MaximumRetentionSeconds)) return (BlobChunkStatus.Expired, []);
                if (objects == maximumObjects) return (BlobChunkStatus.Quota, []);
                var exact = descriptor.CanonicalBytes;
                var pending = Path.Combine(directory, Name(descriptor)[..64] + "." + Guid.NewGuid().ToString("N") + ".pending");
                // Stage and fsync before atomic publication. A crash cannot turn
                // an incomplete descriptor into a committed object or poison the
                // whole owner; published descriptors still never get repaired.
                try
                {
                    using (var stream = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                    { security.SecureFile(pending); stream.Write(exact.Span); stream.Flush(true); }
                    durability.FlushFileAndParentDirectory(pending);
                    ct.ThrowIfCancellationRequested(); RequireNoLinks(path);
                    if (File.Exists(path)) throw new IOException("Blob descriptor changed outside its owner.");
                    durability.ReplaceFile(pending, path); security.SecureFile(path);
                    durability.FlushFileAndParentDirectory(path);
                    if (!Read(path).CanonicalBytes.Span.SequenceEqual(exact.Span)) throw new IOException("Blob descriptor readback differs.");
                    objects++;
                }
                catch { faulted = true; throw; }
                finally
                {
                    if (File.Exists(pending))
                    {
                        RequireNoLinks(pending); security.ValidateSecureFile(pending);
                        durability.DeleteFile(pending);
                    }
                }
            }
            var hash = descriptor.ChunkHash(request.ChunkIndex);
            if (request.Operation == BlobChunkOperation.Get)
            {
                var value = chunks.Read(hash.Span, ct);
                return value is null ? (BlobChunkStatus.Missing, []) : (BlobChunkStatus.Chunk, value);
            }
            var cipher = request.Ciphertext.ToArray();
            try
            {
                var result = chunks.Put(hash.Span, cipher, ct);
                if (result == BlobChunkWriteResult.QuotaExceeded) return (BlobChunkStatus.Quota, []);
                var stored = chunks.Read(hash.Span, ct) ?? throw new IOException("Blob chunk lost durable readback.");
                try { if (!stored.AsSpan().SequenceEqual(cipher)) throw new IOException("Blob chunk durable readback differs."); }
                finally { CryptographicOperations.ZeroMemory(stored); }
                return (result == BlobChunkWriteResult.ExactReplay ? BlobChunkStatus.ExactReplay : BlobChunkStatus.Stored, []);
            }
            finally { CryptographicOperations.ZeroMemory(cipher); }
        }
    }

    private BlobObjectDescriptor Read(string path)
    {
        RequireNoLinks(path); security.ValidateSecureFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        if (stream.Length is < 134 or > 3698) throw new InvalidDataException("Blob descriptor length is invalid.");
        var exact = new byte[(int)stream.Length]; stream.ReadExactly(exact);
        if (stream.ReadByte() != -1) throw new IOException("Blob descriptor changed while reading.");
        return BlobChunkCodec.DecodeDescriptor(exact);
    }
    private static string Name(BlobObjectDescriptor descriptor) => Convert.ToHexString(SHA256.HashData([.. descriptor.NetworkId.Span, .. descriptor.ObjectId.Span])) + ".object";
    private static bool IsPending(string name) => name.Length == 105 && name[64] == '.' &&
        name.AsSpan(0, 64).IndexOfAnyExcept("0123456789ABCDEF") < 0 &&
        name.AsSpan(65, 32).IndexOfAnyExcept("0123456789abcdef") < 0 && name.EndsWith(".pending", StringComparison.Ordinal);
    private static void RequireNoLinks(string path)
    {
        for (var cursor = Path.GetFullPath(path); cursor is not null; cursor = Path.GetDirectoryName(cursor))
            if (Path.Exists(cursor) && (File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0) throw new IOException("Blob custody link rejected.");
    }
    public void Dispose() { lock (gate) { if (disposed) return; disposed = true; chunks.Dispose(); lease.Dispose(); } }
}
