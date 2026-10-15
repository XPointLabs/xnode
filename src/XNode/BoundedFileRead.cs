using System.Security.Cryptography;

namespace XNode;

// Byte acquisition only, never a verified source or cached floor. Callers keep
// their path/ACL, authentication, independent-root and release checks.
internal static class BoundedFileRead
{
    internal static byte[] Read(string path, int minimumBytes, int maximumBytes, string invalidSize,
        ByteBudget? budget = null)
    {
        if (minimumBytes < 1 || maximumBytes < minimumBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, FileOptions.None);
        var length = RandomAccess.GetLength(handle);
        if (length < minimumBytes || length > maximumBytes)
            throw new InvalidDataException(invalidSize);
        budget?.Reserve((int)length);
        var bytes = new byte[(int)length];
        try
        {
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = RandomAccess.Read(handle, bytes.AsSpan(offset), offset);
                if (read == 0) throw new EndOfStreamException("The bounded file ended during its exact read.");
                offset = checked(offset + read);
            }
            // Keep a real EOF probe: Windows may cache length on a handle
            // opened without write sharing. Neither path metadata nor a
            // potentially cached length substitutes for this byte read.
            Span<byte> extra = stackalloc byte[1];
            if (RandomAccess.Read(handle, extra, length) != 0 || RandomAccess.GetLength(handle) != length)
                throw new InvalidDataException("The bounded file changed length during its exact read.");
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    // Allocation/resource bound only, not permission or verified evidence.
    // A failed group is discarded, so reservations are never recycled into
    // another read after an uncertain/failed acquisition.
    internal sealed class ByteBudget(long maximum, string invalidSize)
    {
        private long remaining = maximum > 0 ? maximum : throw new ArgumentOutOfRangeException(nameof(maximum));
        internal void Reserve(int count)
        {
            while (true)
            {
                var available = Interlocked.Read(ref remaining);
                if (count > available) throw new InvalidDataException(invalidSize);
                if (Interlocked.CompareExchange(ref remaining, available - count, available) == available) return;
            }
        }
    }
}
