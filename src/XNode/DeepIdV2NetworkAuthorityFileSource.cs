using System.Security.Cryptography;
using System.Runtime.ExceptionServices;
using System.Buffers.Binary;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

/// <summary>
/// Reads the exact signed XNA1/DTS1 lineage against an independent genesis pin.
/// Only immutable signature verification is memoized; currentness is not.
/// </summary>
internal sealed class DeepIdV2NetworkAuthorityFileSource
{
    private const int MaximumArtifactBytes = 65_535;
    private readonly XPointNetworkGenesisPin pin;
    private readonly string[] authorityPaths;
    private readonly string[] timePolicyPaths;
    private readonly object verificationGate = new();
    private byte[]? verifiedDigest;
    private VerifiedXPointNetworkAuthority? verifiedLineage;

    internal DeepIdV2NetworkAuthorityFileSource(XPointNetworkGenesisPin pin,
        IReadOnlyList<string> exactAuthorityPaths,
        IReadOnlyList<string> exactTimePolicyPaths)
    {
        this.pin = pin ?? throw new ArgumentNullException(nameof(pin));
        ArgumentNullException.ThrowIfNull(exactAuthorityPaths);
        ArgumentNullException.ThrowIfNull(exactTimePolicyPaths);
        if (exactAuthorityPaths.Count is < 1 or > 64 ||
            exactTimePolicyPaths.Count != exactAuthorityPaths.Count)
            throw new ArgumentException(
                "DID2 XNA1/DTS1 authority lineage must contain 1..64 paired artifacts.");
        authorityPaths = exactAuthorityPaths.Select(RequireAbsolutePath).ToArray();
        timePolicyPaths = exactTimePolicyPaths.Select(RequireAbsolutePath).ToArray();
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (authorityPaths.Concat(timePolicyPaths).Distinct(comparer).Count() !=
            authorityPaths.Length + timePolicyPaths.Length)
            throw new ArgumentException(
                "DID2 authority artifact paths must be distinct.");
    }

    internal VerifiedXPointNetworkAuthority ReadCurrent()
    {
        // This small paired keyring is read inside every protected operation
        // check. Do not synchronously fork/join the request's own ThreadPool
        // for each tiny record. Every path/handle/byte check still runs.
        byte[][] exact = [];
        try
        {
            exact = ReadExactMany(authorityPaths.Concat(timePolicyPaths).ToArray(), parallel: false);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            Span<byte> length = stackalloc byte[4];
            foreach (var bytes in exact)
            {
                BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
                hash.AppendData(length); hash.AppendData(bytes);
            }
            var digest = hash.GetHashAndReset();
            lock (verificationGate)
            {
                // Signature/grammar verification of the SAME exact public lineage
                // is immutable. Files/path/handle/EOF guards still run on every
                // call, as do callers' actual floors, time and issuer checks.
                // No freshness, accepted version floor or permission is cached.
                if (verifiedLineage is not null && verifiedDigest is not null &&
                    CryptographicOperations.FixedTimeEquals(digest, verifiedDigest)) return verifiedLineage;
                var verified = XPointNetworkAuthorityVerifier.Verify(pin,
                    exact.Take(authorityPaths.Length).Select(static bytes =>
                        (ReadOnlyMemory<byte>)bytes).ToArray(),
                    exact.Skip(authorityPaths.Length).Select(static bytes =>
                        (ReadOnlyMemory<byte>)bytes).ToArray());
                if (!CryptographicOperations.FixedTimeEquals(
                        verified.NetworkId.Span, pin.NetworkId.Span))
                    throw new CryptographicException(
                        "DID2 authority lineage changed networks.");
                verifiedDigest = digest; verifiedLineage = verified;
                return verified;
            }
        }
        catch
        {
            lock (verificationGate) { verifiedDigest = null; verifiedLineage = null; }
            throw;
        }
        finally
        {
            foreach (var artifact in exact)
                CryptographicOperations.ZeroMemory(artifact);
        }
    }

    private static string RequireAbsolutePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) ||
            path != path.Trim())
            throw new ArgumentException(
                "DID2 authority artifacts require clean absolute paths.");
        return Path.GetFullPath(path);
    }

    internal static byte[] ReadExact(string path) => ReadExact(path, null);

    private static byte[] ReadExact(string path, BoundedFileRead.ByteBudget? budget)
    {
        using var measurement = CurrentMailboxDiagnostics.Measure("authority-record-file");
        var root = Path.GetPathRoot(path) ?? throw new InvalidDataException(
            "DID2 authority artifact has no filesystem root.");
        var current = root;
        foreach (var part in Path.GetRelativePath(root, path).Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException(
                    "DID2 authority artifact path contains a link.");
        }
        return BoundedFileRead.Read(path, 1, MaximumArtifactBytes,
            "DID2 authority artifact exceeds its closed bound.", budget);
    }

    internal static byte[][] ReadExactMany(IReadOnlyList<string> paths, BoundedFileRead.ByteBudget? budget = null,
        bool parallel = true)
    {
        // At most six already bounded 4096-record closure groups. This is an
        // acquisition count bound, not a larger protocol or byte limit.
        if (paths.Count > 6 * 4096) throw new ArgumentException("The file-source group exceeds its closed count bound.");
        var result = new byte[paths.Count][];
        try
        {
            // Only independent, read-only public artifacts are acquired in
            // parallel. Each keeps its own fresh full path checks and handle.
            // Four reads at most; all finish before verification or release.
            var batchSize = parallel ? 4 : 1;
            for (var first = 0; first < paths.Count; first += batchSize)
            {
                var start = first;
                var count = Math.Min(batchSize, paths.Count - start);
                if (count == 1) { result[start] = ReadExact(paths[start], budget); continue; }
                var errors = new ExceptionDispatchInfo?[count];
                Parallel.For(0, count, new ParallelOptions { MaxDegreeOfParallelism = 4 }, offset =>
                {
                    try { result[start + offset] = ReadExact(paths[start + offset], budget); }
                    catch (Exception error) { errors[offset] = ExceptionDispatchInfo.Capture(error); }
                });
                // Preserve a typed first-in-source-order refusal, never an
                // AggregateException or a partial successful source frame.
                foreach (var error in errors) error?.Throw();
            }
            return result;
        }
        catch
        {
            foreach (var bytes in result)
                if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }
}
