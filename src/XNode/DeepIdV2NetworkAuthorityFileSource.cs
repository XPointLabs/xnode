using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

/// <summary>
/// Re-verifies the exact signed XNA1/DTS1 lineage from an independently
/// configured genesis pin. DID2 proof must never borrow the V1 ADP1 snapshot.
/// </summary>
internal sealed class DeepIdV2NetworkAuthorityFileSource
{
    private const int MaximumArtifactBytes = 65_535;
    private readonly XPointNetworkGenesisPin pin;
    private readonly string[] authorityPaths;
    private readonly string[] timePolicyPaths;

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
        var authorities = new List<byte[]>(authorityPaths.Length);
        var policies = new List<byte[]>(timePolicyPaths.Length);
        try
        {
            foreach (var path in authorityPaths) authorities.Add(ReadExact(path));
            foreach (var path in timePolicyPaths) policies.Add(ReadExact(path));
            var verified = XPointNetworkAuthorityVerifier.Verify(pin,
                authorities.Select(static bytes =>
                    (ReadOnlyMemory<byte>)bytes).ToArray(),
                policies.Select(static bytes =>
                    (ReadOnlyMemory<byte>)bytes).ToArray());
            if (!CryptographicOperations.FixedTimeEquals(
                    verified.NetworkId.Span, pin.NetworkId.Span))
                throw new CryptographicException(
                    "DID2 authority lineage changed networks.");
            return verified;
        }
        finally
        {
            foreach (var artifact in authorities.Concat(policies))
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

    internal static byte[] ReadExact(string path)
    {
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
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, bufferSize: 4096, FileOptions.SequentialScan);
        var length = stream.Length;
        if (length is < 1 or > MaximumArtifactBytes)
            throw new InvalidDataException(
                "DID2 authority artifact exceeds its closed bound.");
        var bytes = new byte[(int)length];
        try
        {
            stream.ReadExactly(bytes);
            if (stream.ReadByte() == -1 && stream.Length == length)
                return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
        CryptographicOperations.ZeroMemory(bytes);
        throw new InvalidDataException(
            "DID2 authority artifact changed while being read.");
    }
}
