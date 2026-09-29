using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace XNode;

/// <summary>Offline operator export, never a network verifier or a custody recovery/import path.</summary>
internal static class DeepIdV2NetworkFloorAudit
{
    internal const string ApplicationName = "XPoint.XNode.DID2.DirectoryProof.v2";
    private const int MaximumProtectedBytes = 16 + 225 + 2 * 65_535 + 68 + 1_024;

    internal static IDataProtector Protector(IDataProtectionProvider provider, string genesis, string nodeId) =>
        provider.CreateProtector("Deep.XNode.DID2.NetworkFloor.v2", genesis, nodeId);

    internal static void Run(string[] args)
    {
        if (args.Length != 9 || args[0] != "did2-network-floor-audit" ||
            args[1] != "--snapshot-root" || args[3] != "--directory-genesis-core-hash" ||
            args[5] != "--node-id" || args[7] != "--output")
            throw new ArgumentException("Invalid offline network-floor audit arguments.");
        var genesis = CanonicalHash(args[4]);
        var node = CanonicalHash(args[6]);
        var root = Path.GetFullPath(args[2]);
        RequireRegularPath(root, directory: true);
        var keys = Path.Combine(root, "keys");
        RequireRegularPath(keys, directory: true);
        var entries = Directory.EnumerateFileSystemEntries(root).Take(4).ToArray();
        if (entries.Length != 3 || entries.Any(path => Path.GetFileName(path) is not ("keys" or "floor.bin" or "anchor.bin")))
            throw new InvalidDataException("The offline snapshot must contain exactly floor, anchor and keys.");
        var keyFiles = Directory.EnumerateFileSystemEntries(keys).Take(129).ToArray();
        if (keyFiles.Length is < 1 or > 128)
            throw new InvalidDataException("The snapshot key ring is missing or exceeds its bound.");
        foreach (var key in keyFiles)
        {
            RequireRegularPath(key, directory: false);
            var name = Path.GetFileName(key);
            if ((!name.StartsWith("key-", StringComparison.Ordinal) && !name.StartsWith("revocation-", StringComparison.Ordinal)) ||
                !name.EndsWith(".xml", StringComparison.Ordinal) || new FileInfo(key).Length is < 1 or > 65_536)
                throw new InvalidDataException("The snapshot contains an unsupported key-ring record.");
        }
        var output = Path.GetFullPath(args[8]);
        RequireRegularPath(Path.GetDirectoryName(output)!, directory: true);
        var relative = Path.GetRelativePath(root, output);
        if (!Path.IsPathFullyQualified(relative) && relative != ".." &&
            !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException("The history export must be outside the custody snapshot.");
        if (File.Exists(output) || Directory.Exists(output))
            throw new IOException("The history export already exists.");

        // Same discriminator and purpose as the host, without key initialization or renewal.
        var provider = DataProtectionProvider.Create(new DirectoryInfo(keys), builder =>
            builder.SetApplicationName(ApplicationName).DisableAutomaticKeyGeneration());
        try
        {
            var floor = FileDeepIdV2NetworkFloorStore.AuthenticateSnapshot(
                ReadBounded(Path.Combine(root, "floor.bin")),
                ReadBounded(Path.Combine(root, "anchor.bin")), Protector(provider, genesis, node));
            using var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            stream.Write(floor.History);
            stream.Flush(flushToDisk: true);
            Console.WriteLine($"Authenticated offline history: revision={floor.Revision}; bytes={floor.History.Length}; sha256={Convert.ToHexString(SHA256.HashData(floor.History))}");
            Console.WriteLine("Historical custody only; no current-time authority, readiness or rollback recovery.");
        }
        finally { (provider as IDisposable)?.Dispose(); }
    }

    private static byte[] ReadBounded(string path)
    {
        RequireRegularPath(path, directory: false);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaximumProtectedBytes)
            throw new InvalidDataException("The protected snapshot record exceeds its bound.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw new InvalidDataException("The protected snapshot changed while reading.");
        return bytes;
    }

    private static string CanonicalHash(string value)
    {
        if (value.Length != 64 || value.Any(static c => c is not (>= '0' and <= '9') and not (>= 'A' and <= 'F')) ||
            value.All(static c => c == '0')) throw new ArgumentException("The audit scope requires canonical nonzero 32-byte uppercase hex.");
        return value;
    }

    private static void RequireRegularPath(string path, bool directory)
    {
        if (directory ? !Directory.Exists(path) : !File.Exists(path))
            throw new IOException("An offline audit input or output parent is missing.");
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Offline custody audit cannot traverse links.");
    }
}
