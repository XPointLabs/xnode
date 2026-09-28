using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode;

internal sealed record DeepIdV2NetworkFloor(ulong Revision, byte[] Instance, byte[] History);

/// <summary>
/// Independent anchor first, protected floor second. A split commit or rollback
/// fails closed, never repairs to empty. Joint rollback of both files is outside
/// this local guarantee. Each instance holds one process-independent writer lease.
/// </summary>
internal sealed class FileDeepIdV2NetworkFloorStore : IDisposable
{
    private const int HeaderBytes = 68;
    private const int MaximumHistoryBytes = 16 + 225 + 2 * 65_535;
    private readonly string root, directory, anchorDirectory, floorPath, anchorPath;
    private readonly IDataProtector protector;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lease;
    private readonly SemaphoreSlim gate = new(1, 1);
    private bool initialized, faulted, disposed;

    internal FileDeepIdV2NetworkFloorStore(string nodeDataDirectory,
        IDataProtector protector, IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeDataDirectory);
        this.protector = protector ?? throw new ArgumentNullException(nameof(protector));
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        root = Path.GetFullPath(nodeDataDirectory);
        directory = Path.Combine(root, "did2-network-state");
        anchorDirectory = Path.Combine(root, "did2-network-anchor");
        RejectLinks(directory); RejectLinks(anchorDirectory);
        security.SecureDirectory(directory); security.SecureDirectory(anchorDirectory);
        floorPath = Path.Combine(directory, "floor.bin");
        anchorPath = Path.Combine(anchorDirectory, "anchor.bin");
        var leasePath = Path.Combine(directory, "floor.lock");
        RejectLinks(leasePath);
        lease = new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
            FileShare.None, 1, FileOptions.WriteThrough);
        try { security.SecureFile(leasePath); security.ValidateSecureFile(leasePath); }
        catch { lease.Dispose(); throw; }
    }

    internal async ValueTask<DeepIdV2NetworkFloor?> ReadAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { CheckAvailable(); return ReadCore(); }
        finally { gate.Release(); }
    }

    internal async ValueTask<DeepIdV2NetworkFloor> CommitVerifiedAsync(
        DeepIdV2NetworkFloor? expected, VerifiedOnionNetworkContext verified,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var history = OnionNetworkProtectedHistoryCodec.Encode(verified);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            CheckAvailable(); cancellationToken.ThrowIfCancellationRequested();
            var current = ReadCore();
            if (!Same(current, expected))
                throw new InvalidOperationException("The DID2 network floor changed during verification.");
            if (current is null && verified.PriorProtectedLkg is not null)
                throw new InvalidOperationException("A successor cannot initialize an empty network floor.");
            if (current is not null && !OnionNetworkProtectedHistoryCodec.BindsPredecessor(verified, current.History))
                throw new InvalidOperationException("An existing network floor requires protected predecessor verification.");
            if (current is not null && Fixed(current.History, history)) return current;
            var next = new DeepIdV2NetworkFloor(checked((current?.Revision ?? 0) + 1),
                current?.Instance.ToArray() ?? RandomNumberGenerator.GetBytes(16), history);
            verified.EnsureCurrent();
            // From here any uncertain outcome latches this process. Restart
            // also requires the two independent protected records to agree.
            try
            {
                Write(anchorPath, Encode(next, anchor: true));
                Write(floorPath, Encode(next, anchor: false));
                initialized = true;
                var retained = ReadCore();
                if (!Same(next, retained)) throw new IOException("The committed network floor failed its durable recheck.");
                cancellationToken.ThrowIfCancellationRequested();
                verified.EnsureCurrent();
                return retained!;
            }
            catch { faulted = true; throw; }
        }
        finally { gate.Release(); }
    }

    internal static bool Same(DeepIdV2NetworkFloor? a, DeepIdV2NetworkFloor? b) =>
        a is null ? b is null : b is not null && a.Revision == b.Revision &&
            Fixed(a.Instance, b.Instance) && Fixed(a.History, b.History);

    private DeepIdV2NetworkFloor? ReadCore()
    {
        RejectUnknownFiles(directory, "floor.lock", "floor.bin");
        RejectUnknownFiles(anchorDirectory, "anchor.bin");
        var floor = Read(floorPath, anchor: false);
        var anchor = Read(anchorPath, anchor: true);
        if (floor is null && anchor is null)
        {
            if (initialized) throw new InvalidDataException("The initialized network floor disappeared.");
            return null;
        }
        if (floor is null || anchor is null || floor.Revision != anchor.Revision ||
            !Fixed(floor.Instance, anchor.Instance) || !Fixed(SHA256.HashData(floor.History), anchor.History))
            throw new InvalidDataException("The independent network floor and anchor are missing, split or rolled back.");
        initialized = true;
        return floor;
    }

    private DeepIdV2NetworkFloor? Read(string path, bool anchor)
    {
        if (!File.Exists(path)) return null;
        RejectLinks(path); security.ValidateSecureFile(path);
        var info = new FileInfo(path);
        if (info.Length is < 1 or > MaximumHistoryBytes + HeaderBytes + 1_024)
            throw new InvalidDataException("The protected network floor exceeds its closed byte bound.");
        var protectedBytes = File.ReadAllBytes(path);
        byte[]? plain = null;
        try
        {
            plain = protector.Unprotect(protectedBytes);
            if (plain.Length < HeaderBytes || !plain.AsSpan(0, 4).SequenceEqual("DNF2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(4)) != 2 ||
                BinaryPrimitives.ReadUInt16BigEndian(plain.AsSpan(6)) != (anchor ? 1 : 0))
                throw new InvalidDataException("The protected network floor header is invalid.");
            var revision = BinaryPrimitives.ReadUInt64BigEndian(plain.AsSpan(8));
            var length = BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(64));
            if (revision == 0 || length is < 241 or > MaximumHistoryBytes ||
                plain.AsSpan(16, 16).IndexOfAnyExcept((byte)0) < 0 ||
                plain.AsSpan(32, 32).IndexOfAnyExcept((byte)0) < 0 ||
                plain.Length != HeaderBytes + (anchor ? 0 : (int)length))
                throw new InvalidDataException("The protected network floor shape is invalid.");
            var body = anchor ? plain.AsSpan(32, 32).ToArray() : plain.AsSpan(HeaderBytes).ToArray();
            if (!anchor && !Fixed(SHA256.HashData(body), plain.AsSpan(32, 32)))
                throw new InvalidDataException("The protected network floor hash is invalid.");
            return new(revision, plain.AsSpan(16, 16).ToArray(), body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static byte[] Encode(DeepIdV2NetworkFloor record, bool anchor)
    {
        var bytes = new byte[HeaderBytes + (anchor ? 0 : record.History.Length)];
        "DNF2"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), (ushort)(anchor ? 1 : 0));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), record.Revision);
        record.Instance.CopyTo(bytes, 16);
        SHA256.HashData(record.History).CopyTo(bytes, 32);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(64), checked((uint)record.History.Length));
        if (!anchor) record.History.CopyTo(bytes, HeaderBytes);
        return bytes;
    }

    private void Write(string path, byte[] plain)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        byte[]? protectedBytes = null;
        try
        {
            RejectLinks(path); RejectLinks(temporary);
            protectedBytes = protector.Protect(plain);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4_096, FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes); stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary); security.ValidateSecureFile(temporary);
            durability.ReplaceFile(temporary, path);
            security.SecureFile(path); security.ValidateSecureFile(path);
            durability.FlushFileAndParentDirectory(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary)) durability.DeleteFile(temporary);
        }
    }

    private void RejectUnknownFiles(string path, params string[] allowed)
    {
        RejectLinks(path);
        foreach (var entry in Directory.EnumerateFileSystemEntries(path))
            if (!allowed.Contains(Path.GetFileName(entry), StringComparer.Ordinal) || Directory.Exists(entry))
                throw new InvalidDataException("The network floor contains an unknown or partial record.");
    }

    private void RejectLinks(string path)
    {
        var relative = Path.GetRelativePath(root, path);
        if (relative is "." or ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathFullyQualified(relative)) throw new UnauthorizedAccessException("Network custody is outside the node root.");
        var current = path;
        while (current.Length >= root.Length)
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Network custody cannot traverse links.");
            current = Path.GetDirectoryName(current) ?? string.Empty;
        }
    }

    private void CheckAvailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted) throw new InvalidOperationException("The network floor is faulted after an uncertain commit.");
    }
    public void Dispose() { if (disposed) return; disposed = true; lease.Dispose(); gate.Dispose(); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
