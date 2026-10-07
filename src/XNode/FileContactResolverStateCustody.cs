using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>Independent authenticated root of the existing resolver document.
/// Matching joint rollback of root and data is outside this local guarantee.</summary>
internal sealed class FileContactResolverStateCustody : IContactResolverStateCustody, IDisposable
{
    internal const string RelativeDocumentPath = "contact-service-v1/resolver.state";
    private const int MaximumRecordBytes = 4_096;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string document, directory, enrollmentPath, checkpointPath;
    private readonly byte[] network;
    private readonly long maximumDocumentBytes;
    private readonly IDataProtector enrollmentProtection, checkpointProtection;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream writer;
    private bool disposed, freshScope;

    internal FileContactResolverStateCustody(string nodeDataRoot, string independentCustodyRoot,
        ReadOnlySpan<byte> nodeId32, ReadOnlySpan<byte> networkId16, IDataProtectionProvider protection,
        long maximumDocumentBytes, IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentNullException.ThrowIfNull(protection);
        if (nodeId32.Length != 32 || nodeId32.IndexOfAnyExcept((byte)0) < 0 ||
            networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0 ||
            maximumDocumentBytes is < 1 or > int.MaxValue)
            throw new ArgumentException("Resolver custody requires a bounded exact node/network scope.");
        var data = FullDirectory(nodeDataRoot); var custody = FullDirectory(independentCustodyRoot);
        if (Overlaps(data, custody))
            throw new ArgumentException("Resolver custody must be independent of replaceable node data.");
        this.security = security ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();
        this.maximumDocumentBytes = maximumDocumentBytes; network = networkId16.ToArray();
        document = Path.Combine(data, "contact-service-v1", "resolver.state");
        var scope = Convert.ToHexString(SHA256.HashData([.. nodeId32, .. networkId16]));
        directory = Path.Combine(custody, "contact-resolver", scope);
        enrollmentProtection = protection.CreateProtector("Deep.XNode.ContactResolver.Enrollment.v1", scope, RelativeDocumentPath);
        checkpointProtection = protection.CreateProtector("Deep.XNode.ContactResolver.Checkpoint.v1", scope, RelativeDocumentPath);
        RejectLinks(document); RejectLinks(directory); this.security.SecureDirectory(directory);
        enrollmentPath = Path.Combine(directory, "enrollment.bin");
        checkpointPath = Path.Combine(directory, "checkpoint.bin");
        var lockPath = Path.Combine(directory, "writer.lock"); RejectLinks(lockPath);
        writer = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        try { this.security.SecureFile(lockPath); this.security.ValidateSecureFile(lockPath); }
        catch { writer.Dispose(); throw; }
    }

    public void RequireNetwork(ReadOnlySpan<byte> networkId16)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (networkId16.Length != network.Length || !CryptographicOperations.FixedTimeEquals(networkId16, network))
            throw new CryptographicException("Resolver custody rejected a different network.");
    }

    public void RequireNewScope(string documentPath)
    {
        RequirePath(documentPath); RequireOnlyWriter(); RejectLinks(document);
        if (File.Exists(document) || Directory.Exists(document))
            throw new InvalidDataException("Existing resolver state cannot be enrolled or imported.");
        freshScope = true;
    }

    public void Enroll(string documentPath, ReadOnlySpan<byte> expectedSha256, long expectedLength)
    {
        RequirePath(documentPath); RequireOnlyWriter();
        if (!freshScope) throw new InvalidOperationException("Explicit fresh resolver enrollment was not started.");
        // Never retry a partially written enrollment in this instance.
        freshScope = false;
        var initial = Hash(document);
        RequireDigest(initial, CapturedHash(expectedSha256, expectedLength), expectedLength);
        var enrollment = new Enrollment(1, Guid.NewGuid().ToString("N"), initial.Hash, initial.Length);
        Write(enrollmentPath, enrollment, enrollmentProtection);
        Write(checkpointPath, new Checkpoint(1, enrollment.Id, 0, initial.Hash, initial.Length, null), checkpointProtection);
        RequireSnapshot(documentPath);
    }

    public void RequireSnapshot(string documentPath)
    {
        RequirePath(documentPath); var state = ReadState();
        if (state.Next is not null) throw new InvalidDataException("Resolver document transition is not committed.");
        RequireDigest(Hash(document), state.Hash, state.Length);
    }

    // Check the exact bytes parsed/serialized by the owned store, not merely
    // a second read of a path that could undergo an ABA replacement.
    public void RequireDocumentSnapshot(string documentPath, ReadOnlySpan<byte> sha256, long length)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var captured = (CapturedHash(sha256, length), length); var state = ReadState();
        if (SamePath(documentPath, document))
        {
            if (state.Next is { } next) RequireDigest(captured, next.Hash, next.Length);
            else RequireDigest(captured, state.Hash, state.Length);
        }
        else if (state.Next is { } pending && SamePath(documentPath,
            Path.Combine(Path.GetDirectoryName(document)!, pending.Temporary)))
            RequireDigest(captured, pending.Hash, pending.Length);
        else throw new InvalidDataException("Resolver captured document is outside its protected transition.");
    }

    public void Recover(string documentPath, Action<string> validateDocument)
    {
        ArgumentNullException.ThrowIfNull(validateDocument); RequirePath(documentPath);
        var state = ReadState(); var actual = Hash(document);
        if (state.Next is null)
        {
            RequireDigest(actual, state.Hash, state.Length);
            validateDocument(document);
        }
        else
        {
            var next = state.Next;
            if (!Matches(actual, next.Hash, next.Length))
            {
                RequireDigest(actual, state.Hash, state.Length);
                var temporary = Path.Combine(Path.GetDirectoryName(document)!, next.Temporary);
                RequireDigest(Hash(temporary), next.Hash, next.Length);
                validateDocument(temporary);
                durability.ReplaceFile(temporary, document);
                security.SecureFile(document); durability.FlushFileAndParentDirectory(document);
            }
            validateDocument(document);
            Commit(documentPath);
        }
        RequireSnapshot(documentPath);
        // A metadata write can fail before replacement as well. Only the
        // authenticated committed records authorize recovery; their temporary
        // files are never candidates for enrollment or checkpoint adoption.
        var metadataTemporaries = new List<string>();
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            RejectLinks(entry);
            var name = Path.GetFileName(entry);
            if (Directory.Exists(entry)) throw new InvalidDataException("Unknown resolver custody entry.");
            if (name is "writer.lock" or "enrollment.bin" or "checkpoint.bin") continue;
            if (!IsMetadataTemporary(name)) throw new InvalidDataException("Unknown resolver custody entry.");
            metadataTemporaries.Add(entry);
        }
        // Only after exact committed read-back: unanchored temporary bytes may
        // not advance this floor and must never be adopted as a new document.
        foreach (var temporary in Directory.EnumerateFiles(Path.GetDirectoryName(document)!, "resolver.state.*.tmp"))
        {
            if (!IsTemporary(Path.GetFileName(temporary))) throw new InvalidDataException("Unknown resolver temporary name.");
            RejectLinks(temporary); durability.DeleteFile(temporary); durability.FlushParentDirectory(temporary);
        }
        foreach (var temporary in metadataTemporaries)
            durability.DeleteFile(temporary);
    }

    public void Prepare(string documentPath, string temporaryPath, ReadOnlySpan<byte> expectedSha256, long expectedLength)
    {
        RequirePath(documentPath); var state = ReadState();
        if (state.Next is not null || state.Generation == ulong.MaxValue)
            throw new InvalidDataException("Resolver checkpoint cannot allocate another transition.");
        RequireDigest(Hash(document), state.Hash, state.Length);
        var name = Path.GetFileName(temporaryPath);
        if (!IsTemporary(name) || !SamePath(temporaryPath, Path.Combine(Path.GetDirectoryName(document)!, name)))
            throw new InvalidDataException("Resolver candidate path is not an exact local temporary.");
        security.SecureFile(temporaryPath); var candidate = Hash(temporaryPath);
        RequireDigest(candidate, CapturedHash(expectedSha256, expectedLength), expectedLength);
        durability.FlushFileAndParentDirectory(temporaryPath);
        var prepared = state with { Next = new Pending(candidate.Hash, candidate.Length, name) };
        Write(checkpointPath, prepared, checkpointProtection); RequireState(ReadState(), prepared);
    }

    public void Commit(string documentPath)
    {
        RequirePath(documentPath); var state = ReadState();
        var next = state.Next ?? throw new InvalidDataException("Resolver checkpoint has no prepared document.");
        RequireDigest(Hash(document), next.Hash, next.Length);
        security.SecureFile(document); durability.FlushFileAndParentDirectory(document);
        var committed = state with { Generation = checked(state.Generation + 1), Hash = next.Hash, Length = next.Length, Next = null };
        Write(checkpointPath, committed, checkpointProtection); RequireState(ReadState(), committed);
    }

    private Checkpoint ReadState()
    {
        var enrollment = Read<Enrollment>(enrollmentPath, enrollmentProtection);
        var state = Read<Checkpoint>(checkpointPath, checkpointProtection);
        if (enrollment.Version != 1 || state.Version != 1 || !IsId(enrollment.Id) || state.Enrollment != enrollment.Id ||
            !ValidDigest(enrollment.Hash, enrollment.Length) || !ValidDigest(state.Hash, state.Length) ||
            (state.Generation == 0 && (state.Hash != enrollment.Hash || state.Length != enrollment.Length)) ||
            (state.Next is not null && (state.Generation == ulong.MaxValue ||
                !ValidDigest(state.Next.Hash, state.Next.Length) || !IsTemporary(state.Next.Temporary))))
            throw new InvalidDataException("Resolver enrollment/checkpoint is malformed, foreign or split.");
        return state;
    }

    private T Read<T>(string path, IDataProtector protector)
    {
        RejectLinks(path);
        if (!File.Exists(path)) throw new InvalidDataException("Resolver protected custody is missing.");
        security.ValidateSecureFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaximumRecordBytes) throw new InvalidDataException("Resolver custody record exceeds its bound.");
        var encrypted = new byte[checked((int)stream.Length)]; stream.ReadExactly(encrypted); byte[]? plain = null;
        try
        {
            plain = protector.Unprotect(encrypted);
            return JsonSerializer.Deserialize<T>(plain, Json) ?? throw new InvalidDataException("Resolver custody record is empty.");
        }
        catch (Exception error) when (error is CryptographicException or JsonException)
        { throw new InvalidDataException("Resolver custody authentication failed.", error); }
        finally { CryptographicOperations.ZeroMemory(encrypted); if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private void Write<T>(string path, T value, IDataProtector protector)
    {
        RejectLinks(path); var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp"; RejectLinks(temporary);
        var plain = JsonSerializer.SerializeToUtf8Bytes(value, Json); byte[]? encrypted = null;
        try
        {
            encrypted = protector.Protect(plain);
            if (encrypted.Length > MaximumRecordBytes) throw new InvalidDataException("Resolver checkpoint exceeds its bound.");
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4_096, FileOptions.WriteThrough))
            { stream.Write(encrypted); stream.Flush(flushToDisk: true); }
            security.SecureFile(temporary); security.ValidateSecureFile(temporary);
            durability.ReplaceFile(temporary, path); security.SecureFile(path); durability.FlushFileAndParentDirectory(path);
        }
        finally { CryptographicOperations.ZeroMemory(plain); if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted); }
    }

    private (string Hash, long Length) Hash(string path)
    {
        RejectLinks(path);
        if (!File.Exists(path)) throw new InvalidDataException("Resolver committed document or exact pending file is missing.");
        security.ValidateSecureFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var length = stream.Length;
        if (length < 1 || length > maximumDocumentBytes) throw new InvalidDataException("Resolver document exceeds its bound.");
        var hash = SHA256.HashData(stream);
        if (stream.Position != length || stream.Length != length) throw new InvalidDataException("Resolver document changed while hashing.");
        return (Convert.ToHexString(hash), length);
    }

    private void RequireOnlyWriter()
    {
        RejectLinks(directory);
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            RejectLinks(entry);
            if (Directory.Exists(entry) || Path.GetFileName(entry) != "writer.lock")
                throw new InvalidDataException("Resolver custody is already enrolled, interrupted or contains unknown state.");
        }
    }
    private void RequirePath(string path)
    { ObjectDisposedException.ThrowIf(disposed, this); if (!SamePath(path, document)) throw new InvalidDataException("Resolver custody document path differs."); }
    private bool ValidDigest(string? hash, long length) => length >= 1 && length <= maximumDocumentBytes &&
        hash is { Length: 64 } && hash.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private string CapturedHash(ReadOnlySpan<byte> sha256, long length)
    {
        if (sha256.Length != 32 || length < 1 || length > maximumDocumentBytes)
            throw new InvalidDataException("Resolver captured document digest exceeds its exact bounds.");
        return Convert.ToHexString(sha256);
    }
    private static bool IsId(string? id) => id is { Length: 32 } && id.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool IsTemporary(string? name) => name is { Length: 51 } && name.StartsWith("resolver.state.", StringComparison.Ordinal) &&
        name.EndsWith(".tmp", StringComparison.Ordinal) && IsId(name.Substring(15, 32));
    private static bool IsMetadataTemporary(string name) =>
        IsMetadataTemporary(name, "enrollment.bin.") || IsMetadataTemporary(name, "checkpoint.bin.");
    private static bool IsMetadataTemporary(string name, string prefix) => name.Length == prefix.Length + 36 &&
        name.StartsWith(prefix, StringComparison.Ordinal) && name.EndsWith(".tmp", StringComparison.Ordinal) &&
        IsId(name.Substring(prefix.Length, 32));
    private static bool Matches((string Hash, long Length) actual, string hash, long length) => actual.Hash == hash && actual.Length == length;
    private static void RequireDigest((string Hash, long Length) actual, string hash, long length)
    { if (!Matches(actual, hash, length)) throw new InvalidDataException("Resolver document is corrupt, split or rolled back."); }
    private static void RequireState(Checkpoint actual, Checkpoint expected)
    { if (actual != expected) throw new InvalidDataException("Resolver checkpoint read-back differs."); }
    private static StringComparison PathComparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static bool SamePath(string left, string right) => string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), PathComparison);
    private static bool Overlaps(string left, string right) => SamePath(left, right) ||
        left.StartsWith(right + Path.DirectorySeparatorChar, PathComparison) || right.StartsWith(left + Path.DirectorySeparatorChar, PathComparison);
    private static string FullDirectory(string path)
    {
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Resolver custody requires absolute directories.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (SamePath(full, Path.GetPathRoot(full)!)) throw new ArgumentException("Resolver custody cannot use a filesystem root.");
        return full;
    }
    private static void RejectLinks(string path)
    {
        FileSystemInfo? current = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
        while (current is not null)
        {
            if (current.LinkTarget is not null || (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0))
                throw new UnauthorizedAccessException("Resolver custody cannot traverse links.");
            current = current is DirectoryInfo folder ? folder.Parent : ((FileInfo)current).Directory;
        }
    }
    public void Dispose() { if (!disposed) { disposed = true; writer.Dispose(); } }
    private sealed record Enrollment(int Version, string Id, string Hash, long Length);
    private sealed record Checkpoint(int Version, string Enrollment, ulong Generation, string Hash, long Length, Pending? Next);
    private sealed record Pending(string Hash, long Length, string Temporary);
}
