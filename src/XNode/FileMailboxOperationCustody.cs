using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

/// <summary>Independent protected root for the existing operation document.
/// Joint rollback of the root and matching data can be undetected even with
/// retained keys. No payload, peer request, cursor table or second journal is kept here.</summary>
internal sealed class FileMailboxOperationCustody : IMailboxOperationCustody, IDisposable
{
    private const int MaximumProtectedBytes = 4_096;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    private readonly string operationPath, directory, enrollmentPath, checkpointPath;
    private readonly byte[] node, network;
    private readonly IDataProtector enrollmentProtection, checkpointProtection;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream writer;
    private bool disposed;

    internal FileMailboxOperationCustody(string nodeDataRoot, string independentCustodyRoot,
        string operationDirectory, ReadOnlySpan<byte> nodeId32, ReadOnlySpan<byte> networkId16,
        IDataProtectionProvider protection, IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentNullException.ThrowIfNull(protection);
        if (nodeId32.Length != 32 || nodeId32.IndexOfAnyExcept((byte)0) < 0 ||
            networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0 ||
            string.IsNullOrWhiteSpace(operationDirectory) || operationDirectory.Length > 64 ||
            operationDirectory is "." or ".." || operationDirectory.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            operationDirectory.Contains('/') || operationDirectory.Contains('\\'))
            throw new ArgumentException("Mailbox operation custody scope is invalid.");
        var data = Path.TrimEndingDirectorySeparator(Path.GetFullPath(nodeDataRoot));
        var custody = Path.TrimEndingDirectorySeparator(Path.GetFullPath(independentCustodyRoot));
        if (IsWithin(data, custody) || IsWithin(custody, data) ||
            custody == Path.TrimEndingDirectorySeparator(Path.GetPathRoot(custody)!))
            throw new ArgumentException("Operation custody must be independent of replaceable node data.");
        this.security = security ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();
        node = nodeId32.ToArray(); network = networkId16.ToArray();
        // Stable across PMA/PMT changes: policy rollover cannot reset allocation.
        var scope = Convert.ToHexString(SHA256.HashData([.. node, .. network]));
        var relative = operationDirectory + "/operations.json";
        enrollmentProtection = protection.CreateProtector("Deep.XNode.MailboxOperations.Enrollment.v1", scope, relative);
        checkpointProtection = protection.CreateProtector("Deep.XNode.MailboxOperations.Checkpoint.v1", scope, relative);
        operationPath = Path.Combine(data, operationDirectory, "operations.json");
        directory = Path.Combine(custody, scope);
        RejectLinks(operationPath); RejectLinks(directory);
        this.security.SecureDirectory(directory);
        enrollmentPath = Path.Combine(directory, "enrollment.bin"); checkpointPath = Path.Combine(directory, "checkpoint.bin");
        var lockPath = Path.Combine(directory, "writer.lock"); RejectLinks(lockPath);
        writer = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.WriteThrough);
        try { this.security.SecureFile(lockPath); this.security.ValidateSecureFile(lockPath); }
        catch { writer.Dispose(); throw; }
    }

    public void RequireScope(ReadOnlySpan<byte> localNode, ReadOnlySpan<byte> networkId)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!Fixed(node, localNode) || !Fixed(network, networkId))
            throw new CryptographicException("Mailbox operation custody differs from the current node/network.");
    }

    public async ValueTask EnrollAsync(string operationFile, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        RequireNewScope(operationFile); _ = await lease.CheckAsync(token).ConfigureAwait(false);
        var initial = await HashAsync(operationPath, token).ConfigureAwait(false);
        var enrollment = new Enrollment(1, Guid.NewGuid().ToString("N"), initial.Hash, initial.Length);
        Write(enrollmentPath, enrollment, enrollmentProtection);
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
        Write(checkpointPath, new Checkpoint(1, enrollment.Id, 0, initial.Hash, initial.Length, null), checkpointProtection);
        _ = ReadState();
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
    }

    public void RequireNewScope(string operationFile)
    {
        RequirePath(operationFile);
        RejectLinks(directory);
        foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
        {
            RejectLinks(entry);
            if (Directory.Exists(entry) || Path.GetFileName(entry) != "writer.lock")
                throw new InvalidDataException("Mailbox operation custody is already enrolled, interrupted or contains an unknown record.");
        }
    }

    public void RequireDocumentSnapshot(string operationFile, ReadOnlySpan<byte> sha256, long length)
    {
        RequirePath(operationFile); var state = ReadState();
        if (state.Next is not null || sha256.Length != 32)
            throw new InvalidDataException("Mailbox operation snapshot is not committed.");
        RequireDigest((Convert.ToHexString(sha256), length), state.Hash, state.Length);
    }

    public async ValueTask VerifyAsync(string operationFile, MailboxCurrentOperationLease lease,
        Func<string, CancellationToken, Task> validate, CancellationToken token)
    {
        RequirePath(operationFile); _ = await lease.CheckAsync(token).ConfigureAwait(false);
        var state = ReadState(); var actual = await HashAsync(operationPath, token).ConfigureAwait(false);
        if (state.Next is null)
        {
            RequireDigest(actual, state.Hash, state.Length);
            await validate(operationPath, token).ConfigureAwait(false);
        }
        else
        {
            var next = state.Next;
            if (!Matches(actual, next.Hash, next.Length))
            {
                // Only the exact authenticated predecessor plus the named,
                // already-flushed next file can finish an interrupted replacement.
                RequireDigest(actual, state.Hash, state.Length);
                var temporary = Path.Combine(Path.GetDirectoryName(operationPath)!, next.Temporary);
                var candidate = await HashAsync(temporary, token).ConfigureAwait(false);
                RequireDigest(candidate, next.Hash, next.Length);
                await validate(temporary, token).ConfigureAwait(false);
                _ = await lease.CheckAsync(token).ConfigureAwait(false);
                durability.ReplaceFile(temporary, operationPath);
                security.SecureFile(operationPath); durability.FlushFileAndParentDirectory(operationPath);
            }
            await validate(operationPath, token).ConfigureAwait(false);
            await CommitAsync(operationFile, lease, token).ConfigureAwait(false);
        }
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
        // Unanchored files cannot authorize recovery. Never purge until the
        // committed document/pending plan has been independently verified.
        foreach (var temporary in Directory.EnumerateFiles(Path.GetDirectoryName(operationPath)!, "operations.json.*.tmp"))
        {
            RejectLinks(temporary); durability.DeleteFile(temporary); durability.FlushParentDirectory(temporary);
        }
    }

    public async ValueTask PrepareAsync(string operationFile, string temporaryFile,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        RequirePath(operationFile); _ = await lease.CheckAsync(token).ConfigureAwait(false);
        var state = ReadState();
        if (state.Next is not null || state.Generation == ulong.MaxValue)
            throw new InvalidDataException("Mailbox operation checkpoint cannot allocate another transition.");
        RequireDigest(await HashAsync(operationPath, token).ConfigureAwait(false), state.Hash, state.Length);
        var name = Path.GetFileName(temporaryFile);
        if (!IsTemporary(name) || !SamePath(temporaryFile, Path.Combine(Path.GetDirectoryName(operationPath)!, name)))
            throw new InvalidDataException("Mailbox operation transition has an invalid temporary path.");
        security.SecureFile(temporaryFile); security.ValidateSecureFile(temporaryFile);
        var candidate = await HashAsync(temporaryFile, token).ConfigureAwait(false);
        durability.FlushFileAndParentDirectory(temporaryFile);
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
        var planned = state with { Next = new Pending(candidate.Hash, candidate.Length, name) };
        Write(checkpointPath, planned, checkpointProtection);
        RequireState(ReadState(), planned);
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
    }

    public async ValueTask CommitAsync(string operationFile, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        RequirePath(operationFile); _ = await lease.CheckAsync(token).ConfigureAwait(false);
        var state = ReadState(); var next = state.Next ?? throw new InvalidDataException("Mailbox operation transition is missing.");
        RequireDigest(await HashAsync(operationPath, token).ConfigureAwait(false), next.Hash, next.Length);
        // Reflush after uncertain Replace/parent flush, not only hash read-back.
        security.SecureFile(operationPath); durability.FlushFileAndParentDirectory(operationPath);
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
        var committed = state with { Generation = checked(state.Generation + 1), Hash = next.Hash, Length = next.Length, Next = null };
        Write(checkpointPath, committed, checkpointProtection); RequireState(ReadState(), committed);
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
    }

    private Checkpoint ReadState()
    {
        var enrollment = Read<Enrollment>(enrollmentPath, enrollmentProtection);
        var state = Read<Checkpoint>(checkpointPath, checkpointProtection);
        if (enrollment.Version != 1 || state.Version != 1 || !IsId(enrollment.Id) || enrollment.Id != state.Enrollment ||
            !ValidDigest(enrollment.Hash, enrollment.Length) || !ValidDigest(state.Hash, state.Length) ||
            (state.Generation == 0 && (state.Hash != enrollment.Hash || state.Length != enrollment.Length)) ||
            (state.Next is not null && (state.Generation == ulong.MaxValue || !ValidDigest(state.Next.Hash, state.Next.Length) ||
                !IsTemporary(state.Next.Temporary))))
            throw new InvalidDataException("Mailbox operation enrollment/checkpoint is invalid or split.");
        return state;
    }

    private T Read<T>(string path, IDataProtector protector)
    {
        RejectLinks(path);
        if (!File.Exists(path)) throw new InvalidDataException("Mailbox operation protected custody is missing.");
        security.ValidateSecureFile(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is < 1 or > MaximumProtectedBytes) throw new InvalidDataException("Mailbox operation custody exceeds its bound.");
        var encrypted = new byte[checked((int)stream.Length)]; stream.ReadExactly(encrypted); byte[]? plain = null;
        try
        {
            plain = protector.Unprotect(encrypted);
            return JsonSerializer.Deserialize<T>(plain, JsonOptions) ?? throw new InvalidDataException("Mailbox operation custody is empty.");
        }
        catch (Exception error) when (error is CryptographicException or JsonException)
        { throw new InvalidDataException("Mailbox operation custody authentication failed.", error); }
        finally { CryptographicOperations.ZeroMemory(encrypted); if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
    }

    private void Write<T>(string path, T value, IDataProtector protector)
    {
        RejectLinks(path); var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp"; RejectLinks(temporary);
        var plain = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions); var encrypted = protector.Protect(plain);
        try
        {
            if (encrypted.Length > MaximumProtectedBytes) throw new InvalidDataException("Mailbox operation checkpoint exceeds its bound.");
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4_096, FileOptions.WriteThrough))
            { stream.Write(encrypted); stream.Flush(flushToDisk: true); }
            security.SecureFile(temporary); security.ValidateSecureFile(temporary);
            durability.ReplaceFile(temporary, path);
            security.SecureFile(path); durability.FlushFileAndParentDirectory(path);
        }
        finally { CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(encrypted); }
    }

    private async Task<(string Hash, long Length)> HashAsync(string path, CancellationToken token)
    {
        RejectLinks(path);
        if (!File.Exists(path)) throw new InvalidDataException("Mailbox operation document or exact pending file is missing.");
        security.ValidateSecureFile(path);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 8192, FileOptions.Asynchronous);
        if (stream.Length is < 1 or > MailboxClientOperationLedger.MaximumDocumentBytes)
            throw new InvalidDataException("Mailbox operation document exceeds its bound.");
        var length = stream.Length;
        var hash = await SHA256.HashDataAsync(stream, token).ConfigureAwait(false);
        if (stream.Position != length || stream.Length != length) throw new InvalidDataException("Mailbox operation document changed while reading.");
        return (Convert.ToHexString(hash), length);
    }
    private void RequirePath(string path)
    { ObjectDisposedException.ThrowIf(disposed, this); if (!SamePath(path, operationPath)) throw new InvalidDataException("Mailbox operation owner path differs."); }
    private static bool SamePath(string a, string b) => string.Equals(Path.GetFullPath(a), Path.GetFullPath(b),
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    private static bool IsWithin(string root, string candidate)
    { var relative = Path.GetRelativePath(root, candidate); return relative == "." || (relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) && !Path.IsPathFullyQualified(relative)); }
    private static void RejectLinks(string path) =>
        MailboxCustodyPathSafety.RejectLinks(path, "Mailbox operation custody cannot traverse links.");
    private static bool IsId(string? value) => value is { Length: 32 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool IsTemporary(string? value) => value is { Length: 52 } && value.StartsWith("operations.json.", StringComparison.Ordinal) &&
        value.EndsWith(".tmp", StringComparison.Ordinal) && IsId(value.Substring(16, 32));
    private static bool ValidDigest(string? hash, long length) => length is >= 1 and <= MailboxClientOperationLedger.MaximumDocumentBytes &&
        hash is { Length: 64 } && hash.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');
    private static bool Matches((string Hash, long Length) actual, string hash, long length) => actual.Hash == hash && actual.Length == length;
    private static void RequireDigest((string Hash, long Length) actual, string hash, long length)
    { if (!Matches(actual, hash, length)) throw new InvalidDataException("Mailbox operation document is corrupt, split or rolled back."); }
    private static void RequireState(Checkpoint actual, Checkpoint expected)
    { if (actual != expected) throw new InvalidDataException("Mailbox operation checkpoint read-back differs."); }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    public void Dispose() { if (!disposed) { disposed = true; writer.Dispose(); } }
    private sealed record Enrollment(int Version, string Id, string Hash, long Length);
    private sealed record Checkpoint(int Version, string Enrollment, ulong Generation, string Hash, long Length, Pending? Next);
    private sealed record Pending(string Hash, long Length, string Temporary);
}
