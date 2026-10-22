using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.ExceptionServices;
using System.Globalization;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>
/// Node-local DID2 head custody. Exact signed heads are retained as an
/// monotonic, Data-Protection-authenticated chain; latest is only a
/// recoverable index. The independently located anchor detects journal-only
/// rollback. Only a fully committed prefix below that anchor can be retired;
/// every remaining record is authenticated on every observation. A coordinated
/// rollback of both journal and anchor is outside
/// this local store's threat boundary even when the Data Protection keys
/// remain intact; network freshness still requires live threshold evidence.
/// </summary>
internal sealed class FileDeepIdV2DirectoryProtectedHeadStore :
    IDeepIdV2DirectoryProtectedHeadStore, IDisposable
{
    private const int MaximumProtectedBytes = 65_536;
    private const int HeaderBytes = 130;
    private const int MaximumRetiredTipsPerMaintenance = 64;
    private readonly string directory;
    private readonly string anchorDirectory;
    private readonly string trustRoot;
    private readonly byte[] exactGenesis;
    private readonly byte[] genesisCoreHash;
    private readonly byte[] networkId;
    private readonly IDataProtector protector;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lease;
    private readonly SemaphoreSlim gate = new(1, 1);
    private VerifiedXPointNetworkAuthority? restoredAuthority;
    // Signature-only memo for public signed heads. Native files are still
    // reread, unprotected and structurally joined on EVERY observation.
    // This never caches a floor/currentness decision or private plaintext.
    private VerifiedXPointNetworkAuthority? headSignatureAuthority;
    private (FloorRecord Record, AccountDirectoryProtectedLkg Head)[] verifiedPublicHeads = [];
    internal long PublicHeadSignatureVerifications { get; private set; }
    private long headGrammarDecodes;
    internal long HeadGrammarDecodes => Interlocked.Read(ref headGrammarDecodes);
    private bool disposed;

    internal FileDeepIdV2DirectoryProtectedHeadStore(string stateDirectory,
        string nodeDataDirectory, ReadOnlySpan<byte> exactGenesisAdh1,
        ReadOnlySpan<byte> pinnedGenesisCoreHash32,
        IDataProtectionProvider protection,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stateDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeDataDirectory);
        ArgumentNullException.ThrowIfNull(protection);
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ??
            throw new ArgumentNullException(nameof(durability));
        trustRoot = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(nodeDataDirectory));
        directory = Path.GetFullPath(stateDirectory);
        anchorDirectory = Path.Combine(trustRoot, "did2-head-anchor");
        var relative = Path.GetRelativePath(trustRoot, directory);
        if (relative is "." or ".." ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal) ||
            Path.IsPathFullyQualified(relative))
            throw new ArgumentException(
                "The DID2 head floor must be inside the node data root.",
                nameof(stateDirectory));
        if (IsWithin(directory, anchorDirectory) ||
            IsWithin(anchorDirectory, directory))
            throw new ArgumentException(
                "The DID2 head journal and anchor must be separate.",
                nameof(stateDirectory));
        if (pinnedGenesisCoreHash32.Length != 32 ||
            pinnedGenesisCoreHash32.IndexOfAnyExcept((byte)0) < 0 ||
            exactGenesisAdh1.Length is < 128 or > 16_384)
            throw new ArgumentException("The pinned DID2 genesis is invalid.");
        var parsed = AccountDirectoryAdh1Codec.Decode(exactGenesisAdh1);
        if (parsed.MinimumReader < 2 || parsed.LogGeneration != 0 ||
            parsed.TreeSize != 0)
            throw new CryptographicException(
                "The exact DID2 genesis has an invalid V2 shape.");
        exactGenesis = exactGenesisAdh1.ToArray();
        genesisCoreHash = pinnedGenesisCoreHash32.ToArray();
        networkId = parsed.NetworkId.ToArray();
        protector = protection.CreateProtector(
            "Deep.XNode.DID2.DirectoryHeadFloor.V1");
        RejectExistingLinks(directory);
        RejectExistingLinks(anchorDirectory);
        this.security.SecureDirectory(directory);
        ValidatePath(directory, expectFile: false);
        this.security.SecureDirectory(anchorDirectory);
        ValidatePath(anchorDirectory, expectFile: false);
        var lockPath = Path.Combine(directory, "floor.lock");
        lease = new FileStream(lockPath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough
        });
        try
        {
            this.security.SecureFile(lockPath);
            ValidatePath(lockPath, expectFile: true);
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    public async ValueTask<AccountDirectoryProtectedLkg> RestoreAsync(
        VerifiedXPointNetworkAuthority authority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var genesis = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(
                authority, exactGenesis, genesisCoreHash);
            var records = ReadChain();
            var anchor = ReadRecordIfExists(AnchorPath());
            if (records.Count == 0)
            {
                if (File.Exists(LatestPath()) ||
                    (anchor is not null && (anchor.Revision != 0 ||
                        !anchor.ExactAdh1.AsSpan().SequenceEqual(exactGenesis) ||
                        !anchor.CoreHash.AsSpan().SequenceEqual(genesisCoreHash))))
                    throw new InvalidDataException(
                        "The DID2 head floor lost its append-only chain.");
                var first = FloorRecord.Genesis(networkId, genesisCoreHash,
                    genesis.ExactAdh1.Span);
                if (anchor is null) WriteAnchor(first);
                WriteTip(first);
                WriteLatest(first);
                restoredAuthority = authority;
                return genesis;
            }
            var latest = records[^1];
            ValidateChain(records, authority);
            if (anchor is null || !ContainsExact(records, anchor))
                throw new InvalidDataException(
                    "The independent DID2 head anchor is missing or conflicts.");
            var indexed = ReadRecordIfExists(LatestPath());
            if (indexed is not null && !ContainsExact(records, indexed))
                throw new InvalidDataException(
                    "The DID2 head index is outside its append-only chain.");
            if (anchor.Revision < latest.Revision)
                WriteAnchor(latest);
            if (indexed is null || indexed.Revision < latest.Revision)
                WriteLatest(latest);
            else if (!indexed.ExactlyMatches(latest))
                throw new InvalidDataException(
                    "The DID2 head index conflicts with its append-only tip.");
            RetireCommittedPrefix(records, latest, cancellationToken);
            restoredAuthority = authority;
            return latest.Revision == 0
                ? genesis
                : AccountDirectoryProtectedLkgFactory.Restore(authority,
                    latest.ExactAdh1, latest.CoreHash);
        }
        finally { gate.Release(); }
    }

    public async ValueTask<AccountDirectoryProtectedLkg> ReadRetainedAsync(
        VerifiedXPointNetworkAuthority authority, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            var records = ReadChain();
            if (records.Count == 0)
                throw new InvalidDataException("The observed DID2 head floor has not been initialized.");
            ValidateChain(records, authority);
            var latest = records[^1];
            var anchor = ReadRecordIfExists(AnchorPath());
            var indexed = ReadRecordIfExists(LatestPath());
            if (anchor is null || indexed is null || !anchor.ExactlyMatches(latest) || !indexed.ExactlyMatches(latest))
                throw new InvalidDataException("The observed DID2 floor needs acquisition-owner recovery.");
            cancellationToken.ThrowIfCancellationRequested();
            // ValidateChain above has just authenticated every actual record
            // and joined actual anchor/index. Reuse only its signed public
            // result, not a remembered floor or a skipped native read.
            if (verifiedPublicHeads.Length == records.Count)
                return verifiedPublicHeads[^1].Head;
            return latest.Revision == 0
                ? DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority, latest.ExactAdh1, latest.CoreHash)
                : AccountDirectoryProtectedLkgFactory.Restore(authority, latest.ExactAdh1, latest.CoreHash);
        }
        finally { gate.Release(); }
    }

    public ValueTask CommitVerifiedAsync(
        AccountDirectoryProtectedLkg expected,
        VerifiedDeepIdV2DirectoryFreshness verified,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(verified);
        if (!verified.VerifiedProtectedLkgExactAdh1.Span.SequenceEqual(expected.ExactAdh1.Span) ||
            !verified.NetworkId.Span.SequenceEqual(networkId))
            throw new CryptographicException("The DID2 proof is out of scope.");
        return CommitAuthenticatedAsync(expected, verified.NextProtectedLkg, cancellationToken);
    }

    public ValueTask CommitCatchupAsync(VerifiedDeepIdV2DirectoryCatchup verified,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verified);
        return CommitAuthenticatedAsync(verified.PriorProtectedLkg, verified.ProtectedLkg, cancellationToken);
    }

    private async ValueTask CommitAuthenticatedAsync(AccountDirectoryProtectedLkg expected,
        AccountDirectoryProtectedLkg next, CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (restoredAuthority is null)
                throw new InvalidOperationException(
                    "The DID2 head floor must be restored before commit.");
            var records = ReadChain();
            if (records.Count == 0)
                throw new InvalidDataException(
                    "The DID2 floor has not been independently bootstrapped.");
            var current = records[^1];
            ValidateChain(records, restoredAuthority);
            var anchor = ReadRecordIfExists(AnchorPath());
            if (anchor is null || !anchor.ExactlyMatches(current))
                throw new InvalidDataException(
                    "The independent DID2 head anchor changed since verification.");
            var indexed = ReadRecordIfExists(LatestPath());
            if (indexed is null || !indexed.ExactlyMatches(current))
                throw new InvalidDataException(
                    "The DID2 floor index changed since proof verification.");
            if (!current.ExactAdh1.AsSpan().SequenceEqual(
                    expected.ExactAdh1.Span))
                throw new CryptographicException(
                    "The DID2 proof did not close the current protected floor.");
            if (next.ExactAdh1.Span.SequenceEqual(expected.ExactAdh1.Span))
            {
                if (!next.CoreHash.Span.SequenceEqual(current.CoreHash))
                    throw new CryptographicException(
                        "The DID2 replay changed the protected head hash.");
                RetireCommittedPrefix(records, current, cancellationToken);
                return;
            }
            if (next.LogGeneration <= expected.LogGeneration ||
                !next.Head.NetworkId.Span.SequenceEqual(networkId) ||
                next.Head.MinimumReader < 2)
                throw new CryptographicException(
                    "The DID2 proof has no valid successor head.");
            _ = AccountDirectoryProtectedLkgFactory.Restore(restoredAuthority,
                next.ExactAdh1, next.CoreHash.Span);
            var candidate = new FloorRecord(checked(current.Revision + 1),
                current.CoreHash, networkId, genesisCoreHash,
                next.CoreHash.ToArray(), next.ExactAdh1.ToArray());
            WriteTip(candidate);
            WriteAnchor(candidate);
            WriteLatest(candidate);
            RetireCommittedPrefix(records, candidate, cancellationToken);
        }
        finally { gate.Release(); }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        lease.Dispose();
        gate.Dispose();
    }

    private List<FloorRecord> ReadChain()
    {
        foreach (var file in Directory.EnumerateFiles(directory, "*.floor"))
        {
            var name = Path.GetFileName(file);
            if (name != "latest.floor" &&
                !(name.Length == "tip-0000000000000000.floor".Length &&
                  name.StartsWith("tip-", StringComparison.Ordinal)))
                throw new InvalidDataException(
                    "The DID2 head floor has an unknown record name.");
        }
        var files = Directory.EnumerateFiles(directory, "tip-*.floor")
            .OrderBy(static path => path, StringComparer.Ordinal).ToArray();
        var firstRevision = files.Length == 0 ? 0 : ParseRevision(files[0]);
        for (var index = 0; index < files.Length; index++)
        {
            var expectedName = $"tip-{checked(firstRevision + (ulong)index):X16}.floor";
            if (!string.Equals(Path.GetFileName(files[index]), expectedName,
                    StringComparison.Ordinal))
                throw new InvalidDataException(
                    "The DID2 head floor has a missing or foreign revision.");
        }
        if (files.Length < 16) return files.Select(ReadTip).ToList();
        // Independent native acquisition only. Every record still passes its
        // actual path/ACL/handle/EOF, Data Protection (including revocation)
        // and grammar checks. No authenticated plaintext or permission is cached.
        // The outer owner gate pins the public grammar memo until all workers
        // finish; chain/anchor/index authentication stays ordered afterwards.
        var records = new FloorRecord[files.Length];
        var errors = new ExceptionDispatchInfo?[files.Length];
        Parallel.For(0, files.Length, new ParallelOptions { MaxDegreeOfParallelism = 4 }, index =>
        {
            try { records[index] = ReadTip(files[index]); }
            catch (Exception error) { errors[index] = ExceptionDispatchInfo.Capture(error); }
        });
        // Drain ALL workers before returning/releasing the owner, including
        // failures. Preserve the typed first-in-source-order refusal rather
        // than exposing AggregateException or a partial successful snapshot.
        foreach (var error in errors) error?.Throw();
        return records.ToList();
    }

    private FloorRecord ReadTip(string path)
    {
        var record = ReadRecord(path);
        if (record.Revision != ParseRevision(path))
            throw new InvalidDataException("The DID2 head floor filename differs from its authenticated revision.");
        return record;
    }

    private void ValidateChain(IReadOnlyList<FloorRecord> records,
        VerifiedXPointNetworkAuthority authority)
    {
        var sameAuthority = headSignatureAuthority is { } prior &&
            prior.NetworkId.Span.SequenceEqual(authority.NetworkId.Span) &&
            prior.AuthorityCoreReference.Span.SequenceEqual(authority.AuthorityCoreReference.Span) &&
            prior.DirectoryWitnessPolicyHash.Span.SequenceEqual(authority.DirectoryWitnessPolicyHash.Span) &&
            prior.Dts1PolicyCoreReference.Span.SequenceEqual(authority.Dts1PolicyCoreReference.Span) &&
            prior.TimeSourcePolicyHash.Span.SequenceEqual(authority.TimeSourcePolicyHash.Span);
        // Resource bound only. Larger authentic histories retain the original
        // full verification path; this is not a new accepted-history ceiling.
        var keepMemo = records.Sum(record => (long)record.ExactAdh1.Length) <= 4 * 1024 * 1024;
        var nextMemo = keepMemo ? new (FloorRecord Record, AccountDirectoryProtectedLkg Head)[records.Count] : [];
        ulong previousGeneration = 0;
        for (var index = 0; index < records.Count; index++)
        {
            var record = records[index];
            if (record.Revision != checked(records[0].Revision + (ulong)index) ||
                !record.NetworkId.AsSpan().SequenceEqual(networkId) ||
                !record.GenesisCoreHash.AsSpan().SequenceEqual(genesisCoreHash) ||
                (record.Revision == 0
                    ? !record.ExactAdh1.AsSpan().SequenceEqual(exactGenesis) ||
                      record.PreviousCoreHash.AsSpan().IndexOfAnyExcept((byte)0) >= 0
                    : index > 0 && !record.PreviousCoreHash.AsSpan().SequenceEqual(
                          records[index - 1].CoreHash)))
                throw new InvalidDataException(
                    "The DID2 head floor chain is incomplete or cross-scope.");
            AccountDirectoryProtectedLkg restored;
            var memoIndex = MemoIndex(record.Revision);
            if (sameAuthority && memoIndex >= 0 &&
                record.ExactlyMatches(verifiedPublicHeads[memoIndex].Record))
                restored = verifiedPublicHeads[memoIndex].Head;
            else
            {
                restored = record.Revision == 0
                    ? DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority, record.ExactAdh1, record.CoreHash)
                    : AccountDirectoryProtectedLkgFactory.Restore(authority, record.ExactAdh1, record.CoreHash);
                PublicHeadSignatureVerifications++;
            }
            if (index > 0 && restored.LogGeneration <= previousGeneration)
                throw new InvalidDataException(
                    "The DID2 head floor generation moved backwards.");
            previousGeneration = restored.LogGeneration;
            if (keepMemo) nextMemo[index] = (record, restored);
        }
        verifiedPublicHeads = nextMemo;
        headSignatureAuthority = keepMemo ? authority : null;
    }

    private FloorRecord? ReadRecordIfExists(string path) =>
        File.Exists(path) ? ReadRecord(path) : null;

    private int MemoIndex(ulong revision) => verifiedPublicHeads.Length > 0 &&
        revision >= verifiedPublicHeads[0].Record.Revision &&
        revision - verifiedPublicHeads[0].Record.Revision < (ulong)verifiedPublicHeads.Length
            ? (int)(revision - verifiedPublicHeads[0].Record.Revision) : -1;

    private static bool ContainsExact(IReadOnlyList<FloorRecord> records, FloorRecord record) =>
        records.Count > 0 && record.Revision >= records[0].Revision &&
        record.Revision - records[0].Revision < (ulong)records.Count &&
        record.ExactlyMatches(records[(int)(record.Revision - records[0].Revision)]);

    private static ulong ParseRevision(string path)
    {
        var name = Path.GetFileName(path);
        if (name.Length != 26 || !name.StartsWith("tip-", StringComparison.Ordinal) ||
            !name.EndsWith(".floor", StringComparison.Ordinal) ||
            !ulong.TryParse(name.AsSpan(4, 16), NumberStyles.AllowHexSpecifier,
                CultureInfo.InvariantCulture, out var revision) ||
            name != $"tip-{revision:X16}.floor")
            throw new InvalidDataException("The DID2 head floor revision name is not canonical.");
        return revision;
    }

    // Acquisition-owner maintenance only, NEVER observational repair. No
    // revision is renumbered, and no pending higher descendant is discarded.
    // The independently protected anchor is the rollback floor, not tip count.
    private void RetireCommittedPrefix(IReadOnlyList<FloorRecord> records,
        FloorRecord committed, CancellationToken cancellationToken)
    {
        RequireCommitted(committed);
        var retired = 0;
        foreach (var record in records)
        {
            if (record.Revision >= committed.Revision ||
                retired == MaximumRetiredTipsPerMaintenance) break;
            cancellationToken.ThrowIfCancellationRequested();
            var path = TipPath(record.Revision);
            ValidatePath(path, expectFile: true);
            // Delete in ascending order and stop on ANY failure. A crash leaves
            // a contiguous authenticated suffix, never a hole or a lower floor.
            // Flush EACH deletion before the next: a crash must not persist a
            // later removal while resurrecting an earlier prefix entry.
            durability.DeleteFile(path);
            retired++;
        }
        if (retired > 0)
            durability.FlushFileAndParentDirectory(TipPath(committed.Revision));
        RequireCommitted(committed);
    }

    private void RequireCommitted(FloorRecord committed)
    {
        if (!ReadRecord(TipPath(committed.Revision)).ExactlyMatches(committed) ||
            ReadRecordIfExists(AnchorPath()) is not { } anchor || !anchor.ExactlyMatches(committed) ||
            ReadRecordIfExists(LatestPath()) is not { } indexed || !indexed.ExactlyMatches(committed))
            throw new InvalidDataException("The DID2 floor is not durably joined to its independent anchor and index.");
    }

    private FloorRecord ReadRecord(string path)
    {
        ValidatePath(path, expectFile: true);
        security.ValidateSecureFile(path);
        var protectedBytes = BoundedFileRead.Read(path, HeaderBytes, MaximumProtectedBytes,
            "A DID2 head floor record has an invalid length.");
        byte[]? plaintext = null;
        try
        {
            plaintext = protector.Unprotect(protectedBytes);
            if (plaintext.Length is < HeaderBytes or > MaximumProtectedBytes)
                throw new InvalidDataException(
                    "The unprotected DID2 head floor record exceeds its bound.");
            var revision = plaintext.Length >= HeaderBytes ? BinaryPrimitives.ReadUInt64BigEndian(plaintext.AsSpan(6)) : ulong.MaxValue;
            var memoIndex = MemoIndex(revision);
            var known = memoIndex >= 0 ? verifiedPublicHeads[memoIndex].Record : null;
            var result = FloorRecord.Decode(plaintext, known, out var decodedHead);
            if (decodedHead) Interlocked.Increment(ref headGrammarDecodes);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void WriteTip(FloorRecord record)
    {
        var path = TipPath(record.Revision);
        if (File.Exists(path))
        {
            if (!ReadRecord(path).ExactlyMatches(record))
                throw new InvalidDataException("The DID2 head floor tip forked.");
            return;
        }
        WriteProtected(path, record, replace: false);
    }

    private void WriteLatest(FloorRecord record) =>
        WriteProtected(LatestPath(), record, replace: true);

    private void WriteAnchor(FloorRecord record) =>
        WriteProtected(AnchorPath(), record, replace: true);

    private void WriteProtected(string path, FloorRecord record, bool replace)
    {
        var plaintext = record.Encode();
        byte[] protectedBytes;
        try { protectedBytes = protector.Protect(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
        if (protectedBytes.Length > MaximumProtectedBytes)
            throw new InvalidDataException("The protected DID2 head exceeds its bound.");
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary,
                       FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       16 * 1024, FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            ValidatePath(temporary, expectFile: true);
            if (!replace && File.Exists(path))
                throw new InvalidDataException("The DID2 head tip already exists.");
            if (replace)
                durability.ReplaceFile(temporary, path);
            else
            {
                File.Move(temporary, path, overwrite: false);
                durability.FlushFileAndParentDirectory(path);
            }
            security.SecureFile(path);
            durability.FlushFileAndParentDirectory(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private string TipPath(ulong revision) =>
        Path.Combine(directory, $"tip-{revision:X16}.floor");

    private string LatestPath() => Path.Combine(directory, "latest.floor");

    private string AnchorPath() => Path.Combine(anchorDirectory, "anchor.floor");

    private static bool IsWithin(string candidate, string parent)
    {
        var relative = Path.GetRelativePath(parent, candidate);
        return relative == "." ||
            (relative != ".." &&
             !relative.StartsWith($"..{Path.DirectorySeparatorChar}",
                 StringComparison.Ordinal) &&
             !Path.IsPathFullyQualified(relative));
    }

    private void RejectExistingLinks(string path)
    {
        for (var current = new DirectoryInfo(path); current is not null;
             current = current.Parent)
        {
            if (OperatingSystem.IsWindows() ? IsWindowsReparsePoint(current.FullName) :
                current.Exists && ((current.Attributes & FileAttributes.ReparsePoint) != 0 ||
                 current.LinkTarget is not null))
                throw new InvalidDataException(
                    "The DID2 head floor path contains a linked directory.");
            if (string.Equals(Path.TrimEndingDirectorySeparator(current.FullName),
                    trustRoot, OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
                return;
        }
        throw new UnauthorizedAccessException(
            "The DID2 head floor path escaped its node data root.");
    }

    private void ValidatePath(string candidate, bool expectFile)
    {
        var full = Path.GetFullPath(candidate);
        var relative = Path.GetRelativePath(trustRoot, full);
        if (relative is ".." ||
            relative.StartsWith($"..{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal) ||
            Path.IsPathFullyQualified(relative))
            throw new UnauthorizedAccessException(
                "The DID2 head floor path escaped its node data root.");
        // A fresh attribute query checks the actual entry on every platform.
        // Unix .NET maps lstat's symlink flag (including dangling targets) to
        // ReparsePoint; a second readlink per ancestor adds no validation.
        var expectDirectory = !expectFile;
        for (var currentPath = full; currentPath is not null;
             currentPath = Path.GetDirectoryName(currentPath))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(currentPath); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            { throw new InvalidDataException("The DID2 head floor path is missing or linked.", error); }
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                ((attributes & FileAttributes.Directory) != 0) != expectDirectory)
                throw new InvalidDataException("The DID2 head floor path is missing or linked.");
            if (string.Equals(Path.TrimEndingDirectorySeparator(currentPath), trustRoot,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal)) return;
            expectDirectory = true;
        }
        throw new UnauthorizedAccessException("The DID2 head floor path escaped its node data root.");
    }

    private static bool IsWindowsReparsePoint(string path)
    {
        try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed,
        this);

    private sealed record FloorRecord(ulong Revision, byte[] PreviousCoreHash,
        byte[] NetworkId, byte[] GenesisCoreHash, byte[] CoreHash,
        byte[] ExactAdh1)
    {
        internal static FloorRecord Genesis(ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> genesisHash, ReadOnlySpan<byte> exact) =>
            new(0, new byte[32], network.ToArray(), genesisHash.ToArray(),
                genesisHash.ToArray(), exact.ToArray());

        internal byte[] Encode()
        {
            var result = new byte[checked(HeaderBytes + ExactAdh1.Length)];
            "DHF2"u8.CopyTo(result);
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
            BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(6), Revision);
            PreviousCoreHash.CopyTo(result, 14);
            NetworkId.CopyTo(result, 46);
            GenesisCoreHash.CopyTo(result, 62);
            CoreHash.CopyTo(result, 94);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(126),
                checked((uint)ExactAdh1.Length));
            ExactAdh1.CopyTo(result, HeaderBytes);
            return result;
        }

        internal static FloorRecord Decode(ReadOnlySpan<byte> value, FloorRecord? known, out bool decodedHead)
        {
            if (value.Length < HeaderBytes ||
                !value[..4].SequenceEqual("DHF2"u8) ||
                BinaryPrimitives.ReadUInt16BigEndian(value[4..]) != 1 ||
                BinaryPrimitives.ReadUInt32BigEndian(value[126..]) !=
                    value.Length - HeaderBytes)
                throw new InvalidDataException(
                    "The protected DID2 head floor record is malformed.");
            var exact = value[HeaderBytes..].ToArray();
            // Reuse only canonical grammar of identical public head bytes.
            // The actual protected file was just reread/unprotected; all floor
            // headers, chain joins, anchor/index and authority still revalidate.
            decodedHead = known is null || !exact.AsSpan().SequenceEqual(known.ExactAdh1);
            var parsedNetwork = decodedHead ? AccountDirectoryAdh1Codec.Decode(exact).NetworkId.Span : known!.NetworkId.AsSpan();
            if (!parsedNetwork.SequenceEqual(value.Slice(46, 16)))
                throw new InvalidDataException(
                    "The DID2 head floor network differs.");
            return new FloorRecord(
                BinaryPrimitives.ReadUInt64BigEndian(value[6..]),
                value.Slice(14, 32).ToArray(),
                value.Slice(46, 16).ToArray(),
                value.Slice(62, 32).ToArray(),
                value.Slice(94, 32).ToArray(), exact);
        }

        internal bool ExactlyMatches(FloorRecord other) =>
            Revision == other.Revision &&
            PreviousCoreHash.AsSpan().SequenceEqual(other.PreviousCoreHash) &&
            NetworkId.AsSpan().SequenceEqual(other.NetworkId) &&
            GenesisCoreHash.AsSpan().SequenceEqual(other.GenesisCoreHash) &&
            CoreHash.AsSpan().SequenceEqual(other.CoreHash) &&
            ExactAdh1.AsSpan().SequenceEqual(other.ExactAdh1);
    }
}
