using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed class MailboxClientCanonicalOutcomeStoreOptions
{
    public string DirectoryName { get; set; } = "mailbox-client-canonical-outcomes-v1";

    public int MaximumEntries { get; set; } = 100_000;

    public long MaximumBytes { get; set; } = 16L * 1024 * 1024 * 1024;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || MaximumEntries is < 1 or > 1_000_000
            || MaximumBytes < MailboxClientCanonicalOutcomeStore.HeaderLength + 16L
            || MaximumBytes > 1024L * 1024 * 1024 * 1024)
        {
            throw new InvalidOperationException(
                "Mailbox canonical outcome store options are invalid.");
        }
    }
}

public enum MailboxClientCanonicalOutcomeKind : byte
{
    Success = 1,
    Terminal = 2
}

public enum MailboxClientTerminalOutcome : byte
{
    AuthorizationRejected = 1,
    OperationConflict = 2,
    DurableStateRejected = 3
}

public sealed class MailboxClientCanonicalOutcomeKey
{
    private static ReadOnlySpan<byte> Domain =>
        "XNODE-MAILBOX-CANONICAL-OUTCOME-V1\0"u8;

    private readonly byte[] _digest;

    private MailboxClientCanonicalOutcomeKey(ReadOnlySpan<byte> digest)
    {
        _digest = digest.ToArray();
    }

    public static MailboxClientCanonicalOutcomeKey Create(
        ReadOnlySpan<byte> replayScope,
        ulong replayCounter,
        ReadOnlySpan<byte> claimDigest)
    {
        if (replayScope.Length != 32
            || replayScope.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The mailbox replay scope digest is invalid.",
                nameof(replayScope));
        }

        if (replayCounter == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(replayCounter));
        }

        if (claimDigest.Length != 32
            || claimDigest.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The mailbox replay claim digest is invalid.",
                nameof(claimDigest));
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData(replayScope);
        Span<byte> counter = stackalloc byte[sizeof(ulong)];
        BinaryPrimitives.WriteUInt64BigEndian(counter, replayCounter);
        hash.AppendData(counter);
        hash.AppendData(claimDigest);
        return new(hash.GetHashAndReset());
    }

    public override string ToString() => "[opaque-mailbox-outcome-key]";

    internal ReadOnlySpan<byte> Digest => _digest;
}

public sealed class MailboxClientCanonicalOutcome
{
    private readonly byte[] _canonicalBytes;

    internal MailboxClientCanonicalOutcome(
        MailboxClientCanonicalOutcomeKind kind,
        MailboxAuthenticatedOperation operation,
        MailboxClientTerminalOutcome? terminal,
        ulong retainUntilUnixSeconds,
        ReadOnlySpan<byte> canonicalBytes)
    {
        Kind = kind;
        Operation = operation;
        Terminal = terminal;
        RetainUntilUnixSeconds = retainUntilUnixSeconds;
        _canonicalBytes = canonicalBytes.ToArray();
    }

    public MailboxClientCanonicalOutcomeKind Kind { get; }

    public MailboxAuthenticatedOperation Operation { get; }

    public MailboxClientTerminalOutcome? Terminal { get; }

    public ulong RetainUntilUnixSeconds { get; }

    public ReadOnlyMemory<byte> CanonicalBytes => _canonicalBytes.ToArray();
}

public sealed record MailboxClientCanonicalOutcomeStoreDiagnostics(
    int EntryCount,
    long CanonicalBytes,
    int ReservedEntries,
    long ReservedCanonicalBytes,
    int EntryCapacityRemaining,
    long ByteCapacityRemaining);

internal sealed class MailboxClientCanonicalOutcomeReservation : IDisposable
{
    private MailboxClientCanonicalOutcomeStore? _owner;

    internal MailboxClientCanonicalOutcomeReservation(
        MailboxClientCanonicalOutcomeStore owner,
        MailboxClientCanonicalOutcomeKey key,
        MailboxAuthenticatedOperation operation,
        ulong retainUntilUnixSeconds,
        int maximumCanonicalBytes,
        long reservationId)
    {
        _owner = owner;
        Key = key;
        Operation = operation;
        RetainUntilUnixSeconds = retainUntilUnixSeconds;
        MaximumCanonicalBytes = maximumCanonicalBytes;
        ReservationId = reservationId;
    }

    internal MailboxClientCanonicalOutcomeKey Key { get; }

    internal MailboxAuthenticatedOperation Operation { get; }

    internal ulong RetainUntilUnixSeconds { get; }

    internal int MaximumCanonicalBytes { get; }

    internal long ReservationId { get; }

    public void Dispose()
    {
        Interlocked.Exchange(ref _owner, null)?.Release(this);
        GC.SuppressFinalize(this);
    }

    internal MailboxClientCanonicalOutcomeStore RequireOwner() =>
        Volatile.Read(ref _owner)
        ?? throw new ObjectDisposedException(nameof(MailboxClientCanonicalOutcomeReservation));

    internal void Complete(MailboxClientCanonicalOutcomeStore owner)
    {
        if (!ReferenceEquals(Interlocked.Exchange(ref _owner, null), owner))
        {
            throw new InvalidOperationException(
                "Mailbox canonical outcome reservation ownership is invalid.");
        }
    }
}

internal enum MailboxClientCanonicalOutcomeFaultPoint
{
    BeforeReplace = 1,
    AfterReplaceBeforeDurability = 2,
    AfterCommit = 3
}

internal interface IMailboxClientCanonicalOutcomeFaultInjector
{
    void Inject(MailboxClientCanonicalOutcomeFaultPoint point);
}

public sealed class MailboxClientCanonicalOutcomeStore : IDisposable
{
    public const int HeaderLength = 128;

    private const int SchemaVersion = 1;
    private const int TerminalLength = 16;
    private const string Extension = ".outcome";
    private static ReadOnlySpan<byte> FileMagic => "MCO1"u8;
    private static ReadOnlySpan<byte> TerminalMagic => "MTO1"u8;
    private static ReadOnlySpan<byte> RecordDigestDomain =>
        "XNODE-MAILBOX-CANONICAL-OUTCOME-RECORD-V1\0"u8;

    private readonly string _directory;
    private readonly int _maximumEntries;
    private readonly long _maximumBytes;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly IMailboxClientCanonicalOutcomeFaultInjector? _faults;
    private readonly FileStream _lease;
    private readonly object _gate = new();
    private readonly Dictionary<string, PersistedEntry> _entries =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, ActiveReservation> _reservations =
        new(StringComparer.Ordinal);
    private long _canonicalBytes;
    private long _fileBytes;
    private long _reservedCanonicalBytes;
    private long _reservedFileBytes;
    private long _nextReservationId;
    private int _disposed;

    public MailboxClientCanonicalOutcomeStore(
        string dataDirectory,
        MailboxClientCanonicalOutcomeStoreOptions? options = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
        : this(dataDirectory, options, security, durability, faults: null)
    {
    }

    internal MailboxClientCanonicalOutcomeStore(
        string dataDirectory,
        MailboxClientCanonicalOutcomeStoreOptions? options,
        IMailboxStorageSecurity? security,
        IMailboxDurabilityBarrier? durability,
        IMailboxClientCanonicalOutcomeFaultInjector? faults)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            throw new ArgumentException(
                "A mailbox canonical outcome data directory is required.",
                nameof(dataDirectory));
        }

        options ??= new MailboxClientCanonicalOutcomeStoreOptions();
        options.Validate();
        _directory = Path.Combine(dataDirectory, options.DirectoryName);
        _maximumEntries = options.MaximumEntries;
        _maximumBytes = options.MaximumBytes;
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
        _faults = faults;
        try
        {
            _security.SecureDirectory(_directory);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new MailboxClientCanonicalOutcomePersistenceException();
        }

        var leasePath = Path.Combine(_directory, ".outcomes.lock");
        FileStream? acquiredLease = null;
        try
        {
            acquiredLease = new FileStream(
                leasePath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
            _security.SecureFile(leasePath);
            _lease = acquiredLease;
        }
        catch (IOException)
        {
            acquiredLease?.Dispose();
            throw new InvalidOperationException(
                "Another mailbox canonical outcome store owns this directory.");
        }
        catch (UnauthorizedAccessException)
        {
            acquiredLease?.Dispose();
            throw new MailboxClientCanonicalOutcomePersistenceException();
        }
        catch
        {
            acquiredLease?.Dispose();
            throw;
        }

        try
        {
            PurgeAbandonedFiles();
            LoadAndValidateIndex();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            _lease.Dispose();
            throw new MailboxClientCanonicalOutcomePersistenceException();
        }
        catch
        {
            _lease.Dispose();
            throw;
        }
    }

    public MailboxClientCanonicalOutcomeStoreDiagnostics Diagnostics
    {
        get
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                return new(
                    _entries.Count,
                    _canonicalBytes,
                    _reservations.Values.Count(static item => item.CountsEntry),
                    _reservedCanonicalBytes,
                    _maximumEntries
                        - _entries.Count
                        - _reservations.Values.Count(static item => item.CountsEntry),
                    _maximumBytes - _fileBytes - _reservedFileBytes);
            }
        }
    }

    internal MailboxClientCanonicalOutcomeReservation Reserve(
        MailboxClientCanonicalOutcomeKey key,
        MailboxAuthenticatedOperation operation,
        ulong retainUntilUnixSeconds,
        int maximumCanonicalBytes)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateOperation(operation);
        if (retainUntilUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(retainUntilUnixSeconds));
        }

        if (maximumCanonicalBytes is < TerminalLength
            or > MailboxClientLimits.MaximumPageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCanonicalBytes));
        }

        lock (_gate)
        {
            ThrowIfDisposed();
            var keyText = KeyText(key.Digest);
            if (_reservations.ContainsKey(keyText))
            {
                throw new MailboxClientCanonicalOutcomeConflictException();
            }

            var countsEntry = !_entries.TryGetValue(keyText, out var existing);
            if (existing is not null
                && (existing.Operation != operation
                    || existing.RetainUntilUnixSeconds != retainUntilUnixSeconds))
            {
                throw new MailboxClientCanonicalOutcomeConflictException();
            }

            var reservedFileBytes = countsEntry
                ? checked(HeaderLength + (long)maximumCanonicalBytes)
                : 0;
            if (countsEntry
                && (_entries.Count
                        + _reservations.Values.Count(static item => item.CountsEntry)
                        >= _maximumEntries
                    || _fileBytes + _reservedFileBytes + reservedFileBytes > _maximumBytes))
            {
                throw new MailboxClientCanonicalOutcomeCapacityException();
            }

            var id = checked(++_nextReservationId);
            _reservations.Add(
                keyText,
                new(
                    id,
                    operation,
                    retainUntilUnixSeconds,
                    maximumCanonicalBytes,
                    countsEntry,
                    reservedFileBytes));
            if (countsEntry)
            {
                _reservedCanonicalBytes = checked(
                    _reservedCanonicalBytes + maximumCanonicalBytes);
                _reservedFileBytes = checked(_reservedFileBytes + reservedFileBytes);
            }

            return new(
                this,
                key,
                operation,
                retainUntilUnixSeconds,
                maximumCanonicalBytes,
                id);
        }
    }

    internal MailboxClientCanonicalOutcome PutSuccess(
        MailboxClientCanonicalOutcomeReservation reservation,
        ReadOnlyMemory<byte> canonicalOutcome)
    {
        ArgumentNullException.ThrowIfNull(reservation);
        if (!ReferenceEquals(reservation.RequireOwner(), this))
        {
            throw new ArgumentException(
                "Mailbox canonical outcome reservation belongs to another store.",
                nameof(reservation));
        }

        ValidateSuccessFrame(reservation.Operation, canonicalOutcome.Span);
        return Put(
            reservation,
            MailboxClientCanonicalOutcomeKind.Success,
            terminal: null,
            canonicalOutcome.Span);
    }

    internal MailboxClientCanonicalOutcome PutTerminal(
        MailboxClientCanonicalOutcomeReservation reservation,
        MailboxClientTerminalOutcome terminal)
    {
        ArgumentNullException.ThrowIfNull(reservation);
        if (!ReferenceEquals(reservation.RequireOwner(), this))
        {
            throw new ArgumentException(
                "Mailbox canonical outcome reservation belongs to another store.",
                nameof(reservation));
        }

        ValidateTerminal(terminal);
        Span<byte> canonical = stackalloc byte[TerminalLength];
        canonical.Clear();
        TerminalMagic.CopyTo(canonical);
        canonical[4] = SchemaVersion;
        canonical[5] = (byte)reservation.Operation;
        canonical[6] = (byte)terminal;
        return Put(
            reservation,
            MailboxClientCanonicalOutcomeKind.Terminal,
            terminal,
            canonical);
    }

    public bool TryRead(
        MailboxClientCanonicalOutcomeKey key,
        MailboxAuthenticatedOperation operation,
        out MailboxClientCanonicalOutcome? outcome)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateOperation(operation);
        lock (_gate)
        {
            ThrowIfDisposed();
            var keyText = KeyText(key.Digest);
            if (!_entries.ContainsKey(keyText))
            {
                outcome = null;
                return false;
            }

            outcome = ReadRequiredLocked(keyText, key.Digest, operation);
            return true;
        }
    }

    public MailboxClientCanonicalOutcome ReadRequired(
        MailboxClientCanonicalOutcomeKey key,
        MailboxAuthenticatedOperation operation)
    {
        ArgumentNullException.ThrowIfNull(key);
        ValidateOperation(operation);
        lock (_gate)
        {
            ThrowIfDisposed();
            return ReadRequiredLocked(KeyText(key.Digest), key.Digest, operation);
        }
    }

    public int CollectExpired(ulong nowUnixSeconds, int maximumEntries)
    {
        if (nowUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nowUnixSeconds));
        }

        if (maximumEntries is < 1 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        lock (_gate)
        {
            ThrowIfDisposed();
            var expired = _entries
                .Where(item =>
                    item.Value.RetainUntilUnixSeconds <= nowUnixSeconds
                    && !_reservations.ContainsKey(item.Key))
                .OrderBy(static item => item.Value.RetainUntilUnixSeconds)
                .ThenBy(static item => item.Key, StringComparer.Ordinal)
                .Take(maximumEntries)
                .ToArray();
            foreach (var item in expired)
            {
                _ = ReadFile(PathFor(item.Key), Convert.FromHexString(item.Key));
                try
                {
                    _durability.DeleteFile(PathFor(item.Key));
                }
                catch (Exception exception) when (
                    exception is IOException or UnauthorizedAccessException)
                {
                    throw new MailboxClientCanonicalOutcomePersistenceException();
                }

                _entries.Remove(item.Key);
                _canonicalBytes -= item.Value.CanonicalLength;
                _fileBytes -= item.Value.FileLength;
            }

            return expired.Length;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            lock (_gate)
            {
                _reservations.Clear();
                _reservedCanonicalBytes = 0;
                _reservedFileBytes = 0;
                _lease.Dispose();
            }
        }

        GC.SuppressFinalize(this);
    }

    internal void Release(MailboxClientCanonicalOutcomeReservation reservation)
    {
        lock (_gate)
        {
            if (_disposed != 0)
            {
                return;
            }

            var keyText = KeyText(reservation.Key.Digest);
            if (_reservations.TryGetValue(keyText, out var active)
                && active.ReservationId == reservation.ReservationId)
            {
                RemoveReservation(keyText, active);
            }
        }
    }

    private MailboxClientCanonicalOutcome Put(
        MailboxClientCanonicalOutcomeReservation reservation,
        MailboxClientCanonicalOutcomeKind kind,
        MailboxClientTerminalOutcome? terminal,
        ReadOnlySpan<byte> canonicalOutcome)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (canonicalOutcome.Length > reservation.MaximumCanonicalBytes)
            {
                throw new ArgumentOutOfRangeException(nameof(canonicalOutcome));
            }

            var keyText = KeyText(reservation.Key.Digest);
            if (!_reservations.TryGetValue(keyText, out var active)
                || active.ReservationId != reservation.ReservationId
                || active.Operation != reservation.Operation
                || active.RetainUntilUnixSeconds != reservation.RetainUntilUnixSeconds)
            {
                throw new InvalidOperationException(
                    "Mailbox canonical outcome reservation is not active.");
            }

            var desired = new PersistedRecord(
                kind,
                reservation.Operation,
                terminal,
                reservation.RetainUntilUnixSeconds,
                canonicalOutcome.ToArray(),
                reservation.Key.Digest.ToArray());
            var desiredEntry = ToEntry(desired);
            var finalPath = PathFor(keyText);
            var wasIndexed = _entries.TryGetValue(
                keyText,
                out var indexedBeforeWrite);
            if (wasIndexed)
            {
                if (indexedBeforeWrite != desiredEntry)
                {
                    throw new MailboxClientCanonicalOutcomeConflictException();
                }

                if (!File.Exists(finalPath))
                {
                    throw Corrupt();
                }
            }

            PersistedRecord persisted;
            if (wasIndexed || File.Exists(finalPath))
            {
                persisted = ReadFile(finalPath, reservation.Key.Digest);
                EnsureExact(persisted, desired);
                try
                {
                    _security.SecureFile(finalPath);
                    _durability.FlushFileAndParentDirectory(finalPath);
                }
                catch (Exception exception) when (
                    exception is IOException or UnauthorizedAccessException)
                {
                    throw new MailboxClientCanonicalOutcomePersistenceException();
                }
            }
            else
            {
                Write(finalPath, desired);
                persisted = desired;
            }

            var entry = ToEntry(persisted);
            if (_entries.TryGetValue(keyText, out var indexed))
            {
                if (indexed != entry)
                {
                    throw new MailboxClientCanonicalOutcomeConflictException();
                }
            }
            else
            {
                _entries.Add(keyText, entry);
                _canonicalBytes = checked(_canonicalBytes + entry.CanonicalLength);
                _fileBytes = checked(_fileBytes + entry.FileLength);
            }

            RemoveReservation(keyText, active);
            reservation.Complete(this);
            return ToOutcome(persisted);
        }
    }

    private MailboxClientCanonicalOutcome ReadRequiredLocked(
        string keyText,
        ReadOnlySpan<byte> keyDigest,
        MailboxAuthenticatedOperation operation)
    {
        if (!_entries.TryGetValue(keyText, out var indexed))
        {
            throw new MailboxClientCanonicalOutcomeMissingException();
        }

        var persisted = ReadFile(PathFor(keyText), keyDigest);
        var actual = ToEntry(persisted);
        if (actual != indexed)
        {
            throw Corrupt();
        }

        if (persisted.Operation != operation)
        {
            throw new MailboxClientCanonicalOutcomeConflictException();
        }

        return ToOutcome(persisted);
    }

    private void LoadAndValidateIndex()
    {
        var paths = Directory.EnumerateFiles(_directory, $"*{Extension}")
            .Take(_maximumEntries + 1)
            .ToArray();
        if (paths.Length > _maximumEntries)
        {
            throw Corrupt();
        }

        long observedFileBytes = 0;
        foreach (var path in paths)
        {
            var filename = Path.GetFileNameWithoutExtension(path);
            if (!IsLowerHex(filename, 32))
            {
                throw Corrupt();
            }

            var key = Convert.FromHexString(filename);
            var fileLength = new FileInfo(path).Length;
            if (fileLength is < HeaderLength + TerminalLength
                or > HeaderLength + (long)MailboxClientLimits.MaximumPageBytes
                || checked(observedFileBytes + fileLength) > _maximumBytes)
            {
                throw Corrupt();
            }

            observedFileBytes += fileLength;
            _security.SecureFile(path);
            var record = ReadFile(path, key);
            var entry = ToEntry(record);
            if (!_entries.TryAdd(filename, entry))
            {
                throw Corrupt();
            }

            _canonicalBytes = checked(_canonicalBytes + entry.CanonicalLength);
            _fileBytes = checked(_fileBytes + entry.FileLength);
        }

        if (_fileBytes > _maximumBytes)
        {
            throw Corrupt();
        }
    }

    private void Write(string finalPath, PersistedRecord record)
    {
        var encoded = Encode(record);
        var temporaryPath = $"{finalPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(encoded);
                stream.Flush(flushToDisk: true);
            }

            _security.SecureFile(temporaryPath);
            _faults?.Inject(MailboxClientCanonicalOutcomeFaultPoint.BeforeReplace);
            _durability.ReplaceFile(temporaryPath, finalPath);
            _faults?.Inject(
                MailboxClientCanonicalOutcomeFaultPoint.AfterReplaceBeforeDurability);
            _security.SecureFile(finalPath);
            _durability.FlushFileAndParentDirectory(finalPath);
            _faults?.Inject(MailboxClientCanonicalOutcomeFaultPoint.AfterCommit);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            throw new MailboxClientCanonicalOutcomePersistenceException();
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                try
                {
                    File.Delete(temporaryPath);
                }
                catch (Exception exception) when (
                    exception is IOException or UnauthorizedAccessException)
                {
                    throw new MailboxClientCanonicalOutcomePersistenceException();
                }
            }
        }
    }

    private PersistedRecord ReadFile(string path, ReadOnlySpan<byte> expectedKey)
    {
        if (!File.Exists(path))
        {
            throw new MailboxClientCanonicalOutcomeMissingException();
        }

        try
        {
            var info = new FileInfo(path);
            if (info.Length is < HeaderLength + TerminalLength
                or > HeaderLength + (long)MailboxClientLimits.MaximumPageBytes)
            {
                throw Corrupt();
            }

            var encoded = File.ReadAllBytes(path);
            if (encoded.Length != info.Length)
            {
                throw Corrupt();
            }

            return Decode(encoded, expectedKey);
        }
        catch (MailboxClientCanonicalOutcomeMissingException)
        {
            throw;
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or FormatException
                or ArgumentException
                or CryptographicException)
        {
            throw Corrupt();
        }
    }

    private static byte[] Encode(PersistedRecord record)
    {
        ValidateRecord(record);
        var encoded = new byte[HeaderLength + record.CanonicalBytes.Length];
        FileMagic.CopyTo(encoded);
        encoded[4] = SchemaVersion;
        encoded[5] = (byte)record.Kind;
        encoded[6] = (byte)record.Operation;
        encoded[7] = record.Terminal is null ? (byte)0 : (byte)record.Terminal.Value;
        BinaryPrimitives.WriteUInt64BigEndian(
            encoded.AsSpan(8, 8),
            record.RetainUntilUnixSeconds);
        BinaryPrimitives.WriteUInt32BigEndian(
            encoded.AsSpan(16, 4),
            checked((uint)record.CanonicalBytes.Length));
        SHA256.HashData(record.CanonicalBytes).CopyTo(encoded, 24);
        record.KeyDigest.CopyTo(encoded, 56);
        ComputeRecordDigest(
                record.Kind,
                record.Operation,
                record.Terminal,
                record.RetainUntilUnixSeconds,
                record.CanonicalBytes.Length,
                encoded.AsSpan(24, 32),
                record.KeyDigest)
            .CopyTo(encoded, 88);
        record.CanonicalBytes.CopyTo(encoded, HeaderLength);
        return encoded;
    }

    private static PersistedRecord Decode(
        ReadOnlySpan<byte> encoded,
        ReadOnlySpan<byte> expectedKey)
    {
        if (encoded.Length < HeaderLength + TerminalLength
            || !encoded[..4].SequenceEqual(FileMagic)
            || encoded[4] != SchemaVersion
            || encoded.Slice(20, 4).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(120, 8).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw Corrupt();
        }

        var kind = (MailboxClientCanonicalOutcomeKind)encoded[5];
        var operation = (MailboxAuthenticatedOperation)encoded[6];
        var terminalByte = encoded[7];
        var retainUntil = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        var canonicalLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(16, 4));
        if (canonicalLength > MailboxClientLimits.MaximumPageBytes
            || encoded.Length != HeaderLength + canonicalLength
            || expectedKey.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                encoded.Slice(56, 32),
                expectedKey))
        {
            throw Corrupt();
        }

        var canonical = encoded[HeaderLength..].ToArray();
        if (!CryptographicOperations.FixedTimeEquals(
                encoded.Slice(24, 32),
                SHA256.HashData(canonical)))
        {
            throw Corrupt();
        }

        MailboxClientTerminalOutcome? terminal = terminalByte == 0
            ? null
            : (MailboxClientTerminalOutcome)terminalByte;
        var expectedRecordDigest = ComputeRecordDigest(
            kind,
            operation,
            terminal,
            retainUntil,
            checked((int)canonicalLength),
            encoded.Slice(24, 32),
            encoded.Slice(56, 32));
        if (!CryptographicOperations.FixedTimeEquals(
                encoded.Slice(88, 32),
                expectedRecordDigest))
        {
            throw Corrupt();
        }

        var record = new PersistedRecord(
            kind,
            operation,
            terminal,
            retainUntil,
            canonical,
            encoded.Slice(56, 32).ToArray());
        ValidateRecord(record);
        return record;
    }

    private static void ValidateRecord(PersistedRecord record)
    {
        ValidateOperation(record.Operation);
        if (record.RetainUntilUnixSeconds == 0
            || record.KeyDigest.Length != 32
            || record.KeyDigest.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || record.CanonicalBytes.Length is < TerminalLength
                or > MailboxClientLimits.MaximumPageBytes)
        {
            throw Corrupt();
        }

        switch (record.Kind)
        {
            case MailboxClientCanonicalOutcomeKind.Success
                when record.Terminal is null:
                ValidateSuccessFrame(record.Operation, record.CanonicalBytes);
                break;
            case MailboxClientCanonicalOutcomeKind.Terminal
                when record.Terminal is not null:
                ValidateTerminal(record.Terminal.Value);
                if (record.CanonicalBytes.Length != TerminalLength
                    || !record.CanonicalBytes.AsSpan(0, 4).SequenceEqual(TerminalMagic)
                    || record.CanonicalBytes[4] != SchemaVersion
                    || record.CanonicalBytes[5] != (byte)record.Operation
                    || record.CanonicalBytes[6] != (byte)record.Terminal.Value
                    || record.CanonicalBytes.AsSpan(7).IndexOfAnyExcept((byte)0) >= 0)
                {
                    throw Corrupt();
                }

                break;
            default:
                throw Corrupt();
        }
    }

    private static void ValidateSuccessFrame(
        MailboxAuthenticatedOperation operation,
        ReadOnlySpan<byte> canonical)
    {
        ValidateOperation(operation);
        if (canonical.Length is < 8 or > MailboxClientLimits.MaximumPageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(canonical));
        }

        try
        {
            var reencoded = operation switch
            {
                MailboxAuthenticatedOperation.Store =>
                    MailboxReceiptV3Codec.EncodeDurableQuorum(
                        MailboxReceiptV3Codec.DecodeDurableQuorum(canonical)),
                MailboxAuthenticatedOperation.Retrieve =>
                    MailboxClientCodec.EncodeRetrievePage(
                        DecodeCanonicalRetrievePage(canonical)),
                MailboxAuthenticatedOperation.Ack =>
                    MailboxAggregateAckCodec.EncodeMqr3(
                        MailboxAggregateAckCodec.DecodeMqr3(canonical)),
                _ => throw new ArgumentOutOfRangeException(nameof(operation))
            };
            if (!reencoded.AsSpan().SequenceEqual(canonical))
            {
                throw new ArgumentException(
                    "The canonical mailbox outcome frame is invalid.",
                    nameof(canonical));
            }
        }
        catch (Exception exception) when (
            exception is MailboxReceiptException
                or MailboxClientException
                or MailboxPeerReplicationException
                or MailboxAuthenticatedCapabilityException
                or ArgumentException
                or OverflowException)
        {
            throw new ArgumentException(
                "The canonical mailbox outcome frame is invalid.",
                nameof(canonical));
        }
    }

    private static MailboxRetrievePage DecodeCanonicalRetrievePage(
        ReadOnlySpan<byte> canonical)
    {
        const int pageHeaderLength = 48;
        if (canonical.Length is < pageHeaderLength
            or > MailboxClientLimits.MaximumPageBytes
            || !canonical[..4].SequenceEqual("MRP1"u8)
            || canonical[4] != 1
            || canonical[5] > 1
            || canonical.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || canonical.Slice(44, 4).IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new ArgumentException(
                "The canonical mailbox retrieve page header is invalid.",
                nameof(canonical));
        }

        var epoch = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(8, 8));
        var operationId = canonical
            .Slice(16, MailboxClientLimits.OperationIdLength)
            .ToArray();
        var nextCursor = BinaryPrimitives.ReadUInt64BigEndian(
            canonical.Slice(32, 8));
        var tokenLength = BinaryPrimitives.ReadUInt16BigEndian(
            canonical.Slice(40, 2));
        var count = BinaryPrimitives.ReadUInt16BigEndian(
            canonical.Slice(42, 2));
        var hasMore = canonical[5] == 1;
        if (epoch == 0
            || operationId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || count > MailboxClientLimits.MaximumPageItems
            || tokenLength > MailboxClientLimits.MaximumContinuationTokenLength
            || pageHeaderLength + tokenLength > canonical.Length
            || hasMore != (tokenLength != 0)
            || hasMore && count == 0)
        {
            throw new ArgumentException(
                "The canonical mailbox retrieve page metadata is invalid.",
                nameof(canonical));
        }

        var token = canonical.Slice(pageHeaderLength, tokenLength).ToArray();
        var offset = pageHeaderLength + tokenLength;
        var items = new List<MailboxRetrievedEnvelope>(count);
        ulong priorCursor = 0;
        for (var index = 0; index < count; index++)
        {
            if (offset > canonical.Length - 12)
            {
                throw new ArgumentException(
                    "The canonical mailbox retrieve page item is truncated.",
                    nameof(canonical));
            }

            var cursor = BinaryPrimitives.ReadUInt64BigEndian(
                canonical.Slice(offset, 8));
            var envelopeLength = BinaryPrimitives.ReadUInt32BigEndian(
                canonical.Slice(offset + 8, 4));
            offset += 12;
            if (cursor == 0
                || cursor <= priorCursor
                || envelopeLength > MailboxClientLimits.MaximumEncryptedEnvelopeLength
                || envelopeLength > canonical.Length - offset)
            {
                throw new ArgumentException(
                    "The canonical mailbox retrieve page item is invalid.",
                    nameof(canonical));
            }

            var encodedEnvelope = canonical.Slice(
                offset,
                checked((int)envelopeLength));
            var envelope =
                MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
                    encodedEnvelope);
            if (envelope.Epoch != epoch
                || !MailboxClientCodec.EncodeEncryptedEnvelope(envelope)
                    .AsSpan()
                    .SequenceEqual(encodedEnvelope))
            {
                throw new ArgumentException(
                    "The canonical mailbox retrieve page envelope is invalid.",
                    nameof(canonical));
            }

            items.Add(new MailboxRetrievedEnvelope
            {
                Cursor = cursor,
                Envelope = envelope
            });
            priorCursor = cursor;
            offset += checked((int)envelopeLength);
        }

        if (offset != canonical.Length
            || (items.Count == 0
                ? nextCursor != 0 || hasMore
                : nextCursor != priorCursor))
        {
            throw new ArgumentException(
                "The canonical mailbox retrieve page cursor binding is invalid.",
                nameof(canonical));
        }

        return new MailboxRetrievePage
        {
            Epoch = epoch,
            OperationId = operationId,
            NextCursor = nextCursor,
            HasMore = hasMore,
            ContinuationToken = token,
            Items = items
        };
    }

    private static void ValidateOperation(MailboxAuthenticatedOperation operation)
    {
        if (operation is not (
            MailboxAuthenticatedOperation.Store
            or MailboxAuthenticatedOperation.Retrieve
            or MailboxAuthenticatedOperation.Ack))
        {
            throw new ArgumentOutOfRangeException(nameof(operation));
        }
    }

    private static void ValidateTerminal(MailboxClientTerminalOutcome terminal)
    {
        if (terminal is not (
            MailboxClientTerminalOutcome.AuthorizationRejected
            or MailboxClientTerminalOutcome.OperationConflict
            or MailboxClientTerminalOutcome.DurableStateRejected))
        {
            throw new ArgumentOutOfRangeException(nameof(terminal));
        }
    }

    private void RemoveReservation(string keyText, ActiveReservation active)
    {
        _reservations.Remove(keyText);
        if (active.CountsEntry)
        {
            _reservedCanonicalBytes -= active.MaximumCanonicalBytes;
            _reservedFileBytes -= active.ReservedFileBytes;
        }
    }

    private void PurgeAbandonedFiles()
    {
        foreach (var path in Directory.EnumerateFiles(_directory, "*.tmp"))
        {
            File.Delete(path);
        }

        foreach (var path in Directory.EnumerateFiles(_directory, "*.deleted"))
        {
            File.Delete(path);
        }
    }

    private string PathFor(string keyText) =>
        Path.Combine(_directory, $"{keyText}{Extension}");

    private static string KeyText(ReadOnlySpan<byte> digest) =>
        Convert.ToHexString(digest).ToLowerInvariant();

    private static bool IsLowerHex(string? value, int bytes) =>
        value is not null
        && value.Length == bytes * 2
        && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static PersistedEntry ToEntry(PersistedRecord record) =>
        new(
            record.Kind,
            record.Operation,
            record.Terminal,
            record.RetainUntilUnixSeconds,
            record.CanonicalBytes.Length,
            HeaderLength + record.CanonicalBytes.Length,
            Convert.ToHexString(SHA256.HashData(record.CanonicalBytes))
                .ToLowerInvariant());

    private static MailboxClientCanonicalOutcome ToOutcome(PersistedRecord record) =>
        new(
            record.Kind,
            record.Operation,
            record.Terminal,
            record.RetainUntilUnixSeconds,
            record.CanonicalBytes);

    private static void EnsureExact(PersistedRecord actual, PersistedRecord expected)
    {
        if (actual.Kind != expected.Kind
            || actual.Operation != expected.Operation
            || actual.Terminal != expected.Terminal
            || actual.RetainUntilUnixSeconds != expected.RetainUntilUnixSeconds
            || !CryptographicOperations.FixedTimeEquals(
                actual.KeyDigest,
                expected.KeyDigest)
            || !CryptographicOperations.FixedTimeEquals(
                actual.CanonicalBytes,
                expected.CanonicalBytes))
        {
            throw new MailboxClientCanonicalOutcomeConflictException();
        }
    }

    private static byte[] ComputeRecordDigest(
        MailboxClientCanonicalOutcomeKind kind,
        MailboxAuthenticatedOperation operation,
        MailboxClientTerminalOutcome? terminal,
        ulong retainUntilUnixSeconds,
        int canonicalLength,
        ReadOnlySpan<byte> canonicalDigest,
        ReadOnlySpan<byte> keyDigest)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(RecordDigestDomain);
        Span<byte> fixedFields = stackalloc byte[16];
        fixedFields.Clear();
        fixedFields[0] = SchemaVersion;
        fixedFields[1] = (byte)kind;
        fixedFields[2] = (byte)operation;
        fixedFields[3] = terminal is null ? (byte)0 : (byte)terminal.Value;
        BinaryPrimitives.WriteUInt64BigEndian(
            fixedFields.Slice(4, 8),
            retainUntilUnixSeconds);
        BinaryPrimitives.WriteUInt32BigEndian(
            fixedFields.Slice(12, 4),
            checked((uint)canonicalLength));
        hash.AppendData(fixedFields);
        hash.AppendData(canonicalDigest);
        hash.AppendData(keyDigest);
        return hash.GetHashAndReset();
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(_disposed != 0, this);

    private static InvalidDataException Corrupt() =>
        new("The mailbox canonical outcome store is corrupt and cannot be used.");

    private sealed record PersistedRecord(
        MailboxClientCanonicalOutcomeKind Kind,
        MailboxAuthenticatedOperation Operation,
        MailboxClientTerminalOutcome? Terminal,
        ulong RetainUntilUnixSeconds,
        byte[] CanonicalBytes,
        byte[] KeyDigest);

    private sealed record PersistedEntry(
        MailboxClientCanonicalOutcomeKind Kind,
        MailboxAuthenticatedOperation Operation,
        MailboxClientTerminalOutcome? Terminal,
        ulong RetainUntilUnixSeconds,
        int CanonicalLength,
        int FileLength,
        string CanonicalDigest);

    private sealed record ActiveReservation(
        long ReservationId,
        MailboxAuthenticatedOperation Operation,
        ulong RetainUntilUnixSeconds,
        int MaximumCanonicalBytes,
        bool CountsEntry,
        long ReservedFileBytes);
}

public sealed class MailboxClientCanonicalOutcomeCapacityException : Exception
{
    public MailboxClientCanonicalOutcomeCapacityException()
        : base("The mailbox canonical outcome store capacity is exhausted.")
    {
    }
}

public sealed class MailboxClientCanonicalOutcomeConflictException : Exception
{
    public MailboxClientCanonicalOutcomeConflictException()
        : base("The mailbox canonical outcome conflicts with durable state.")
    {
    }
}

public sealed class MailboxClientCanonicalOutcomeMissingException : Exception
{
    public MailboxClientCanonicalOutcomeMissingException()
        : base("The required mailbox canonical outcome is unavailable.")
    {
    }
}

public sealed class MailboxClientCanonicalOutcomePersistenceException : Exception
{
    public MailboxClientCanonicalOutcomePersistenceException()
        : base("The mailbox canonical outcome could not be persisted durably.")
    {
    }
}
