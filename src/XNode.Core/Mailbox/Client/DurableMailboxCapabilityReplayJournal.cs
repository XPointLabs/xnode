using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed class DurableMailboxCapabilityReplayJournalOptions
{
    public string DirectoryName { get; set; } = "mailbox-capability-replay-v2";

    public int MaximumScopes { get; set; } = 100_000;

    public TimeSpan RetentionAfterValidity { get; set; } = TimeSpan.FromDays(7);

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || MaximumScopes is < 1 or > 1_000_000
            || RetentionAfterValidity != TimeSpan.FromDays(7))
        {
            throw new InvalidOperationException("Mailbox replay journal options are invalid.");
        }
    }
}

public sealed record MailboxCapabilityReplayJournalDiagnostics(
    int ScopeCount,
    int PendingCount,
    int CompletedCount,
    int ReleasedCount,
    int CapacityRemaining);

internal sealed class MailboxCapabilityReplayJournalDocument
{
    public int SchemaVersion { get; set; } = 2;
    public Dictionary<string, MailboxCapabilityReplayJournalRecord> Records { get; set; } =
        new(StringComparer.Ordinal);
}

internal sealed class MailboxCapabilityReplayJournalRecord
{
    public ulong HighestCounter { get; set; }
    public string ClaimDigest { get; set; } = "";
    public string Status { get; set; } = "";
    public string CanonicalOutcome { get; set; } = "";
    public ulong RetainUntilUnixSeconds { get; set; } = ulong.MaxValue;
}

/// <summary>
/// Crash-safe host implementation of the P03B2 atomic replay journal. The persisted key is a
/// domain-separated hash produced by the protocol state machine; raw operation, capability,
/// mailbox and issuer identifiers are never persisted or emitted as diagnostics.
/// </summary>
public sealed class DurableMailboxCapabilityReplayJournal
    : IMailboxCapabilityReplayJournal, IDisposable
{
    private const int SchemaVersion = 2;
    private const string ReleasedStatus = "Released";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _path;
    private readonly int _maximumScopes;
    private readonly ulong _retentionSeconds;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly FileStream _lease;
    private readonly object _gate = new();
    private MailboxCapabilityReplayJournalDocument _document;
    private int _disposed;

    public DurableMailboxCapabilityReplayJournal(
        string dataDirectory,
        DurableMailboxCapabilityReplayJournalOptions? options = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory))
        {
            throw new ArgumentException(
                "A mailbox replay data directory is required.",
                nameof(dataDirectory));
        }

        options ??= new DurableMailboxCapabilityReplayJournalOptions();
        options.Validate();
        _directory = Path.Combine(dataDirectory, options.DirectoryName);
        _path = Path.Combine(_directory, "replay.json");
        _maximumScopes = options.MaximumScopes;
        _retentionSeconds = checked((ulong)options.RetentionAfterValidity.TotalSeconds);
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
        _security.SecureDirectory(_directory);
        try
        {
            _lease = new FileStream(
                Path.Combine(_directory, ".replay.lock"),
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                "Another mailbox replay journal owns this directory.",
                exception);
        }

        try
        {
            _document = Load();
            if (_document.SchemaVersion == 1)
            {
                _document.SchemaVersion = SchemaVersion;
                foreach (var record in _document.Records.Values)
                {
                    // Schema v1 did not retain validity metadata. Keeping those records
                    // indefinitely is the only fail-closed migration.
                    record.RetainUntilUnixSeconds = ulong.MaxValue;
                }
            }
            if (_document.Records.Count > _maximumScopes)
            {
                throw new InvalidDataException(
                    "Mailbox replay journal exceeds its configured capacity.");
            }

            DeleteAbandonedTemporaryFiles();
        }
        catch
        {
            _lease.Dispose();
            throw;
        }
    }

    public MailboxCapabilityReplayJournalDiagnostics Diagnostics
    {
        get
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                return new(
                    _document.Records.Count,
                    _document.Records.Values.Count(static record =>
                        record.Status == nameof(MailboxCapabilityReplayRecordStatus.Pending)),
                    _document.Records.Values.Count(static record =>
                        record.Status == nameof(MailboxCapabilityReplayRecordStatus.Completed)),
                    _document.Records.Values.Count(static record =>
                        record.Status == ReleasedStatus),
                    _maximumScopes - _document.Records.Count);
            }
        }
    }

    public ulong RetainUntilUnixSeconds(ulong validityEndsAtUnixSeconds) =>
        validityEndsAtUnixSeconds > ulong.MaxValue - _retentionSeconds
            ? ulong.MaxValue
            : validityEndsAtUnixSeconds + _retentionSeconds;

    public IMailboxCapabilityReplayJournal CreateEvaluationScope(
        ulong nowUnixSeconds,
        ulong retainUntilUnixSeconds) =>
        new EvaluationScope(this, nowUnixSeconds, retainUntilUnixSeconds);

    public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
        MailboxCapabilityAtomicReplayClaim claim) =>
        EvaluateAndReserve(claim, nowUnixSeconds: 0, retainUntilUnixSeconds: ulong.MaxValue);

    public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
        MailboxCapabilityAtomicReplayClaim claim,
        ulong nowUnixSeconds,
        ulong retainUntilUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ThrowIfDisposed();
            CollectExpiredLocked(nowUnixSeconds);
            var scope = ScopeKey(claim);
            _document.Records.TryGetValue(scope, out var persisted);
            var current = persisted is null || persisted.Status == ReleasedStatus
                ? null
                : ToSnapshot(persisted);
            if (persisted?.Status == ReleasedStatus)
            {
                var exactClaim = persisted.HighestCounter == claim.ReplayCounter
                    && Fixed(persisted.ClaimDigest, claim.ClaimDigest.Span);
                if (!exactClaim && claim.ReplayCounter <= persisted.HighestCounter)
                {
                    current = ToPendingSnapshot(persisted);
                }
            }

            var transition = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
                current,
                claim);
            if (transition.NextSnapshot is not null &&
                (current is null || !SnapshotsEqual(current, transition.NextSnapshot)))
            {
                if (persisted is null && _document.Records.Count >= _maximumScopes)
                {
                    throw new InvalidOperationException(
                        "Mailbox replay journal capacity is exhausted.");
                }

                var replacement = Clone(_document);
                replacement.Records[scope] = FromSnapshot(
                    transition.NextSnapshot,
                    retainUntilUnixSeconds);
                Save(replacement);
                _document = replacement;
            }

            return transition.Evaluation with
            {
                CachedOutcome = transition.Evaluation.CachedOutcome.ToArray()
            };
        }
    }

    public void CompleteAtomically(
        MailboxCapabilityAtomicReplayClaim claim,
        ReadOnlyMemory<byte> canonicalOutcome)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ThrowIfDisposed();
            var scope = ScopeKey(claim);
            if (!_document.Records.TryGetValue(scope, out var persisted))
            {
                throw new MailboxAuthenticatedCapabilityException(
                    MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
                    "Mailbox replay completion has no durable reservation.");
            }

            if (persisted.Status == ReleasedStatus)
            {
                throw InvalidCompletion("Mailbox replay completion was safely released.");
            }

            var current = ToSnapshot(persisted);
            if (current.Status == MailboxCapabilityReplayRecordStatus.Completed)
            {
                var exactClaim = current.HighestCounter == claim.ReplayCounter
                    && CryptographicOperations.FixedTimeEquals(
                        current.ClaimDigest.Span,
                        claim.ClaimDigest.Span);
                if (!exactClaim
                    || !current.CanonicalOutcome.Span.SequenceEqual(canonicalOutcome.Span))
                {
                    throw InvalidCompletion(
                        "Completed mailbox replay outcome conflicts.");
                }

                return;
            }

            var completed = MailboxCapabilityReplayStateMachine.Complete(
                current,
                claim,
                canonicalOutcome.Span);
            var replacement = Clone(_document);
            replacement.Records[scope] = FromSnapshot(
                completed,
                persisted.RetainUntilUnixSeconds);
            Save(replacement);
            _document = replacement;
        }
    }

    public void AbortAtomically(MailboxCapabilityAtomicReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ThrowIfDisposed();
            var scope = ScopeKey(claim);
            if (!_document.Records.TryGetValue(scope, out var persisted)
                || persisted.Status != nameof(MailboxCapabilityReplayRecordStatus.Pending)
                || persisted.HighestCounter != claim.ReplayCounter
                || !Fixed(persisted.ClaimDigest, claim.ClaimDigest.Span))
            {
                throw InvalidCompletion(
                    "Mailbox replay abort has no matching pending reservation.");
            }

            var replacement = Clone(_document);
            replacement.Records[scope].Status = ReleasedStatus;
            replacement.Records[scope].CanonicalOutcome = "";
            Save(replacement);
            _document = replacement;
        }
    }

    public int CollectExpired(ulong nowUnixSeconds)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return CollectExpiredLocked(nowUnixSeconds);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _lease.Dispose();
            }
        }
    }

    private MailboxCapabilityReplayJournalDocument Load()
    {
        if (!File.Exists(_path))
        {
            return new MailboxCapabilityReplayJournalDocument();
        }

        try
        {
            var document = JsonSerializer.Deserialize<MailboxCapabilityReplayJournalDocument>(
                File.ReadAllBytes(_path),
                JsonOptions)
                ?? throw new InvalidDataException("Mailbox replay journal is empty.");
            Validate(document);
            return document;
        }
        catch (Exception exception) when (
            exception is JsonException
                or InvalidDataException
                or FormatException
                or MailboxAuthenticatedCapabilityException)
        {
            throw new InvalidDataException(
                "Mailbox replay journal is corrupt and cannot be opened.",
                exception);
        }
    }

    private void Save(MailboxCapabilityReplayJournalDocument document)
    {
        Validate(document);
        _security.SecureDirectory(_directory);
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       8192,
                       FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, document, JsonOptions);
                stream.Flush(flushToDisk: true);
            }

            ReplaceAtomically(temporary);
            _security.SecureFile(_path);
            _durability.FlushFileAndParentDirectory(_path);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private void ReplaceAtomically(string temporary)
    {
        const int maximumAttempts = 4;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(temporary, _path, overwrite: true);
                return;
            }
            catch (Exception exception) when (
                OperatingSystem.IsWindows()
                && attempt < maximumAttempts
                && exception is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(5 * attempt));
            }
        }
    }

    private static void Validate(MailboxCapabilityReplayJournalDocument document)
    {
        if (document.SchemaVersion is not (1 or SchemaVersion) || document.Records is null)
        {
            throw new InvalidDataException("Mailbox replay journal schema is unsupported.");
        }

        foreach (var pair in document.Records)
        {
            if (!TryDecodeHex(pair.Key, 32, out _) || pair.Value is null)
            {
                throw new InvalidDataException("Mailbox replay journal record key is invalid.");
            }

            ValidateRecord(pair.Value, document.SchemaVersion);
        }
    }

    private static void ValidateRecord(
        MailboxCapabilityReplayJournalRecord record,
        int schemaVersion)
    {
        if (record.Status == ReleasedStatus)
        {
            if (schemaVersion < SchemaVersion
                || !TryDecodeHex(record.ClaimDigest, 32, out _)
                || !string.IsNullOrEmpty(record.CanonicalOutcome))
            {
                throw new InvalidDataException("Released mailbox replay record is invalid.");
            }

            return;
        }

        _ = ToSnapshot(record);
    }

    private static MailboxCapabilityReplaySnapshot ToSnapshot(
        MailboxCapabilityReplayJournalRecord record)
    {
        if (!TryDecodeHex(record.ClaimDigest, 32, out var claimDigest)
            || !Enum.TryParse<MailboxCapabilityReplayRecordStatus>(
                record.Status,
                ignoreCase: false,
                out var status)
            || status is not (
                MailboxCapabilityReplayRecordStatus.Pending or
                MailboxCapabilityReplayRecordStatus.Completed))
        {
            throw new InvalidDataException("Mailbox replay journal record is invalid.");
        }

        byte[] outcome;
        try
        {
            outcome = string.IsNullOrEmpty(record.CanonicalOutcome)
                ? []
                : Convert.FromBase64String(record.CanonicalOutcome);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException(
                "Mailbox replay journal outcome is invalid.",
                exception);
        }

        var snapshot = new MailboxCapabilityReplaySnapshot
        {
            HighestCounter = record.HighestCounter,
            ClaimDigest = claimDigest,
            Status = status,
            CanonicalOutcome = outcome
        };
        // Reuse the protocol's strict snapshot validator without duplicating its rules.
        _ = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
            snapshot,
            new MailboxCapabilityAtomicReplayClaim
            {
                ClaimDigest = claimDigest,
                IssuerPublicKey = Enumerable.Repeat((byte)1, 32).ToArray(),
                Serial = Enumerable.Repeat((byte)1, 16).ToArray(),
                Epoch = 1,
                Generation = 1,
                Operation = MailboxAuthenticatedOperation.Store,
                OperationId = Enumerable.Repeat((byte)1, 16).ToArray(),
                ReplayCounter = record.HighestCounter,
                RequestDigest = Enumerable.Repeat((byte)1, 32).ToArray()
            });
        return snapshot;
    }

    private static MailboxCapabilityReplaySnapshot ToPendingSnapshot(
        MailboxCapabilityReplayJournalRecord record)
    {
        if (!TryDecodeHex(record.ClaimDigest, 32, out var claimDigest))
        {
            throw new InvalidDataException("Mailbox replay claim digest is invalid.");
        }

        return new MailboxCapabilityReplaySnapshot
        {
            HighestCounter = record.HighestCounter,
            ClaimDigest = claimDigest,
            Status = MailboxCapabilityReplayRecordStatus.Pending,
            CanonicalOutcome = ReadOnlyMemory<byte>.Empty
        };
    }

    private static MailboxCapabilityReplayJournalRecord FromSnapshot(
        MailboxCapabilityReplaySnapshot snapshot,
        ulong retainUntilUnixSeconds) => new()
        {
            HighestCounter = snapshot.HighestCounter,
            ClaimDigest = Convert.ToHexString(snapshot.ClaimDigest.Span).ToLowerInvariant(),
            Status = snapshot.Status.ToString(),
            CanonicalOutcome = snapshot.CanonicalOutcome.IsEmpty
            ? ""
            : Convert.ToBase64String(snapshot.CanonicalOutcome.Span),
            RetainUntilUnixSeconds = retainUntilUnixSeconds
        };

    private static MailboxCapabilityReplayJournalDocument Clone(
        MailboxCapabilityReplayJournalDocument source) => new()
        {
            SchemaVersion = source.SchemaVersion,
            Records = source.Records.ToDictionary(
            static pair => pair.Key,
            static pair => new MailboxCapabilityReplayJournalRecord
            {
                HighestCounter = pair.Value.HighestCounter,
                ClaimDigest = pair.Value.ClaimDigest,
                Status = pair.Value.Status,
                CanonicalOutcome = pair.Value.CanonicalOutcome,
                RetainUntilUnixSeconds = pair.Value.RetainUntilUnixSeconds
            },
            StringComparer.Ordinal)
        };

    private int CollectExpiredLocked(ulong nowUnixSeconds)
    {
        if (nowUnixSeconds == 0)
        {
            return 0;
        }

        var expired = _document.Records
            .Where(pair => pair.Value.RetainUntilUnixSeconds < nowUnixSeconds)
            .Select(static pair => pair.Key)
            .ToArray();
        if (expired.Length == 0)
        {
            return 0;
        }

        var replacement = Clone(_document);
        foreach (var scope in expired)
        {
            replacement.Records.Remove(scope);
        }

        Save(replacement);
        _document = replacement;
        return expired.Length;
    }

    private static bool SnapshotsEqual(
        MailboxCapabilityReplaySnapshot left,
        MailboxCapabilityReplaySnapshot right) =>
        left.HighestCounter == right.HighestCounter
        && left.Status == right.Status
        && CryptographicOperations.FixedTimeEquals(
            left.ClaimDigest.Span,
            right.ClaimDigest.Span)
        && left.CanonicalOutcome.Span.SequenceEqual(right.CanonicalOutcome.Span);

    private static string ScopeKey(MailboxCapabilityAtomicReplayClaim claim) =>
        Convert.ToHexString(MailboxCapabilityReplayStateMachine.ComputeScopeKey(claim))
            .ToLowerInvariant();

    private static bool Fixed(string encoded, ReadOnlySpan<byte> expected) =>
        TryDecodeHex(encoded, expected.Length, out var decoded)
        && CryptographicOperations.FixedTimeEquals(decoded, expected);

    private static MailboxAuthenticatedCapabilityException InvalidCompletion(string message) =>
        new(
            MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
            message);

    private static bool TryDecodeHex(string? value, int bytes, out byte[] decoded)
    {
        decoded = [];
        if (value is null
            || value.Length != bytes * 2
            || value.Any(static character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            return false;
        }

        decoded = Convert.FromHexString(value);
        return decoded.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
    }

    private void DeleteAbandonedTemporaryFiles()
    {
        foreach (var temporary in Directory.EnumerateFiles(_directory, "*.tmp"))
        {
            File.Delete(temporary);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
    }

    private sealed class EvaluationScope(
        DurableMailboxCapabilityReplayJournal owner,
        ulong nowUnixSeconds,
        ulong retainUntilUnixSeconds) : IMailboxCapabilityReplayJournal
    {
        public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
            MailboxCapabilityAtomicReplayClaim claim) =>
            owner.EvaluateAndReserve(claim, nowUnixSeconds, retainUntilUnixSeconds);

        public void CompleteAtomically(
            MailboxCapabilityAtomicReplayClaim claim,
            ReadOnlyMemory<byte> canonicalOutcome) =>
            owner.CompleteAtomically(claim, canonicalOutcome);
    }
}
