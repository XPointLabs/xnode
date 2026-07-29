using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed class DurableMailboxCapabilityReplayJournalOptions
{
    public string DirectoryName { get; set; } = "mailbox-capability-replay-v3";

    public int MaximumScopes { get; set; } = 100_000;

    public TimeSpan RetentionAfterValidity { get; set; } = TimeSpan.FromDays(7);

    public TimeSpan MaximumAcceptedClockRollback { get; set; } = TimeSpan.FromSeconds(60);

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || MaximumScopes is < 1 or > 1_000_000
            || RetentionAfterValidity != TimeSpan.FromDays(7)
            || MaximumAcceptedClockRollback != TimeSpan.FromSeconds(60))
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
    int CapacityRemaining,
    ulong AcceptedTimeHighWatermarkUnixSeconds);

internal sealed class MailboxCapabilityReplayJournalDocument
{
    public int SchemaVersion { get; set; } = 3;
    public ulong AcceptedTimeHighWatermarkUnixSeconds { get; set; }
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

internal sealed record MailboxExpiredReplayCollectionItem(
    string ScopeKey,
    ulong ReplayCounter,
    string ClaimDigest,
    ulong RetainUntilUnixSeconds,
    ulong EffectiveNowUnixSeconds,
    MailboxClientCanonicalOutcomeKey OutcomeKey);

/// <summary>
/// Crash-safe host implementation of the P03B2 atomic replay journal. The persisted key is a
/// domain-separated hash produced by the protocol state machine; raw operation, capability,
/// mailbox and issuer identifiers are never persisted or emitted as diagnostics.
/// </summary>
public sealed class DurableMailboxCapabilityReplayJournal
    : IMailboxCapabilityReplayJournal, IDisposable
{
    private const int SchemaVersion = 3;
    private const string ReleasedStatus = "Released";
    private const string ExpiredStatus = "Expired";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _path;
    private readonly int _maximumScopes;
    private readonly ulong _retentionSeconds;
    private readonly ulong _maximumClockRollbackSeconds;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly IClock _clock;
    private readonly FileStream _lease;
    private readonly object _gate = new();
    private MailboxCapabilityReplayJournalDocument _document;
    private int _disposed;

    public DurableMailboxCapabilityReplayJournal(
        string dataDirectory,
        DurableMailboxCapabilityReplayJournalOptions? options = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null,
        IClock? clock = null)
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
        _maximumClockRollbackSeconds =
            checked((ulong)options.MaximumAcceptedClockRollback.TotalSeconds);
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
        _clock = clock ?? new SystemClock();
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
                    _maximumScopes - _document.Records.Count,
                    _document.AcceptedTimeHighWatermarkUnixSeconds);
            }
        }
    }

    public ulong RetainUntilUnixSeconds(ulong validityEndsAtUnixSeconds) =>
        validityEndsAtUnixSeconds > ulong.MaxValue - _retentionSeconds
            ? ulong.MaxValue
            : validityEndsAtUnixSeconds + _retentionSeconds;

    public MailboxCapabilityReplayEvaluationScope CreateEvaluationScope(
        ulong nowUnixSeconds,
        ulong retainUntilUnixSeconds)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var effectiveNow = AdvanceAcceptedTimeLocked(nowUnixSeconds);
            return new(
                this,
                nowUnixSeconds,
                retainUntilUnixSeconds,
                effectiveNow);
        }
    }

    public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
        MailboxCapabilityAtomicReplayClaim claim) =>
        throw InvalidCompletion(
            "Mailbox replay evaluation requires a durable accepted-time scope.");

    public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
        MailboxCapabilityAtomicReplayClaim claim,
        ulong nowUnixSeconds,
        ulong retainUntilUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ThrowIfDisposed();
            var effectiveNow = ResolveEffectiveTime(nowUnixSeconds);
            if (retainUntilUnixSeconds < effectiveNow)
            {
                throw InvalidCompletion(
                    "Mailbox replay claim is outside the durable accepted-time window.");
            }

            var replacement = Clone(_document);
            var changed = AdvanceAcceptedTime(
                replacement,
                nowUnixSeconds,
                effectiveNow);
            var scope = ScopeKey(claim);
            replacement.Records.TryGetValue(scope, out var persisted);
            if (persisted?.Status == ExpiredStatus)
            {
                throw InvalidCompletion(
                    "Mailbox replay scope is awaiting coordinated expiry collection.");
            }

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
                if (persisted is null && replacement.Records.Count >= _maximumScopes)
                {
                    throw new InvalidOperationException(
                        "Mailbox replay journal capacity is exhausted.");
                }

                replacement.Records[scope] = FromSnapshot(
                    transition.NextSnapshot,
                    retainUntilUnixSeconds);
                changed = true;
            }

            if (changed)
            {
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

    public bool IsExactPending(MailboxCapabilityAtomicReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ThrowIfDisposed();
            return _document.Records.TryGetValue(ScopeKey(claim), out var persisted)
                && persisted.Status
                    == nameof(MailboxCapabilityReplayRecordStatus.Pending)
                && persisted.HighestCounter == claim.ReplayCounter
                && Fixed(persisted.ClaimDigest, claim.ClaimDigest.Span);
        }
    }

    internal int CollectExpiredForTestsOnly(ulong nowUnixSeconds)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var effectiveNow = ResolveEffectiveTime(nowUnixSeconds);
            var replacement = Clone(_document);
            var changed = AdvanceAcceptedTime(
                replacement,
                nowUnixSeconds,
                effectiveNow);
            var collected = CollectExpired(replacement, effectiveNow);
            if (changed || collected != 0)
            {
                Save(replacement);
                _document = replacement;
            }

            return collected;
        }
    }

    internal IReadOnlyList<MailboxExpiredReplayCollectionItem>
        PrepareExpiredCollection(
            ulong nowUnixSeconds,
            int maximumEntries,
            IReadOnlySet<string> activeOutcomeKeys)
    {
        if (maximumEntries is < 1 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEntries));
        }

        ArgumentNullException.ThrowIfNull(activeOutcomeKeys);
        lock (_gate)
        {
            ThrowIfDisposed();
            var effectiveNow = ResolveEffectiveTime(nowUnixSeconds);
            var replacement = Clone(_document);
            var changed = false;
            var selected = replacement.Records
                .Where(pair =>
                    pair.Value.RetainUntilUnixSeconds < effectiveNow)
                .OrderByDescending(static pair =>
                    pair.Value.Status == ExpiredStatus)
                .ThenBy(static pair => pair.Value.RetainUntilUnixSeconds)
                .ThenBy(static pair => pair.Key, StringComparer.Ordinal)
                .Select(pair =>
                    ToExpiredCollectionItem(pair, effectiveNow))
                .Where(item =>
                    !activeOutcomeKeys.Contains(
                        Convert.ToHexString(item.OutcomeKey.Digest)))
                .Take(maximumEntries)
                .ToArray();
            if (selected.Length != 0)
            {
                changed = AdvanceAcceptedTime(
                    replacement,
                    nowUnixSeconds,
                    effectiveNow);
            }

            foreach (var item in selected)
            {
                var record = replacement.Records[item.ScopeKey];
                if (record.Status != ExpiredStatus)
                {
                    record.Status = ExpiredStatus;
                    record.CanonicalOutcome = "";
                    changed = true;
                }
            }

            if (changed)
            {
                Save(replacement);
                _document = replacement;
            }

            return selected;
        }
    }

    internal void CompleteExpiredCollection(
        IReadOnlyList<MailboxExpiredReplayCollectionItem> collected)
    {
        ArgumentNullException.ThrowIfNull(collected);
        if (collected.Count == 0)
        {
            return;
        }

        lock (_gate)
        {
            ThrowIfDisposed();
            var replacement = Clone(_document);
            foreach (var item in collected)
            {
                if (!replacement.Records.TryGetValue(item.ScopeKey, out var record)
                    || record.Status != ExpiredStatus
                    || record.HighestCounter != item.ReplayCounter
                    || !string.Equals(
                        record.ClaimDigest,
                        item.ClaimDigest,
                        StringComparison.Ordinal)
                    || record.RetainUntilUnixSeconds
                        != item.RetainUntilUnixSeconds)
                {
                    throw InvalidCompletion(
                        "Mailbox replay expiry collection identity changed.");
                }

                replacement.Records.Remove(item.ScopeKey);
            }

            Save(replacement);
            _document = replacement;
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
                _durability.ReplaceFile(temporary, _path);
                return;
            }
            catch (Exception exception) when (
                OperatingSystem.IsWindows()
                && attempt < maximumAttempts
                && exception is IOException
                    or UnauthorizedAccessException
                    or Win32Exception)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(5 * attempt));
            }
        }
    }

    private static void Validate(MailboxCapabilityReplayJournalDocument document)
    {
        if (document.SchemaVersion != SchemaVersion
            || document.Records is null
            || document.SchemaVersion == SchemaVersion
                && document.Records.Count != 0
                && document.AcceptedTimeHighWatermarkUnixSeconds == 0)
        {
            throw new InvalidDataException("Mailbox replay journal schema is unsupported.");
        }

        foreach (var pair in document.Records)
        {
            if (!TryDecodeHex(pair.Key, 32, out _) || pair.Value is null)
            {
                throw new InvalidDataException("Mailbox replay journal record key is invalid.");
            }

            ValidateRecord(pair.Value);
        }
    }

    private static void ValidateRecord(MailboxCapabilityReplayJournalRecord record)
    {
        if (record.Status is ReleasedStatus or ExpiredStatus)
        {
            if (!TryDecodeHex(record.ClaimDigest, 32, out _)
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
            AcceptedTimeHighWatermarkUnixSeconds =
                source.AcceptedTimeHighWatermarkUnixSeconds,
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

    private static int CollectExpired(
        MailboxCapabilityReplayJournalDocument document,
        ulong effectiveNowUnixSeconds)
    {
        if (effectiveNowUnixSeconds == 0)
        {
            return 0;
        }

        var expired = document.Records
            .Where(pair => pair.Value.RetainUntilUnixSeconds < effectiveNowUnixSeconds)
            .Select(static pair => pair.Key)
            .ToArray();
        foreach (var scope in expired)
        {
            document.Records.Remove(scope);
        }

        return expired.Length;
    }

    private static MailboxExpiredReplayCollectionItem ToExpiredCollectionItem(
        KeyValuePair<string, MailboxCapabilityReplayJournalRecord> pair,
        ulong effectiveNowUnixSeconds)
    {
        if (!TryDecodeHex(pair.Key, 32, out var scope)
            || !TryDecodeHex(pair.Value.ClaimDigest, 32, out var claimDigest))
        {
            throw new InvalidDataException(
                "Mailbox replay expiry identity is invalid.");
        }

        return new(
            pair.Key,
            pair.Value.HighestCounter,
            pair.Value.ClaimDigest,
            pair.Value.RetainUntilUnixSeconds,
            effectiveNowUnixSeconds,
            MailboxClientCanonicalOutcomeKey.Create(
                scope,
                pair.Value.HighestCounter,
                claimDigest));
    }

    private ulong AdvanceAcceptedTimeLocked(ulong observedNowUnixSeconds)
    {
        var effectiveNow = ResolveEffectiveTime(observedNowUnixSeconds);
        if (observedNowUnixSeconds > _document.AcceptedTimeHighWatermarkUnixSeconds)
        {
            var replacement = Clone(_document);
            replacement.AcceptedTimeHighWatermarkUnixSeconds = observedNowUnixSeconds;
            Save(replacement);
            _document = replacement;
        }

        return effectiveNow;
    }

    private ulong ResolveEffectiveTime(ulong observedNowUnixSeconds)
    {
        if (observedNowUnixSeconds == 0)
        {
            throw InvalidCompletion("Mailbox replay accepted time cannot be zero.");
        }

        var floor = _document.AcceptedTimeHighWatermarkUnixSeconds;
        if (observedNowUnixSeconds >= floor)
        {
            return observedNowUnixSeconds;
        }

        if (floor - observedNowUnixSeconds > _maximumClockRollbackSeconds)
        {
            throw InvalidCompletion(
                "Mailbox replay verification rejected excessive wall-clock rollback.");
        }

        return floor;
    }

    private static bool AdvanceAcceptedTime(
        MailboxCapabilityReplayJournalDocument document,
        ulong observedNowUnixSeconds,
        ulong effectiveNowUnixSeconds)
    {
        if (effectiveNowUnixSeconds <= document.AcceptedTimeHighWatermarkUnixSeconds)
        {
            return false;
        }

        document.AcceptedTimeHighWatermarkUnixSeconds = observedNowUnixSeconds;
        return true;
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

    public sealed class MailboxCapabilityReplayEvaluationScope
        : IMailboxCapabilityReplayJournal
    {
        private readonly DurableMailboxCapabilityReplayJournal _owner;
        private readonly ulong _nowUnixSeconds;
        private readonly ulong _retainUntilUnixSeconds;

        internal MailboxCapabilityReplayEvaluationScope(
            DurableMailboxCapabilityReplayJournal owner,
            ulong nowUnixSeconds,
            ulong retainUntilUnixSeconds,
            ulong effectiveNowUnixSeconds)
        {
            _owner = owner;
            _nowUnixSeconds = nowUnixSeconds;
            _retainUntilUnixSeconds = retainUntilUnixSeconds;
            EffectiveNowUnixSeconds = effectiveNowUnixSeconds;
        }

        public ulong EffectiveNowUnixSeconds { get; }

        public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
            MailboxCapabilityAtomicReplayClaim claim) =>
            _owner.EvaluateAndReserve(
                claim,
                _nowUnixSeconds,
                _retainUntilUnixSeconds);

        public void CompleteAtomically(
            MailboxCapabilityAtomicReplayClaim claim,
            ReadOnlyMemory<byte> canonicalOutcome) =>
            _owner.CompleteAtomically(claim, canonicalOutcome);
    }
}
