using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed class DurableMailboxCapabilityReplayJournalOptions
{
    public string DirectoryName { get; set; } = "mailbox-capability-replay-v2";

    public int MaximumScopes { get; set; } = 100_000;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || MaximumScopes is < 1 or > 1_000_000)
        {
            throw new InvalidOperationException("Mailbox replay journal options are invalid.");
        }
    }
}

public sealed record MailboxCapabilityReplayJournalDiagnostics(
    int ScopeCount,
    int PendingCount,
    int CompletedCount);

internal sealed class MailboxCapabilityReplayJournalDocument
{
    public int SchemaVersion { get; set; } = 1;
    public Dictionary<string, MailboxCapabilityReplayJournalRecord> Records { get; set; } =
        new(StringComparer.Ordinal);
}

internal sealed class MailboxCapabilityReplayJournalRecord
{
    public ulong HighestCounter { get; set; }
    public string ClaimDigest { get; set; } = "";
    public string Status { get; set; } = "";
    public string CanonicalOutcome { get; set; } = "";
}

/// <summary>
/// Crash-safe host implementation of the P03B2 atomic replay journal. The persisted key is a
/// domain-separated hash produced by the protocol state machine; raw operation, capability,
/// mailbox and issuer identifiers are never persisted or emitted as diagnostics.
/// </summary>
public sealed class DurableMailboxCapabilityReplayJournal
    : IMailboxCapabilityReplayJournal, IDisposable
{
    private const int SchemaVersion = 1;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _path;
    private readonly int _maximumScopes;
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
                        record.Status == nameof(MailboxCapabilityReplayRecordStatus.Completed)));
            }
        }
    }

    public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
        MailboxCapabilityAtomicReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ThrowIfDisposed();
            var scope = ScopeKey(claim);
            _document.Records.TryGetValue(scope, out var persisted);
            var current = persisted is null ? null : ToSnapshot(persisted);
            var transition = MailboxCapabilityReplayStateMachine.EvaluateAndReserve(
                current,
                claim);
            if (transition.NextSnapshot is not null &&
                (current is null || !SnapshotsEqual(current, transition.NextSnapshot)))
            {
                if (current is null && _document.Records.Count >= _maximumScopes)
                {
                    throw new InvalidOperationException(
                        "Mailbox replay journal capacity is exhausted.");
                }

                var replacement = Clone(_document);
                replacement.Records[scope] = FromSnapshot(transition.NextSnapshot);
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

            var completed = MailboxCapabilityReplayStateMachine.Complete(
                ToSnapshot(persisted),
                claim,
                canonicalOutcome.Span);
            var replacement = Clone(_document);
            replacement.Records[scope] = FromSnapshot(completed);
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
        if (document.SchemaVersion != SchemaVersion || document.Records is null)
        {
            throw new InvalidDataException("Mailbox replay journal schema is unsupported.");
        }

        foreach (var pair in document.Records)
        {
            if (!TryDecodeHex(pair.Key, 32, out _) || pair.Value is null)
            {
                throw new InvalidDataException("Mailbox replay journal record key is invalid.");
            }

            _ = ToSnapshot(pair.Value);
        }
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

    private static MailboxCapabilityReplayJournalRecord FromSnapshot(
        MailboxCapabilityReplaySnapshot snapshot) => new()
        {
            HighestCounter = snapshot.HighestCounter,
            ClaimDigest = Convert.ToHexString(snapshot.ClaimDigest.Span).ToLowerInvariant(),
            Status = snapshot.Status.ToString(),
            CanonicalOutcome = snapshot.CanonicalOutcome.IsEmpty
            ? ""
            : Convert.ToBase64String(snapshot.CanonicalOutcome.Span)
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
                CanonicalOutcome = pair.Value.CanonicalOutcome
            },
            StringComparer.Ordinal)
        };

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
}
