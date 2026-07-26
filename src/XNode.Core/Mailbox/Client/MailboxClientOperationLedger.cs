using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public enum MailboxClientLedgerState
{
    Reserved,
    Retryable,
    Completing,
    Durable,
    Terminal
}

public sealed record MailboxClientCompletionReservation(
    ulong CoordinatorSequence,
    ReadOnlyMemory<byte> FirstReplicaReceipt,
    ReadOnlyMemory<byte> SecondReplicaReceipt);

public sealed record MailboxClientStoreReservation(
    string OperationKey,
    ulong Epoch,
    ReadOnlyMemory<byte> MailboxId,
    ReadOnlyMemory<byte> OperationId,
    ReadOnlyMemory<byte> RequestDigest,
    ReadOnlyMemory<byte> EnvelopeDigest,
    IReadOnlyList<ReadOnlyMemory<byte>> ExpectedReplicaIds,
    ulong Cursor,
    ulong ExpiresAtUnixSeconds,
    MailboxClientLedgerState State,
    MailboxReplicaDisposition? Disposition,
    ulong AcceptedAtUnixSeconds,
    string Error,
    MailboxClientCompletionReservation? Completion,
    ReadOnlyMemory<byte> CachedReceipt);

internal sealed record MailboxClientLedgerDocument(
    int SchemaVersion,
    ulong NextCoordinatorSequence,
    Dictionary<string, ulong> NextCursorByMailbox,
    Dictionary<string, MailboxClientLedgerOperation> Operations);

internal sealed record MailboxClientLedgerOperation(
    ulong Epoch,
    string MailboxId,
    string OperationId,
    string RequestDigest,
    string EnvelopeDigest,
    string[] ExpectedReplicaIds,
    ulong Cursor,
    ulong ExpiresAtUnixSeconds,
    string State,
    string Disposition,
    ulong AcceptedAtUnixSeconds,
    string Error,
    ulong CoordinatorSequence,
    string FirstReplicaReceipt,
    string SecondReplicaReceipt,
    string Receipt);

public sealed class MailboxClientOperationLedger
{
    private const int SchemaVersion = 2;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _path;
    private readonly int _maxEntries;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public MailboxClientOperationLedger(
        string dataDirectory,
        MailboxClientAdapterOptions options,
        IClock? clock = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        options.Validate();
        _directory = Path.Combine(dataDirectory, options.DirectoryName);
        _path = Path.Combine(_directory, "operations.json");
        _maxEntries = options.MaxOperationEntries;
        _clock = clock ?? new SystemClock();
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        _security.SecureDirectory(_directory);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpired(document, NowUnixSeconds());
            if (changed)
            {
                await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            }

            foreach (var temporary in Directory.EnumerateFiles(_directory, "*.tmp"))
            {
                File.Delete(temporary);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<MailboxClientStoreReservation> ReserveStoreAsync(
        ulong epoch,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> requestDigest,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> envelopeDigest,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        var operationKey = BuildOperationKey(epoch, mailboxId.Span, operationId.Span);
        var mailboxKey = BuildMailboxKey(epoch, mailboxId.Span);
        var requestKey = ToLowerHex(requestDigest.Span, 32, nameof(requestDigest));
        var envelopeKey = ToLowerHex(envelopeDigest.Span, 32, nameof(envelopeDigest));
        var replicaKeys = expectedReplicaIds
            .Select(static replica => ToLowerHex(replica.Span, 32, nameof(expectedReplicaIds)))
            .ToArray();
        if (replicaKeys.Length is < 2 or > 9
            || replicaKeys.Distinct(StringComparer.Ordinal).Count() != replicaKeys.Length)
        {
            throw new ArgumentException("Expected mailbox replicas are invalid.", nameof(expectedReplicaIds));
        }
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpired(document, NowUnixSeconds());
            if (document.Operations.TryGetValue(operationKey, out var existing))
            {
                if (!FixedHexEquals(existing.RequestDigest, requestKey))
                {
                    throw new MailboxClientOperationConflictException();
                }

                if (changed)
                {
                    await SaveAsync(document, cancellationToken).ConfigureAwait(false);
                }

                return ToReservation(operationKey, existing);
            }

            if (document.Operations.Count >= _maxEntries)
            {
                throw new MailboxClientLedgerCapacityException();
            }

            document.NextCursorByMailbox.TryGetValue(mailboxKey, out var priorCursor);
            if (priorCursor == ulong.MaxValue)
            {
                throw new MailboxClientLedgerCapacityException();
            }

            var cursor = priorCursor + 1;
            document.NextCursorByMailbox[mailboxKey] = cursor;
            var operation = new MailboxClientLedgerOperation(
                epoch,
                ToLowerHex(mailboxId.Span, 32, nameof(mailboxId)),
                ToLowerHex(operationId.Span, 16, nameof(operationId)),
                requestKey,
                envelopeKey,
                replicaKeys,
                cursor,
                expiresAtUnixSeconds,
                "reserved",
                "",
                0,
                "",
                0,
                "",
                "",
                "");
            document.Operations.Add(operationKey, operation);
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            return ToReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<MailboxClientStoreReservation> SetDispositionAsync(
        string operationKey,
        MailboxReplicaDisposition disposition,
        ulong acceptedAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (disposition is not (
            MailboxReplicaDisposition.Stored or MailboxReplicaDisposition.Duplicate)
            || acceptedAtUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(disposition));
        }

        return await MutateAsync(
            operationKey,
            operation =>
            {
                if (!string.IsNullOrEmpty(operation.Disposition))
                {
                    if (operation.Disposition != DispositionName(disposition)
                        || operation.AcceptedAtUnixSeconds != acceptedAtUnixSeconds)
                    {
                        throw new InvalidDataException("Mailbox disposition reservation conflicts.");
                    }

                    return operation;
                }

                if (operation.State is "completing" or "durable" or "terminal")
                {
                    throw new InvalidDataException("Mailbox operation cannot reserve a disposition.");
                }

                return operation with
                {
                    Disposition = DispositionName(disposition),
                    AcceptedAtUnixSeconds = acceptedAtUnixSeconds,
                    State = "reserved",
                    Error = ""
                };
            },
            cancellationToken).ConfigureAwait(false);
    }

    public Task<MailboxClientStoreReservation> MarkRetryableAsync(
        string operationKey,
        string error,
        CancellationToken cancellationToken) =>
        MutateAsync(
            operationKey,
            operation => operation.State is "completing" or "durable" or "terminal"
                ? throw new InvalidDataException("Completed mailbox operation cannot become retryable.")
                : operation with { State = "retryable", Error = CanonicalError(error) },
            cancellationToken);

    public Task<MailboxClientStoreReservation> MarkTerminalAsync(
        string operationKey,
        string error,
        CancellationToken cancellationToken) =>
        MutateAsync(
            operationKey,
            operation => operation.State is "completing" or "durable"
                ? throw new InvalidDataException("Completing mailbox operation cannot become terminal.")
                : operation with
                {
                    State = "terminal",
                    Error = CanonicalError(error),
                    CoordinatorSequence = 0,
                    FirstReplicaReceipt = "",
                    SecondReplicaReceipt = "",
                    Receipt = ""
                },
            cancellationToken);

    public async Task<MailboxClientStoreReservation> BeginCompletionAsync(
        string operationKey,
        ReadOnlyMemory<byte> firstReplicaReceipt,
        ReadOnlyMemory<byte> secondReplicaReceipt,
        CancellationToken cancellationToken)
    {
        var first = Convert.ToBase64String(firstReplicaReceipt.Span);
        var second = Convert.ToBase64String(secondReplicaReceipt.Span);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var operation = GetOperation(document, operationKey);
            if (operation.State is "completing" or "durable")
            {
                if (!FixedBase64Equals(operation.FirstReplicaReceipt, first)
                    || !FixedBase64Equals(operation.SecondReplicaReceipt, second))
                {
                    throw new InvalidDataException(
                        "Coordinator sequence is already bound to another mailbox statement.");
                }

                return ToReservation(operationKey, operation);
            }

            if (operation.State == "terminal"
                || string.IsNullOrEmpty(operation.Disposition)
                || operation.AcceptedAtUnixSeconds == 0
                || document.NextCoordinatorSequence == ulong.MaxValue)
            {
                throw new InvalidDataException("Mailbox operation cannot begin completion.");
            }

            var sequence = document.NextCoordinatorSequence + 1;
            document = document with { NextCoordinatorSequence = sequence };
            operation = operation with
            {
                State = "completing",
                Error = "",
                CoordinatorSequence = sequence,
                FirstReplicaReceipt = first,
                SecondReplicaReceipt = second,
                Receipt = ""
            };
            document.Operations[operationKey] = operation;
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            return ToReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<MailboxClientStoreReservation> CompleteStoreAsync(
        string operationKey,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> receipt,
        CancellationToken cancellationToken) =>
        MutateAsync(
            operationKey,
            operation =>
            {
                var encoded = Convert.ToBase64String(receipt.Span);
                if (operation.State == "durable")
                {
                    if (operation.CoordinatorSequence != coordinatorSequence
                        || !FixedBase64Equals(operation.Receipt, encoded))
                    {
                        throw new InvalidDataException("Durable mailbox receipt conflicts.");
                    }

                    return operation;
                }

                if (operation.State != "completing"
                    || operation.CoordinatorSequence != coordinatorSequence
                    || string.IsNullOrEmpty(operation.FirstReplicaReceipt)
                    || string.IsNullOrEmpty(operation.SecondReplicaReceipt))
                {
                    throw new InvalidDataException("Mailbox completion reservation is missing.");
                }

                return operation with { State = "durable", Receipt = encoded, Error = "" };
            },
            cancellationToken);

    private async Task<MailboxClientStoreReservation> MutateAsync(
        string operationKey,
        Func<MailboxClientLedgerOperation, MailboxClientLedgerOperation> mutation,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var operation = mutation(GetOperation(document, operationKey));
            document.Operations[operationKey] = operation;
            ValidateDocument(document);
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            return ToReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<MailboxClientLedgerDocument> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return new(
                SchemaVersion,
                0,
                new(StringComparer.Ordinal),
                new(StringComparer.Ordinal));
        }

        if (new FileInfo(_path).Length > 768L * 1024 * 1024)
        {
            throw new InvalidDataException("Mailbox client operation ledger exceeds its bound.");
        }

        try
        {
            await using var stream = File.OpenRead(_path);
            var document = await JsonSerializer.DeserializeAsync<MailboxClientLedgerDocument>(
                stream,
                JsonOptions,
                cancellationToken).ConfigureAwait(false);
            if (document is null)
            {
                throw new InvalidDataException("Mailbox client operation ledger is empty.");
            }

            document = document with
            {
                NextCursorByMailbox = new(
                    document.NextCursorByMailbox ?? throw new InvalidDataException(
                        "Mailbox cursor authority is missing."),
                    StringComparer.Ordinal),
                Operations = new(
                    document.Operations ?? throw new InvalidDataException(
                        "Mailbox operation authority is missing."),
                    StringComparer.Ordinal)
            };
            ValidateDocument(document);
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Mailbox client operation ledger is corrupt.", exception);
        }
    }

    private void ValidateDocument(MailboxClientLedgerDocument document)
    {
        if (document.SchemaVersion != SchemaVersion
            || document.Operations.Count > _maxEntries)
        {
            throw new InvalidDataException("Mailbox client operation ledger schema is invalid.");
        }

        var cursors = new HashSet<string>(StringComparer.Ordinal);
        var sequences = new HashSet<ulong>();
        ulong maximumSequence = 0;
        foreach (var cursor in document.NextCursorByMailbox)
        {
            if (!IsCanonicalMailboxKey(cursor.Key) || cursor.Value == 0)
            {
                throw new InvalidDataException("Mailbox cursor authority is non-canonical.");
            }
        }

        foreach (var pair in document.Operations)
        {
            var operation = pair.Value;
            var mailboxKey = BuildMailboxKey(
                operation.Epoch,
                DecodeLowerHex(operation.MailboxId, 32));
            var expectedKey = BuildOperationKey(
                operation.Epoch,
                DecodeLowerHex(operation.MailboxId, 32),
                DecodeLowerHex(operation.OperationId, 16));
            _ = DecodeLowerHex(operation.RequestDigest, 32);
            _ = DecodeLowerHex(operation.EnvelopeDigest, 32);
            if (operation.ExpectedReplicaIds is null
                || operation.ExpectedReplicaIds.Length is < 2 or > 9
                || operation.ExpectedReplicaIds
                    .Select(replica => Convert.ToHexString(
                        DecodeLowerHex(replica, 32)).ToLowerInvariant())
                    .Distinct(StringComparer.Ordinal)
                    .Count() != operation.ExpectedReplicaIds.Length)
            {
                throw new InvalidDataException("Mailbox expected replica authority is invalid.");
            }
            if (!string.Equals(pair.Key, expectedKey, StringComparison.Ordinal)
                || operation.Epoch == 0
                || operation.Cursor == 0
                || operation.ExpiresAtUnixSeconds == 0
                || !document.NextCursorByMailbox.TryGetValue(mailboxKey, out var cursorAuthority)
                || cursorAuthority < operation.Cursor
                || !cursors.Add($"{mailboxKey}:{operation.Cursor:x16}"))
            {
                throw new InvalidDataException("Mailbox operation scope/cursor is invalid.");
            }

            ValidateState(operation);
            if (operation.CoordinatorSequence != 0)
            {
                maximumSequence = Math.Max(maximumSequence, operation.CoordinatorSequence);
                if (!sequences.Add(operation.CoordinatorSequence))
                {
                    throw new InvalidDataException("Mailbox coordinator sequence was reused.");
                }
            }
        }

        if (document.NextCoordinatorSequence < maximumSequence)
        {
            throw new InvalidDataException("Mailbox coordinator sequence authority was rewound.");
        }
    }

    private static void ValidateState(MailboxClientLedgerOperation operation)
    {
        var hasDisposition = operation.Disposition is "stored" or "duplicate";
        var hasAcceptedAt = operation.AcceptedAtUnixSeconds != 0;
        var hasCompletion = operation.CoordinatorSequence != 0
            && IsCanonicalBase64(
                operation.FirstReplicaReceipt,
                MailboxReceiptV2Limits.MaximumReplicaLength)
            && IsCanonicalBase64(
                operation.SecondReplicaReceipt,
                MailboxReceiptV2Limits.MaximumReplicaLength);
        var hasReceipt = IsCanonicalBase64(
            operation.Receipt,
            MailboxReceiptV2Limits.MaximumQuorumLength);
        switch (operation.State)
        {
            case "reserved":
                if (operation.CoordinatorSequence != 0 || hasReceipt || !string.IsNullOrEmpty(operation.Error)
                    || hasDisposition != hasAcceptedAt)
                {
                    throw new InvalidDataException("Reserved mailbox operation is inconsistent.");
                }
                break;
            case "retryable":
                if (!hasDisposition || !hasAcceptedAt || operation.CoordinatorSequence != 0
                    || hasReceipt || string.IsNullOrEmpty(operation.Error))
                {
                    throw new InvalidDataException("Retryable mailbox operation is inconsistent.");
                }
                break;
            case "completing":
                if (!hasDisposition || !hasAcceptedAt || !hasCompletion || hasReceipt
                    || !string.IsNullOrEmpty(operation.Error))
                {
                    throw new InvalidDataException("Completing mailbox operation is inconsistent.");
                }
                break;
            case "durable":
                if (!hasDisposition || !hasAcceptedAt || !hasCompletion || !hasReceipt
                    || !string.IsNullOrEmpty(operation.Error))
                {
                    throw new InvalidDataException("Durable mailbox operation is inconsistent.");
                }
                break;
            case "terminal":
                if (operation.CoordinatorSequence != 0 || hasCompletion || hasReceipt
                    || string.IsNullOrEmpty(operation.Error))
                {
                    throw new InvalidDataException("Terminal mailbox operation is inconsistent.");
                }
                break;
            default:
                throw new InvalidDataException("Mailbox operation state is invalid.");
        }
    }

    private static bool RemoveExpired(MailboxClientLedgerDocument document, ulong nowUnixSeconds)
    {
        var expired = document.Operations
            .Where(pair => pair.Value.ExpiresAtUnixSeconds < nowUnixSeconds)
            .Select(static pair => pair.Key)
            .ToArray();
        foreach (var key in expired)
        {
            document.Operations.Remove(key);
        }

        return expired.Length != 0;
    }

    private async Task SaveAsync(
        MailboxClientLedgerDocument document,
        CancellationToken cancellationToken)
    {
        ValidateDocument(document);
        _security.SecureDirectory(_directory);
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             8192,
                             FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(
                    stream,
                    document,
                    JsonOptions,
                    cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, _path, overwrite: true);
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

    private ulong NowUnixSeconds() => checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());

    private static MailboxClientLedgerOperation GetOperation(
        MailboxClientLedgerDocument document,
        string key) =>
        document.Operations.TryGetValue(key, out var operation)
            ? operation
            : throw new InvalidDataException("Mailbox operation reservation is missing.");

    private static MailboxClientStoreReservation ToReservation(
        string operationKey,
        MailboxClientLedgerOperation operation) =>
        new(
            operationKey,
            operation.Epoch,
            DecodeLowerHex(operation.MailboxId, 32),
            DecodeLowerHex(operation.OperationId, 16),
            DecodeLowerHex(operation.RequestDigest, 32),
            DecodeLowerHex(operation.EnvelopeDigest, 32),
            operation.ExpectedReplicaIds
                .Select(static replica =>
                    (ReadOnlyMemory<byte>)DecodeLowerHex(replica, 32))
                .ToArray(),
            operation.Cursor,
            operation.ExpiresAtUnixSeconds,
            ParseState(operation.State),
            ParseDisposition(operation.Disposition),
            operation.AcceptedAtUnixSeconds,
            operation.Error,
            operation.CoordinatorSequence == 0
                ? null
                : new(
                    operation.CoordinatorSequence,
                    Convert.FromBase64String(operation.FirstReplicaReceipt),
                    Convert.FromBase64String(operation.SecondReplicaReceipt)),
            string.IsNullOrEmpty(operation.Receipt)
                ? ReadOnlyMemory<byte>.Empty
                : Convert.FromBase64String(operation.Receipt));

    public static string BuildOperationKey(
        ulong epoch,
        ReadOnlySpan<byte> mailboxId,
        ReadOnlySpan<byte> operationId) =>
        $"{epoch:x16}:{ToLowerHex(mailboxId, 32, nameof(mailboxId))}:" +
        $"{ToLowerHex(operationId, 16, nameof(operationId))}";

    private static string BuildMailboxKey(ulong epoch, ReadOnlySpan<byte> mailboxId) =>
        $"{epoch:x16}:{ToLowerHex(mailboxId, 32, nameof(mailboxId))}";

    private static bool IsCanonicalMailboxKey(string value)
    {
        var parts = value.Split(':');
        return parts.Length == 2
            && ulong.TryParse(
                parts[0],
                System.Globalization.NumberStyles.HexNumber,
                null,
                out var epoch)
            && epoch != 0
            && parts[0].Length == 16
            && IsLowerHex(parts[0])
            && IsLowerHex(parts[1], 64);
    }

    private static string ToLowerHex(ReadOnlySpan<byte> value, int length, string parameter)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"Expected {length} nonzero bytes.", parameter);
        }

        return Convert.ToHexString(value).ToLowerInvariant();
    }

    private static byte[] DecodeLowerHex(string value, int length)
    {
        if (!IsLowerHex(value, length * 2))
        {
            throw new InvalidDataException("Mailbox ledger hex field is non-canonical.");
        }

        var decoded = Convert.FromHexString(value);
        if (decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidDataException("Mailbox ledger identifiers must be nonzero.");
        }

        return decoded;
    }

    private static bool IsLowerHex(string value, int? length = null) =>
        (length is null || value.Length == length)
        && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCanonicalBase64(string value, int maximumBytes = int.MaxValue)
    {
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        try
        {
            var decoded = Convert.FromBase64String(value);
            return decoded.Length is > 0
                && decoded.Length <= maximumBytes
                && string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool FixedHexEquals(string left, string right) =>
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left),
            Convert.FromHexString(right));

    private static bool FixedBase64Equals(string left, string right) =>
        IsCanonicalBase64(left, MailboxReceiptV2Limits.MaximumQuorumLength)
        && IsCanonicalBase64(right, MailboxReceiptV2Limits.MaximumQuorumLength)
        && CryptographicOperations.FixedTimeEquals(
            Convert.FromBase64String(left),
            Convert.FromBase64String(right));

    private static string CanonicalError(string error) =>
        !string.IsNullOrWhiteSpace(error)
        && error.Length <= 128
        && error.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')
            ? error
            : throw new ArgumentException("Mailbox ledger error is non-canonical.", nameof(error));

    private static string DispositionName(MailboxReplicaDisposition disposition) =>
        disposition == MailboxReplicaDisposition.Stored ? "stored" : "duplicate";

    private static MailboxReplicaDisposition? ParseDisposition(string disposition) =>
        disposition switch
        {
            "" => null,
            "stored" => MailboxReplicaDisposition.Stored,
            "duplicate" => MailboxReplicaDisposition.Duplicate,
            _ => throw new InvalidDataException("Mailbox disposition is invalid.")
        };

    private static MailboxClientLedgerState ParseState(string state) =>
        state switch
        {
            "reserved" => MailboxClientLedgerState.Reserved,
            "retryable" => MailboxClientLedgerState.Retryable,
            "completing" => MailboxClientLedgerState.Completing,
            "durable" => MailboxClientLedgerState.Durable,
            "terminal" => MailboxClientLedgerState.Terminal,
            _ => throw new InvalidDataException("Mailbox state is invalid.")
        };
}

public sealed class MailboxClientOperationConflictException : Exception;

public sealed class MailboxClientLedgerCapacityException : Exception;
