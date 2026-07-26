using System.Text.Json;

namespace XNode.Core.Mailbox.Client;

public sealed record MailboxClientStoreReservation(
    ulong Cursor,
    bool IsNew,
    ReadOnlyMemory<byte> CachedReceipt);

internal sealed record MailboxClientLedgerDocument(
    ulong NextCursor,
    Dictionary<string, MailboxClientLedgerOperation> Operations);

internal sealed record MailboxClientLedgerOperation(
    string RequestDigest,
    ulong Cursor,
    string MailboxId,
    string EnvelopeDigest,
    string State,
    string Receipt);

public sealed class MailboxClientOperationLedger
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _path;
    private readonly int _maxEntries;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public MailboxClientOperationLedger(
        string dataDirectory,
        MailboxClientAdapterOptions options,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        options.Validate();
        _directory = Path.Combine(dataDirectory, options.DirectoryName);
        _path = Path.Combine(_directory, "operations.json");
        _maxEntries = options.MaxOperationEntries;
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        _security.SecureDirectory(_directory);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _ = await LoadAsync(cancellationToken).ConfigureAwait(false);
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
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> requestDigest,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> envelopeDigest,
        CancellationToken cancellationToken)
    {
        var operationKey = Convert.ToHexString(operationId.Span).ToLowerInvariant();
        var requestKey = Convert.ToHexString(requestDigest.Span).ToLowerInvariant();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (document.Operations.TryGetValue(operationKey, out var existing))
            {
                if (!string.Equals(existing.RequestDigest, requestKey, StringComparison.Ordinal))
                {
                    throw new MailboxClientOperationConflictException();
                }

                return new MailboxClientStoreReservation(
                    existing.Cursor,
                    false,
                    string.IsNullOrEmpty(existing.Receipt)
                        ? ReadOnlyMemory<byte>.Empty
                        : Convert.FromBase64String(existing.Receipt));
            }

            if (document.Operations.Count >= _maxEntries || document.NextCursor == ulong.MaxValue)
            {
                throw new MailboxClientLedgerCapacityException();
            }

            var cursor = document.NextCursor + 1;
            document.Operations.Add(operationKey, new MailboxClientLedgerOperation(
                requestKey,
                cursor,
                Convert.ToHexString(mailboxId.Span).ToLowerInvariant(),
                Convert.ToHexString(envelopeDigest.Span).ToLowerInvariant(),
                "reserved",
                ""));
            await SaveAsync(document with { NextCursor = cursor }, cancellationToken).ConfigureAwait(false);
            return new MailboxClientStoreReservation(cursor, true, ReadOnlyMemory<byte>.Empty);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task CompleteStoreAsync(
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> receipt,
        CancellationToken cancellationToken)
    {
        var key = Convert.ToHexString(operationId.Span).ToLowerInvariant();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            if (!document.Operations.TryGetValue(key, out var operation))
            {
                throw new InvalidDataException("Mailbox operation reservation is missing.");
            }

            document.Operations[key] = operation with
            {
                State = "durable",
                Receipt = Convert.ToBase64String(receipt.Span)
            };
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
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
            return new MailboxClientLedgerDocument(0, new(StringComparer.Ordinal));
        }

        try
        {
            await using var stream = File.OpenRead(_path);
            var document = await JsonSerializer.DeserializeAsync<MailboxClientLedgerDocument>(
                stream,
                JsonOptions,
                cancellationToken).ConfigureAwait(false);
            if (document is null
                || document.Operations is null
                || document.Operations.Count > _maxEntries
                || document.Operations.Values.Any(static operation =>
                    operation.Cursor == 0
                    || operation.RequestDigest.Length != 64
                    || operation.MailboxId.Length != 64
                    || operation.EnvelopeDigest.Length != 64
                    || operation.State is not ("reserved" or "durable")))
            {
                throw new InvalidDataException("Mailbox client operation ledger is invalid.");
            }

            return document with
            {
                Operations = new Dictionary<string, MailboxClientLedgerOperation>(
                    document.Operations,
                    StringComparer.Ordinal)
            };
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("Mailbox client operation ledger is corrupt.", exception);
        }
    }

    private async Task SaveAsync(
        MailboxClientLedgerDocument document,
        CancellationToken cancellationToken)
    {
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
}

public sealed class MailboxClientOperationConflictException : Exception;

public sealed class MailboxClientLedgerCapacityException : Exception;
