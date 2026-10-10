using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

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
    ReadOnlyMemory<byte> BlobDigest,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    IReadOnlyList<ReadOnlyMemory<byte>> ExpectedReplicaIds,
    ulong Cursor,
    ulong ExpiresAtUnixSeconds,
    MailboxClientLedgerState State,
    MailboxReplicaDisposition? Disposition,
    ulong AcceptedAtUnixSeconds,
    string Error,
    MailboxClientCompletionReservation? Completion,
    ReadOnlyMemory<byte> CachedReceipt)
{
    internal ReadOnlyMemory<byte> CanonicalPeerRequest { get; init; }
}

internal sealed class MailboxClientLedgerDocument
{
    public MailboxClientLedgerDocument(
        int schemaVersion,
        ulong nextCoordinatorSequence,
        ulong retiredCursorFloor,
        Dictionary<string, ulong> nextCursorByMailbox,
        Dictionary<string, MailboxClientLedgerOperation> operations,
        Dictionary<string, MailboxClientLedgerAckOperation> ackOperations,
        Dictionary<string, MailboxCurrentClientReplayFloor> clientReplayFloors)
    {
        SchemaVersion = schemaVersion;
        NextCoordinatorSequence = nextCoordinatorSequence;
        RetiredCursorFloor = retiredCursorFloor;
        NextCursorByMailbox = nextCursorByMailbox;
        Operations = operations;
        AckOperations = ackOperations;
        ClientReplayFloors = clientReplayFloors;
    }

    public int SchemaVersion { get; set; }
    public ulong NextCoordinatorSequence { get; set; }
    public ulong RetiredCursorFloor { get; set; }
    public Dictionary<string, ulong> NextCursorByMailbox { get; set; }
    public Dictionary<string, MailboxClientLedgerOperation> Operations { get; set; }
    public Dictionary<string, MailboxClientLedgerAckOperation> AckOperations { get; set; }
    [JsonRequired]
    public Dictionary<string, MailboxCurrentClientReplayFloor> ClientReplayFloors { get; set; }
}

internal sealed record MailboxClientLedgerOperation(
    ulong Epoch,
    string MailboxId,
    string OperationId,
    string RequestDigest,
    string EnvelopeDigest,
    string BlobDigest,
    string PlacementCommitment,
    string MembershipCommitment,
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
    string Receipt,
    bool Tombstoned,
    ulong TombstonedAtUnixSeconds,
    bool BlobCleaned,
    string PeerRequest);

public sealed partial class MailboxClientOperationLedger : IDisposable
{
    private const int SchemaVersion = 7;
    internal const long MaximumDocumentBytes = 768L * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _path;
    private readonly int _maxEntries;
    private readonly int _maxCursorAuthorities;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly IClock _clock;
    private readonly IMailboxOperationCustody? _currentCustody;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly FileStream _directoryLease;
    private readonly object _lifecycleGate = new();
    private int _disposed;
    private int _adapterClaimed;

    public MailboxClientOperationLedger(
        string dataDirectory,
        MailboxClientAdapterOptions options,
        IClock? clock = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
        : this(dataDirectory, options, null, clock, security, durability) { }

    internal MailboxClientOperationLedger(string dataDirectory, MailboxClientAdapterOptions options,
        IMailboxOperationCustody? currentCustody, IClock? clock = null,
        IMailboxStorageSecurity? security = null, IMailboxDurabilityBarrier? durability = null)
    {
        options.Validate();
        _directory = Path.Combine(dataDirectory, options.DirectoryName);
        _path = Path.Combine(_directory, "operations.json");
        _maxEntries = options.MaxOperationEntries;
        _maxCursorAuthorities = options.MaxCursorAuthorities;
        _clock = clock ?? new SystemClock();
        _currentCustody = currentCustody;
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
        _security.SecureDirectory(_directory);
        try
        {
            _directoryLease = new FileStream(
                Path.Combine(_directory, ".adapter.lock"),
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                "Another mailbox client ledger owns this directory.",
                exception);
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (_currentCustody is not null)
            throw new InvalidOperationException("Current operation custody requires live native host initialization.");
        _security.SecureDirectory(_directory);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            // Current exact Store/ACK custody is not wall-clock collectible.
            // Even reading UTC here breaks restart on the current-only lane;
            // its retention/retirement owner must provide a protected fence.
            var hasNeutralWork = document.Operations.Values.Any(operation => operation.PeerRequest.Length == 0)
                || document.AckOperations.Values.Any(operation => operation.Items.Any(item => item.PeerRequest.Length == 0));
            var changed = hasNeutralWork && RemoveExpiredAndCompact(document, NowUnixSeconds());
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

    public IDisposable ClaimAdapter()
    {
        lock (_lifecycleGate)
        {
            ThrowIfDisposed();
            if (_adapterClaimed != 0)
            {
                throw new InvalidOperationException(
                    "A mailbox client adapter already owns this ledger.");
            }

            _adapterClaimed = 1;
            return new AdapterClaim(this);
        }
    }

    public Task<MailboxClientStoreReservation> ReserveStoreAsync(
        ulong epoch,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> requestDigest,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> envelopeDigest,
        ReadOnlyMemory<byte> blobDigest,
        ReadOnlyMemory<byte> placementCommitment,
        ReadOnlyMemory<byte> membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken) => ReserveStoreCoreAsync(epoch, operationId, requestDigest,
            mailboxId, envelopeDigest, blobDigest, placementCommitment, membershipCommitment,
            expectedReplicaIds, expiresAtUnixSeconds, cancellationToken);

    internal Task<MailboxClientStoreReservation> ReserveCurrentStoreAsync(
        MailboxEncryptedEnvelope envelope, ReadOnlyMemory<byte> membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> selectedReplicaIds, MailboxCurrentOperationLease lease,
        Func<ulong, ulong, ReadOnlyMemory<byte>> author, VerifiedMailboxHostAuthorityV2 host,
        CancellationToken token, bool requireExisting = false)
    {
        ArgumentNullException.ThrowIfNull(envelope); ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(author); lease.RequireActive();
        ArgumentNullException.ThrowIfNull(host);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        return ReserveStoreCoreAsync(envelope.Epoch, envelope.OperationId, binding.RequestDigest,
            envelope.MailboxId.Bytes, envelope.DeduplicationDigest, SHA256.HashData(binding.CanonicalRequest.Span),
            MailboxPlacementCommitment.Compute(envelope.PlacementId), membershipCommitment,
            selectedReplicaIds, envelope.ExpiresAtUnixSeconds, token, lease, author, requireExisting, host);
    }

    private async Task<MailboxClientStoreReservation> ReserveStoreCoreAsync(
        ulong epoch, ReadOnlyMemory<byte> operationId, ReadOnlyMemory<byte> requestDigest,
        ReadOnlyMemory<byte> mailboxId, ReadOnlyMemory<byte> envelopeDigest, ReadOnlyMemory<byte> blobDigest,
        ReadOnlyMemory<byte> placementCommitment, ReadOnlyMemory<byte> membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds, ulong expiresAtUnixSeconds,
        CancellationToken cancellationToken, MailboxCurrentOperationLease? lease = null,
        Func<ulong, ulong, ReadOnlyMemory<byte>>? author = null, bool requireExisting = false,
        VerifiedMailboxHostAuthorityV2? host = null)
    {
        ThrowIfDisposed();
        var operationKey = BuildOperationKey(epoch, mailboxId.Span, operationId.Span);
        var mailboxKey = BuildMailboxKey(epoch, mailboxId.Span);
        var mailboxHex = ToLowerHex(mailboxId.Span, 32, nameof(mailboxId));
        var requestKey = ToLowerHex(requestDigest.Span, 32, nameof(requestDigest));
        var envelopeKey = ToLowerHex(envelopeDigest.Span, 32, nameof(envelopeDigest));
        var blobKey = ToLowerHex(blobDigest.Span, 32, nameof(blobDigest));
        var placementKey = ToLowerHex(
            placementCommitment.Span,
            32,
            nameof(placementCommitment));
        var membershipKey = ToLowerHex(
            membershipCommitment.Span,
            32,
            nameof(membershipCommitment));
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
            if (lease is not null) _ = await lease.CheckAsync(cancellationToken).ConfigureAwait(false);
            var document = await LoadAsync(cancellationToken, lease).ConfigureAwait(false);
            // Current requests never collect other operations using host UTC or
            // their short-lived grant. Protected retention/GC is a separate owner.
            var changed = lease is null && RemoveExpiredAndCompact(document, NowUnixSeconds());
            if (document.Operations.TryGetValue(operationKey, out var existing))
            {
                if (!FixedHexEquals(existing.RequestDigest, requestKey))
                {
                    throw new MailboxClientOperationConflictException();
                }

                if (lease is not null)
                {
                    if (string.IsNullOrEmpty(existing.PeerRequest))
                        throw new InvalidDataException("Current Store intent has no exact peer request.");
                    _ = await lease.CheckAsync(cancellationToken).ConfigureAwait(false);
                }

                if (changed)
                {
                    await SaveAsync(document, cancellationToken).ConfigureAwait(false);
                }

                return ToReservation(operationKey, existing);
            }

            if (requireExisting)
                throw new InvalidDataException("Known current Store replay has lost its exact peer intent.");

            if (lease is not null)
            {
                // Across independently signed grants, not merely a MAU3 counter.
                // An intent can exist before any local mutation, so the mutation
                // index alone cannot establish a completed Store prefix.
                await RequireCurrentStorePrefixAsync(document, epoch, mailboxHex, placementKey, membershipKey,
                    host!, lease, cancellationToken).ConfigureAwait(false);
            }

            if (LedgerEntryCost(document) >= _maxEntries)
            {
                throw new MailboxClientLedgerCapacityException();
            }

            if (!document.NextCursorByMailbox.ContainsKey(mailboxKey)
                && document.NextCursorByMailbox.Count >= _maxCursorAuthorities)
            {
                CompactUnusedCursorAuthorities(document);
                if (document.NextCursorByMailbox.Count >= _maxCursorAuthorities)
                {
                    throw new MailboxClientLedgerCapacityException();
                }
            }

            document.NextCursorByMailbox.TryGetValue(mailboxKey, out var priorCursor);
            priorCursor = Math.Max(priorCursor, document.RetiredCursorFloor);
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
                blobKey,
                placementKey,
                membershipKey,
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
                "",
                false,
                0,
                false,
                "");
            if (lease is not null)
            {
                var upper = await lease.CheckAsync(cancellationToken).ConfigureAwait(false);
                var exactPeer = author!(cursor, upper);
                var parsed = MailboxPeerWireV2Codec.Decode(exactPeer.Span);
                var canonical = MailboxPeerWireV2Codec.Encode(parsed);
                if (!canonical.AsSpan().SequenceEqual(exactPeer.Span))
                    throw new InvalidDataException("Current Store producer is not canonical.");
                operation = operation with { PeerRequest = Convert.ToBase64String(canonical) };
            }
            document.Operations.Add(operationKey, operation);
            await SaveAsync(document, cancellationToken, lease).ConfigureAwait(false);
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
        ThrowIfDisposed();
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

            var sequence = ++document.NextCoordinatorSequence;
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
        ThrowIfDisposed();
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

    private async Task<MailboxClientLedgerDocument> LoadAsync(CancellationToken cancellationToken,
        MailboxCurrentOperationLease? lease = null)
    {
        if (_currentCustody is not null || lease is not null)
        {
            if (_currentCustody is null || lease is null)
                throw new InvalidOperationException("Current operation custody and live host lease are required together.");
            await _currentCustody.VerifyAsync(_path, lease, ValidateFileAsync, cancellationToken).ConfigureAwait(false);
        }
        return await ReadDocumentAsync(_path, cancellationToken, allowMissing: _currentCustody is null,
            authenticateSnapshot: _currentCustody is not null).ConfigureAwait(false);
    }

    private async Task ValidateFileAsync(string path, CancellationToken token) =>
        _ = await ReadDocumentAsync(path, token, allowMissing: false).ConfigureAwait(false);

    private async Task<MailboxClientLedgerDocument> ReadDocumentAsync(string path, CancellationToken cancellationToken,
        bool allowMissing, bool authenticateSnapshot = false)
    {
        if (!File.Exists(path))
        {
            if (!allowMissing) throw new InvalidDataException("Current operation document is missing.");
            return new(
                SchemaVersion,
                0,
                0,
                new(StringComparer.Ordinal),
                new(StringComparer.Ordinal),
                new(StringComparer.Ordinal),
                new(StringComparer.Ordinal));
        }

        if (new FileInfo(path).Length > MaximumDocumentBytes)
        {
            throw new InvalidDataException("Mailbox client operation ledger exceeds its bound.");
        }

        try
        {
            await using var stream = File.OpenRead(path);
            var length = stream.Length;
            if (length is < 1 or > MaximumDocumentBytes)
                throw new InvalidDataException("Mailbox client operation snapshot exceeds its bound.");
            // Hash and parse the same opened snapshot, not a path verified before
            // an external authority callback and reopened without authentication.
            using var algorithm = authenticateSnapshot ? SHA256.Create() : null;
            using var hashing = authenticateSnapshot ? new CryptoStream(stream, algorithm!, CryptoStreamMode.Read, leaveOpen: true) : null;
            var document = await JsonSerializer.DeserializeAsync<MailboxClientLedgerDocument>(
                hashing ?? (Stream)stream,
                JsonOptions,
                cancellationToken).ConfigureAwait(false);
            if (document is null)
            {
                throw new InvalidDataException("Mailbox client operation ledger is empty.");
            }
            if (authenticateSnapshot)
            {
                if (await hashing!.ReadAsync(new byte[1], cancellationToken).ConfigureAwait(false) != 0 ||
                    stream.Length != length || stream.Position != length)
                    throw new InvalidDataException("Mailbox operation snapshot changed while reading.");
                _currentCustody!.RequireDocumentSnapshot(path, algorithm!.Hash ??
                    throw new InvalidDataException("Mailbox operation snapshot hashing is incomplete."), length);
            }

            document.NextCursorByMailbox = new(
                document.NextCursorByMailbox ?? throw new InvalidDataException(
                    "Mailbox cursor authority is missing."),
                StringComparer.Ordinal);
            document.Operations = new(
                document.Operations ?? throw new InvalidDataException(
                    "Mailbox operation authority is missing."),
                StringComparer.Ordinal);
            document.AckOperations = new(
                document.AckOperations ?? throw new InvalidDataException("Mailbox ack intent authority is missing."),
                StringComparer.Ordinal);
            document.ClientReplayFloors = new(
                document.ClientReplayFloors ?? throw new InvalidDataException("Mailbox client replay floors are missing."),
                StringComparer.Ordinal);
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
            || LedgerEntryCost(document) > _maxEntries
            || document.ClientReplayFloors.Count > _maxEntries
            || document.NextCursorByMailbox.Count > _maxCursorAuthorities)
        {
            throw new InvalidDataException("Mailbox client operation ledger schema is invalid.");
        }
        foreach (var pair in document.ClientReplayFloors)
        {
            _ = DecodeLowerHex(pair.Key, 32);
            var floor = pair.Value ?? throw new InvalidDataException("Mailbox client replay floor is null.");
            _ = DecodeLowerHex(floor.ClaimDigest, 32);
            if (floor.HighestCounter == 0 || floor.CanonicalOutcomeDigest is null)
                throw new InvalidDataException("Mailbox client replay floor is malformed.");
            if (floor.CanonicalOutcomeDigest.Length != 0) _ = DecodeLowerHex(floor.CanonicalOutcomeDigest, 32);
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
            var operation = pair.Value
                ?? throw new InvalidDataException("Mailbox operation authority contains null.");
            var mailboxKey = BuildMailboxKey(
                operation.Epoch,
                DecodeLowerHex(operation.MailboxId, 32));
            var expectedKey = BuildOperationKey(
                operation.Epoch,
                DecodeLowerHex(operation.MailboxId, 32),
                DecodeLowerHex(operation.OperationId, 16));
            _ = DecodeLowerHex(operation.RequestDigest, 32);
            _ = DecodeLowerHex(operation.EnvelopeDigest, 32);
            _ = DecodeLowerHex(operation.BlobDigest, 32);
            _ = DecodeLowerHex(operation.PlacementCommitment, 32);
            _ = DecodeLowerHex(operation.MembershipCommitment, 32);
            if (operation.PeerRequest is null)
                throw new InvalidDataException("Mailbox exact peer request field is missing.");
            if (operation.ExpectedReplicaIds is null
                || operation.ExpectedReplicaIds.Length is < 2 or > 9
                || operation.ExpectedReplicaIds.Any(static replica => replica is null)
                || operation.ExpectedReplicaIds
                    .Select(replica => Convert.ToHexString(
                        DecodeLowerHex(replica, 32)).ToLowerInvariant())
                    .Distinct(StringComparer.Ordinal)
                    .Count() != operation.ExpectedReplicaIds.Length)
            {
                throw new InvalidDataException("Mailbox expected replica authority is invalid.");
            }
            if (operation.PeerRequest.Length != 0)
                ValidatePeerIntent(operation);
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
            if (operation.Tombstoned != (operation.TombstonedAtUnixSeconds != 0)
                || operation.BlobCleaned && !operation.Tombstoned
                || operation.Tombstoned
                && (operation.State != "durable"
                    || operation.TombstonedAtUnixSeconds < operation.AcceptedAtUnixSeconds
                    || operation.TombstonedAtUnixSeconds >= operation.ExpiresAtUnixSeconds))
            {
                throw new InvalidDataException("Mailbox tombstone state is inconsistent.");
            }
            if (operation.CoordinatorSequence != 0)
            {
                maximumSequence = Math.Max(maximumSequence, operation.CoordinatorSequence);
                if (!sequences.Add(operation.CoordinatorSequence))
                {
                    throw new InvalidDataException("Mailbox coordinator sequence was reused.");
                }
            }
        }

        ValidateAckOperations(document, sequences, ref maximumSequence);
        if (document.NextCoordinatorSequence < maximumSequence)
        {
            throw new InvalidDataException("Mailbox coordinator sequence authority was rewound.");
        }
    }

    private static void ValidateState(MailboxClientLedgerOperation operation)
    {
        if (operation.State is null
            || operation.Disposition is null
            || operation.Error is null
            || operation.FirstReplicaReceipt is null
            || operation.SecondReplicaReceipt is null
            || operation.Receipt is null)
        {
            throw new InvalidDataException("Mailbox operation state contains null fields.");
        }

        var dispositionEmpty = operation.Disposition.Length == 0;
        var hasDisposition = operation.Disposition is "stored" or "duplicate";
        var hasAcceptedAt = operation.AcceptedAtUnixSeconds != 0;
        if (!dispositionEmpty && !hasDisposition
            || hasDisposition != hasAcceptedAt)
        {
            throw new InvalidDataException("Mailbox disposition/time pairing is invalid.");
        }

        if (operation.Error.Length != 0)
        {
            try
            {
                _ = CanonicalError(operation.Error);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Mailbox ledger error is non-canonical.", exception);
            }
        }

        var rawCompletionEmpty = operation.FirstReplicaReceipt.Length == 0
            && operation.SecondReplicaReceipt.Length == 0;
        var hasCompletion = operation.CoordinatorSequence != 0
            && IsCanonicalBase64(
                operation.FirstReplicaReceipt,
                MailboxReceiptV2Limits.MaximumReplicaLength)
            && IsCanonicalBase64(
                operation.SecondReplicaReceipt,
                MailboxReceiptV2Limits.MaximumReplicaLength);
        var rawReceiptEmpty = operation.Receipt.Length == 0;
        var hasReceipt = IsCanonicalBase64(
            operation.Receipt,
            MailboxReceiptV2Limits.MaximumQuorumLength);
        if (operation.PeerRequest.Length != 0)
        {
            if (!dispositionEmpty || hasAcceptedAt || operation.CoordinatorSequence != 0 ||
                !rawCompletionEmpty || operation.Error.Length != 0 ||
                operation.State == "reserved" && !rawReceiptEmpty ||
                operation.State == "durable" && !IsCanonicalBase64(operation.Receipt, MailboxReceiptV3Limits.MaximumQuorumLength) ||
                operation.State is not ("reserved" or "durable"))
                throw new InvalidDataException("Current Store settlement state is inconsistent.");
            if (operation.State == "durable")
                _ = MailboxReceiptV3Codec.DecodeDurableQuorum(Convert.FromBase64String(operation.Receipt));
            return;
        }
        switch (operation.State)
        {
            case "reserved":
                if (operation.CoordinatorSequence != 0 || !rawCompletionEmpty || !rawReceiptEmpty
                    || operation.Error.Length != 0)
                {
                    throw new InvalidDataException("Reserved mailbox operation is inconsistent.");
                }
                break;
            case "retryable":
                if (!hasDisposition || !hasAcceptedAt || operation.CoordinatorSequence != 0
                    || !rawCompletionEmpty || !rawReceiptEmpty || operation.Error.Length == 0)
                {
                    throw new InvalidDataException("Retryable mailbox operation is inconsistent.");
                }
                break;
            case "completing":
                if (!hasDisposition || !hasAcceptedAt || !hasCompletion || !rawReceiptEmpty
                    || operation.Error.Length != 0)
                {
                    throw new InvalidDataException("Completing mailbox operation is inconsistent.");
                }
                break;
            case "durable":
                if (!hasDisposition || !hasAcceptedAt || !hasCompletion || !hasReceipt
                    || operation.Error.Length != 0)
                {
                    throw new InvalidDataException("Durable mailbox operation is inconsistent.");
                }
                break;
            case "terminal":
                if (operation.CoordinatorSequence != 0 || !rawCompletionEmpty || hasCompletion
                    || !rawReceiptEmpty || operation.Error.Length == 0)
                {
                    throw new InvalidDataException("Terminal mailbox operation is inconsistent.");
                }
                break;
            default:
                throw new InvalidDataException("Mailbox operation state is invalid.");
        }
    }

    private static bool RemoveExpiredAndCompact(
        MailboxClientLedgerDocument document,
        ulong nowUnixSeconds)
    {
        // Remove dependent ACK replay authorities first, then retain every store
        // referenced by a surviving multi-item ACK until its latest item expires.
        // This preserves exact cached-replay semantics across staggered item TTLs.
        var expiredAcks = RemoveExpiredAckOperations(document, nowUnixSeconds);
        var ackTargets = document.AckOperations.Values
            .SelectMany(operation => operation.Items.Select(item => (
                operation.Epoch,
                operation.MailboxId,
                item.Cursor)))
            .ToHashSet();
        var expired = document.Operations
            .Where(pair =>
                pair.Value.PeerRequest.Length == 0
                && pair.Value.ExpiresAtUnixSeconds <= nowUnixSeconds
                && !ackTargets.Contains((
                    pair.Value.Epoch,
                    pair.Value.MailboxId,
                    pair.Value.Cursor))
                && (!pair.Value.Tombstoned || pair.Value.BlobCleaned))
            .Select(static pair => pair.Key)
            .ToArray();
        foreach (var key in expired)
        {
            document.Operations.Remove(key);
        }

        var compacted = CompactUnusedCursorAuthorities(document);
        return expired.Length != 0 || expiredAcks || compacted;
    }

    private static bool CompactUnusedCursorAuthorities(MailboxClientLedgerDocument document)
    {
        var liveScopes = document.Operations.Values
            .Select(operation => BuildMailboxKey(
                operation.Epoch,
                DecodeLowerHex(operation.MailboxId, 32)))
            .ToHashSet(StringComparer.Ordinal);
        var retired = document.NextCursorByMailbox
            .Where(pair => !liveScopes.Contains(pair.Key))
            .ToArray();
        if (retired.Length == 0)
        {
            return false;
        }

        var floor = document.RetiredCursorFloor;
        foreach (var authority in retired)
        {
            floor = Math.Max(floor, authority.Value);
            document.NextCursorByMailbox.Remove(authority.Key);
        }

        document.RetiredCursorFloor = floor;
        return true;
    }

    private async Task SaveAsync(
        MailboxClientLedgerDocument document,
        CancellationToken cancellationToken,
        MailboxCurrentOperationLease? lease = null, bool enrolling = false)
    {
        if ((_currentCustody is not null && lease is null) || (lease is not null && _currentCustody is null))
            throw new InvalidOperationException("Current operation persistence requires protected custody and live host lease.");
        if (lease is not null) _ = await lease.CheckAsync(cancellationToken).ConfigureAwait(false);
        ValidateDocument(document);
        _security.SecureDirectory(_directory);
        var temporary = $"{_path}.{Guid.NewGuid():N}.tmp";
        var preservePending = false;
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
                if (stream.Length > MaximumDocumentBytes)
                    throw new MailboxClientLedgerCapacityException();
            }

            if (lease is not null) _ = await lease.CheckAsync(cancellationToken).ConfigureAwait(false);
            if (_currentCustody is not null && !enrolling)
            {
                // Prepare can fail after its durable native write. Preserve the
                // exact file; only verified startup may collect it.
                preservePending = true;
                await _currentCustody.PrepareAsync(_path, temporary, lease!, cancellationToken).ConfigureAwait(false);
            }
            await ReplaceAtomicallyAsync(temporary, cancellationToken).ConfigureAwait(false);
            _security.SecureFile(_path);
            _durability.FlushFileAndParentDirectory(_path);
            if (lease is not null) _ = await lease.CheckAsync(cancellationToken).ConfigureAwait(false);
            if (_currentCustody is not null && !enrolling)
                await _currentCustody.CommitAsync(_path, lease!, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (!preservePending && File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private async Task ReplaceAtomicallyAsync(
        string temporary,
        CancellationToken cancellationToken)
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
                && exception is IOException or UnauthorizedAccessException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(5 * attempt), cancellationToken)
                    .ConfigureAwait(false);
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
            DecodeLowerHex(operation.BlobDigest, 32),
            DecodeLowerHex(operation.PlacementCommitment, 32),
            DecodeLowerHex(operation.MembershipCommitment, 32),
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
                : Convert.FromBase64String(operation.Receipt))
        { CanonicalPeerRequest = string.IsNullOrEmpty(operation.PeerRequest) ? ReadOnlyMemory<byte>.Empty : Convert.FromBase64String(operation.PeerRequest) };

    private static void ValidatePeerIntent(MailboxClientLedgerOperation operation)
    {
        if (!IsCanonicalBase64(operation.PeerRequest, MailboxPeerWireV2Limits.MaximumRequestLength))
            throw new InvalidDataException("Mailbox exact peer request is non-canonical or oversized.");
        var peer = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(operation.PeerRequest));
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(peer.Payload.Span);
        if (peer.Operation != MailboxPeerReplicationOperation.Store || peer.Epoch != operation.Epoch ||
            peer.Cursor != operation.Cursor || peer.ExpiresAtUnixSeconds != operation.ExpiresAtUnixSeconds ||
            !FixedHexEquals(peer.OperationId.Span, operation.OperationId) ||
            !FixedHexEquals(peer.BlindedMailboxId.Span, operation.MailboxId) ||
            !FixedHexEquals(peer.PayloadDigest.Span, operation.BlobDigest) ||
            !FixedHexEquals(peer.MembershipCommitment.Span, operation.MembershipCommitment) ||
            !FixedHexEquals(peer.PlacementCommitment.Span, operation.PlacementCommitment) ||
            !FixedHexEquals(body.DeduplicationDigest.Span, operation.EnvelopeDigest) ||
            !FixedHexEquals(MailboxAuthenticatedRequestTranscript.ForStore(body).RequestDigest.Span, operation.RequestDigest) ||
            !operation.ExpectedReplicaIds.Contains(Convert.ToHexString(peer.SenderRouterId.Span).ToLowerInvariant(), StringComparer.Ordinal) ||
            !operation.ExpectedReplicaIds.Contains(Convert.ToHexString(peer.RecipientRouterId.Span).ToLowerInvariant(), StringComparer.Ordinal))
            throw new InvalidDataException("Mailbox exact peer request differs from its durable operation.");
    }

    private static bool FixedHexEquals(ReadOnlySpan<byte> bytes, string hex) =>
        CryptographicOperations.FixedTimeEquals(bytes, Convert.FromHexString(hex));

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

    private static byte[] DecodeLowerHex(string? value, int length)
    {
        if (value is null || !IsLowerHex(value, length * 2))
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

    private static bool IsLowerHex(string? value, int? length = null) =>
        value is not null
        && (length is null || value.Length == length)
        && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsCanonicalBase64(string value, int maximumBytes = int.MaxValue)
    {
        if (string.IsNullOrEmpty(value) || value.Length > ((long)maximumBytes + 2) / 3 * 4)
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

    public void Dispose()
    {
        lock (_lifecycleGate)
        {
            if (_disposed != 0)
            {
                return;
            }

            if (_adapterClaimed != 0)
            {
                throw new InvalidOperationException(
                    "Cannot release a mailbox ledger while an adapter owns it.");
            }

            _disposed = 1;
            _directoryLease.Dispose();
            _gate.Dispose();
        }
        GC.SuppressFinalize(this);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

    private sealed class AdapterClaim(MailboxClientOperationLedger owner) : IDisposable
    {
        private MailboxClientOperationLedger? _owner = owner;

        public void Dispose()
        {
            var current = Interlocked.Exchange(ref _owner, null);
            if (current is not null)
            {
                lock (current._lifecycleGate)
                {
                    current._adapterClaimed = 0;
                }
            }
        }
    }
}

public sealed class MailboxClientOperationConflictException : Exception;

public sealed class MailboxClientLedgerCapacityException : Exception;
