using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

public sealed record MailboxPeerMutationResult(
    MailboxReplicaDisposition Disposition,
    string Error = "");

public enum MailboxPeerMutationFaultPoint
{
    StoreReserved,
    TombstoneReserved,
    TombstoneBlobDeleted
}

public interface IMailboxPeerMutationFaultInjector
{
    void Inject(MailboxPeerMutationFaultPoint point);
}

/// <summary>
/// Durable local PRQ2 mutation boundary. One record owns the Store and its optional Tombstone,
/// avoiding a two-file transactional gap. Records carry protocol retirement metadata and are
/// collected only after their replay/live-state retention boundary.
/// </summary>
public sealed class MailboxPeerMutationStore : IDisposable
{
    private const int SchemaVersion = 3;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly ReplicatedMailboxOptions _options;
    private readonly ReplicatedMailboxStore _blobStore;
    private readonly IClock _clock;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly IMailboxPeerMutationFaultInjector? _faults;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly FileStream _lease;
    private readonly PriorityQueue<string, ulong> _collectionQueue = new();
    private int _recordCount;
    private int _disposed;

    public MailboxPeerMutationStore(
        string dataDirectory,
        ReplicatedMailboxOptions options,
        ReplicatedMailboxStore blobStore,
        IClock? clock = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null,
        IMailboxPeerMutationFaultInjector? faults = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        options.Validate();
        _options = options;
        _blobStore = blobStore;
        _clock = clock ?? new SystemClock();
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
        _faults = faults;
        _directory = Path.Combine(dataDirectory, options.PeerMutationDirectoryName);
        _security.SecureDirectory(_directory);
        var leasePath = Path.Combine(_directory, ".lease");
        try
        {
            _lease = new FileStream(
                leasePath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
        }
        catch (IOException exception)
        {
            throw new InvalidOperationException(
                "The PRQ2 mutation journal is already owned by another runtime.",
                exception);
        }

        try
        {
            _security.SecureFile(leasePath);
            PurgeTemporaryFiles();
            LoadAndValidateIndex();
        }
        catch
        {
            _lease.Dispose();
            throw;
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json")
                         .Order(StringComparer.Ordinal)
                         .Take(_options.MaxPeerMutationRecords))
            {
                var record = Read(path);
                if (record.State is not ("tombstone-pending" or "tombstoned"))
                {
                    continue;
                }

                _ = await _blobStore.DeleteExactAsync(
                    record.MailboxId,
                    record.BlobId,
                    cancellationToken).ConfigureAwait(false);
                if (record.State == "tombstone-pending")
                {
                    Write(path, record with { State = "tombstoned" });
                }
            }

            _ = await CollectExpiredUnderGateAsync(
                checked((ulong)_clock.UtcNow.ToUnixTimeSeconds()),
                _options.MaxPeerMutationGcBatch,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public bool TryResolveTombstonePlacement(
        MailboxPeerWireRequestV2 request,
        out BlindedPlacementId placementId)
    {
        ArgumentNullException.ThrowIfNull(request);
        placementId = default!;
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone)
        {
            return false;
        }

        _gate.Wait();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var path = StorePath(
                request.Epoch,
                request.BlindedMailboxId.Span,
                request.Payload.Span);
            if (!File.Exists(path))
            {
                return false;
            }

            var record = Read(path);
            if (!record.MatchesTombstoneTarget(request)
                || record.State == "pending"
                || record.State is "tombstone-pending" or "tombstoned"
                    && !record.MatchesTombstoneOperation(request))
            {
                return false;
            }

            placementId = new BlindedPlacementId(Convert.FromHexString(record.PlacementId));
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<MailboxPeerMutationResult> ApplyAsync(
        VerifiedMailboxPeerWireRequestV2 verified,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verified);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await CollectExpiredUnderGateAsync(
                verified.ReplayClaim.ReservedAtUnixSeconds,
                _options.MaxPeerMutationGcBatch,
                cancellationToken).ConfigureAwait(false);
            return verified.Request.Operation == MailboxPeerReplicationOperation.Store
                ? await StoreUnderGateAsync(verified, cancellationToken).ConfigureAwait(false)
                : await TombstoneUnderGateAsync(verified, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<int> CollectExpiredAsync(
        ulong nowUnixSeconds,
        int maximumRecords,
        CancellationToken cancellationToken = default)
    {
        ValidateBatch(maximumRecords);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return await CollectExpiredUnderGateAsync(
                nowUnixSeconds,
                maximumRecords,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _lease.Dispose();
            _gate.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    private async Task<MailboxPeerMutationResult> StoreUnderGateAsync(
        VerifiedMailboxPeerWireRequestV2 verified,
        CancellationToken cancellationToken)
    {
        var request = verified.Request;
        var envelope = verified.Envelope
            ?? throw new InvalidOperationException("A verified PRQ2 Store has no envelope.");
        var path = StorePath(
            request.Epoch,
            request.BlindedMailboxId.Span,
            envelope.DeduplicationDigest.Span);
        PersistedMutation record;
        var firstLogicalStore = !File.Exists(path);
        if (firstLogicalStore)
        {
            await EnsureCapacityUnderGateAsync(
                verified.ReplayClaim.ReservedAtUnixSeconds,
                cancellationToken).ConfigureAwait(false);
            record = PersistedMutation.StorePending(verified, envelope);
            Write(path, record);
            _recordCount++;
            _collectionQueue.Enqueue(path, record.RetainUntilUnixSeconds);
            _faults?.Inject(MailboxPeerMutationFaultPoint.StoreReserved);
        }
        else
        {
            record = Read(path);
            if (!record.MatchesStoreContext(request, envelope)
                || record.State is "tombstone-pending" or "tombstoned"
                || record.State == "pending"
                    && !FixedHex(record.ReplayNonce, request.ReplayNonce.Span))
            {
                return ContextConflict(MailboxReplicaDisposition.Stored, "store");
            }

            // A crash after the durable Store reservation must recreate the original Stored
            // receipt only for that exact replay identity. A later nonce is merely Duplicate.
            firstLogicalStore = FixedHex(record.ReplayNonce, request.ReplayNonce.Span);
        }

        long expiresAtUnixMs;
        try
        {
            expiresAtUnixMs = checked((long)record.ExpiresAtUnixSeconds * 1000L);
        }
        catch (OverflowException)
        {
            return new MailboxPeerMutationResult(
                MailboxReplicaDisposition.Stored,
                "mailbox-peer-expiry-overflow");
        }

        var blob = new EncryptedMailboxBlob(
            record.MailboxId,
            record.BlobId,
            expiresAtUnixMs,
            Convert.ToBase64String(request.Payload.Span));
        var stored = await _blobStore.PutPeerAsync(blob, cancellationToken).ConfigureAwait(false);
        if (stored.Disposition == MailboxPutDisposition.Rejected)
        {
            return new MailboxPeerMutationResult(
                MailboxReplicaDisposition.Stored,
                stored.Error);
        }

        if (record.State == "pending")
        {
            Write(path, record with { State = "completed" });
        }

        return new MailboxPeerMutationResult(
            firstLogicalStore
                ? MailboxReplicaDisposition.Stored
                : MailboxReplicaDisposition.Duplicate);
    }

    private async Task<MailboxPeerMutationResult> TombstoneUnderGateAsync(
        VerifiedMailboxPeerWireRequestV2 verified,
        CancellationToken cancellationToken)
    {
        var request = verified.Request;
        var path = StorePath(
            request.Epoch,
            request.BlindedMailboxId.Span,
            request.Payload.Span);
        if (!File.Exists(path))
        {
            return ContextConflict(MailboxReplicaDisposition.Tombstone, "tombstone-target-missing");
        }

        var record = Read(path);
        if (!record.MatchesTombstoneTarget(request)
            || record.State == "pending"
            || record.EpochExpiresAtUnixSeconds
                != verified.ReplayClaim.EpochExpiresAtUnixSeconds
            || record.RetainUntilUnixSeconds
                != verified.ReplayClaim.RetainUntilUnixSeconds
            || record.State is "tombstone-pending" or "tombstoned"
                && !record.MatchesTombstoneOperation(request))
        {
            return ContextConflict(MailboxReplicaDisposition.Tombstone, "tombstone");
        }

        if (record.State == "completed")
        {
            record = record.BeginTombstone(verified);
            Write(path, record);
            _collectionQueue.Enqueue(path, record.RetainUntilUnixSeconds);
            _faults?.Inject(MailboxPeerMutationFaultPoint.TombstoneReserved);
        }

        _ = await _blobStore.DeleteExactAsync(
            record.MailboxId,
            record.BlobId,
            cancellationToken).ConfigureAwait(false);
        _faults?.Inject(MailboxPeerMutationFaultPoint.TombstoneBlobDeleted);
        if (record.State == "tombstone-pending")
        {
            Write(path, record with { State = "tombstoned" });
        }

        return new MailboxPeerMutationResult(MailboxReplicaDisposition.Tombstone);
    }

    private async Task EnsureCapacityUnderGateAsync(
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (_recordCount < _options.MaxPeerMutationRecords)
        {
            return;
        }

        _ = await CollectExpiredUnderGateAsync(
            nowUnixSeconds,
            _options.MaxPeerMutationGcBatch,
            cancellationToken).ConfigureAwait(false);
        if (_recordCount >= _options.MaxPeerMutationRecords)
        {
            throw new MailboxPeerMutationCapacityException();
        }
    }

    private async Task<int> CollectExpiredUnderGateAsync(
        ulong nowUnixSeconds,
        int maximumRecords,
        CancellationToken cancellationToken)
    {
        ValidateBatch(maximumRecords);
        var removed = 0;
        var examined = 0;
        while (examined < maximumRecords
               && _collectionQueue.TryPeek(out _, out var retainUntil)
               && retainUntil <= nowUnixSeconds)
        {
            var path = _collectionQueue.Dequeue();
            examined++;
            if (!File.Exists(path))
            {
                continue;
            }

            var record = Read(path);
            if (record.RetainUntilUnixSeconds > nowUnixSeconds)
            {
                _collectionQueue.Enqueue(path, record.RetainUntilUnixSeconds);
                continue;
            }

            _ = await _blobStore.DeleteExactAsync(
                record.MailboxId,
                record.BlobId,
                cancellationToken).ConfigureAwait(false);
            _durability.DeleteFile(path);
            _recordCount--;
            removed++;
        }

        return removed;
    }

    private void LoadAndValidateIndex()
    {
        var records = Directory.EnumerateFiles(_directory, "*.json")
            .Take(_options.MaxPeerMutationRecords + 1)
            .ToArray();
        if (records.Length > _options.MaxPeerMutationRecords)
        {
            throw new InvalidOperationException("The PRQ2 mutation journal capacity is exceeded.");
        }

        foreach (var path in records)
        {
            var record = Read(path);
            if (!string.Equals(
                    Path.GetFileNameWithoutExtension(path),
                    RecordKey(record.Epoch, record.MailboxId, record.EnvelopeDigest),
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("A PRQ2 mutation record filename is inconsistent.");
            }

            _recordCount++;
            _collectionQueue.Enqueue(path, record.RetainUntilUnixSeconds);
        }
    }

    private PersistedMutation Read(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Length is <= 0 or > 16 * 1024)
            {
                throw new InvalidDataException("A PRQ2 mutation record is not bounded.");
            }

            using var stream = File.OpenRead(path);
            var record = JsonSerializer.Deserialize<PersistedMutation>(stream, JsonOptions)
                ?? throw new InvalidDataException("A PRQ2 mutation record is empty.");
            record.Validate();
            return record;
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or FormatException)
        {
            throw new InvalidDataException(
                "The PRQ2 mutation journal is corrupt and cannot be opened.",
                exception);
        }
    }

    private void Write(string finalPath, PersistedMutation record)
    {
        record.Validate();
        var temporaryPath = $"{finalPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, record, JsonOptions);
                stream.Flush(flushToDisk: true);
            }

            _security.SecureFile(temporaryPath);
            _durability.ReplaceFile(temporaryPath, finalPath);
            _security.SecureFile(finalPath);
            _durability.FlushFileAndParentDirectory(finalPath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void PurgeTemporaryFiles()
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

    private string StorePath(ulong epoch, ReadOnlySpan<byte> mailbox, ReadOnlySpan<byte> digest) =>
        Path.Combine(_directory, $"{RecordKey(epoch, mailbox, digest)}.json");

    private static string RecordKey(
        ulong epoch,
        string mailbox,
        string digest) =>
        RecordKey(epoch, Convert.FromHexString(mailbox), Convert.FromHexString(digest));

    private static string RecordKey(
        ulong epoch,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> digest)
    {
        var bytes = new byte[8 + 64];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, epoch);
        mailbox.CopyTo(bytes.AsSpan(8));
        digest.CopyTo(bytes.AsSpan(40));
        return Hex(SHA256.HashData(bytes));
    }

    private static MailboxPeerMutationResult ContextConflict(
        MailboxReplicaDisposition disposition,
        string kind) =>
        new(disposition, $"mailbox-peer-{kind}-context-conflict");

    private static void ValidateBatch(int maximumRecords)
    {
        if (maximumRecords is <= 0 or > 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }
    }

    private static string Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();

    private static bool FixedHex(string encoded, ReadOnlySpan<byte> expected)
    {
        try
        {
            var actual = Convert.FromHexString(encoded);
            return actual.Length == expected.Length
                && CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private sealed record PersistedMutation
    {
        public int Schema { get; init; } = SchemaVersion;
        public string State { get; init; } = "";
        public ulong Epoch { get; init; }
        public ulong Cursor { get; init; }
        public string OperationId { get; init; } = "";
        public string MailboxId { get; init; } = "";
        public string PlacementId { get; init; } = "";
        public string PlacementCommitment { get; init; } = "";
        public string MembershipCommitment { get; init; } = "";
        public string EnvelopeDigest { get; init; } = "";
        public string ReplayNonce { get; init; } = "";
        public string BlobId { get; init; } = "";
        public ulong StoreCreatedAtUnixSeconds { get; init; }
        public ulong StoreReservedAtUnixSeconds { get; init; }
        public ulong ExpiresAtUnixSeconds { get; init; }
        public ulong EpochExpiresAtUnixSeconds { get; init; }
        public ulong RetainUntilUnixSeconds { get; init; }
        public string TombstoneOperationId { get; init; } = "";
        public string TombstoneReplayNonce { get; init; } = "";
        public ulong TombstoneCreatedAtUnixSeconds { get; init; }
        public ulong TombstoneReservedAtUnixSeconds { get; init; }

        public static PersistedMutation StorePending(
            VerifiedMailboxPeerWireRequestV2 verified,
            MailboxEncryptedEnvelope envelope)
        {
            var request = verified.Request;
            return new()
            {
                State = "pending",
                Epoch = request.Epoch,
                Cursor = request.Cursor,
                OperationId = Hex(request.OperationId.Span),
                MailboxId = Hex(request.BlindedMailboxId.Span),
                PlacementId = Hex(envelope.PlacementId.Bytes.Span),
                PlacementCommitment = Hex(request.PlacementCommitment.Span),
                MembershipCommitment = Hex(request.MembershipCommitment.Span),
                EnvelopeDigest = Hex(envelope.DeduplicationDigest.Span),
                ReplayNonce = Hex(request.ReplayNonce.Span),
                BlobId = Hex(SHA256.HashData(request.Payload.Span)),
                StoreCreatedAtUnixSeconds = request.CreatedAtUnixSeconds,
                StoreReservedAtUnixSeconds = verified.ReplayClaim.ReservedAtUnixSeconds,
                ExpiresAtUnixSeconds = request.ExpiresAtUnixSeconds,
                EpochExpiresAtUnixSeconds = verified.ReplayClaim.EpochExpiresAtUnixSeconds,
                RetainUntilUnixSeconds = verified.ReplayClaim.RetainUntilUnixSeconds
            };
        }

        public PersistedMutation BeginTombstone(VerifiedMailboxPeerWireRequestV2 verified)
        {
            var request = verified.Request;
            return this with
            {
                State = "tombstone-pending",
                TombstoneOperationId = Hex(request.OperationId.Span),
                TombstoneReplayNonce = Hex(request.ReplayNonce.Span),
                TombstoneCreatedAtUnixSeconds = request.CreatedAtUnixSeconds,
                TombstoneReservedAtUnixSeconds =
                    verified.ReplayClaim.ReservedAtUnixSeconds
            };
        }

        public bool MatchesStoreContext(
            MailboxPeerWireRequestV2 request,
            MailboxEncryptedEnvelope envelope) =>
            Schema == SchemaVersion
            && Epoch == request.Epoch
            && Cursor == request.Cursor
            && StoreCreatedAtUnixSeconds == request.CreatedAtUnixSeconds
            && ExpiresAtUnixSeconds == request.ExpiresAtUnixSeconds
            && FixedHex(OperationId, request.OperationId.Span)
            && FixedHex(MailboxId, request.BlindedMailboxId.Span)
            && FixedHex(PlacementId, envelope.PlacementId.Bytes.Span)
            && FixedHex(PlacementCommitment, request.PlacementCommitment.Span)
            && FixedHex(MembershipCommitment, request.MembershipCommitment.Span)
            && FixedHex(EnvelopeDigest, envelope.DeduplicationDigest.Span);

        public bool MatchesTombstoneTarget(MailboxPeerWireRequestV2 request) =>
            Epoch == request.Epoch
            && Cursor == request.Cursor
            && FixedHex(MailboxId, request.BlindedMailboxId.Span)
            && FixedHex(PlacementCommitment, request.PlacementCommitment.Span)
            && FixedHex(MembershipCommitment, request.MembershipCommitment.Span)
            && FixedHex(EnvelopeDigest, request.Payload.Span);

        public bool MatchesTombstoneOperation(MailboxPeerWireRequestV2 request) =>
            FixedHex(TombstoneOperationId, request.OperationId.Span)
            && FixedHex(TombstoneReplayNonce, request.ReplayNonce.Span)
            && TombstoneCreatedAtUnixSeconds == request.CreatedAtUnixSeconds;

        public void Validate()
        {
            if (Schema != SchemaVersion
                || State is not ("pending" or "completed"
                    or "tombstone-pending" or "tombstoned")
                || Epoch == 0
                || Cursor == 0
                || StoreCreatedAtUnixSeconds == 0
                || StoreReservedAtUnixSeconds < StoreCreatedAtUnixSeconds
                || StoreReservedAtUnixSeconds >= ExpiresAtUnixSeconds
                || ExpiresAtUnixSeconds == 0
                || EpochExpiresAtUnixSeconds == 0
                || ExpiresAtUnixSeconds > EpochExpiresAtUnixSeconds
                || !HasExactRetention(
                    EpochExpiresAtUnixSeconds,
                    RetainUntilUnixSeconds)
                || !IsHex(OperationId, 16)
                || !IsHex(MailboxId, 32)
                || !IsHex(PlacementId, 32)
                || !IsHex(PlacementCommitment, 32)
                || !IsHex(MembershipCommitment, 32)
                || !IsHex(EnvelopeDigest, 32)
                || !IsHex(ReplayNonce, 32)
                || !IsHex(BlobId, 32)
                || State is "pending" or "completed"
                    && (!string.IsNullOrEmpty(TombstoneOperationId)
                        || !string.IsNullOrEmpty(TombstoneReplayNonce)
                        || TombstoneCreatedAtUnixSeconds != 0
                        || TombstoneReservedAtUnixSeconds != 0)
                || State is "tombstone-pending" or "tombstoned"
                    && (!IsHex(TombstoneOperationId, 16)
                        || !IsHex(TombstoneReplayNonce, 32)
                        || TombstoneCreatedAtUnixSeconds < StoreCreatedAtUnixSeconds
                        || TombstoneReservedAtUnixSeconds
                            < TombstoneCreatedAtUnixSeconds
                        || TombstoneReservedAtUnixSeconds
                            < StoreReservedAtUnixSeconds
                        || TombstoneReservedAtUnixSeconds >= ExpiresAtUnixSeconds))
            {
                throw new InvalidDataException("A PRQ2 mutation record is malformed.");
            }
        }

        private static bool IsHex(string? value, int bytes) =>
            value is not null
            && value.Length == bytes * 2
            && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

        private static bool HasExactRetention(
            ulong epochExpiresAtUnixSeconds,
            ulong retainUntilUnixSeconds)
        {
            try
            {
                return retainUntilUnixSeconds == checked(
                    epochExpiresAtUnixSeconds
                    + MailboxPeerWireV2Limits.ReplayRetentionSeconds);
            }
            catch (OverflowException)
            {
                return false;
            }
        }
    }
}

public sealed class MailboxPeerMutationCapacityException : Exception
{
    public MailboxPeerMutationCapacityException()
        : base("The PRQ2 mutation journal capacity is exhausted.")
    {
    }
}
