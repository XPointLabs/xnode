using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

public sealed record MailboxPeerMutationResult(
    MailboxReplicaDisposition Disposition,
    string Error = "");

/// <summary>
/// Durable local PRQ2 mutation boundary. Store reservations make crash disposition deterministic;
/// tombstones are journaled before best-effort physical blob deletion.
/// </summary>
public sealed class MailboxPeerMutationStore : IDisposable
{
    private const int SchemaVersion = 1;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly ReplicatedMailboxOptions _options;
    private readonly ReplicatedMailboxStore _blobStore;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly FileStream _lease;
    private int _recordCount;
    private int _disposed;

    public MailboxPeerMutationStore(
        string dataDirectory,
        ReplicatedMailboxOptions options,
        ReplicatedMailboxStore blobStore,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        options.Validate();
        _options = options;
        _blobStore = blobStore;
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
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
            foreach (var temporary in Directory.EnumerateFiles(_directory, "*.tmp"))
            {
                File.Delete(temporary);
            }

            var records = Directory.EnumerateFiles(_directory, "*.json")
                .Take(options.MaxPeerMutationRecords + 1)
                .ToArray();
            if (records.Length > options.MaxPeerMutationRecords)
            {
                throw new InvalidOperationException(
                    "The PRQ2 mutation journal capacity is exceeded.");
            }

            foreach (var path in records)
            {
                var record = Read(path);
                if (!string.Equals(
                        Path.GetFileNameWithoutExtension(path),
                        RecordKey(
                            record.Kind,
                            record.Epoch,
                            record.MailboxId,
                            record.EnvelopeDigest),
                        StringComparison.Ordinal))
                {
                    throw new InvalidDataException(
                        "A PRQ2 mutation record filename is inconsistent.");
                }
            }

            _recordCount = records.Length;
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
                if (record.Kind != "store" || record.State != "tombstoned")
                {
                    continue;
                }

                _ = await _blobStore.DeleteExactAsync(
                    record.MailboxId,
                    record.BlobId,
                    cancellationToken).ConfigureAwait(false);
            }
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
            if (record.Kind != "store"
                || record.State is not ("completed" or "tombstoned")
                || record.Epoch != request.Epoch
                || !FixedHex(record.MailboxId, request.BlindedMailboxId.Span)
                || !FixedHex(record.EnvelopeDigest, request.Payload.Span)
                || !FixedHex(record.MembershipCommitment, request.MembershipCommitment.Span)
                || !FixedHex(record.PlacementCommitment, request.PlacementCommitment.Span)
                || record.Cursor != request.Cursor
                || record.State == "tombstoned"
                    && !FixedHex(record.TombstoneOperationId, request.OperationId.Span))
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
            return verified.Request.Operation == MailboxPeerReplicationOperation.Store
                ? await StoreUnderGateAsync(verified, cancellationToken).ConfigureAwait(false)
                : await TombstoneUnderGateAsync(verified, cancellationToken).ConfigureAwait(false);
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
            EnsureCapacity();
            record = PersistedMutation.StorePending(request, envelope);
            Write(path, record);
            _recordCount++;
        }
        else
        {
            record = Read(path);
            if (!record.MatchesStore(request, envelope) || record.State == "tombstoned")
            {
                return new MailboxPeerMutationResult(
                    MailboxReplicaDisposition.Stored,
                    "mailbox-peer-store-context-conflict");
            }

            firstLogicalStore = record.State == "pending"
                || FixedHex(record.ReplayNonce, request.ReplayNonce.Span);
        }

        long expiresAtUnixMs;
        try
        {
            expiresAtUnixMs = checked((long)request.ExpiresAtUnixSeconds * 1000L);
        }
        catch (OverflowException)
        {
            return new MailboxPeerMutationResult(
                MailboxReplicaDisposition.Stored,
                "mailbox-peer-expiry-overflow");
        }

        var blob = new EncryptedMailboxBlob(
            Hex(request.BlindedMailboxId.Span),
            Hex(SHA256.HashData(request.Payload.Span)),
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
            record = record with { State = "completed", BlobId = blob.BlobId };
            Write(path, record);
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
        var storePath = StorePath(
            request.Epoch,
            request.BlindedMailboxId.Span,
            request.Payload.Span);
        if (!File.Exists(storePath))
        {
            return new MailboxPeerMutationResult(
                MailboxReplicaDisposition.Tombstone,
                "mailbox-peer-tombstone-target-missing");
        }

        var store = Read(storePath);
        if (store.Kind != "store"
            || store.State == "pending"
            || !store.MatchesTombstoneTarget(request)
            || store.State == "tombstoned"
                && !FixedHex(store.TombstoneOperationId, request.OperationId.Span))
        {
            return new MailboxPeerMutationResult(
                MailboxReplicaDisposition.Tombstone,
                "mailbox-peer-tombstone-context-conflict");
        }

        var tombstonePath = TombstonePath(
            request.Epoch,
            request.BlindedMailboxId.Span,
            request.Payload.Span);
        PersistedMutation tombstone;
        if (File.Exists(tombstonePath))
        {
            tombstone = Read(tombstonePath);
            if (!tombstone.MatchesTombstone(request))
            {
                return new MailboxPeerMutationResult(
                    MailboxReplicaDisposition.Tombstone,
                    "mailbox-peer-tombstone-operation-conflict");
            }
        }
        else
        {
            EnsureCapacity();
            tombstone = PersistedMutation.TombstonePending(request, store.PlacementId);
            Write(tombstonePath, tombstone);
            _recordCount++;
        }

        if (store.State != "tombstoned")
        {
            store = store with
            {
                State = "tombstoned",
                TombstoneOperationId = Hex(request.OperationId.Span)
            };
            Write(storePath, store);
        }

        _ = await _blobStore.DeleteExactAsync(
            store.MailboxId,
            store.BlobId,
            cancellationToken).ConfigureAwait(false);
        if (tombstone.State != "completed")
        {
            Write(tombstonePath, tombstone with { State = "completed" });
        }

        return new MailboxPeerMutationResult(MailboxReplicaDisposition.Tombstone);
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
            File.Move(temporaryPath, finalPath, overwrite: true);
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

    private void EnsureCapacity()
    {
        if (_recordCount >= _options.MaxPeerMutationRecords)
        {
            throw new MailboxPeerMutationCapacityException();
        }
    }

    private string StorePath(ulong epoch, ReadOnlySpan<byte> mailbox, ReadOnlySpan<byte> digest) =>
        Path.Combine(_directory, $"{RecordKey("store", epoch, mailbox, digest)}.json");

    private string TombstonePath(
        ulong epoch,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> digest) =>
        Path.Combine(_directory, $"{RecordKey("tombstone", epoch, mailbox, digest)}.json");

    private static string RecordKey(
        string kind,
        ulong epoch,
        string mailbox,
        string digest) =>
        RecordKey(kind, epoch, Convert.FromHexString(mailbox), Convert.FromHexString(digest));

    private static string RecordKey(
        string kind,
        ulong epoch,
        ReadOnlySpan<byte> mailbox,
        ReadOnlySpan<byte> digest)
    {
        var kindBytes = kind == "store" ? "store"u8 : "tombstone"u8;
        var bytes = new byte[1 + kindBytes.Length + 8 + 64];
        bytes[0] = checked((byte)kindBytes.Length);
        kindBytes.CopyTo(bytes.AsSpan(1));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(1 + kindBytes.Length), epoch);
        mailbox.CopyTo(bytes.AsSpan(1 + kindBytes.Length + 8));
        digest.CopyTo(bytes.AsSpan(1 + kindBytes.Length + 40));
        return Hex(SHA256.HashData(bytes));
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
        public string Kind { get; init; } = "";
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
        public string TombstoneOperationId { get; init; } = "";

        public static PersistedMutation StorePending(
            MailboxPeerWireRequestV2 request,
            MailboxEncryptedEnvelope envelope) => new()
        {
            Kind = "store",
            State = "pending",
            Epoch = request.Epoch,
            Cursor = request.Cursor,
            OperationId = Hex(request.OperationId.Span),
            MailboxId = Hex(request.BlindedMailboxId.Span),
            PlacementId = Hex(envelope.PlacementId.Bytes.Span),
            PlacementCommitment = Hex(request.PlacementCommitment.Span),
            MembershipCommitment = Hex(request.MembershipCommitment.Span),
            EnvelopeDigest = Hex(envelope.DeduplicationDigest.Span),
            ReplayNonce = Hex(request.ReplayNonce.Span)
        };

        public static PersistedMutation TombstonePending(
            MailboxPeerWireRequestV2 request,
            string placementId) => new()
        {
            Kind = "tombstone",
            State = "pending",
            Epoch = request.Epoch,
            Cursor = request.Cursor,
            OperationId = Hex(request.OperationId.Span),
            MailboxId = Hex(request.BlindedMailboxId.Span),
            PlacementId = placementId,
            PlacementCommitment = Hex(request.PlacementCommitment.Span),
            MembershipCommitment = Hex(request.MembershipCommitment.Span),
            EnvelopeDigest = Hex(request.Payload.Span),
            ReplayNonce = Hex(request.ReplayNonce.Span)
        };

        public bool MatchesStore(
            MailboxPeerWireRequestV2 request,
            MailboxEncryptedEnvelope envelope) =>
            Kind == "store"
            && Schema == SchemaVersion
            && Epoch == request.Epoch
            && Cursor == request.Cursor
            && FixedHex(OperationId, request.OperationId.Span)
            && FixedHex(MailboxId, request.BlindedMailboxId.Span)
            && FixedHex(PlacementId, envelope.PlacementId.Bytes.Span)
            && FixedHex(PlacementCommitment, request.PlacementCommitment.Span)
            && FixedHex(MembershipCommitment, request.MembershipCommitment.Span)
            && FixedHex(EnvelopeDigest, envelope.DeduplicationDigest.Span);

        public bool MatchesTombstoneTarget(MailboxPeerWireRequestV2 request) =>
            Kind == "store"
            && Epoch == request.Epoch
            && Cursor == request.Cursor
            && FixedHex(MailboxId, request.BlindedMailboxId.Span)
            && FixedHex(PlacementCommitment, request.PlacementCommitment.Span)
            && FixedHex(MembershipCommitment, request.MembershipCommitment.Span)
            && FixedHex(EnvelopeDigest, request.Payload.Span);

        public bool MatchesTombstone(MailboxPeerWireRequestV2 request) =>
            Kind == "tombstone"
            && Epoch == request.Epoch
            && Cursor == request.Cursor
            && FixedHex(OperationId, request.OperationId.Span)
            && FixedHex(MailboxId, request.BlindedMailboxId.Span)
            && FixedHex(PlacementCommitment, request.PlacementCommitment.Span)
            && FixedHex(MembershipCommitment, request.MembershipCommitment.Span)
            && FixedHex(EnvelopeDigest, request.Payload.Span);

        public void Validate()
        {
            var validState = Kind == "store"
                ? State is "pending" or "completed" or "tombstoned"
                : Kind == "tombstone" && State is "pending" or "completed";
            if (Schema != SchemaVersion
                || !validState
                || Epoch == 0
                || Cursor == 0
                || !IsHex(OperationId, 16)
                || !IsHex(MailboxId, 32)
                || !IsHex(PlacementId, 32)
                || !IsHex(PlacementCommitment, 32)
                || !IsHex(MembershipCommitment, 32)
                || !IsHex(EnvelopeDigest, 32)
                || !IsHex(ReplayNonce, 32)
                || Kind == "store" && State != "pending" && !IsHex(BlobId, 32)
                || Kind == "store" && State == "tombstoned"
                    && !IsHex(TombstoneOperationId, 16))
            {
                throw new InvalidDataException("A PRQ2 mutation record is malformed.");
            }
        }

        private static bool IsHex(string? value, int bytes) =>
            value is not null
            && value.Length == bytes * 2
            && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}

public sealed class MailboxPeerMutationCapacityException : Exception
{
    public MailboxPeerMutationCapacityException()
        : base("The PRQ2 mutation journal capacity is exhausted.")
    {
    }
}
