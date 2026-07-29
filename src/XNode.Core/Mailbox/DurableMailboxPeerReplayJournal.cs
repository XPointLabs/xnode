using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

/// <summary>
/// Exclusive, crash-safe PRQ2 replay journal. Persisted records contain only protocol digests and
/// replay timing state; router ids, nonces and mailbox ids are never used as filenames or logs.
/// </summary>
public sealed class DurableMailboxPeerReplayJournal : IMailboxPeerReplayJournal, IDisposable
{
    private const int SchemaVersion = 1;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly ReplicatedMailboxOptions _options;
    private readonly IMailboxStorageSecurity _security;
    private readonly IMailboxDurabilityBarrier _durability;
    private readonly IClock _clock;
    private readonly FileStream _lease;
    private readonly Dictionary<string, int> _partitionCounts = new(StringComparer.Ordinal);
    private readonly PriorityQueue<string, ulong> _collectionQueue = new();
    private int _recordCount;
    private int _disposed;

    public DurableMailboxPeerReplayJournal(
        string dataDirectory,
        ReplicatedMailboxOptions options,
        IClock? clock = null,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        options.Validate();
        _options = options;
        _security = security ?? new MailboxStorageSecurity();
        _durability = durability ?? new MailboxDurabilityBarrier();
        _clock = clock ?? new SystemClock();
        _directory = Path.Combine(dataDirectory, options.PeerReplayDirectoryName);
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
                "The PRQ2 replay journal is already owned by another runtime.",
                exception);
        }

        try
        {
            _security.SecureFile(leasePath);
            PurgeTemporaryFiles();
            LoadAndValidateIndex();
            _ = CollectExpired(
                checked((ulong)_clock.UtcNow.ToUnixTimeSeconds()),
                _options.MaxPeerReplayGcBatch);
        }
        catch
        {
            _lease.Dispose();
            throw;
        }
    }

    public MailboxPeerReplayEvaluation EvaluateAndReserve(MailboxPeerReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = CollectExpiredUnderGate(
                claim.ReservedAtUnixSeconds,
                _options.MaxPeerReplayGcBatch);
            var scope = Hex(claim.ScopeKey.Span);
            var path = RecordPath(scope);
            var current = File.Exists(path) ? Read(path).Snapshot() : null;
            var (evaluation, next) =
                MailboxPeerReplayStateMachine.EvaluateAndReserve(current, claim);
            if (evaluation.State != MailboxPeerReplayState.NewReserved)
            {
                return evaluation;
            }

            var partition = PartitionKey(claim);
            if (_recordCount >= _options.MaxPeerReplayRecords
                || _partitionCounts.GetValueOrDefault(partition)
                    >= _options.MaxPeerReplayRecordsPerRouterPairEpoch)
            {
                throw new MailboxPeerReplayCapacityException();
            }

            Write(path, PersistedReplay.From(partition, next));
            _recordCount++;
            _partitionCounts[partition] = _partitionCounts.GetValueOrDefault(partition) + 1;
            _collectionQueue.Enqueue(path, next.RetainUntilUnixSeconds);
            return evaluation;
        }
    }

    public MailboxPeerReplayEvaluation? EvaluateExisting(MailboxPeerReplayClaim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var path = RecordPath(Hex(claim.ScopeKey.Span));
            if (!File.Exists(path))
            {
                return null;
            }

            var current = Read(path).Snapshot();
            return MailboxPeerReplayStateMachine.EvaluateAndReserve(current, claim)
                .Evaluation;
        }
    }

    public void CompleteAtomically(
        MailboxPeerReplayClaim claim,
        ReadOnlyMemory<byte> canonicalMrr2Response)
    {
        ArgumentNullException.ThrowIfNull(claim);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var path = RecordPath(Hex(claim.ScopeKey.Span));
            if (!File.Exists(path))
            {
                throw new MailboxPeerReplicationException(
                    MailboxPeerReplicationError.ReplayConflict,
                    "PRQ2 replay reservation is missing.");
            }

            var persisted = Read(path);
            var completed = MailboxPeerReplayStateMachine.Complete(
                persisted.Snapshot(),
                claim,
                canonicalMrr2Response.Span);
            Write(path, PersistedReplay.From(persisted.PartitionKey, completed));
        }
    }

    public int CollectExpired(ulong nowUnixSeconds, int maximumRecords)
    {
        if (maximumRecords is <= 0 or > MailboxPeerWireV2Limits.MaximumReplayCollectionBatch)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            return CollectExpiredUnderGate(nowUnixSeconds, maximumRecords);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _lease.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    private void LoadAndValidateIndex()
    {
        var maximumStartupRecords = checked(
            _options.MaxPeerReplayRecords + _options.MaxPeerReplayGcBatch + 1);
        foreach (var path in Directory.EnumerateFiles(_directory, "*.json")
                     .Take(maximumStartupRecords))
        {
            var persisted = Read(path);
            var scope = Hex(persisted.Snapshot().ScopeKey.Span);
            if (!string.Equals(
                    Path.GetFileNameWithoutExtension(path),
                    scope,
                    StringComparison.Ordinal))
            {
                throw new InvalidDataException("A PRQ2 replay journal filename is inconsistent.");
            }

            _recordCount++;
            _partitionCounts[persisted.PartitionKey] =
                _partitionCounts.GetValueOrDefault(persisted.PartitionKey) + 1;
            _collectionQueue.Enqueue(path, persisted.RetainUntilUnixSeconds);
        }
    }

    private int CollectExpiredUnderGate(ulong nowUnixSeconds, int maximumRecords)
    {
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

            var persisted = Read(path);
            if (!MailboxPeerReplayStateMachine.IsCollectable(
                    persisted.Snapshot(),
                    nowUnixSeconds))
            {
                _collectionQueue.Enqueue(path, persisted.RetainUntilUnixSeconds);
                continue;
            }

            _durability.DeleteFile(path);
            _recordCount--;
            var remaining = _partitionCounts[persisted.PartitionKey] - 1;
            if (remaining == 0)
            {
                _partitionCounts.Remove(persisted.PartitionKey);
            }
            else
            {
                _partitionCounts[persisted.PartitionKey] = remaining;
            }
            removed++;
        }

        if (_recordCount > _options.MaxPeerReplayRecords
            || _partitionCounts.Values.Any(
                count => count > _options.MaxPeerReplayRecordsPerRouterPairEpoch))
        {
            throw new InvalidOperationException("The PRQ2 replay journal capacity is exceeded.");
        }

        return removed;
    }

    private PersistedReplay Read(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Length is <= 0 or > 16 * 1024)
            {
                throw new InvalidDataException("A PRQ2 replay journal record is not bounded.");
            }

            using var stream = File.OpenRead(path);
            var persisted = JsonSerializer.Deserialize<PersistedReplay>(stream, JsonOptions)
                ?? throw new InvalidDataException("A PRQ2 replay journal record is empty.");
            var snapshot = persisted.Snapshot();
            _ = MailboxPeerReplayStateMachine.IsCollectable(snapshot, 0);
            if (snapshot.Status == MailboxPeerReplayRecordStatus.Completed)
            {
                var receipt = MailboxReceiptV2Codec.DecodeReplica(
                    snapshot.CanonicalResponse.Span);
                var canonical = MailboxReceiptV2Codec.EncodeReplica(receipt);
                if (!CryptographicOperations.FixedTimeEquals(
                        canonical,
                        snapshot.CanonicalResponse.Span))
                {
                    throw new InvalidDataException(
                        "The cached MRR2 response is not canonical.");
                }
            }

            if (persisted.Schema != SchemaVersion
                || !IsLowerHex(persisted.PartitionKey, 32))
            {
                throw new InvalidDataException("A PRQ2 replay journal record is malformed.");
            }

            return persisted;
        }
        catch (Exception exception) when (
            exception is IOException or JsonException or FormatException
                or MailboxPeerReplicationException or MailboxReceiptException)
        {
            throw new InvalidDataException(
                "The PRQ2 replay journal is corrupt and cannot be opened.",
                exception);
        }
    }

    private void Write(string finalPath, PersistedReplay persisted)
    {
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
                JsonSerializer.Serialize(stream, persisted, JsonOptions);
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

    private string RecordPath(string scope) => Path.Combine(_directory, $"{scope}.json");

    private static string PartitionKey(MailboxPeerReplayClaim claim)
    {
        var bytes = new byte[8 + 64];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, claim.Epoch);
        claim.SenderRouterId.Span.CopyTo(bytes.AsSpan(8));
        claim.RecipientRouterId.Span.CopyTo(bytes.AsSpan(40));
        return Hex(SHA256.HashData(bytes));
    }

    private static string Hex(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(value).ToLowerInvariant();

    private static bool IsLowerHex(string? value, int bytes) =>
        value is not null
        && value.Length == bytes * 2
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private sealed record PersistedReplay
    {
        public int Schema { get; init; }
        public string PartitionKey { get; init; } = "";
        public string ScopeKey { get; init; } = "";
        public ulong Epoch { get; init; }
        public string RequestDigest { get; init; } = "";
        public byte Status { get; init; }
        public string CanonicalResponse { get; init; } = "";
        public ulong CreatedAtUnixSeconds { get; init; }
        public ulong ExpiresAtUnixSeconds { get; init; }
        public ulong ReservedAtUnixSeconds { get; init; }
        public ulong EpochExpiresAtUnixSeconds { get; init; }
        public ulong RetainUntilUnixSeconds { get; init; }

        public static PersistedReplay From(
            string partitionKey,
            MailboxPeerReplaySnapshot snapshot) => new()
        {
            Schema = SchemaVersion,
            PartitionKey = partitionKey,
            ScopeKey = Hex(snapshot.ScopeKey.Span),
            Epoch = snapshot.Epoch,
            RequestDigest = Hex(snapshot.RequestDigest.Span),
            Status = (byte)snapshot.Status,
            CanonicalResponse = Convert.ToBase64String(snapshot.CanonicalResponse.Span),
            CreatedAtUnixSeconds = snapshot.CreatedAtUnixSeconds,
            ExpiresAtUnixSeconds = snapshot.ExpiresAtUnixSeconds,
            ReservedAtUnixSeconds = snapshot.ReservedAtUnixSeconds,
            EpochExpiresAtUnixSeconds = snapshot.EpochExpiresAtUnixSeconds,
            RetainUntilUnixSeconds = snapshot.RetainUntilUnixSeconds
        };

        public MailboxPeerReplaySnapshot Snapshot()
        {
            if (Schema != SchemaVersion
                || !IsLowerHex(ScopeKey, 32)
                || !IsLowerHex(RequestDigest, 32))
            {
                throw new InvalidDataException("A PRQ2 replay journal record is malformed.");
            }

            return new MailboxPeerReplaySnapshot
            {
                ScopeKey = Convert.FromHexString(ScopeKey),
                Epoch = Epoch,
                RequestDigest = Convert.FromHexString(RequestDigest),
                Status = (MailboxPeerReplayRecordStatus)Status,
                CanonicalResponse = Convert.FromBase64String(CanonicalResponse),
                CreatedAtUnixSeconds = CreatedAtUnixSeconds,
                ExpiresAtUnixSeconds = ExpiresAtUnixSeconds,
                ReservedAtUnixSeconds = ReservedAtUnixSeconds,
                EpochExpiresAtUnixSeconds = EpochExpiresAtUnixSeconds,
                RetainUntilUnixSeconds = RetainUntilUnixSeconds
            };
        }
    }
}

public sealed class MailboxPeerReplayCapacityException : Exception
{
    public MailboxPeerReplayCapacityException()
        : base("The PRQ2 replay journal capacity is exhausted.")
    {
    }
}
