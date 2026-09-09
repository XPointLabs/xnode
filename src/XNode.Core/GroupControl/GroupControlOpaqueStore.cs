using System.Buffers.Binary;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using XNode.Core.Mailbox;

namespace XNode.Core.GroupControl;

/// <summary>
/// Durable storage for already-authorized opaque group-control ciphertext.
/// It knows no group, member, account, device, or plaintext protocol metadata.
/// </summary>
internal sealed class GroupControlOpaqueStore : IDisposable
{
    private const int StateVersion = 1;
    private const int EnvelopeOverhead = 8 + sizeof(uint) + 32;
    private static readonly byte[] EnvelopeMagic = "XGCSTR01"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly object gate = new();
    private readonly string path;
    private readonly GroupControlOpaqueStoreOptions options;
    private readonly IClock clock;
    private readonly IMailboxStorageSecurity storageSecurity;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lifetimeLease;
    private PersistedState state;
    private bool disposed;
    private bool faulted;

    internal GroupControlOpaqueStore(
        string statePath,
        GroupControlOpaqueStoreOptions? options = null,
        IClock? clock = null,
        IMailboxStorageSecurity? storageSecurity = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        path = Path.GetFullPath(statePath);
        this.options = options ?? new GroupControlOpaqueStoreOptions();
        this.options.Validate();
        this.clock = clock ?? new SystemClock();
        this.storageSecurity = storageSecurity ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();

        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The group-control state path has no parent directory.", nameof(statePath));
        this.storageSecurity.SecureDirectory(directory);
        var lockPath = path + ".lock";
        lifetimeLease = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
        this.storageSecurity.SecureFile(lockPath);
        try
        {
            state = LoadState();
        }
        catch
        {
            lifetimeLease.Dispose();
            throw;
        }
    }

    internal GroupControlMutationResult Write(OpaqueGroupControlWriteRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfUnavailable();
            var now = CurrentUnixSeconds();
            ValidateDeadline(request.EffectiveExpiresAtUnixSeconds, now);
            if (request.EffectiveExpiresAtUnixSeconds <= now)
            {
                return GroupControlMutationResult.Empty(GroupControlMutationDisposition.Expired);
            }

            var priorOperation = FindOperation(request.OperationId, out var operationStream);
            if (priorOperation is not null)
            {
                if (operationStream is not null && Matches(operationStream, priorOperation, request))
                {
                    return Mutation(GroupControlMutationDisposition.ExactReplay, priorOperation);
                }
                if (operationStream is not null
                    && GroupControlOpaqueValue.FixedEquals(
                        operationStream.ServiceCapability,
                        request.ServiceCapability)
                    && priorOperation.ControlSequence == request.ControlSequence
                    && !operationStream.ForkLatched)
                {
                    operationStream.ForkLatched = true;
                    SaveState();
                }
                return GroupControlMutationResult.Empty(GroupControlMutationDisposition.Conflict);
            }

            var stream = FindStream(request.ServiceCapability);
            if (stream is null)
            {
                if (request.ControlSequence != 1 || !GroupControlOpaqueValue.IsZero(request.PredecessorControlHash))
                {
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.StaleSequence);
                }
                if (state.Streams.Count >= options.MaximumStreams
                    || TotalCiphertextBytes() + request.SealedGcf1.Length > options.MaximumCiphertextBytes)
                {
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.QuotaExceeded);
                }
                stream = new StreamState
                {
                    ServiceCapability = request.ServiceCapability.ToArray(),
                    ExactGsr1Hash = request.ExactGsr1Hash.ToArray()
                };
                state.Streams.Add(stream);
            }
            else
            {
                if (stream.ForkLatched)
                {
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.ForkLatched);
                }
                if (!GroupControlOpaqueValue.FixedEquals(stream.ExactGsr1Hash, request.ExactGsr1Hash))
                {
                    stream.ForkLatched = true;
                    SaveState();
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.Conflict);
                }

                var sameSequence = stream.Records.FirstOrDefault(item =>
                    item.ControlSequence == request.ControlSequence);
                if (sameSequence is not null)
                {
                    if (Matches(stream, sameSequence, request, compareOperation: false))
                    {
                        return Mutation(GroupControlMutationDisposition.ExactReplay, sameSequence);
                    }
                    stream.ForkLatched = true;
                    SaveState();
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.Conflict);
                }

                var current = stream.Records[^1];
                if (current.ControlSequence == ulong.MaxValue
                    || request.ControlSequence != current.ControlSequence + 1)
                {
                    return new GroupControlMutationResult(
                        GroupControlMutationDisposition.StaleSequence,
                        current.ControlSequence,
                        current.SealedGcf1Hash.ToArray());
                }
                if (!GroupControlOpaqueValue.FixedEquals(
                        current.SealedGcf1Hash,
                        request.PredecessorControlHash))
                {
                    stream.ForkLatched = true;
                    SaveState();
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.Conflict);
                }
                if (stream.Records.Count >= options.MaximumRecordsPerStream
                    || TotalCiphertextBytes() + request.SealedGcf1.Length > options.MaximumCiphertextBytes)
                {
                    return GroupControlMutationResult.Empty(GroupControlMutationDisposition.QuotaExceeded);
                }
            }

            var record = ToState(request, now);
            stream.Records.Add(record);
            CanonicalizeState();
            SaveState();
            return Mutation(GroupControlMutationDisposition.Committed, record);
        }
    }

    internal GroupControlReadResult Fetch(OpaqueGroupControlFetchRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfUnavailable();
            var stream = FindStream(request.ServiceCapability);
            if (stream is null)
            {
                return Read(GroupControlReadDisposition.NotFound);
            }
            if (stream.ForkLatched
                || !GroupControlOpaqueValue.FixedEquals(stream.ExactGsr1Hash, request.ExactGsr1Hash))
            {
                return Read(GroupControlReadDisposition.Conflict, stream);
            }

            var current = stream.Records[^1];
            var now = CurrentUnixSeconds();
            if (request.AfterControlSequence > current.ControlSequence)
            {
                return Read(GroupControlReadDisposition.StaleCursor, stream);
            }
            if (stream.HasCompactionAnchor
                && request.AfterControlSequence < stream.CompactedThroughSequence)
            {
                return Read(GroupControlReadDisposition.Gap, stream);
            }
            if (request.AfterControlSequence == current.ControlSequence)
            {
                return Read(
                    current.EffectiveExpiresAtUnixSeconds <= now
                        ? GroupControlReadDisposition.Expired
                        : GroupControlReadDisposition.NoChange,
                    stream);
            }

            var expected = checked(request.AfterControlSequence + 1);
            var start = stream.Records.FindIndex(item => item.ControlSequence == expected);
            if (start < 0)
            {
                return Read(GroupControlReadDisposition.Gap, stream);
            }
            if (stream.Records[start].EffectiveExpiresAtUnixSeconds <= now)
            {
                return Read(GroupControlReadDisposition.Gap, stream);
            }

            var records = new List<OpaqueGroupControlRecord>(request.MaximumRecords);
            var index = start;
            while (index < stream.Records.Count && records.Count < request.MaximumRecords)
            {
                var candidate = stream.Records[index];
                if (candidate.EffectiveExpiresAtUnixSeconds <= now)
                {
                    break;
                }
                if (records.Count != 0
                    && candidate.ControlSequence != records[^1].ControlSequence + 1)
                {
                    return Read(GroupControlReadDisposition.Gap, stream);
                }
                records.Add(ToPublic(candidate));
                index++;
            }

            return new GroupControlReadResult(
                GroupControlReadDisposition.Events,
                records,
                current.ControlSequence,
                current.SealedGcf1Hash.ToArray(),
                index < stream.Records.Count);
        }
    }

    internal int Compact(VerifiedGroupControlCompactionCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        lock (gate)
        {
            ThrowIfUnavailable();
            var stream = FindStream(checkpoint.ServiceCapability);
            if (stream is null || stream.ForkLatched)
            {
                return 0;
            }

            var checkpointRecord = stream.Records.FirstOrDefault(item =>
                item.ControlSequence == checkpoint.ControlSequence);
            if (checkpointRecord is null
                && stream.HasCompactionAnchor
                && stream.CompactedThroughSequence == checkpoint.ControlSequence
                && GroupControlOpaqueValue.FixedEquals(
                    stream.CompactedThroughControlHash,
                    checkpoint.ControlHash))
            {
                return 0;
            }
            if (checkpointRecord is null
                || !GroupControlOpaqueValue.FixedEquals(
                    checkpointRecord.SealedGcf1Hash,
                    checkpoint.ControlHash))
            {
                throw new InvalidOperationException("The verified group-control checkpoint does not match retained state.");
            }

            var now = CurrentUnixSeconds();
            var removed = 0;
            while (stream.Records.Count > GroupControlOpaqueStoreOptions.MinimumRetainedCommits)
            {
                var candidate = stream.Records[0];
                if (candidate.ControlSequence > checkpoint.ControlSequence
                    || candidate.EffectiveExpiresAtUnixSeconds > now)
                {
                    break;
                }
                stream.HasCompactionAnchor = true;
                stream.CompactedThroughSequence = candidate.ControlSequence;
                stream.CompactedThroughControlHash = candidate.SealedGcf1Hash.ToArray();
                stream.Records.RemoveAt(0);
                removed++;
            }
            if (removed != 0)
            {
                SaveState();
            }
            return removed;
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            lifetimeLease.Dispose();
        }
    }

    private PersistedState LoadState()
    {
        if (!File.Exists(path))
        {
            return new PersistedState();
        }
        try
        {
            var info = new FileInfo(path);
            if (info.Length < EnvelopeOverhead || info.Length > options.MaximumPersistedBytes)
            {
                throw new InvalidDataException("Group-control state envelope length is invalid.");
            }
            var bytes = File.ReadAllBytes(path);
            if (!bytes.AsSpan(0, EnvelopeMagic.Length).SequenceEqual(EnvelopeMagic))
            {
                throw new InvalidDataException("Group-control state envelope magic is invalid.");
            }
            var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(EnvelopeMagic.Length, 4));
            if (payloadLength > int.MaxValue
                || checked(EnvelopeOverhead + (int)payloadLength) != bytes.Length)
            {
                throw new InvalidDataException("Group-control state payload length is invalid.");
            }
            var payload = bytes.AsSpan(EnvelopeMagic.Length + 4, (int)payloadLength);
            var digest = bytes.AsSpan(EnvelopeMagic.Length + 4 + (int)payloadLength, 32);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), digest))
            {
                throw new InvalidDataException("Group-control state digest is invalid.");
            }
            var loaded = JsonSerializer.Deserialize<PersistedState>(payload, JsonOptions)
                ?? throw new InvalidDataException("Group-control state payload is empty.");
            ValidateState(loaded);
            return loaded;
        }
        catch (Exception exception) when (exception is InvalidDataException
            or JsonException
            or OverflowException
            or ArgumentException)
        {
            throw QuarantineAndCreateException(exception);
        }
    }

    private void SaveState()
    {
        try
        {
            ValidateState(state);
            var payload = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
            if ((long)payload.Length + EnvelopeOverhead > options.MaximumPersistedBytes)
            {
                throw new InvalidOperationException("The group-control state exceeds its configured durable bound.");
            }
            var envelope = new byte[checked(payload.Length + EnvelopeOverhead)];
            EnvelopeMagic.CopyTo(envelope, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                envelope.AsSpan(EnvelopeMagic.Length, sizeof(uint)),
                checked((uint)payload.Length));
            payload.CopyTo(envelope.AsSpan(EnvelopeMagic.Length + sizeof(uint)));
            SHA256.HashData(payload).CopyTo(envelope, EnvelopeMagic.Length + sizeof(uint) + payload.Length);
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(
                           temporary,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           64 * 1024,
                           FileOptions.WriteThrough))
                {
                    stream.Write(envelope);
                    stream.Flush(flushToDisk: true);
                }
                storageSecurity.SecureFile(temporary);
                durability.FlushFileAndParentDirectory(temporary);
                ReplaceFileWithBoundedRetry(temporary);
                durability.FlushFileAndParentDirectory(path);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(envelope);
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
        }
        catch
        {
            faulted = true;
            throw;
        }
    }

    private void ReplaceFileWithBoundedRetry(string temporary)
    {
        const int maximumAttempts = 8;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                durability.ReplaceFile(temporary, path);
                return;
            }
            catch (Win32Exception exception) when (
                OperatingSystem.IsWindows()
                && attempt < maximumAttempts
                && exception.NativeErrorCode is 5 or 32)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(1 << (attempt - 1)));
            }
        }
    }

    private GroupControlStoreCorruptException QuarantineAndCreateException(Exception exception)
    {
        try
        {
            if (File.Exists(path))
            {
                var quarantine = path + ".quarantine." + Guid.NewGuid().ToString("N");
                durability.ReplaceFile(path, quarantine);
                durability.FlushFileAndParentDirectory(quarantine);
            }
        }
        catch (Exception quarantineFailure)
        {
            return new GroupControlStoreCorruptException(new AggregateException(exception, quarantineFailure));
        }
        return new GroupControlStoreCorruptException(exception);
    }

    private void ValidateState(PersistedState candidate)
    {
        if (candidate.Version != StateVersion
            || candidate.Streams is null
            || candidate.Streams.Count > options.MaximumStreams)
        {
            throw new InvalidDataException("Group-control state version or stream bounds are invalid.");
        }

        var priorCapability = Array.Empty<byte>();
        var operations = new HashSet<string>(StringComparer.Ordinal);
        long totalBytes = 0;
        foreach (var stream in candidate.Streams)
        {
            Validate32(stream.ServiceCapability, allowZero: false);
            Validate32(stream.ExactGsr1Hash, allowZero: false);
            if (priorCapability.Length != 0
                && priorCapability.AsSpan().SequenceCompareTo(stream.ServiceCapability) >= 0)
            {
                throw new InvalidDataException("Group-control stream keys are not canonical.");
            }
            priorCapability = stream.ServiceCapability;
            if (stream.Records is null
                || stream.Records.Count == 0
                || stream.Records.Count > options.MaximumRecordsPerStream)
            {
                throw new InvalidDataException("Group-control retained history bounds are invalid.");
            }
            if (stream.HasCompactionAnchor)
            {
                Validate32(stream.CompactedThroughControlHash, allowZero: false);
            }
            else if (stream.CompactedThroughSequence != 0
                || stream.CompactedThroughControlHash is null
                || stream.CompactedThroughControlHash.Length != 0)
            {
                throw new InvalidDataException("Group-control compaction anchor is invalid.");
            }

            ControlRecordState? previous = null;
            foreach (var record in stream.Records)
            {
                Validate32(record.OperationId, allowZero: false);
                Validate32(record.RequestHash, allowZero: false);
                Validate32(record.SealedGcf1Hash, allowZero: false);
                ValidatePredecessor(record.ControlSequence, record.PredecessorControlHash);
                if (record.SealedGcf1 is null
                    || record.SealedGcf1.Length is < 1 or > GroupControlOpaqueStoreOptions.MaximumSealedGcf1Bytes
                    || record.AcceptedAtUnixSeconds >= record.EffectiveExpiresAtUnixSeconds
                    || record.EffectiveExpiresAtUnixSeconds - record.AcceptedAtUnixSeconds
                        > (ulong)GroupControlOpaqueStoreOptions.MaximumRetention.TotalSeconds
                    || !GroupControlOpaqueValue.FixedEquals(
                        SHA256.HashData(record.SealedGcf1),
                        record.SealedGcf1Hash)
                    || !operations.Add(Convert.ToHexString(record.OperationId)))
                {
                    throw new InvalidDataException("Group-control record is invalid.");
                }

                if (previous is null)
                {
                    if (stream.HasCompactionAnchor
                        && (stream.CompactedThroughSequence == ulong.MaxValue
                            || record.ControlSequence != stream.CompactedThroughSequence + 1
                            || !GroupControlOpaqueValue.FixedEquals(
                                record.PredecessorControlHash,
                                stream.CompactedThroughControlHash)))
                    {
                        throw new InvalidDataException("Group-control compacted lineage is discontinuous.");
                    }
                    if (!stream.HasCompactionAnchor && record.ControlSequence != 1)
                    {
                        throw new InvalidDataException("Group-control history does not begin at sequence one.");
                    }
                }
                else if (previous.ControlSequence == ulong.MaxValue
                    || record.ControlSequence != previous.ControlSequence + 1
                    || !GroupControlOpaqueValue.FixedEquals(
                        record.PredecessorControlHash,
                        previous.SealedGcf1Hash))
                {
                    throw new InvalidDataException("Group-control history is discontinuous.");
                }
                totalBytes = checked(totalBytes + record.SealedGcf1.Length);
                previous = record;
            }
        }
        if (totalBytes > options.MaximumCiphertextBytes)
        {
            throw new InvalidDataException("Group-control ciphertext quota is exceeded.");
        }
    }

    private void CanonicalizeState() =>
        state.Streams.Sort(static (left, right) =>
            left.ServiceCapability.AsSpan().SequenceCompareTo(right.ServiceCapability));

    private StreamState? FindStream(ReadOnlySpan<byte> capability)
    {
        foreach (var stream in state.Streams)
        {
            if (GroupControlOpaqueValue.FixedEquals(stream.ServiceCapability, capability))
            {
                return stream;
            }
        }
        return null;
    }

    private ControlRecordState? FindOperation(ReadOnlySpan<byte> operationId, out StreamState? owner)
    {
        foreach (var stream in state.Streams)
        {
            foreach (var record in stream.Records)
            {
                if (GroupControlOpaqueValue.FixedEquals(record.OperationId, operationId))
                {
                    owner = stream;
                    return record;
                }
            }
        }
        owner = null;
        return null;
    }

    private long TotalCiphertextBytes() =>
        state.Streams.SelectMany(static stream => stream.Records)
            .Sum(static record => (long)record.SealedGcf1.Length);

    private ulong CurrentUnixSeconds()
    {
        var seconds = clock.UtcNow.ToUnixTimeSeconds();
        if (seconds < 0)
        {
            throw new InvalidOperationException("Group-control trusted service time is before the Unix epoch.");
        }
        return checked((ulong)seconds);
    }

    private static void ValidateDeadline(ulong deadline, ulong now)
    {
        if (deadline > now
            && deadline - now > (ulong)GroupControlOpaqueStoreOptions.MaximumRetention.TotalSeconds)
        {
            throw new ArgumentOutOfRangeException(
                nameof(deadline),
                "The signed group-control object exceeds its retention bound.");
        }
    }

    private static bool Matches(
        StreamState stream,
        ControlRecordState record,
        OpaqueGroupControlWriteRequest request,
        bool compareOperation = true) =>
        GroupControlOpaqueValue.FixedEquals(stream.ServiceCapability, request.ServiceCapability)
        && GroupControlOpaqueValue.FixedEquals(stream.ExactGsr1Hash, request.ExactGsr1Hash)
        && (!compareOperation || GroupControlOpaqueValue.FixedEquals(record.OperationId, request.OperationId))
        && GroupControlOpaqueValue.FixedEquals(record.RequestHash, request.RequestHash)
        && record.ControlSequence == request.ControlSequence
        && GroupControlOpaqueValue.FixedEquals(record.PredecessorControlHash, request.PredecessorControlHash)
        && GroupControlOpaqueValue.FixedEquals(record.SealedGcf1Hash, request.SealedGcf1Hash)
        && record.SealedGcf1.AsSpan().SequenceEqual(request.SealedGcf1)
        && record.EffectiveExpiresAtUnixSeconds == request.EffectiveExpiresAtUnixSeconds;

    private static GroupControlMutationResult Mutation(
        GroupControlMutationDisposition disposition,
        ControlRecordState record) =>
        new(disposition, record.ControlSequence, record.SealedGcf1Hash.ToArray());

    private static GroupControlReadResult Read(
        GroupControlReadDisposition disposition,
        StreamState? stream = null)
    {
        var current = stream?.Records.LastOrDefault();
        return new(
            disposition,
            [],
            current?.ControlSequence ?? 0,
            current?.SealedGcf1Hash.ToArray() ?? [],
            false);
    }

    private static OpaqueGroupControlRecord ToPublic(ControlRecordState record) =>
        new(
            record.ControlSequence,
            record.PredecessorControlHash.ToArray(),
            record.SealedGcf1Hash.ToArray(),
            record.SealedGcf1.ToArray(),
            record.EffectiveExpiresAtUnixSeconds);

    private static ControlRecordState ToState(OpaqueGroupControlWriteRequest request, ulong now) => new()
    {
        OperationId = request.OperationId.ToArray(),
        RequestHash = request.RequestHash.ToArray(),
        ControlSequence = request.ControlSequence,
        PredecessorControlHash = request.PredecessorControlHash.ToArray(),
        SealedGcf1Hash = request.SealedGcf1Hash.ToArray(),
        SealedGcf1 = request.SealedGcf1.ToArray(),
        AcceptedAtUnixSeconds = now,
        EffectiveExpiresAtUnixSeconds = request.EffectiveExpiresAtUnixSeconds
    };

    private static void Validate32(byte[]? value, bool allowZero)
    {
        if (value is null || value.Length != 32 || (!allowZero && GroupControlOpaqueValue.IsZero(value)))
        {
            throw new InvalidDataException("A persisted opaque 32-byte value is invalid.");
        }
    }

    private static void ValidatePredecessor(ulong sequence, byte[]? predecessor)
    {
        if (predecessor is null
            || predecessor.Length != 32
            || sequence == 0
            || (sequence == 1) != GroupControlOpaqueValue.IsZero(predecessor))
        {
            throw new InvalidDataException("A persisted group-control predecessor is invalid.");
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted)
        {
            throw new InvalidOperationException("The group-control store is faulted after a durability failure.");
        }
    }

    private sealed class PersistedState
    {
        public int Version { get; set; } = StateVersion;
        public List<StreamState> Streams { get; set; } = [];
    }

    private sealed class StreamState
    {
        public byte[] ServiceCapability { get; set; } = [];
        public byte[] ExactGsr1Hash { get; set; } = [];
        public bool ForkLatched { get; set; }
        public bool HasCompactionAnchor { get; set; }
        public ulong CompactedThroughSequence { get; set; }
        public byte[] CompactedThroughControlHash { get; set; } = [];
        public List<ControlRecordState> Records { get; set; } = [];
    }

    private sealed class ControlRecordState
    {
        public byte[] OperationId { get; set; } = [];
        public byte[] RequestHash { get; set; } = [];
        public ulong ControlSequence { get; set; }
        public byte[] PredecessorControlHash { get; set; } = [];
        public byte[] SealedGcf1Hash { get; set; } = [];
        public byte[] SealedGcf1 { get; set; } = [];
        public ulong AcceptedAtUnixSeconds { get; set; }
        public ulong EffectiveExpiresAtUnixSeconds { get; set; }
    }
}
