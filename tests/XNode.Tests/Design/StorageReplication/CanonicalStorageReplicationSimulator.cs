using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace XNode.Tests.Design.StorageReplication;

internal sealed class StorageReplicaId : IEquatable<StorageReplicaId>, IComparable<StorageReplicaId>
{
    private readonly byte[] _bytes;

    public StorageReplicaId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 16)
        {
            throw new ArgumentException("A storage replica receipt ID is exactly 16 bytes.");
        }

        _bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => _bytes;

    public int CompareTo(StorageReplicaId? other) =>
        other is null ? 1 : _bytes.AsSpan().SequenceCompareTo(other._bytes);

    public bool Equals(StorageReplicaId? other) =>
        other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    public override bool Equals(object? obj) => Equals(obj as StorageReplicaId);

    public override int GetHashCode() =>
        BinaryPrimitives.ReadInt32BigEndian(SHA256.HashData(_bytes));

    public override string ToString() => Convert.ToHexStringLower(_bytes);
}

internal sealed class RouteHopId : IEquatable<RouteHopId>
{
    private readonly byte[] _bytes;

    public RouteHopId(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32)
        {
            throw new ArgumentException("A route hop router ID is exactly 32 bytes.");
        }

        _bytes = bytes.ToArray();
    }

    public ReadOnlyMemory<byte> Bytes => _bytes;

    public bool Equals(RouteHopId? other) =>
        other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    public override bool Equals(object? obj) => Equals(obj as RouteHopId);

    public override int GetHashCode() =>
        BinaryPrimitives.ReadInt32BigEndian(SHA256.HashData(_bytes));

    public override string ToString() => Convert.ToHexStringLower(_bytes);
}

internal sealed class OpaquePlacementKey32
{
    private readonly byte[] _bytes;

    public OpaquePlacementKey32(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32)
        {
            throw new ArgumentException("The P05 placement key profile is exactly 32 bytes.");
        }

        _bytes = bytes.ToArray();
    }

    public ReadOnlySpan<byte> Span => _bytes;
}

internal sealed class RequestNonce
{
    private readonly byte[] _bytes;

    public RequestNonce(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 16 or > 64)
        {
            throw new ArgumentException("The test nonce must be 16..64 bytes.");
        }

        _bytes = bytes.ToArray();
    }

    public ReadOnlySpan<byte> Span => _bytes;
}

internal sealed record CanonicalStoragePlacementResult(
    ulong MembershipEpoch,
    OpaquePlacementKey32 PlacementKey,
    IReadOnlyList<RouteHopId> RouteHops,
    IReadOnlyList<StorageReplicaId> Replicas);

internal sealed record CanonicalPlacementDistribution(
    int Minimum,
    int Maximum,
    double Mean,
    double CoefficientOfVariation)
{
    public static CanonicalPlacementDistribution Create(
        int membershipSize,
        int keyCount,
        IEnumerable<int> assignmentCounts)
    {
        var counts = assignmentCounts.ToArray();
        if (counts.Length != membershipSize || counts.Sum() != keyCount * 3)
        {
            throw new ArgumentException("Distribution counts do not cover the exact N=3 assignment set.");
        }

        var mean = counts.Average();
        var variance = counts.Sum(value => Math.Pow(value - mean, 2)) / counts.Length;
        return new CanonicalPlacementDistribution(
            counts.Min(),
            counts.Max(),
            mean,
            Math.Sqrt(variance) / mean);
    }
}

internal static class CanonicalStoragePlacementSimulator
{
    private static ReadOnlySpan<byte> Domain => "deep-storage-placement-hrw-v1"u8;

    public static CanonicalStoragePlacementResult Assign(
        OpaquePlacementKey32 placementKey,
        ulong membershipEpoch,
        RequestNonce requestNonce,
        IReadOnlyList<RouteHopId> routeHops,
        IReadOnlyList<StorageReplicaId> eligibleReplicas)
    {
        ArgumentNullException.ThrowIfNull(placementKey);
        ArgumentNullException.ThrowIfNull(requestNonce);
        ArgumentNullException.ThrowIfNull(routeHops);
        ArgumentNullException.ThrowIfNull(eligibleReplicas);
        if (membershipEpoch == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(membershipEpoch));
        }

        if (requestNonce.Span.IsEmpty)
        {
            throw new ArgumentException("Nonce is transport replay input, even though placement excludes it.");
        }

        if (routeHops.Count == 0 || routeHops.Distinct().Count() != routeHops.Count)
        {
            throw new ArgumentException("Route hops are a separate, duplicate-free input.");
        }

        var members = eligibleReplicas.Distinct().Order().ToArray();
        if (members.Length < 3 || members.Length != eligibleReplicas.Count)
        {
            throw new ArgumentException("At least three exact, distinct replica IDs are required.");
        }

        var selected = members
            .Select(replica => new ScoredReplica(replica, Score(placementKey.Span, replica.Bytes.Span)))
            .OrderByDescending(static value => value.Score, ByteArrayComparer.Instance)
            .ThenBy(static value => value.Replica)
            .Take(3)
            .Select(static value => value.Replica)
            .ToArray();

        return new CanonicalStoragePlacementResult(
            membershipEpoch,
            placementKey,
            routeHops.ToArray(),
            selected);
    }

    private static byte[] Score(ReadOnlySpan<byte> placementKey, ReadOnlySpan<byte> replicaId)
    {
        var input = new byte[Domain.Length + 2 + placementKey.Length + 2 + replicaId.Length];
        var offset = 0;
        Domain.CopyTo(input);
        offset += Domain.Length;
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), checked((ushort)placementKey.Length));
        offset += 2;
        placementKey.CopyTo(input.AsSpan(offset));
        offset += placementKey.Length;
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), checked((ushort)replicaId.Length));
        offset += 2;
        replicaId.CopyTo(input.AsSpan(offset));
        return SHA256.HashData(input);
    }

    private sealed record ScoredReplica(StorageReplicaId Replica, byte[] Score);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();

        public int Compare(byte[]? left, byte[]? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }

            if (left is null)
            {
                return -1;
            }

            return right is null ? 1 : left.AsSpan().SequenceCompareTo(right);
        }
    }
}

internal sealed record ReceiptExpectation(
    CanonicalStoragePlacementResult Placement,
    ulong Generation,
    ulong Cursor,
    byte[] OperationId,
    byte[] PreviousCommitHash,
    byte[] PayloadDigest,
    byte[]? TombstoneTarget)
{
    public static ReceiptExpectation Create(
        CanonicalStoragePlacementResult placement,
        ulong generation,
        ulong cursor,
        byte[] operationId,
        byte[] previousCommitHash,
        byte[] payloadDigest,
        byte[]? tombstoneTarget)
    {
        if (generation == 0 || cursor == 0 ||
            operationId.Length != 16 ||
            previousCommitHash.Length != 32 ||
            payloadDigest.Length != 32 ||
            tombstoneTarget is { Length: not 16 })
        {
            throw new ArgumentException("Receipt expectation has a non-canonical field.");
        }

        return new ReceiptExpectation(
            placement,
            generation,
            cursor,
            operationId.ToArray(),
            previousCommitHash.ToArray(),
            payloadDigest.ToArray(),
            tombstoneTarget?.ToArray());
    }
}

internal sealed record SimulatedBoundReceipt(
    ulong MembershipEpoch,
    StorageReplicaId ReplicaId,
    ulong Generation,
    ulong Cursor,
    byte[] OperationId,
    byte[] PreviousCommitHash,
    byte[] PayloadDigest,
    byte[]? TombstoneTarget,
    bool Durable)
{
    public static SimulatedBoundReceipt From(
        ReceiptExpectation expectation,
        StorageReplicaId replicaId) =>
        new(
            expectation.Placement.MembershipEpoch,
            replicaId,
            expectation.Generation,
            expectation.Cursor,
            expectation.OperationId.ToArray(),
            expectation.PreviousCommitHash.ToArray(),
            expectation.PayloadDigest.ToArray(),
            expectation.TombstoneTarget?.ToArray(),
            true);
}

internal enum BoundQuorumStatus
{
    NoQuorum,
    Durable
}

internal static class BoundReceiptEvaluator
{
    public static BoundQuorumStatus Evaluate(
        ReceiptExpectation expectation,
        IReadOnlyCollection<SimulatedBoundReceipt> receipts)
    {
        var owners = expectation.Placement.Replicas.ToHashSet();
        var valid = receipts
            .Where(receipt =>
                receipt.Durable &&
                owners.Contains(receipt.ReplicaId) &&
                receipt.MembershipEpoch == expectation.Placement.MembershipEpoch &&
                receipt.Generation == expectation.Generation &&
                receipt.Cursor == expectation.Cursor &&
                Equal(receipt.OperationId, expectation.OperationId) &&
                Equal(receipt.PreviousCommitHash, expectation.PreviousCommitHash) &&
                Equal(receipt.PayloadDigest, expectation.PayloadDigest) &&
                Equal(receipt.TombstoneTarget, expectation.TombstoneTarget))
            .Select(static receipt => receipt.ReplicaId)
            .Distinct()
            .Count();

        return valid >= 2 ? BoundQuorumStatus.Durable : BoundQuorumStatus.NoQuorum;
    }

    private static bool Equal(byte[]? left, byte[]? right) =>
        left is null ? right is null : right is not null && left.AsSpan().SequenceEqual(right);
}

internal enum EpochOverlapStatus
{
    NoActiveQuorum,
    ActiveDurablePreviousGap,
    DurableBothEpochs
}

internal static class EpochOverlapEvaluator
{
    public static EpochOverlapStatus Evaluate(
        ReceiptExpectation previous,
        IReadOnlyCollection<SimulatedBoundReceipt> previousReceipts,
        ReceiptExpectation active,
        IReadOnlyCollection<SimulatedBoundReceipt> activeReceipts,
        bool previousContinuityWasComplete)
    {
        if (active.Placement.MembershipEpoch != previous.Placement.MembershipEpoch + 1)
        {
            throw new ArgumentException("Only E/E+1 overlap is permitted.");
        }

        if (BoundReceiptEvaluator.Evaluate(active, activeReceipts) != BoundQuorumStatus.Durable)
        {
            return EpochOverlapStatus.NoActiveQuorum;
        }

        return previousContinuityWasComplete &&
               BoundReceiptEvaluator.Evaluate(previous, previousReceipts) == BoundQuorumStatus.Durable
            ? EpochOverlapStatus.DurableBothEpochs
            : EpochOverlapStatus.ActiveDurablePreviousGap;
    }
}

internal sealed record CanonicalStorageOperation(
    byte[] LogicalObjectId,
    byte[] PayloadDigest,
    byte[]? TombstoneTarget)
{
    public bool IsTombstone => TombstoneTarget is not null;
}

internal sealed record CommittedStorageRecord(
    ulong MembershipEpoch,
    ulong Generation,
    ulong Cursor,
    byte[] LogicalObjectId,
    byte[] EpochOperationId,
    byte[] PreviousCommitHash,
    byte[] CommitHash,
    byte[] PayloadDigest,
    byte[]? TombstoneTarget,
    IReadOnlyList<SimulatedBoundReceipt> DurableOwnerReceipts);

internal enum QuorumAppendStatus
{
    Committed,
    Idempotent,
    HeadConflict,
    IdempotencyConflict
}

internal sealed record QuorumAppendResult(QuorumAppendStatus Status, ulong Cursor);

internal enum AuthenticatedReadStatus
{
    Complete,
    NoMatchingHighWater
}

internal sealed record ReplicaHighWaterEvidence(
    StorageReplicaId ReplicaId,
    ulong MembershipEpoch,
    ulong Generation,
    ulong Cursor,
    byte[] CommitHash,
    byte[] EvidenceDigest);

internal sealed record VisibleStorageObject(byte[] LogicalObjectId, byte[] PayloadDigest);

internal sealed record AuthenticatedReadPage(
    AuthenticatedReadStatus Status,
    ulong HighWaterCursor,
    IReadOnlyList<ReplicaHighWaterEvidence> HighWaterEvidence,
    IReadOnlyList<CommittedStorageRecord> Records,
    IReadOnlyList<VisibleStorageObject> VisibleObjects);

/// <summary>
/// A pure executable protocol model. The global record list is the model oracle;
/// individual replica prefixes are the observable state used by every operation.
/// A production implementation would use a per-slot quorum ballot/CAS protocol,
/// not this in-memory oracle.
/// </summary>
internal sealed class QuorumLogProtocolSimulator
{
    private static ReadOnlySpan<byte> OperationDomain => "deep-storage-epoch-operation-v1"u8;
    private static ReadOnlySpan<byte> CommitDomain => "deep-storage-commit-chain-v1"u8;
    private static ReadOnlySpan<byte> HighWaterDomain => "deep-storage-high-water-v1"u8;

    private readonly CanonicalStoragePlacementResult _placement;
    private readonly ulong _generation;
    private readonly Dictionary<StorageReplicaId, List<CommittedStorageRecord>> _replicaPrefixes;
    private readonly List<CommittedStorageRecord> _committed = new();

    public QuorumLogProtocolSimulator(
        CanonicalStoragePlacementResult placement,
        ulong generation)
    {
        _placement = placement;
        _generation = generation;
        if (generation == 0 || placement.Replicas.Count != 3)
        {
            throw new ArgumentException("A nonzero generation and exact N=3 placement are required.");
        }

        _replicaPrefixes = placement.Replicas.ToDictionary(
            static replica => replica,
            static _ => new List<CommittedStorageRecord>());
    }

    public IReadOnlyList<CommittedStorageRecord> CommittedRecords => _committed;

    public QuorumAppendResult TryAppend(
        CanonicalStorageOperation operation,
        ulong expectedCommittedCursor,
        IReadOnlyCollection<StorageReplicaId> quorum)
    {
        ValidateOperation(operation);
        var existing = _committed.FirstOrDefault(record =>
            record.LogicalObjectId.AsSpan().SequenceEqual(operation.LogicalObjectId));
        if (existing is not null)
        {
            var same = existing.PayloadDigest.AsSpan().SequenceEqual(operation.PayloadDigest) &&
                       Equal(existing.TombstoneTarget, operation.TombstoneTarget);
            return new QuorumAppendResult(
                same ? QuorumAppendStatus.Idempotent : QuorumAppendStatus.IdempotencyConflict,
                existing.Cursor);
        }

        var owners = quorum.Distinct().ToArray();
        if (owners.Length != 2 || owners.Any(owner => !_replicaPrefixes.ContainsKey(owner)))
        {
            throw new ArgumentException("An append requires two distinct exact HRW owners.");
        }

        var expectedHash = expectedCommittedCursor == 0
            ? new byte[32]
            : _committed.Single(record => record.Cursor == expectedCommittedCursor).CommitHash;
        var headsMatch = owners.All(owner =>
        {
            var prefix = _replicaPrefixes[owner];
            var cursor = (ulong)prefix.Count;
            var hash = prefix.Count == 0 ? new byte[32] : prefix[^1].CommitHash;
            return cursor == expectedCommittedCursor && hash.AsSpan().SequenceEqual(expectedHash);
        });
        if (!headsMatch || expectedCommittedCursor != (ulong)_committed.Count)
        {
            return new QuorumAppendResult(QuorumAppendStatus.HeadConflict, (ulong)_committed.Count);
        }

        var cursor = expectedCommittedCursor + 1;
        var epochOperationId = DeriveEpochOperationId(operation, cursor, expectedHash);
        var commitHash = DeriveCommitHash(operation, cursor, epochOperationId, expectedHash);
        var expectation = ReceiptExpectation.Create(
            _placement,
            _generation,
            cursor,
            epochOperationId,
            expectedHash,
            operation.PayloadDigest,
            operation.TombstoneTarget);
        var receipts = owners
            .Select(owner => SimulatedBoundReceipt.From(expectation, owner))
            .ToArray();
        if (BoundReceiptEvaluator.Evaluate(expectation, receipts) != BoundQuorumStatus.Durable)
        {
            throw new InvalidOperationException("The model cannot commit without exact W=2 evidence.");
        }

        var record = new CommittedStorageRecord(
            _placement.MembershipEpoch,
            _generation,
            cursor,
            operation.LogicalObjectId.ToArray(),
            epochOperationId,
            expectedHash.ToArray(),
            commitHash,
            operation.PayloadDigest.ToArray(),
            operation.TombstoneTarget?.ToArray(),
            receipts);
        _committed.Add(record);
        foreach (var owner in owners)
        {
            _replicaPrefixes[owner].Add(record);
        }

        return new QuorumAppendResult(QuorumAppendStatus.Committed, cursor);
    }

    public void CatchUp(StorageReplicaId target, StorageReplicaId source)
    {
        var targetPrefix = _replicaPrefixes[target];
        var sourcePrefix = _replicaPrefixes[source];
        if (targetPrefix.Count > sourcePrefix.Count)
        {
            throw new InvalidOperationException("Repair cannot roll a prefix back.");
        }

        for (var index = 0; index < targetPrefix.Count; index++)
        {
            if (!targetPrefix[index].CommitHash.AsSpan().SequenceEqual(sourcePrefix[index].CommitHash))
            {
                throw new InvalidOperationException("Conflicting authenticated prefixes cannot be repaired silently.");
            }
        }

        foreach (var record in sourcePrefix.Skip(targetPrefix.Count))
        {
            if (record.DurableOwnerReceipts.Count < 2)
            {
                throw new InvalidOperationException("Repair requires per-record W2 evidence.");
            }

            targetPrefix.Add(record);
        }
    }

    public AuthenticatedReadPage ReadAuthenticatedPage(
        IReadOnlyCollection<StorageReplicaId> readQuorum,
        ulong afterCursor)
    {
        var readers = readQuorum.Distinct().ToArray();
        if (readers.Length != 2 || readers.Any(reader => !_replicaPrefixes.ContainsKey(reader)))
        {
            throw new ArgumentException("Read requires two distinct exact HRW owners.");
        }

        var prefixes = readers.Select(reader => _replicaPrefixes[reader]).ToArray();
        var sameHead = prefixes[0].Count == prefixes[1].Count &&
                       (prefixes[0].Count == 0 ||
                        prefixes[0][^1].CommitHash.AsSpan().SequenceEqual(prefixes[1][^1].CommitHash));
        if (!sameHead)
        {
            return EmptyRead(AuthenticatedReadStatus.NoMatchingHighWater);
        }

        var head = (ulong)prefixes[0].Count;
        var headHash = head == 0 ? new byte[32] : prefixes[0][^1].CommitHash;
        var evidence = readers
            .Select(reader => new ReplicaHighWaterEvidence(
                reader,
                _placement.MembershipEpoch,
                _generation,
                head,
                headHash.ToArray(),
                HighWaterDigest(reader, head, headHash)))
            .ToArray();
        var records = prefixes[0]
            .Where(record => record.Cursor > afterCursor)
            .ToArray();
        var expectedCount = head > afterCursor ? checked((int)(head - afterCursor)) : 0;
        if (records.Length != expectedCount ||
            records.Select(static record => record.Cursor)
                .SequenceEqual(Enumerable.Range(1, records.Length).Select(index => afterCursor + (ulong)index)) is false ||
            records.Any(static record => record.DurableOwnerReceipts.Count < 2))
        {
            return EmptyRead(AuthenticatedReadStatus.NoMatchingHighWater);
        }

        var visible = new Dictionary<string, VisibleStorageObject>(StringComparer.Ordinal);
        foreach (var record in prefixes[0])
        {
            if (record.TombstoneTarget is null)
            {
                visible[Convert.ToHexString(record.LogicalObjectId)] =
                    new VisibleStorageObject(record.LogicalObjectId.ToArray(), record.PayloadDigest.ToArray());
            }
            else
            {
                visible.Remove(Convert.ToHexString(record.TombstoneTarget));
            }
        }

        return new AuthenticatedReadPage(
            AuthenticatedReadStatus.Complete,
            head,
            evidence,
            records,
            visible.Values.ToArray());
    }

    private AuthenticatedReadPage EmptyRead(AuthenticatedReadStatus status) =>
        new(status, 0, Array.Empty<ReplicaHighWaterEvidence>(),
            Array.Empty<CommittedStorageRecord>(), Array.Empty<VisibleStorageObject>());

    private byte[] DeriveEpochOperationId(
        CanonicalStorageOperation operation,
        ulong cursor,
        ReadOnlySpan<byte> previousCommitHash)
    {
        var tombstone = operation.TombstoneTarget ?? Array.Empty<byte>();
        var input = new byte[
            OperationDomain.Length + 8 + 8 + 8 + 32 + 16 + 32 + 1 + tombstone.Length];
        var offset = 0;
        OperationDomain.CopyTo(input);
        offset += OperationDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), _placement.MembershipEpoch);
        offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), _generation);
        offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), cursor);
        offset += 8;
        previousCommitHash.CopyTo(input.AsSpan(offset));
        offset += 32;
        operation.LogicalObjectId.CopyTo(input, offset);
        offset += 16;
        operation.PayloadDigest.CopyTo(input, offset);
        offset += 32;
        input[offset++] = operation.IsTombstone ? (byte)1 : (byte)0;
        tombstone.CopyTo(input, offset);
        return SHA256.HashData(input)[..16];
    }

    private static byte[] DeriveCommitHash(
        CanonicalStorageOperation operation,
        ulong cursor,
        ReadOnlySpan<byte> epochOperationId,
        ReadOnlySpan<byte> previousCommitHash)
    {
        var tombstone = operation.TombstoneTarget ?? Array.Empty<byte>();
        var input = new byte[
            CommitDomain.Length + 8 + 16 + 32 + 16 + 32 + 1 + tombstone.Length];
        var offset = 0;
        CommitDomain.CopyTo(input);
        offset += CommitDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), cursor);
        offset += 8;
        epochOperationId.CopyTo(input.AsSpan(offset));
        offset += 16;
        previousCommitHash.CopyTo(input.AsSpan(offset));
        offset += 32;
        operation.LogicalObjectId.CopyTo(input, offset);
        offset += 16;
        operation.PayloadDigest.CopyTo(input, offset);
        offset += 32;
        input[offset++] = operation.IsTombstone ? (byte)1 : (byte)0;
        tombstone.CopyTo(input, offset);
        return SHA256.HashData(input);
    }

    private byte[] HighWaterDigest(
        StorageReplicaId replica,
        ulong cursor,
        ReadOnlySpan<byte> commitHash)
    {
        var input = new byte[HighWaterDomain.Length + 16 + 8 + 8 + 8 + 32];
        var offset = 0;
        HighWaterDomain.CopyTo(input);
        offset += HighWaterDomain.Length;
        replica.Bytes.Span.CopyTo(input.AsSpan(offset));
        offset += 16;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), _placement.MembershipEpoch);
        offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), _generation);
        offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(offset), cursor);
        offset += 8;
        commitHash.CopyTo(input.AsSpan(offset));
        return SHA256.HashData(input);
    }

    private static void ValidateOperation(CanonicalStorageOperation operation)
    {
        if (operation.LogicalObjectId.Length != 16 ||
            operation.PayloadDigest.Length != 32 ||
            operation.TombstoneTarget is { Length: not 16 } ||
            operation.TombstoneTarget is not null &&
            operation.TombstoneTarget.AsSpan().SequenceEqual(operation.LogicalObjectId))
        {
            throw new ArgumentException("Operation identity, digest or tombstone target is invalid.");
        }
    }

    private static bool Equal(byte[]? left, byte[]? right) =>
        left is null ? right is null : right is not null && left.AsSpan().SequenceEqual(right);
}
