using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace XNode.Tests.Design.StorageReplication;

internal sealed record PlacementSimulationRequest(
    ReadOnlyMemory<byte> OpaquePlacementKey,
    ulong MembershipEpoch,
    string RequestNonce,
    IReadOnlyList<string> RouteHopIds);

internal sealed record StoragePlacementResult(
    ulong MembershipEpoch,
    IReadOnlyList<string> RouteHopIds,
    IReadOnlyList<string> ReplicaIds);

internal sealed record EpochOverlapPlan(
    bool IsActive,
    IReadOnlyList<ulong> Epochs,
    IReadOnlySet<string> DistinctReplicaIds);

internal sealed record SimulatedReplicaReceipt(
    ulong MembershipEpoch,
    string ReplicaId,
    ulong Cursor,
    bool IsTombstone,
    string PayloadDigest,
    bool IsDurable);

internal enum SimulatedWriteStatus
{
    NoQuorum,
    Durable
}

internal sealed record SimulatedWriteDecision(
    SimulatedWriteStatus Status,
    ulong Cursor,
    bool IsTombstone,
    string? PayloadDigest);

internal enum SimulatedReadStatus
{
    NoQuorum,
    Quorum
}

internal sealed record SimulatedReadDecision(
    SimulatedReadStatus Status,
    ulong Cursor,
    bool IsTombstone,
    string? PayloadDigest,
    bool RepairRequired);

internal enum SimulatedRetryStatus
{
    New,
    Cached,
    Conflict
}

internal sealed record SimulatedRetryCacheEntry(
    string IdempotencyKey,
    string CanonicalRequestDigest,
    string ResultDigest);

internal sealed record SimulatedRetryDecision(
    SimulatedRetryStatus Status,
    string? ResultDigest,
    SimulatedRetryCacheEntry? CacheEntry);

internal sealed record PlacementDistributionReport(
    int MembershipSize,
    int KeyCount,
    int AssignmentCount,
    int Minimum,
    int Maximum,
    double Mean,
    double CoefficientOfVariation,
    double SevenSigmaUpperBound)
{
    public static PlacementDistributionReport Create(
        int membershipSize,
        int keyCount,
        IEnumerable<int> assignmentCounts)
    {
        var counts = assignmentCounts.ToArray();
        if (counts.Length != membershipSize || membershipSize < StoragePlacementSimulator.ReplicationFactor)
        {
            throw new ArgumentException("A count is required for every eligible replica.");
        }

        var assignmentCount = counts.Sum();
        var mean = assignmentCount / (double)membershipSize;
        var variance = counts.Sum(value => Math.Pow(value - mean, 2)) / membershipSize;
        var coefficientOfVariation = Math.Sqrt(variance) / mean;
        var ownershipProbability = StoragePlacementSimulator.ReplicationFactor / (double)membershipSize;
        var theoreticalVariance = keyCount * ownershipProbability * (1 - ownershipProbability);

        return new PlacementDistributionReport(
            membershipSize,
            keyCount,
            assignmentCount,
            counts.Min(),
            counts.Max(),
            mean,
            coefficientOfVariation,
            mean + (7 * Math.Sqrt(theoreticalVariance)));
    }
}

/// <summary>
/// Test-only executable model for P05. It is deliberately not referenced by
/// XNode production projects and cannot alter current route or storage behavior.
/// </summary>
internal static class StoragePlacementSimulator
{
    public const int ReplicationFactor = 3;
    public const int WriteQuorum = 2;
    public const int ReadQuorum = 2;

    private static readonly byte[] PlacementDomain =
        Encoding.ASCII.GetBytes("deep-storage-placement-hrw-v1");

    public static StoragePlacementResult Assign(
        PlacementSimulationRequest request,
        IReadOnlyCollection<string> eligibleReplicaIds)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(eligibleReplicaIds);

        if (request.OpaquePlacementKey.Length != 32)
        {
            throw new ArgumentException("The P05 simulator requires an opaque 32-byte placement key.");
        }

        if (request.MembershipEpoch == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "Membership epoch zero is reserved and cannot identify an approved snapshot.");
        }

        if (string.IsNullOrWhiteSpace(request.RequestNonce))
        {
            throw new ArgumentException("A request nonce is required for replay handling, but never for placement.");
        }

        var routeHops = request.RouteHopIds?.ToArray()
            ?? throw new ArgumentException("Route hops are required as a separate input.");
        if (routeHops.Length == 0 || routeHops.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Route hops must be explicit, non-empty router IDs.");
        }

        var members = eligibleReplicaIds
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (members.Length < ReplicationFactor || members.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException($"At least {ReplicationFactor} distinct eligible replicas are required.");
        }

        // Epoch binds the selected membership snapshot and is emitted into every
        // receipt. It intentionally does not salt the HRW score: salting every
        // epoch would remap almost all keys and defeat minimal-remap behavior.
        // RequestNonce is likewise intentionally absent from the score.
        var replicas = members
            .Select(nodeId => new ScoredReplica(nodeId, Score(request.OpaquePlacementKey.Span, nodeId)))
            .OrderByDescending(static item => item.Score, ByteArrayLexicographicComparer.Instance)
            .ThenBy(static item => item.ReplicaId, StringComparer.Ordinal)
            .Take(ReplicationFactor)
            .Select(static item => item.ReplicaId)
            .ToArray();

        return new StoragePlacementResult(request.MembershipEpoch, routeHops, replicas);
    }

    public static EpochOverlapPlan PlanEpochOverlap(
        StoragePlacementResult epochE,
        StoragePlacementResult epochEPlusOne,
        long nowUnixSeconds,
        long overlapUntilUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(epochE);
        ArgumentNullException.ThrowIfNull(epochEPlusOne);
        if (epochEPlusOne.MembershipEpoch != epochE.MembershipEpoch + 1)
        {
            throw new ArgumentException("Overlap is permitted only for adjacent E and E+1 snapshots.");
        }

        var isActive = nowUnixSeconds <= overlapUntilUnixSeconds;
        var activePlacements = isActive
            ? new[] { epochE, epochEPlusOne }
            : new[] { epochEPlusOne };

        return new EpochOverlapPlan(
            isActive,
            activePlacements.Select(static placement => placement.MembershipEpoch).ToArray(),
            activePlacements
                .SelectMany(static placement => placement.ReplicaIds)
                .ToHashSet(StringComparer.Ordinal));
    }

    public static SimulatedWriteDecision EvaluateWrite(
        ulong membershipEpoch,
        IReadOnlyCollection<SimulatedReplicaReceipt> receipts)
    {
        var sameEpoch = ValidDistinctReceipts(membershipEpoch, receipts);
        var quorum = sameEpoch
            .GroupBy(static receipt => new ReceiptValue(
                receipt.Cursor,
                receipt.IsTombstone,
                receipt.PayloadDigest))
            .Where(group => group.Count() >= WriteQuorum)
            .OrderByDescending(static group => group.Key.Cursor)
            .ThenByDescending(static group => group.Key.IsTombstone)
            .FirstOrDefault();

        return quorum is null
            ? new SimulatedWriteDecision(SimulatedWriteStatus.NoQuorum, 0, false, null)
            : new SimulatedWriteDecision(
                SimulatedWriteStatus.Durable,
                quorum.Key.Cursor,
                quorum.Key.IsTombstone,
                quorum.Key.PayloadDigest);
    }

    public static SimulatedReadDecision EvaluateRead(
        ulong membershipEpoch,
        IReadOnlyCollection<SimulatedReplicaReceipt> receipts)
    {
        var sameEpoch = ValidDistinctReceipts(membershipEpoch, receipts);
        if (sameEpoch.Length < ReadQuorum)
        {
            return NoReadQuorum();
        }

        var highestCursor = sameEpoch.Max(static receipt => receipt.Cursor);
        var highest = sameEpoch.Where(receipt => receipt.Cursor == highestCursor).ToArray();

        // At the same cursor a tombstone is irreversible. Never fall back to a
        // payload quorum if any replica has observed deletion at that cursor.
        var tombstoneObserved = highest.Any(static receipt => receipt.IsTombstone);
        var candidates = tombstoneObserved
            ? highest.Where(static receipt => receipt.IsTombstone).ToArray()
            : highest;

        var quorum = candidates
            .GroupBy(static receipt => new ReceiptValue(
                receipt.Cursor,
                receipt.IsTombstone,
                receipt.PayloadDigest))
            .FirstOrDefault(group => group.Count() >= ReadQuorum);
        if (quorum is null)
        {
            return NoReadQuorum();
        }

        var repairRequired = sameEpoch.Any(receipt =>
            receipt.Cursor != quorum.Key.Cursor ||
            receipt.IsTombstone != quorum.Key.IsTombstone ||
            !StringComparer.Ordinal.Equals(receipt.PayloadDigest, quorum.Key.PayloadDigest));

        return new SimulatedReadDecision(
            SimulatedReadStatus.Quorum,
            quorum.Key.Cursor,
            quorum.Key.IsTombstone,
            quorum.Key.PayloadDigest,
            repairRequired);
    }

    public static SimulatedRetryDecision EvaluateRetry(
        SimulatedRetryCacheEntry? previous,
        string idempotencyKey,
        string canonicalRequestDigest,
        string cachedResultDigest)
    {
        if (string.IsNullOrWhiteSpace(idempotencyKey) ||
            string.IsNullOrWhiteSpace(canonicalRequestDigest))
        {
            throw new ArgumentException("Idempotency key and canonical request digest are required.");
        }

        if (previous is null)
        {
            if (string.IsNullOrWhiteSpace(cachedResultDigest))
            {
                throw new ArgumentException("A bounded result digest is required for a new operation.");
            }

            var created = new SimulatedRetryCacheEntry(
                idempotencyKey,
                canonicalRequestDigest,
                cachedResultDigest);
            return new SimulatedRetryDecision(SimulatedRetryStatus.New, cachedResultDigest, created);
        }

        if (!StringComparer.Ordinal.Equals(previous.IdempotencyKey, idempotencyKey) ||
            !StringComparer.Ordinal.Equals(previous.CanonicalRequestDigest, canonicalRequestDigest))
        {
            return new SimulatedRetryDecision(SimulatedRetryStatus.Conflict, null, previous);
        }

        return new SimulatedRetryDecision(
            SimulatedRetryStatus.Cached,
            previous.ResultDigest,
            previous);
    }

    private static SimulatedReplicaReceipt[] ValidDistinctReceipts(
        ulong membershipEpoch,
        IReadOnlyCollection<SimulatedReplicaReceipt> receipts)
    {
        ArgumentNullException.ThrowIfNull(receipts);
        return receipts
            .Where(receipt =>
                receipt.IsDurable &&
                receipt.MembershipEpoch == membershipEpoch &&
                !string.IsNullOrWhiteSpace(receipt.ReplicaId) &&
                !string.IsNullOrWhiteSpace(receipt.PayloadDigest))
            .GroupBy(static receipt => receipt.ReplicaId, StringComparer.Ordinal)
            .Select(static group => group.First())
            .ToArray();
    }

    private static SimulatedReadDecision NoReadQuorum() =>
        new(SimulatedReadStatus.NoQuorum, 0, false, null, false);

    private static byte[] Score(ReadOnlySpan<byte> opaquePlacementKey, string replicaId)
    {
        var replicaBytes = Encoding.UTF8.GetBytes(replicaId);
        var input = new byte[
            PlacementDomain.Length +
            sizeof(ushort) +
            opaquePlacementKey.Length +
            sizeof(ushort) +
            replicaBytes.Length];
        var offset = 0;

        PlacementDomain.CopyTo(input, offset);
        offset += PlacementDomain.Length;
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), checked((ushort)opaquePlacementKey.Length));
        offset += sizeof(ushort);
        opaquePlacementKey.CopyTo(input.AsSpan(offset));
        offset += opaquePlacementKey.Length;
        BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), checked((ushort)replicaBytes.Length));
        offset += sizeof(ushort);
        replicaBytes.CopyTo(input, offset);

        return SHA256.HashData(input);
    }

    private sealed record ScoredReplica(string ReplicaId, byte[] Score);

    private sealed record ReceiptValue(ulong Cursor, bool IsTombstone, string PayloadDigest);

    private sealed class ByteArrayLexicographicComparer : IComparer<byte[]>
    {
        public static ByteArrayLexicographicComparer Instance { get; } = new();

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

            if (right is null)
            {
                return 1;
            }

            return left.AsSpan().SequenceCompareTo(right);
        }
    }
}
