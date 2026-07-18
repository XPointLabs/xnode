using System.Security.Cryptography;
using Xunit.Abstractions;

namespace XNode.Tests.Design.StorageReplication;

public sealed class StoragePlacementSimulatorTests(ITestOutputHelper output)
{
    private static readonly int[] MembershipSizes = [4, 20, 100, 1000];

    [Theory]
    [MemberData(nameof(MembershipSizeCases))]
    public void ReplicaOwnership_IsIndependentOfRequestNonce(int membershipSize)
    {
        var membership = CreateMembership(membershipSize);
        var placementKey = PlacementKey(17);
        var routeHops = new[] { "route-entry", "route-middle", "route-exit" };

        var first = StoragePlacementSimulator.Assign(
            new PlacementSimulationRequest(placementKey, 41, "nonce-a", routeHops),
            membership);
        var retry = StoragePlacementSimulator.Assign(
            new PlacementSimulationRequest(placementKey, 41, "nonce-b", routeHops),
            membership);

        Assert.Equal(first.ReplicaIds, retry.ReplicaIds);
        Assert.Equal(3, first.ReplicaIds.Count);
        Assert.Equal(3, first.ReplicaIds.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(routeHops, first.RouteHopIds);
        Assert.DoesNotContain(first.ReplicaIds, routeHops.Contains);
    }

    [Theory]
    [MemberData(nameof(MembershipSizeCases))]
    public void Distribution_RemainsWithinPublishedDeterministicBound(int membershipSize)
    {
        const int keyCount = 8192;
        var membership = CreateMembership(membershipSize);
        var counts = membership.ToDictionary(static node => node, static _ => 0, StringComparer.Ordinal);

        for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
        {
            var result = StoragePlacementSimulator.Assign(
                new PlacementSimulationRequest(
                    PlacementKey(keyIndex),
                    73,
                    $"nonce-{keyIndex}",
                    ["route-entry", "route-middle", "route-exit"]),
                membership);

            foreach (var replicaId in result.ReplicaIds)
            {
                counts[replicaId]++;
            }
        }

        var report = PlacementDistributionReport.Create(membershipSize, keyCount, counts.Values);
        output.WriteLine(
            "members={0}; keys={1}; assignments={2}; min={3}; max={4}; mean={5:F2}; cv={6:F4}; sevenSigmaMax={7:F2}",
            report.MembershipSize,
            report.KeyCount,
            report.AssignmentCount,
            report.Minimum,
            report.Maximum,
            report.Mean,
            report.CoefficientOfVariation,
            report.SevenSigmaUpperBound);

        Assert.Equal(keyCount * StoragePlacementSimulator.ReplicationFactor, report.AssignmentCount);
        Assert.True(
            report.CoefficientOfVariation <= 0.35,
            $"N={membershipSize}: CV {report.CoefficientOfVariation:F4} exceeded 0.35; " +
            $"min={report.Minimum}, max={report.Maximum}, mean={report.Mean:F2}.");
        Assert.True(
            report.Maximum <= report.SevenSigmaUpperBound,
            $"N={membershipSize}: max {report.Maximum} exceeded seven-sigma bound " +
            $"{report.SevenSigmaUpperBound:F2}.");
    }

    [Theory]
    [MemberData(nameof(MembershipSizeCases))]
    public void AddingMember_HasMinimalRemap_AndPreservesSurvivingReplicaOrder(int membershipSize)
    {
        const int keyCount = 8192;
        var beforeMembership = CreateMembership(membershipSize);
        var afterMembership = CreateMembership(membershipSize + 1);
        var addedMember = $"storage-node-{membershipSize:D4}";
        var changed = 0;

        for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
        {
            var before = Assign(keyIndex, 90, beforeMembership);
            var after = Assign(keyIndex, 91, afterMembership);

            if (before.ReplicaIds.SequenceEqual(after.ReplicaIds, StringComparer.Ordinal))
            {
                continue;
            }

            changed++;
            Assert.Contains(addedMember, after.ReplicaIds);
            Assert.True(
                before.ReplicaIds.Intersect(after.ReplicaIds, StringComparer.Ordinal).Count() >= 2,
                "Adding one member may evict at most one of three existing owners.");
        }

        var remapFraction = changed / (double)keyCount;
        var expectedFraction = StoragePlacementSimulator.ReplicationFactor / (double)(membershipSize + 1);
        output.WriteLine(
            "members={0}->{1}; changed={2}/{3}; remap={4:F6}; expected={5:F6}",
            membershipSize,
            membershipSize + 1,
            changed,
            keyCount,
            remapFraction,
            expectedFraction);
        Assert.InRange(
            remapFraction,
            Math.Max(0, expectedFraction * 0.35),
            Math.Min(1, (expectedFraction * 1.65) + 0.002));
    }

    [Fact]
    public void RemovingMember_OnlyRemapsKeysPreviouslyOwnedByThatMember()
    {
        const int keyCount = 4096;
        var beforeMembership = CreateMembership(100);
        var removed = "storage-node-0042";
        var afterMembership = beforeMembership.Where(node => node != removed).ToArray();

        for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
        {
            var before = Assign(keyIndex, 105, beforeMembership);
            var after = Assign(keyIndex, 106, afterMembership);

            if (!before.ReplicaIds.Contains(removed, StringComparer.Ordinal))
            {
                Assert.Equal(before.ReplicaIds, after.ReplicaIds);
                continue;
            }

            Assert.Equal(
                before.ReplicaIds.Where(node => node != removed),
                after.ReplicaIds.Take(2));
        }
    }

    [Fact]
    public void EpochOverlap_IsBoundedAndNeverCombinesQuorumsAcrossEpochs()
    {
        var epochE = Assign(31, 300, CreateMembership(20));
        var epochEPlusOne = Assign(31, 301, CreateMembership(21));

        var overlap = StoragePlacementSimulator.PlanEpochOverlap(
            epochE,
            epochEPlusOne,
            nowUnixSeconds: 1_000,
            overlapUntilUnixSeconds: 1_100);

        Assert.True(overlap.IsActive);
        Assert.Equal(2, overlap.Epochs.Count);
        Assert.InRange(overlap.DistinctReplicaIds.Count, 3, 6);

        var wrongEpochReceipts = new[]
        {
            new SimulatedReplicaReceipt(300, epochE.ReplicaIds[0], 8, false, "digest-a", true),
            new SimulatedReplicaReceipt(301, epochEPlusOne.ReplicaIds[0], 8, false, "digest-a", true)
        };

        var decision = StoragePlacementSimulator.EvaluateRead(301, wrongEpochReceipts);
        Assert.Equal(SimulatedReadStatus.NoQuorum, decision.Status);
    }

    [Fact]
    public void FailureMatrix_OneReplicaLossStaleReadSplitMembershipAndRetries()
    {
        var writeWithOneLoss = StoragePlacementSimulator.EvaluateWrite(
            membershipEpoch: 500,
            [
                Receipt(500, "a", cursor: 10, digest: "payload", durable: true),
                Receipt(500, "b", cursor: 10, digest: "payload", durable: true)
            ]);
        Assert.Equal(SimulatedWriteStatus.Durable, writeWithOneLoss.Status);

        var staleRead = StoragePlacementSimulator.EvaluateRead(
            membershipEpoch: 500,
            [
                Receipt(500, "a", cursor: 10, digest: "old", durable: true),
                Receipt(500, "b", cursor: 11, digest: "new", durable: true),
                Receipt(500, "c", cursor: 11, digest: "new", durable: true)
            ]);
        Assert.Equal(SimulatedReadStatus.Quorum, staleRead.Status);
        Assert.Equal<ulong>(11, staleRead.Cursor);
        Assert.True(staleRead.RepairRequired);

        var splitMembership = StoragePlacementSimulator.EvaluateWrite(
            membershipEpoch: 501,
            [
                Receipt(500, "a", cursor: 12, digest: "payload", durable: true),
                Receipt(501, "b", cursor: 12, digest: "payload", durable: true)
            ]);
        Assert.Equal(SimulatedWriteStatus.NoQuorum, splitMembership.Status);

        var first = StoragePlacementSimulator.EvaluateRetry(
            previous: null,
            idempotencyKey: "idem-1",
            canonicalRequestDigest: "request-a",
            cachedResultDigest: "result-a");
        var exactRetry = StoragePlacementSimulator.EvaluateRetry(
            first.CacheEntry,
            "idem-1",
            "request-a",
            "ignored");
        var conflict = StoragePlacementSimulator.EvaluateRetry(
            first.CacheEntry,
            "idem-1",
            "request-b",
            "ignored");

        Assert.Equal(SimulatedRetryStatus.New, first.Status);
        Assert.Equal(SimulatedRetryStatus.Cached, exactRetry.Status);
        Assert.Equal("result-a", exactRetry.ResultDigest);
        Assert.Equal(SimulatedRetryStatus.Conflict, conflict.Status);
    }

    [Fact]
    public void TombstoneDominatesEqualCursor_AndRollbackCannotResurrectPayload()
    {
        var read = StoragePlacementSimulator.EvaluateRead(
            membershipEpoch: 700,
            [
                Receipt(700, "a", cursor: 23, digest: "payload", durable: true),
                Receipt(700, "b", cursor: 23, digest: "tombstone", durable: true, tombstone: true),
                Receipt(700, "c", cursor: 23, digest: "tombstone", durable: true, tombstone: true)
            ]);

        Assert.Equal(SimulatedReadStatus.Quorum, read.Status);
        Assert.True(read.IsTombstone);
        Assert.Equal("tombstone", read.PayloadDigest);
        Assert.True(read.RepairRequired);
    }

    public static IEnumerable<object[]> MembershipSizeCases() =>
        MembershipSizes.Select(static size => new object[] { size });

    private static StoragePlacementResult Assign(
        int keyIndex,
        ulong epoch,
        IReadOnlyList<string> membership) =>
        StoragePlacementSimulator.Assign(
            new PlacementSimulationRequest(
                PlacementKey(keyIndex),
                epoch,
                $"nonce-{keyIndex}",
                ["route-entry", "route-middle", "route-exit"]),
            membership);

    private static SimulatedReplicaReceipt Receipt(
        ulong epoch,
        string replicaId,
        ulong cursor,
        string digest,
        bool durable,
        bool tombstone = false) =>
        new(epoch, replicaId, cursor, tombstone, digest, durable);

    private static string[] CreateMembership(int count) =>
        Enumerable.Range(0, count)
            .Select(static index => $"storage-node-{index:D4}")
            .ToArray();

    private static byte[] PlacementKey(int index) =>
        SHA256.HashData(BitConverter.GetBytes(index));
}
