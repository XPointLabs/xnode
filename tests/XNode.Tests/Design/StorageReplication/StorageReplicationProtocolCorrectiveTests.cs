using System.Buffers.Binary;
using System.Security.Cryptography;
using Xunit.Abstractions;

namespace XNode.Tests.Design.StorageReplication;

public sealed class StorageReplicationProtocolCorrectiveTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> MembershipSizes() =>
        new[] { 4, 20, 100, 1000 }.Select(static value => new object[] { value });

    [Theory]
    [MemberData(nameof(MembershipSizes))]
    public void CanonicalBinaryPlacement_IsNonceIndependentBalancedAndMinimalRemap(int memberCount)
    {
        const int keyCount = 8192;
        var before = Members(memberCount);
        var after = Members(memberCount + 1);
        var route = Route();
        var loads = before.ToDictionary(static id => id, static _ => 0);
        var changed = 0;

        for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
        {
            var key = Key(keyIndex);
            var first = CanonicalStoragePlacementSimulator.Assign(key, 50, Nonce(keyIndex, 1), route, before);
            var retry = CanonicalStoragePlacementSimulator.Assign(key, 50, Nonce(keyIndex, 2), route, before);
            var next = CanonicalStoragePlacementSimulator.Assign(key, 51, Nonce(keyIndex, 3), route, after);

            Assert.Equal(first.Replicas, retry.Replicas);
            Assert.Equal(3, first.Replicas.Distinct().Count());
            Assert.Equal(route, first.RouteHops);
            Assert.All(first.Replicas, replica => loads[replica]++);

            if (!first.Replicas.SequenceEqual(next.Replicas))
            {
                changed++;
                Assert.Contains(after[^1], next.Replicas);
                Assert.True(first.Replicas.Intersect(next.Replicas).Count() >= 2);
            }
        }

        var report = CanonicalPlacementDistribution.Create(memberCount, keyCount, loads.Values);
        var actualRemap = changed / (double)keyCount;
        var expectedRemap = 3d / (memberCount + 1);
        output.WriteLine(
            "members={0}; min={1}; max={2}; mean={3:F2}; cv={4:F4}; remap={5:F6}; expected={6:F6}",
            memberCount,
            report.Minimum,
            report.Maximum,
            report.Mean,
            report.CoefficientOfVariation,
            actualRemap,
            expectedRemap);

        Assert.True(report.CoefficientOfVariation <= 0.35);
        Assert.InRange(
            actualRemap,
            Math.Max(0, expectedRemap * 0.35),
            Math.Min(1, (expectedRemap * 1.65) + 0.002));
    }

    [Fact]
    public void CanonicalPlacement_HasPinnedBinaryGoldenOwners_AndDistinctIdTypes()
    {
        var result = CanonicalStoragePlacementSimulator.Assign(
            Key(0x01020304),
            99,
            Nonce(1, 1),
            Route(),
            Members(20));

        Assert.NotEqual(typeof(RouteHopId), typeof(StorageReplicaId));
        Assert.All(result.RouteHops, static hop => Assert.Equal(32, hop.Bytes.Length));
        Assert.All(result.Replicas, static replica => Assert.Equal(16, replica.Bytes.Length));
        Assert.Equal(
            new[]
            {
                "7fde8eebf388fcff667a89be60430cc6",
                "5085cb99dbe1e374ccd321e5b58182d2",
                "14236fe421fe9ddb8377a19b60ce71dd"
            },
            result.Replicas.Select(static replica => replica.ToString()));
    }

    [Fact]
    public void ReceiptQuorum_RequiresExactOwnersEpochOperationGenerationCursorAndDigest()
    {
        var placement = CanonicalStoragePlacementSimulator.Assign(
            Key(7), 200, Nonce(7, 1), Route(), Members(20));
        var expectation = ReceiptExpectation.Create(
            placement,
            generation: 8,
            cursor: 12,
            operationId: Fixed16(0xA0),
            previousCommitHash: Fixed32(0xB0),
            payloadDigest: Fixed32(0xC0),
            tombstoneTarget: null);

        var valid = new[]
        {
            SimulatedBoundReceipt.From(expectation, placement.Replicas[0]),
            SimulatedBoundReceipt.From(expectation, placement.Replicas[1])
        };

        Assert.Equal(BoundQuorumStatus.Durable, BoundReceiptEvaluator.Evaluate(expectation, valid));

        var outsider = new StorageReplicaId(Fixed16(0x01));
        Assert.Equal(
            BoundQuorumStatus.NoQuorum,
            BoundReceiptEvaluator.Evaluate(
                expectation,
                [valid[0], SimulatedBoundReceipt.From(expectation, outsider)]));
        Assert.Equal(
            BoundQuorumStatus.NoQuorum,
            BoundReceiptEvaluator.Evaluate(
                expectation,
                [valid[0], valid[1] with { Generation = 9 }]));
        Assert.Equal(
            BoundQuorumStatus.NoQuorum,
            BoundReceiptEvaluator.Evaluate(
                expectation,
                [valid[0], valid[1] with { OperationId = Fixed16(0xD0) }]));
    }

    [Fact]
    public void QuorumLog_AlternatingPairsPreserveCanonicalCursorAndPrefix()
    {
        var replicas = Members(3);
        var log = new QuorumLogProtocolSimulator(Placement(replicas, 300), generation: 4);

        var first = log.TryAppend(Operation(1), expectedCommittedCursor: 0, [replicas[0], replicas[1]]);
        Assert.Equal(QuorumAppendStatus.Committed, first.Status);
        Assert.Equal<ulong>(1, first.Cursor);

        var staleConcurrent = log.TryAppend(
            Operation(2),
            expectedCommittedCursor: 0,
            [replicas[1], replicas[2]]);
        Assert.Equal(QuorumAppendStatus.HeadConflict, staleConcurrent.Status);

        log.CatchUp(replicas[2], replicas[1]);
        var second = log.TryAppend(
            Operation(2),
            expectedCommittedCursor: 1,
            [replicas[1], replicas[2]]);
        Assert.Equal(QuorumAppendStatus.Committed, second.Status);
        Assert.Equal<ulong>(2, second.Cursor);

        log.CatchUp(replicas[0], replicas[2]);
        var third = log.TryAppend(
            Operation(3),
            expectedCommittedCursor: 2,
            [replicas[0], replicas[2]]);
        Assert.Equal(QuorumAppendStatus.Committed, third.Status);
        Assert.Equal<ulong>(3, third.Cursor);

        Assert.Equal(new ulong[] { 1, 2, 3 }, log.CommittedRecords.Select(static record => record.Cursor));
        Assert.All(log.CommittedRecords, static record => Assert.Equal(2, record.DurableOwnerReceipts.Count));

        log.CatchUp(replicas[1], replicas[0]);
        var challenge = Nonce(300, 1);
        var lkg = new ClientHighWaterLkg();
        var firstPage = log.ReadAuthenticatedPage(
            [replicas[0], replicas[1]], 0, maximumRecords: 2, challenge, issuedBucket: 1000);
        Assert.True(AuthenticatedReadPageVerifier.Verify(
            firstPage, log.Placement, log.Generation, 0, new byte[32],
            challenge, currentBucket: 1000, lkg));
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            firstPage with { Records = firstPage.Records.Where(record => record.Cursor != 2).ToArray() },
            log.Placement,
            log.Generation,
            0,
            new byte[32],
            challenge,
            1000,
            new ClientHighWaterLkg()));
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            firstPage with { Records = firstPage.Records.Reverse().ToArray() },
            log.Placement,
            log.Generation,
            0,
            new byte[32],
            challenge,
            1000,
            new ClientHighWaterLkg()));

        var secondPage = log.ReadAuthenticatedPage(
            [replicas[0], replicas[1]], firstPage.PageEndCursor, 2, challenge, 1000);
        Assert.True(AuthenticatedReadPageVerifier.Verify(
            secondPage,
            log.Placement,
            log.Generation,
            firstPage.PageEndCursor,
            firstPage.ContinuationHash,
            challenge,
            1000,
            lkg));
        Assert.Equal<ulong>(3, secondPage.PageEndCursor);
    }

    [Fact]
    public void UnknownOutcomeRetryIsIdempotent_AndReadRequiresAuthenticatedCompletePrefix()
    {
        var replicas = Members(3);
        var log = new QuorumLogProtocolSimulator(Placement(replicas, 301), generation: 4);
        var operation = Operation(11);

        var unknownToClient = log.TryAppend(operation, 0, [replicas[0], replicas[1]]);
        Assert.Equal(QuorumAppendStatus.Committed, unknownToClient.Status);

        var retryViaAlternateCoordinator = log.TryAppend(operation, 0, [replicas[1], replicas[2]]);
        Assert.Equal(QuorumAppendStatus.Idempotent, retryViaAlternateCoordinator.Status);
        Assert.Equal(unknownToClient.Cursor, retryViaAlternateCoordinator.Cursor);

        var challenge = Nonce(400, 1);
        var incomplete = log.ReadAuthenticatedPage(
            [replicas[1], replicas[2]], afterCursor: 0, 16, challenge, 1000);
        Assert.Equal(AuthenticatedReadStatus.NoMatchingHighWater, incomplete.Status);

        log.CatchUp(replicas[2], replicas[1]);
        var complete = log.ReadAuthenticatedPage(
            [replicas[1], replicas[2]], afterCursor: 0, 16, challenge, 1000);
        Assert.Equal(AuthenticatedReadStatus.Complete, complete.Status);
        Assert.Equal<ulong>(1, complete.HighWaterCursor);
        Assert.Equal(2, complete.HighWaterEvidence.Count);
        Assert.Single(complete.Records);
        Assert.All(complete.Records, static record => Assert.Equal(2, record.DurableOwnerReceipts.Count));
    }

    [Fact]
    public void TombstoneTargetsImmutableObject_AndHigherCursorCannotResurrectIt()
    {
        var replicas = Members(3);
        var log = new QuorumLogProtocolSimulator(Placement(replicas, 302), generation: 4);
        var original = Operation(21);
        var stored = log.TryAppend(original, 0, [replicas[0], replicas[1]]);
        log.CatchUp(replicas[2], replicas[1]);

        var tombstone = TombstoneOperation(22, original.LogicalObjectId);
        var removed = log.TryAppend(tombstone, stored.Cursor, [replicas[1], replicas[2]]);
        Assert.Equal(QuorumAppendStatus.Committed, removed.Status);
        Assert.Equal<ulong>(2, removed.Cursor);

        log.CatchUp(replicas[0], replicas[2]);
        var page = log.ReadAuthenticatedPage(
            [replicas[0], replicas[2]], 0, 16, Nonce(500, 1), 1000);
        Assert.Equal(AuthenticatedReadStatus.Complete, page.Status);
        Assert.DoesNotContain(
            page.VisibleObjects,
            item => item.LogicalObjectId.AsSpan().SequenceEqual(original.LogicalObjectId));
        Assert.Contains(
            page.Records,
            record => record.TombstoneTarget is not null &&
                record.TombstoneTarget.AsSpan().SequenceEqual(original.LogicalObjectId));
    }

    [Fact]
    public void EpochOverlapRequiresIndependentW2AndContinuityGapDisablesRollback()
    {
        var membersE = Members(20);
        var membersE1 = Members(21);
        var e = CanonicalStoragePlacementSimulator.Assign(Key(91), 400, Nonce(1, 1), Route(), membersE);
        var e1 = CanonicalStoragePlacementSimulator.Assign(Key(91), 401, Nonce(1, 2), Route(), membersE1);
        var previous = ReceiptExpectation.Create(
            e, 5, 9, Fixed16(0x10), Fixed32(0x20), Fixed32(0x30), null);
        var active = ReceiptExpectation.Create(
            e1, 5, 9, Fixed16(0x11), Fixed32(0x21), Fixed32(0x30), null);

        var gap = EpochOverlapEvaluator.Evaluate(
            previous,
            [SimulatedBoundReceipt.From(previous, e.Replicas[0])],
            active,
            [
                SimulatedBoundReceipt.From(active, e1.Replicas[0]),
                SimulatedBoundReceipt.From(active, e1.Replicas[1])
            ],
            previousContinuityWasComplete: true);
        Assert.Equal(EpochOverlapStatus.ActiveDurablePreviousGap, gap);

        var continuous = EpochOverlapEvaluator.Evaluate(
            previous,
            [
                SimulatedBoundReceipt.From(previous, e.Replicas[0]),
                SimulatedBoundReceipt.From(previous, e.Replicas[1])
            ],
            active,
            [
                SimulatedBoundReceipt.From(active, e1.Replicas[0]),
                SimulatedBoundReceipt.From(active, e1.Replicas[1])
            ],
            previousContinuityWasComplete: true);
        Assert.Equal(EpochOverlapStatus.DurableBothEpochs, continuous);
    }

    [Fact]
    public void LegacyMirrorMigration_IsSeparateAndAnyGapRemovesRollbackClaim()
    {
        Assert.Equal(
            LegacyMirrorStatus.RollbackSafe,
            LegacyMirrorEvaluator.Evaluate(
                v2FinalizedW2: true,
                legacyDurableAck: true,
                legacyReadBackMatches: true,
                continuityJournalComplete: true));
        Assert.Equal(
            LegacyMirrorStatus.NotRollbackSafe,
            LegacyMirrorEvaluator.Evaluate(
                v2FinalizedW2: true,
                legacyDurableAck: true,
                legacyReadBackMatches: false,
                continuityJournalComplete: true));
        Assert.Equal(
            LegacyMirrorStatus.NotRollbackSafe,
            LegacyMirrorEvaluator.Evaluate(
                v2FinalizedW2: true,
                legacyDurableAck: true,
                legacyReadBackMatches: true,
                continuityJournalComplete: false));
    }

    [Fact]
    public void HighWater_IsLogScopedChallengeFreshAndClientLkgRejectsReplay()
    {
        var replicas = Members(3);
        var context = new CanonicalMembershipContext(Fixed16(0x91), Fixed32(0x92));
        var placement = CanonicalStoragePlacementSimulator.Assign(
            Key(800), 500, Nonce(1, 1), Route(), replicas, context);
        var log = new QuorumLogProtocolSimulator(placement, generation: 7);
        var clientLkg = new ClientHighWaterLkg();

        log.TryAppend(Operation(31), 0, [replicas[0], replicas[1]]);
        log.CatchUp(replicas[2], replicas[1]);
        var challengeOne = Nonce(900, 1);
        var pageOne = log.ReadAuthenticatedPage(
            [replicas[1], replicas[2]], 0, 16, challengeOne, 1000);
        Assert.True(AuthenticatedReadPageVerifier.Verify(
            pageOne, placement, log.Generation, 0, new byte[32],
            challengeOne, 1000, clientLkg));

        log.TryAppend(Operation(32), 1, [replicas[1], replicas[2]]);
        log.CatchUp(replicas[0], replicas[2]);
        var challengeTwo = Nonce(900, 2);
        var pageTwo = log.ReadAuthenticatedPage(
            [replicas[0], replicas[2]], 0, 16, challengeTwo, 1000);
        Assert.True(AuthenticatedReadPageVerifier.Verify(
            pageTwo, placement, log.Generation, 0, new byte[32],
            challengeTwo, 1000, clientLkg));

        Assert.False(AuthenticatedReadPageVerifier.Verify(
            pageOne, placement, log.Generation, 0, new byte[32],
            challengeTwo, 1000, clientLkg));
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            pageOne, placement, log.Generation, 0, new byte[32],
            challengeOne, 1000, clientLkg));
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            pageTwo, placement, log.Generation, 0, new byte[32],
            challengeTwo, 1002, new ClientHighWaterLkg()));

        var otherNetwork = new CanonicalMembershipContext(Fixed16(0xA1), context.MembershipStatementHash);
        var otherPlacement = CanonicalStoragePlacementSimulator.Assign(
            Key(800), 500, Nonce(1, 1), Route(), replicas, otherNetwork);
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            pageTwo, otherPlacement, log.Generation, 0, new byte[32], challengeTwo,
            1000, new ClientHighWaterLkg()));

        var otherPlacementKey = CanonicalStoragePlacementSimulator.Assign(
            Key(801), 500, Nonce(1, 1), Route(), replicas, context);
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            pageTwo, otherPlacementKey, log.Generation, 0, new byte[32], challengeTwo,
            1000, new ClientHighWaterLkg()));

        var emptyPlacement = CanonicalStoragePlacementSimulator.Assign(
            Key(802), 501, Nonce(1, 1), Route(), replicas, context);
        var emptyLog = new QuorumLogProtocolSimulator(emptyPlacement, generation: 8);
        var emptyChallenge = Nonce(901, 1);
        var emptyPage = emptyLog.ReadAuthenticatedPage(
            [emptyPlacement.Replicas[0], emptyPlacement.Replicas[1]],
            0,
            16,
            emptyChallenge,
            1000);
        Assert.True(AuthenticatedReadPageVerifier.Verify(
            emptyPage, emptyPlacement, emptyLog.Generation, 0, new byte[32],
            emptyChallenge, 1000, new ClientHighWaterLkg()));
        var emptyOtherPlacement = CanonicalStoragePlacementSimulator.Assign(
            Key(803), 501, Nonce(1, 1), Route(), replicas, context);
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            emptyPage, emptyOtherPlacement, emptyLog.Generation, 0, new byte[32],
            emptyChallenge, 1000, new ClientHighWaterLkg()));
        var emptyOtherNetwork = CanonicalStoragePlacementSimulator.Assign(
            Key(802), 501, Nonce(1, 1), Route(), replicas, otherNetwork);
        Assert.False(AuthenticatedReadPageVerifier.Verify(
            emptyPage, emptyOtherNetwork, emptyLog.Generation, 0, new byte[32],
            emptyChallenge, 1000, new ClientHighWaterLkg()));
    }

    private static CanonicalStorageOperation Operation(int value) =>
        new(Fixed16((byte)value), Fixed32((byte)(value + 1)), null);

    private static CanonicalStorageOperation TombstoneOperation(int value, byte[] target) =>
        new(Fixed16((byte)value), Fixed32((byte)(value + 1)), target);

    private static CanonicalStoragePlacementResult Placement(
        IReadOnlyList<StorageReplicaId> replicas,
        ulong epoch) =>
        CanonicalStoragePlacementSimulator.Assign(
            Key(700),
            epoch,
            Nonce(700, 1),
            Route(),
            replicas);

    private static IReadOnlyList<StorageReplicaId> Members(int count) =>
        Enumerable.Range(0, count)
            .Select(static index =>
            {
                Span<byte> canonical = stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(canonical, index);
                return new StorageReplicaId(SHA256.HashData(canonical)[..16]);
            })
            .ToArray();

    private static IReadOnlyList<RouteHopId> Route() =>
        Enumerable.Range(0, 3)
            .Select(static index =>
            {
                Span<byte> canonical = stackalloc byte[4];
                BinaryPrimitives.WriteInt32BigEndian(canonical, index + 10_000);
                return new RouteHopId(SHA256.HashData(canonical));
            })
            .ToArray();

    private static OpaquePlacementKey32 Key(int value)
    {
        Span<byte> canonical = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(canonical, value);
        return new OpaquePlacementKey32(SHA256.HashData(canonical));
    }

    private static RequestNonce Nonce(int value, int suffix)
    {
        Span<byte> canonical = stackalloc byte[8];
        BinaryPrimitives.WriteInt32BigEndian(canonical, value);
        BinaryPrimitives.WriteInt32BigEndian(canonical[4..], suffix);
        return new RequestNonce(SHA256.HashData(canonical)[..16]);
    }

    private static byte[] Fixed16(byte value) => Enumerable.Repeat(value, 16).ToArray();

    private static byte[] Fixed32(byte value) => Enumerable.Repeat(value, 32).ToArray();
}
