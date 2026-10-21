using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.ExceptionServices;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using Peer = XNode.IntegrationTests.Runtime.CurrentMailboxReplicaReceiverTests.Fixture;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Pure document grammar tests, not authority or network acceptance.</summary>
[Collection(nameof(CurrentMailboxTlsCustodyCollection))]
public sealed class CurrentMailboxAckTargetGrammarTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task AckTargetGrammarAllowsAbsentOrIdenticalOrdinaryTombstoneFacts(int matchingFloors)
    {
        await using var peer = await Peer.CreateAsync();
        var document = Document(peer);
        for (var i = 0; i < matchingFloors; i++)
            document.PeerReplayFloors.Add(Hex((byte)(10 + i)), Floor(Target(document), Hex(20)));
        Validate(document);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task AckTargetGrammarRejectsEveryMatchingAbsentOrConflictingFactRegardlessOfOrder(
        bool absent, bool badFirst)
    {
        await using var peer = await Peer.CreateAsync();
        var document = Document(peer);
        var good = Floor(Target(document), Hex(20));
        var bad = absent ? AbsentFloor(Target(document)) : good with { TombstoneDigest = Hex(21) };
        document.PeerReplayFloors.Add(Hex(10), badFirst ? bad : good);
        document.PeerReplayFloors.Add(Hex(11), badFirst ? good : bad);
        var failure = Assert.Throws<InvalidDataException>(() => Validate(document));
        Assert.Equal("Current ACK target has conflicting original mutation custody.", failure.Message);
    }

    [Fact]
    public async Task AckTargetGrammarDoesNotConfuseUnrelatedConflictsOrEmptyTombstonesWithItsTarget()
    {
        await using var peer = await Peer.CreateAsync();
        var document = Document(peer);
        document.PeerReplayFloors.Add(Hex(10), Floor(Target(document), Hex(20)));
        document.PeerReplayFloors.Add(Hex(11), Floor(Target(document), ""));
        document.PeerReplayFloors.Add(Hex(12), Floor(Hex(30), Hex(21)));
        document.PeerReplayFloors.Add(Hex(13), Floor(Hex(30), Hex(22)));
        document.PeerReplayFloors.Add(Hex(14), AbsentFloor(Hex(30)));
        Validate(document);
    }

    [Fact]
    public async Task AckTargetGrammarRebuildsItsIndexAfterActualInputChangesBetweenInvocations()
    {
        await using var peer = await Peer.CreateAsync();
        var document = Document(peer);
        document.PeerReplayFloors.Add(Hex(10), Floor(Target(document), Hex(20)));
        Validate(document);
        document.PeerReplayFloors.Add(Hex(11), Floor(Target(document), Hex(21)));
        Assert.Throws<InvalidDataException>(() => Validate(document));
        document.PeerReplayFloors.Remove(Hex(11));
        Validate(document);
        var operation = document.AckOperations.Values.Last();
        var originalReplica = operation.ExpectedReplicaIds[0];
        operation.ExpectedReplicaIds[0] = Hex(31);
        Assert.Throws<InvalidDataException>(() => Validate(document));
        operation.ExpectedReplicaIds[0] = originalReplica;
        Validate(document);
        operation.Items[0] = operation.Items[0] with { EnvelopeDigest = Hex(32) };
        Assert.Throws<InvalidDataException>(() => Validate(document));
    }

    [Fact]
    public async Task AckTargetGrammarRetainsAllMatchingFactsAcrossManyRepeatedOriginalTargets()
    {
        await using var peer = await Peer.CreateAsync();
        var document = Document(peer, 128);
        for (var i = 1; i < 128; i++)
            document.PeerReplayFloors.Add(Key(i), Floor(Hex(30), Hex(20)));
        document.PeerReplayFloors.Add(Key(128), Floor(Target(document), Hex(20)));
        Validate(document);
        document.PeerReplayFloors.Add(Key(129), AbsentFloor(Target(document)));
        Assert.Throws<InvalidDataException>(() => Validate(document));
    }

    private static MailboxClientLedgerDocument Document(Peer peer, int acknowledgements = 2)
    {
        var document = new MailboxClientLedgerDocument(8, 0, 0, new(), new(), new(), new(), new());
        var original = MailboxPeerWireV2Codec.Decode(peer.Frame(MailboxPeerReplicationOperation.Tombstone));
        for (var index = 1; index <= acknowledgements; index++)
        {
            var operationId = new byte[16];
            BinaryPrimitives.WriteInt32BigEndian(operationId, index);
            var request = original with { OperationId = operationId };
            var item = new MailboxClientLedgerAckItem(request.Cursor, Lower(request.Payload.Span),
                request.ExpiresAtUnixSeconds, "reserved", "", 0, "", "", "",
                Convert.ToBase64String(MailboxPeerWireV2Codec.Encode(request)));
            var operation = new MailboxClientLedgerAckOperation(request.Epoch, Lower(request.BlindedMailboxId.Span),
                Lower(operationId), Hex(40), Lower(request.PlacementCommitment.Span),
                Lower(request.MembershipCommitment.Span),
                [Lower(request.SenderRouterId.Span), Lower(request.RecipientRouterId.Span)],
                request.CreatedAtUnixSeconds, request.ExpiresAtUnixSeconds, [item]);
            document.AckOperations.Add(MailboxClientOperationLedger.BuildAckOperationKey(request.Epoch,
                request.BlindedMailboxId.Span, operationId), operation);
        }
        return document;
    }

    private static string Target(MailboxClientLedgerDocument document)
    {
        var operation = document.AckOperations.Values.First();
        return MailboxPeerMutationStore.RecordKey(operation.Epoch, Convert.FromHexString(operation.MailboxId),
            Convert.FromHexString(operation.Items[0].EnvelopeDigest));
    }

    private static MailboxCurrentPeerReplayFloor Floor(string target, string tombstone) =>
        new(Hex(41), target, Hex(42), tombstone, false, "", 2_000);

    private static MailboxCurrentPeerReplayFloor AbsentFloor(string target)
    {
        var floor = Floor(target, "");
        return floor with { TombstoneDigest = MailboxCurrentPeerReplayFloor.AbsentTargetDigest(
            floor.TargetKey, floor.StoreDigest, floor.ReplayDigest) };
    }

    private static string Key(int value)
    {
        var bytes = new byte[32]; BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        return Lower(bytes);
    }

    private static string Hex(byte value) => Lower(Enumerable.Repeat(value, 32).ToArray());
    private static string Lower(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static void Validate(MailboxClientLedgerDocument document)
    {
        // Keep the production seam private: this test isolates its deterministic
        // cross-row checks without claiming live grant/lease/native admission.
        var method = typeof(MailboxClientOperationLedger).GetMethod("ValidateAckOperations",
            BindingFlags.Static | BindingFlags.NonPublic)!;
        try { method.Invoke(null, [document, new HashSet<ulong>(), 0UL]); }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        { ExceptionDispatchInfo.Capture(exception.InnerException).Throw(); }
    }
}
