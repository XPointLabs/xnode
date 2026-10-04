using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData("pending", true)]
    [InlineData("pending", false)]
    [InlineData("completed", true)]
    [InlineData("completed", false)]
    [InlineData("tombstoned", true)]
    [InlineData("tombstoned", false)]
    public async Task NewGrantCannotPassLostOrRolledBackIntentForAnyRetainedNativeState(string state, bool deleteFile)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var original = f.ClientStoreFrame();
        if (state == "pending")
        {
            f.Sender.Fault.Action = point =>
            {
                if (point == MailboxPeerMutationFaultPoint.StoreReserved)
                    throw new IOException("Test-owned reserved mutation interruption.");
            };
            await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(original, f.Ledger!).AsTask());
            f.Sender.Fault.Action = null;
        }
        else
        {
            Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(original, f.Ledger!)).Status);
            if (state == "tombstoned")
            {
                var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
                AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.Ledger!)).Span, page, 0x74);
            }
        }
        var preserved = File.ReadAllBytes(f.LedgerFile);
        f.Ledger!.Dispose(); f.Ledger = null;
        if (deleteFile) File.Delete(f.LedgerFile);
        else
        {
            var document = JsonNode.Parse(preserved)!;
            document["operations"]!.AsObject().Clear();
            // Retaining the cursor floor is insufficient: the exact intent and
            // settlement cannot be inferred from an independent mutation file.
            File.WriteAllText(f.LedgerFile, document.ToJsonString());
        }
        f.Reopen(); f.OpenLedger();
        var damaged = deleteFile ? null : File.ReadAllBytes(f.LedgerFile);
        var replay = f.Sender.Node.Replay.Diagnostics;
        var outcomes = f.Sender.Node.OutcomeCount; var http = f.AllHttpRequests;
        var native = f.Sender.MutationFiles.Select(File.ReadAllBytes).ToArray();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(DifferentGrantStore(f), f.Ledger!).AsTask());
        Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics);
        Assert.Equal(outcomes, f.Sender.Node.OutcomeCount); Assert.Equal(http, f.AllHttpRequests);
        Assert.Equal(native.Length, f.Sender.MutationFiles.Length);
        for (var i = 0; i < native.Length; i++) Assert.Equal(native[i], File.ReadAllBytes(f.Sender.MutationFiles[i]));
        if (deleteFile) Assert.False(File.Exists(f.LedgerFile));
        else Assert.Equal(damaged, File.ReadAllBytes(f.LedgerFile));

        // Restore test-owned exact custody, not reconstruct it from the node.
        f.Ledger!.Dispose(); f.Ledger = null;
        File.WriteAllBytes(f.LedgerFile, preserved); f.Reopen(); f.OpenLedger();
        await f.Ledger!.InitializeAsync(); // the fixture's UTC clock throws
        if (state == "pending")
            Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(original, f.Ledger!)).Status);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(DifferentGrantStore(f), f.Ledger!)).Status);
        Assert.Equal(new ulong[] { 1, 2 }, f.ExactIntents.Select(bytes => MailboxPeerWireV2Codec.Decode(bytes).Cursor).Order());
    }

    [Fact]
    public async Task CurrentLedgerInitializationDoesNotUseUtcOrRemoveStoreAndAckIntents()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        await f.Ledger!.InitializeAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var ack = AckFrame(f, page);
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(ack, f.Ledger!)).Span, page, 0x74);
        var preserved = File.ReadAllBytes(f.LedgerFile); var http = f.AllHttpRequests;
        f.Reopen(); await f.Ledger!.InitializeAsync();
        Assert.Equal(preserved, File.ReadAllBytes(f.LedgerFile));
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(ack, f.Ledger!)).Span, page, 0x74);
        Assert.Equal(http, f.AllHttpRequests);
        Assert.Equal(preserved, File.ReadAllBytes(f.LedgerFile));
    }

    [Fact]
    public async Task NeutralCollectionCannotDeleteCurrentAckCustody()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.Ledger!)).Span, page, 0x74);
        var ack = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!["ackOperations"]!.ToJsonString();
        const ulong utc = 1_900_000_000;
        f.OpenLedger(clock: new RecoveryUtcClock(utc));
        byte[] Bytes(byte value, int length = 32) => Enumerable.Repeat(value, length).ToArray();
        // Exercise only the neutral collector. These raw primitive inputs are
        // not a signed grant, current admission, or network durability evidence.
        await f.Ledger!.ReserveStoreAsync(777, Bytes(0x99, 16), Bytes(0x98), Bytes(0x97),
            Bytes(0x96), Bytes(0x95), Bytes(0x94), Bytes(0x93),
            new ReadOnlyMemory<byte>[] { Bytes(0x91), Bytes(0x92) }, utc + 600, default);
        await f.Ledger.InitializeAsync();
        Assert.Equal(ack, JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!["ackOperations"]!.ToJsonString());
        Assert.Single(f.ExactIntents, bytes => bytes.Length != 0);
    }

    private sealed class RecoveryUtcClock(ulong seconds) : IClock
    { public DateTimeOffset UtcNow => DateTimeOffset.FromUnixTimeSeconds(checked((long)seconds)); }
}
