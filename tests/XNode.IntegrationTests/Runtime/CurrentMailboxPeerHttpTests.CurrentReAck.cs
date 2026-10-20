using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task CurrentPeerCannotReplaceAnotherPreparedTombstoneBeforeItsFirstEffect()
    {
        await using var f = await Fixture.CreateAsync();
        Assert.Equal(XNode.Core.Mailbox.MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store)).Status);
        var old = f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone);
        var fault = new PeerFloorWriteFault(1, beforeReplace: false); f.OpenLedger(fault);
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.ReplicateAsync(old, MailboxPeerReplicationOperation.Tombstone).AsTask());
        Assert.True(fault.Reached); f.Reopen();
        var before = f.Sender.MutationFiles.Select(File.ReadAllBytes).ToArray(); var replays = f.Sender.ReplayFiles.Length; var calls = f.AllHttpRequests;
        var candidate = MailboxPeerWireV2Codec.Decode(old) with
        { OperationId = Enumerable.Repeat((byte)0x76, 16).ToArray(), ReplayNonce = Enumerable.Repeat((byte)0x77, 32).ToArray() };
        var next = MailboxPeerWireV2Codec.Encode(f.Recipient.Crypto.SignRequest(candidate, f.Recipient.SenderSeed));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.ReplicateAsync(next, MailboxPeerReplicationOperation.Tombstone).AsTask());
        Assert.Equal(before, f.Sender.MutationFiles.Select(File.ReadAllBytes).ToArray());
        Assert.Equal(replays, f.Sender.ReplayFiles.Length); Assert.Equal(calls, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task CurrentClientReAckKeepsOriginalBatchAndTerminalNativeBytes(bool onRecipient)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        f.Bind(onRecipient); if (onRecipient) f.OpenRecipientLedger();
        var old = AckFrame(f, page); f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(old, f.AckLedger).AsTask());
        var original = Assert.Single(AckIntents(f));
        var native = f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Select(File.ReadAllBytes).ToArray();
        f.Reopen(); f.Signed.Sample = 101;
        var next = AckFrame(f, page, operation: 0x76, grantSerial: 0x53);
        var reply = (await f.Coordinator.AcknowledgeClientAsync(next, f.AckLedger)).ToArray();
        AssertAck(reply, page, 0x76);
        Assert.Contains(AckIntents(f), bytes => bytes.AsSpan().SequenceEqual(original)); Assert.Equal(2, AckIntents(f).Length);
        Assert.Equal(native, f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Select(File.ReadAllBytes).ToArray());
        var calls = f.AllHttpRequests; f.Reopen();
        Assert.Equal(reply, (await f.Coordinator.AcknowledgeClientAsync(next, f.AckLedger)).ToArray());
        Assert.Equal(calls, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false, false)] [InlineData(true, false)] [InlineData(true, true)]
    public async Task CurrentClientReAckCannotRepairMissingOrChangedOriginalIntent(bool changed, bool unusedItem)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        if (unusedItem) await StoreItem(f, 2);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger).AsTask());
        var document = JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!;
        if (!changed) document["ackOperations"]!.AsObject().Clear();
        else
        {
            var item = document["ackOperations"]!.AsObject().Single().Value!["items"]!.AsArray()[unusedItem ? 1 : 0]!;
            var bytes = Convert.FromBase64String(item["peerRequest"]!.GetValue<string>()); bytes[^1] ^= 1;
            item["peerRequest"] = Convert.ToBase64String(bytes);
        }
        await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        var original = AckIntents(f); var calls = f.AllHttpRequests;
        var native = f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Select(File.ReadAllBytes).ToArray();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.AcknowledgeClientAsync(
            AckFrame(f, page, operation: 0x76, grantSerial: 0x53), f.AckLedger).AsTask());
        Assert.Equal(original, AckIntents(f)); Assert.Equal(calls, f.AllHttpRequests);
        Assert.Equal(native, f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Select(File.ReadAllBytes).ToArray());
    }

    [Fact]
    public async Task CurrentClientReAckKeepsUnadmittedOriginalBatchItemAndCompletesWholePage()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        Assert.Equal(2, page.Items.Count); f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger).AsTask());
        var original = AckIntents(f); Assert.Equal(2, original.Length);
        var terminal = f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Where(path =>
            JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>() == "tombstoned").ToDictionary(path => path, File.ReadAllBytes);
        Assert.Equal(2, terminal.Count);
        f.Reopen(); f.Signed.Sample = 101;
        var exact = AckFrame(f, page, operation: 0x76, grantSerial: 0x53);
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).Span, page, 0x76);
        foreach (var row in terminal) Assert.Equal(row.Value, File.ReadAllBytes(row.Key));
        AssertTombstones(f, 2); Assert.Equal(4, AckIntents(f).Length);
        foreach (var before in original) Assert.Contains(AckIntents(f), bytes => bytes.AsSpan().SequenceEqual(before));
        f.Reopen(); await f.Sender.Receiver.InitializeHostAsync(); await f.Recipient.Receiver.InitializeHostAsync();
    }
}
