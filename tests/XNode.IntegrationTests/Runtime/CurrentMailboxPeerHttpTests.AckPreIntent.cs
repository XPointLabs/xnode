using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task NativeTombstoneFloorRejectsEvenReprotectedMissingAckIntent()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var exact = AckFrame(f, page); f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        var document = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!;
        document["ackOperations"]!.AsObject().Clear();
        await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        var original = File.ReadAllBytes(f.AckLedgerFile); var calls = f.AllHttpRequests;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        Assert.Equal(original, File.ReadAllBytes(f.AckLedgerFile)); Assert.Empty(AckIntents(f));
        Assert.Equal(calls, f.AllHttpRequests); AssertTombstones(f, 1);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PendingCurrentMauBeforeFirstAckIntentColdResumesExactlyOnce(bool nonFinal)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        await StoreItem(f, 1); if (nonFinal) await StoreItem(f, 2);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        Assert.Equal(nonFinal, page.HasMore);
        var exact = AckFrame(f, page); var calls = f.AllHttpRequests;
        await Assert.ThrowsAsync<IOException>(() => f.Sender.Receiver.WithClientRequestAsync<int>(exact,
            MailboxAuthenticatedOperation.Ack, async (request, ct) =>
            {
                Assert.True(await request.TryAcquireExecutionAndReserveOutcomeAsync(
                    MailboxWireHttpContract.Acknowledge.MaximumResponseBytes, ct));
                throw new IOException("Interrupted after actual client reservation, before first ACK intent.");
            }, default, storeLedger: f.AckLedger).AsTask());
        Assert.Empty(AckIntents(f)); Assert.Equal(calls, f.AllHttpRequests);
        Assert.All(f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles), path =>
            Assert.Equal("completed", System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>()));
        f.Reopen(); await f.InitializeLedgerAsync();
        var reply = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
        AssertAck(reply, page, 0x74);
        var originals = AckIntents(f); Assert.Single(originals);
        Assert.Equal(calls + 1, f.AllHttpRequests);
        f.Reopen();
        Assert.Equal(reply, (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray());
        Assert.Equal(originals, AckIntents(f)); Assert.Equal(calls + 1, f.AllHttpRequests);
    }
}
