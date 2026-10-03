using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task NonWriterClientAndSignedHttpPeerCannotReserveOrAllocateCursor()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); f.OpenRecipientLedger();
        var client = f.ClientStoreFrame();
        var reversed = f.Sender.Frame(MailboxPeerReplicationOperation.Store);
        var target = f.Sender.Node.Replicas.Single(replica => replica.NodeId.Span.SequenceEqual(f.Sender.Node.Node)).Transport;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            f.Bind(true);
            await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.StoreClientAsync(client, f.RecipientLedger!).AsTask());
            Assert.Equal(0, f.Recipient.Node.Replay.Diagnostics.ScopeCount);
            Assert.Equal(0UL, f.Recipient.Node.Replay.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
            Assert.Equal(0, f.Recipient.Node.OutcomeCount);
            Assert.False(File.Exists(f.AckLedgerFile));
            Assert.Null(await new CurrentMailboxReplicaPeerClient().SendAsync(
                target, MailboxPeerReplicationOperation.Store, reversed, default));
            Assert.Equal((int)HttpStatusCode.Forbidden, f.RemoteHost.LastStatus);
            Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Recipient.ReplayFiles);
            Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
            Assert.Empty(f.ExactIntents);
            f.Reopen();
        }
        f.Bind(false);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, f.Ledger!)).Status);
        var peer = MailboxPeerWireV2Codec.Decode(Assert.Single(f.ExactIntents));
        Assert.Equal(1UL, peer.Cursor); Assert.Equal(f.Sender.Node.Replicas[0].NodeId.ToArray(), peer.SenderRouterId.ToArray());
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        Assert.Equal(1UL, Assert.Single(page.Items).Cursor);
    }
}
