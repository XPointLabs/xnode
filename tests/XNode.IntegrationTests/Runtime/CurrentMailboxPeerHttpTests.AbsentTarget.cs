using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    private static ValueTask<ReadOnlyMemory<byte>> CaptureTombstoneForwardingAsync(Fixture f, ReadOnlyMemory<byte> exact) =>
        f.Sender.Receiver.WithPeerAsync(exact, MailboxPeerReplicationOperation.Tombstone,
            MailboxPeerWireResponseReplicaV2.Sender, async (operation, token) =>
                operation.CreateForwarding(await operation.ApplyAndSignLocalAsync(token)));

    [Fact]
    public async Task CurrentAbsentTargetClosesKnownPartialStoreWithoutResurrectionAndColdReplays()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var store = await CaptureStoreForwardingAsync(f, exact);
        f.Recipient.InjectUnpairedPending(store.Claim);
        await f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(store.Forwarding);
        var forwarding = await CaptureTombstoneForwardingAsync(f, f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone));
        var response = await f.Recipient.Receiver.ReceiveForwardedTombstoneAsync(forwarding);
        Assert.Equal(MailboxReplicaDisposition.Tombstone, MailboxReceiptV2Codec.DecodeReplica(response.Span).Disposition);
        Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(2, f.Recipient.ReplayFiles.Length);
        f.Reopen(); await f.Recipient.Receiver.InitializeHostAsync();
        Assert.Equal(response.ToArray(), (await f.Recipient.Receiver.ReceiveForwardedTombstoneAsync(forwarding)).ToArray());
        var before = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.ReceiveForwardedStoreAsync(store.Forwarding).AsTask()));
        Assert.Equal(before, AdmissionOwnerDigest(f.Recipient.Node.DataRoot)); Assert.Empty(f.Recipient.MutationFiles);
    }

    [Theory]
    [InlineData(1, false)] [InlineData(1, true)]
    [InlineData(2, false)] [InlineData(2, true)]
    [InlineData(3, false)] [InlineData(3, true)]
    public async Task CurrentAbsentTargetProtectedCrashRetainsExactNegativeCustody(int write, bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        var store = await CaptureStoreForwardingAsync(f, f.Recipient.Frame(MailboxPeerReplicationOperation.Store));
        f.Recipient.InjectUnpairedPending(store.Claim);
        await f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(store.Forwarding);
        var forwarding = await CaptureTombstoneForwardingAsync(f, f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone));
        var fault = new PeerFloorWriteFault(write, beforeReplace); f.OpenRecipientLedger(durability: fault);
        await Assert.ThrowsAsync<IOException>(() => f.Recipient.Receiver.ReceiveForwardedTombstoneAsync(forwarding).AsTask());
        Assert.True(fault.Reached); Assert.Empty(f.Recipient.MutationFiles);
        f.Reopen(); await f.Recipient.Receiver.InitializeHostAsync();
        var response = await f.Recipient.Receiver.ReceiveForwardedTombstoneAsync(forwarding);
        Assert.Equal(MailboxReplicaDisposition.Tombstone, MailboxReceiptV2Codec.DecodeReplica(response.Span).Disposition);
        Assert.Empty(f.Recipient.MutationFiles);
    }

    [Theory]
    [InlineData("unknown")] [InlineData("signature")] [InlineData("expired")]
    [InlineData("lost-completed")]
    public async Task CurrentAbsentTargetRejectsUnknownForgedExpiredAndLostPositiveHistory(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var store = await CaptureStoreForwardingAsync(f, f.Recipient.Frame(MailboxPeerReplicationOperation.Store));
        if (defect != "unknown")
        {
            if (defect == "lost-completed")
                _ = await f.Recipient.Receiver.ReceiveForwardedStoreAsync(store.Forwarding);
            else
            {
                f.Recipient.InjectUnpairedPending(store.Claim);
                await f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(store.Forwarding);
            }
        }
        var forwarding = (await CaptureTombstoneForwardingAsync(f, f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone))).ToArray();
        if (defect == "lost-completed") File.Delete(Assert.Single(f.Recipient.MutationFiles));
        if (defect == "signature") forwarding[^1] ^= 1;
        if (defect == "expired") await f.Signed.RefreshNetworkProofAsync(101, 1111);
        var before = AdmissionOwnerDigest(f.Recipient.Node.DataRoot); var independent = PeerProtectionDigest(f.Recipient);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.ReceiveForwardedTombstoneAsync(forwarding).AsTask()));
        Assert.Equal(before, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Equal(independent, PeerProtectionDigest(f.Recipient));
    }

    [Fact]
    public async Task CurrentTerminalTombstoneAcceptsNewCurrentAckWithoutRewritingOriginalNativeTarget()
    {
        await using var f = await Fixture.CreateAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store)).Status);
        var first = f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(first, MailboxPeerReplicationOperation.Tombstone)).Status);
        var rows = f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Select(File.ReadAllBytes).ToArray();
        var next = MailboxPeerWireV2Codec.Decode(first) with
        {
            OperationId = Enumerable.Repeat((byte)0x61, 16).ToArray(),
            ReplayNonce = Enumerable.Repeat((byte)0x62, 32).ToArray(), Signature = new byte[64]
        };
        var exact = MailboxPeerWireV2Codec.Encode(f.Recipient.Crypto.SignRequest(next, f.Recipient.SenderSeed));
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Tombstone)).Status);
        Assert.Equal(rows, f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles).Select(File.ReadAllBytes).ToArray());
        f.Reopen(); await f.Sender.Receiver.InitializeHostAsync(); await f.Recipient.Receiver.InitializeHostAsync();
    }
}
