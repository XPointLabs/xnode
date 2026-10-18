using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using System.Diagnostics;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task WholeCapturedAckRecoversNeverVisitedSenderItemAfter120SecondsWithoutReminting()
    {
        await using var f = await Fixture.CreateAsync(envelopeExpiry: 1400);
        f.OpenLedger();
        await StoreItem(f, 1); await StoreItem(f, 2);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(
            RetrieveFrame(f, grantExpiry: 1390))).ToArray(), f);
        Assert.Equal(2, page.Items.Count);
        foreach (var peer in new[] { f.Sender, f.Recipient })
            foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
                await (role == MailboxCapabilityDomain.Deposit ? peer.Node.Deposit : peer.Node.Retrieve).AdvanceAsync(peer.Node.Host,
                    Snapshot(f.Signed, role, generation: 2, prior: Snapshot(f.Signed, role), expires: 1390, issued: 1090));
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope);
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(page.Epoch, Enumerable.Repeat((byte)0x74, 16).ToArray(),
            envelope.MailboxId, envelope.PlacementId, true, [], page.Items.Select(item => item.ToAcknowledgement()).ToArray());
        var grant = Grant(f.Signed, f.Recipient.Node.Host, MailboxCapabilityDomain.Retrieve, 0x52, expires: 1390);
        var exact = MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant), binding, 1, Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
        f.PeerClient.SuppressNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        var originals = AckIntents(f);
        Assert.Equal(2, originals.Length);
        Assert.Equal(3, f.Sender.ReplayFiles.Length); // two Stores, only first ACK item visited
        Assert.Equal(2, f.Recipient.ReplayFiles.Length);
        f.Reopen();
        await f.Signed.RefreshNetworkProofAsync(101, 1230);
        var recovered = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
        AssertAck(recovered, page, 0x74);
        Assert.Equal(originals, AckIntents(f));
        AssertTombstones(f, 2);
        var calls = f.AllHttpRequests;
        f.Reopen(); f.Signed.Sample = 102;
        Assert.Equal(recovered, (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray());
        Assert.Equal(originals, AckIntents(f)); Assert.Equal(calls, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task IndependentRecipientUpperBoundMustActuallyCoverSignedOriginDurability(bool converge)
    {
        await using var f = await Fixture.CreateAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store)).Status);
        f.Signed.Sample = 103;
        var clock = new RecipientMaturityClock(converge);
        var authority = new RecipientMaturityAuthority(f.Signed, clock);
        var node = f.Recipient.Node;
        node.Admission = new(authority, clock, node.Node, node.Deposit, node.Retrieve, node.Runtime);
        f.Recipient.Reopen(); f.Bind();
        f.PeerClient.BeforeSend = clock.Arm;
        var tombstone = f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone);
        var result = await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.True(clock.LaggedReads > 0);
        Assert.Equal(converge ? MailboxPeerQuorumStatus.Durable : MailboxPeerQuorumStatus.PartialFailure, result.Status);
        if (converge)
        {
            Assert.Null(await f.Recipient.ReadBlobAsync());
            Assert.Equal(2, f.Recipient.ReplayFiles.Length);
            f.Reopen();
            Assert.Equal(result.CanonicalMqr3.ToArray(),
                (await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone)).CanonicalMqr3.ToArray());
        }
        else
        {
            Assert.NotNull(await f.Recipient.ReadBlobAsync());
            Assert.Single(f.Recipient.ReplayFiles); Assert.Single(f.Recipient.MutationFiles);
        }
    }

    private sealed class RecipientMaturityClock(bool converge) : IOnionMonotonicClock
    {
        private readonly Stopwatch elapsed = new();
        internal int LaggedReads;
        internal void Arm() => elapsed.Restart();
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var lagged = elapsed.IsRunning && (!converge || elapsed.Elapsed < TimeSpan.FromSeconds(2.5));
            if (lagged) LaggedReads++;
            return ValueTask.FromResult(new OnionMonotonicReading(
                DeepIdV2PublicationAuthorityFixture.Boot, lagged ? 101UL : 103UL));
        }
    }

    private sealed class RecipientMaturityAuthority(DeepIdV2PublicationAuthorityFixture signed,
        IOnionMonotonicClock clock) : IDeepIdV2ContactStoreAuthoritySource
    {
        public async ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken ct) =>
            (await signed.ReadPublicationAuthorityAsync(ct)) with { TrustedTime = new OnionTrustedTimeAuthority(clock) };
    }

    [Fact]
    public async Task DelayedFirstRecipientTombstone_UsesActualSourceCustody_AndPinnedHttp2AfterColdReopen()
    {
        await using var f = await Fixture.CreateAsync(envelopeExpiry: 1400);
        var store = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.Durable,
            (await f.Coordinator.ReplicateAsync(store, MailboxPeerReplicationOperation.Store)).Status);
        // Genuine role-signed grants and revocation successors outlive the
        // 120-second first-admission window; no fixture clock/window extension.
        var retrieve = Grant(f.Signed, f.Recipient.Node.Host, MailboxCapabilityDomain.Retrieve,
            0x51, expires: 1390, notBefore: 1090);
        foreach (var peer in new[] { f.Sender, f.Recipient })
        {
            foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
            {
                var next = Snapshot(f.Signed, role, generation: 2, prior: Snapshot(f.Signed, role),
                    expires: 1390, issued: 1090);
                await (role == MailboxCapabilityDomain.Deposit ? peer.Node.Deposit : peer.Node.Retrieve)
                    .AdvanceAsync(peer.Node.Host, next);
            }
        }
        var tombstone = f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone, retrieve);
        f.PeerClient.SuppressNext = true;
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure,
            (await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone)).Status);
        Assert.Null(await f.Sender.ReadBlobAsync());
        Assert.NotNull(await f.Recipient.ReadBlobAsync());
        Assert.Single(f.Recipient.ReplayFiles); // Store only; no first ACK reservation.
        f.Reopen();
        await f.Signed.RefreshNetworkProofAsync(101, 1230);
        var recovered = await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Equal(tombstone, MailboxPeerWireV2Codec.DecodeForwardedTombstoneRequest(f.PeerClient.ExactRequests[^1]));
        Assert.Null(await f.Recipient.ReadBlobAsync(retrieve));
        Assert.Equal(2, f.RemoteHost.Requests);
        f.Reopen();
        Assert.Equal(recovered.CanonicalMqr3.ToArray(),
            (await f.Coordinator.ReplicateAsync(tombstone, MailboxPeerReplicationOperation.Tombstone)).CanonicalMqr3.ToArray());
        Assert.Equal(2, f.RemoteHost.Requests);
    }
}
