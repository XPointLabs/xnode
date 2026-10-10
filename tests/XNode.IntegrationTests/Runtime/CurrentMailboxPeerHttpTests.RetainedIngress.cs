using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task NativeIngressRetainedReadAndAckKeepOriginalEpochAcrossProjectionAdvanceAndColdHttpRetry()
    {
        await using var f = await Fixture.CreateAsync(envelopeExpiry: 1_600, shortMailboxProjection: true);
        AssertDescriptorKeys(f);
        var originalHost = f.Sender.Node.Host;
        var originalEnd = BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode(f.Signed.Projection.Span).Field(12).Span);
        var storedRequest = f.ClientStoreFrame();
        await f.Signed.RefreshInitialMailboxLeaseAsync();
        using (var services = NativeServices(f))
            Assert.True((await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, storedRequest, default)).Success);
        Assert.Equal(1, f.AllHttpRequests);

        await f.Signed.AdvanceMailboxProjectionAsync();
        var current = await MailboxGrantRevocationStoreTests.Host(f.Signed);
        Assert.Equal(originalHost.SelectionEpoch + 1, current.SelectionEpoch);
        Assert.True(f.Signed.Freshness.TrustedLowerUnixSeconds >= originalEnd);
        foreach (var node in new[] { f.Sender.Node, f.Recipient.Node })
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
        {
            var owner = role == MailboxCapabilityDomain.Deposit ? node.Deposit : node.Retrieve;
            var prior = (await owner.ReadProtectedAsync()).ToArray();
            await owner.AdvanceAsync(current, MailboxGrantRevocationStoreTests.Snapshot(f.Signed, role,
                generation: 2, prior: prior, expires: 1_300, issued: originalEnd));
        }
        var exactGrant = MailboxGrantRevocationStoreTests.Grant(f.Signed, originalHost,
            MailboxCapabilityDomain.Retrieve, 0x52, expires: 1_300, notBefore: originalEnd + 1);
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(exactGrant);
        var selected = await current.GetSelectedRetainedReadReplicasAsync(exactGrant);
        Assert.Equal(originalHost.SelectionEpoch, grant.Epoch);
        Assert.Equal(f.Sender.Node.Replicas.SelectMany(replica => replica.NodeId.ToArray()),
            selected.SelectMany(replica => replica.NodeId.ToArray()));
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope);
        var read = Frame(MailboxAuthenticatedRequestTranscript.ForRetrieve(envelope.Epoch,
            Repeated(16, 0x71), envelope.MailboxId, envelope.PlacementId, 0, 10, []), 1);
        var decodePolicy = new MailboxClientDecodePolicy
        {
            NowUnixSeconds = f.Signed.Freshness.TrustedUpperUnixSeconds,
            // This is the verified current retained-read grant's interval,
            // not a claim that the original PMT projection is still current.
            EpochWindow = new()
            {
                CurrentEpoch = grant.Epoch, CurrentNotBeforeUnixSeconds = grant.NotBeforeUnixSeconds,
                CurrentExpiresAtUnixSeconds = grant.ExpiresAtUnixSeconds,
                NextEpoch = 0, NextNotBeforeUnixSeconds = 0, NextExpiresAtUnixSeconds = 0
            },
            CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }
        };

        f.Reopen();
        byte[] pageBytes, ackRequest;
        using (var services = NativeServices(f))
        {
            var dispatcher = NativeDispatcher(services);
            var retrieved = await dispatcher.DispatchAsync(OnionOperation.Retrieve, read, default);
            Assert.True(retrieved.Success); pageBytes = retrieved.CanonicalBody.ToArray();
            var page = MailboxClientCodec.DecodeRetrievePage(pageBytes, decodePolicy);
            Assert.Equal(envelope.Epoch, page.Epoch);
            Assert.Equal(f.Recipient.Envelope, MailboxClientCodec.EncodeEncryptedEnvelope(Assert.Single(page.Items).Envelope));
            ackRequest = Frame(MailboxAuthenticatedRequestTranscript.ForAck(envelope.Epoch,
                Repeated(16, 0x74), envelope.MailboxId, envelope.PlacementId, true, [],
                page.Items.Select(item => item.ToAcknowledgement()).ToArray()), 1);
            f.RemoteHost.DropNext = true;
            AssertUnknown(await dispatcher.DispatchAsync(OnionOperation.Acknowledge, ackRequest, default));
        }
        var intents = AckIntents(f);
        var intent = MailboxPeerWireV2Codec.Decode(Assert.Single(intents));
        Assert.Equal(grant.Epoch, intent.Epoch);
        Assert.Equal(grant.MembershipCommitment.ToArray(), intent.MembershipCommitment.ToArray());
        Assert.NotEqual(current.MembershipCommitment.ToArray(), intent.MembershipCommitment.ToArray());
        Assert.Equal(2, f.AllHttpRequests);
        f.Reopen();
        using var reopenedServices = NativeServices(f);
        var reopened = NativeDispatcher(reopenedServices);
        var ack = await reopened.DispatchAsync(OnionOperation.Acknowledge, ackRequest, default);
        Assert.True(ack.Success); Assert.Equal(intents, AckIntents(f)); AssertTombstones(f, 1);
        Assert.Equal(3, f.AllHttpRequests);
        Assert.Equal(pageBytes, (await reopened.DispatchAsync(OnionOperation.Retrieve, read, default)).CanonicalBody.ToArray());
        var empty = await reopened.DispatchAsync(OnionOperation.Retrieve, Frame(
            MailboxAuthenticatedRequestTranscript.ForRetrieve(envelope.Epoch, Repeated(16, 0x75),
                envelope.MailboxId, envelope.PlacementId, 0, 10, []), 2), default);
        Assert.True(empty.Success); Assert.Empty(MailboxClientCodec.DecodeRetrievePage(empty.CanonicalBody.Span, decodePolicy).Items);
        Assert.Null(await f.Sender.ReadBlobAsync(exactGrant)); Assert.Null(await f.Recipient.ReadBlobAsync(exactGrant));
        var senderState = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var recipientState = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        AssertUnknown(await reopened.DispatchAsync(OnionOperation.Store, storedRequest, default));
        Assert.Equal(senderState, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(recipientState, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Equal(3, f.AllHttpRequests); AssertTombstones(f, 1);

        byte[] Frame(MailboxAuthenticatedRequestBinding binding, ulong counter) =>
            MailboxAuthenticatedClientRequestCodec.Encode(new()
            {
                Binding = binding, Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(grant,
                    binding, counter, Repeated(32, 0x57))
            });
    }
}
