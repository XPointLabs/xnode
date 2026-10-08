using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(1_600UL)]
    [InlineData(2_593_090UL)]
    public async Task CurrentClientStoreRetrieveAckPreservesObjectBeyondShortAuthorityOverPinnedHttp(ulong objectExpiry)
    {
        await using var f = await Fixture.CreateAsync(envelopeExpiry: objectExpiry);
        f.OpenLedger(); AssertDescriptorKeys(f);
        var exactStore = f.ClientStoreFrame();
        var grant = MailboxAuthenticatedClientRequestCodec.Decode(exactStore).Presentation.Grant;
        Assert.True(objectExpiry > grant.ExpiresAtUnixSeconds);
        f.RemoteHost.DropNext = true;
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure,
            (await f.Coordinator.StoreClientAsync(exactStore, f.Ledger!)).Status);
        var intent = Assert.Single(f.ExactIntents);
        f.Reopen(); f.Signed.Sample = 101;
        var stored = await f.Coordinator.StoreClientAsync(exactStore, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, stored.Status);
        Assert.Equal(intent, Assert.Single(f.ExactIntents));
        AssertQuorumDescriptorKeys(f, stored.CanonicalMqr3.Span);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).Span, f);
        Assert.Equal(objectExpiry, Assert.Single(page.Items).Envelope.ExpiresAtUnixSeconds);
        var exactAck = AckFrame(f, page);
        var ack = (await f.Coordinator.AcknowledgeClientAsync(exactAck, f.AckLedger)).ToArray();
        AssertAck(ack, page, 0x74); AssertTombstones(f, 1);
        f.Reopen(); f.Signed.Sample = 102;
        Assert.Equal(ack, (await f.Coordinator.AcknowledgeClientAsync(exactAck, f.AckLedger)).ToArray());
        Assert.Equal(stored.CanonicalMqr3.ToArray(),
            (await f.Coordinator.StoreClientAsync(exactStore, f.Ledger!)).CanonicalMqr3.ToArray());
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
        Assert.Equal(3, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DistinctDescriptorKeysCompleteStorePaginationAckAndExactRecovery(bool ackOnRecipient)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        AssertDescriptorKeys(f);
        var client = f.ClientStoreFrame(); f.RemoteHost.DropNext = true;
        var unknown = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, unknown.Status);
        Assert.True(unknown.CanonicalMqr3.IsEmpty);
        var intent = Assert.Single(f.ExactIntents);
        f.Reopen(); f.Signed.Sample = 101;
        var stored = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, stored.Status);
        Assert.Equal(intent, Assert.Single(f.ExactIntents));
        AssertQuorumDescriptorKeys(f, stored.CanonicalMqr3.Span);
        await f.Sender.Node.Host.VerifyStoreSettlementAsync(intent, stored.CanonicalMqr3);

        // New allocation checks the earlier authenticated Store prefix. The
        // second counter reuses neither an operation ID nor ciphertext.
        await StoreItem(f, 2);
        Assert.Equal(3, f.AllHttpRequests);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).Span, f);
        Assert.Equal(1UL, Assert.Single(first.Items).Cursor); Assert.True(first.HasMore);
        var second = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f,
            counter: 2, operation: 0x72, after: first.NextCursor, maximum: 1,
            continuation: first.ContinuationToken))).Span, f);
        Assert.Equal(2UL, Assert.Single(second.Items).Cursor); Assert.False(second.HasMore);

        // The continuation was signed on the writer; either distinct-key
        // replica must authenticate it for ACK without treating its ID as key.
        f.Bind(ackOnRecipient); if (ackOnRecipient) f.OpenRecipientLedger();
        var exactAck = AckFrame(f, first);
        var acknowledged = (await f.Coordinator.AcknowledgeClientAsync(exactAck, f.AckLedger)).ToArray();
        AssertAck(acknowledged, first, 0x74);
        AssertQuorumDescriptorKeys(f, Assert.Single(MailboxAggregateAckCodec.DecodeMqr3(acknowledged).TombstoneQuorums).Span);
        f.Reopen(); f.Signed.Sample = 102;
        Assert.Equal(acknowledged, (await f.Coordinator.AcknowledgeClientAsync(exactAck, f.AckLedger)).ToArray());
        Assert.Equal(4, f.AllHttpRequests);
        var remaining = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(
            RetrieveFrame(f, counter: 3, operation: 0x73))).Span, f);
        Assert.Equal(2UL, Assert.Single(remaining.Items).Cursor);
        var final = (await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, remaining,
            counter: 2, operation: 0x78), f.AckLedger)).ToArray();
        AssertAck(final, remaining, 0x78);
        AssertQuorumDescriptorKeys(f, Assert.Single(MailboxAggregateAckCodec.DecodeMqr3(final).TombstoneQuorums).Span);
        AssertTombstones(f, 2); Assert.Equal(5, f.AllHttpRequests);
        Assert.Empty(DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(
            RetrieveFrame(f, counter: 4, operation: 0x79))).Span, f).Items);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NodeIdCannotReplaceDescriptorKeyInEitherSignedPeerProof(bool recipientProof)
    {
        await using var f = await Fixture.CreateAsync(); AssertDescriptorKeys(f);
        var original = MailboxPeerWireV2Codec.Decode(f.Recipient.Frame(MailboxPeerReplicationOperation.Store));
        var changed = recipientProof
            ? original with { RecipientMembershipProof = original.RecipientMembershipProof with { SigningPublicKey = original.RecipientRouterId } }
            : original with { SenderMembershipProof = original.SenderMembershipProof with { SigningPublicKey = original.SenderRouterId } };
        // The enclosing signature is valid for the genuine sender. Rejection
        // must be the authenticated descriptor binding, not malformed bytes.
        var privateKey = Sodium.PublicKeyAuth.GenerateKeyPair(f.Signed.Node(f.Sender.Node.Node).Seed).PrivateKey;
        byte[] exact;
        try
        {
            exact = MailboxPeerWireV2Codec.Encode(changed with
            { Signature = Sodium.PublicKeyAuth.SignDetached(MailboxPeerWireV2Codec.GetSigningDigest(changed), privateKey) });
        }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.ReplicateAsync(
            exact, MailboxPeerReplicationOperation.Store).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Recipient.Receiver.ReceiveAsync(
            exact, MailboxPeerReplicationOperation.Store).AsTask());
        AssertNoPeerEffects(f);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NodeIdCannotBeUsedAsSigningCustodyForEitherNativeReplica(bool recipientCustody)
    {
        await using var f = await Fixture.CreateAsync(); AssertDescriptorKeys(f);
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var peer = recipientCustody ? f.Recipient : f.Sender;
        peer.Reopen(signingSeed: peer.Node.Node); f.Bind();
        if (recipientCustody)
            await Assert.ThrowsAsync<CryptographicException>(() => f.Recipient.Receiver.ReceiveAsync(
                exact, MailboxPeerReplicationOperation.Store).AsTask());
        else
            await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.ReplicateAsync(
                exact, MailboxPeerReplicationOperation.Store).AsTask());
        AssertNoPeerEffects(f);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrongRemoteSigningKeyCannotBecomeQuorumOrSavedSettlement(bool useNodeIdAsSeed)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); AssertDescriptorKeys(f);
        var client = f.ClientStoreFrame();
        f.RemoteHost.AfterReceive = bytes => MailboxReceiptV2Codec.EncodeReplica(
            f.Recipient.Crypto.SignReplicaResponse(MailboxReceiptV2Codec.DecodeReplica(bytes.Span),
                useNodeIdAsSeed ? f.Recipient.Node.Node : f.Signed.Node(f.Sender.Node.Node).Seed));
        var rejected = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, rejected.Status);
        Assert.True(rejected.CanonicalMqr3.IsEmpty);
        Assert.Equal(0, f.Sender.Node.OutcomeCount);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Sender.ReplayFiles)));
        var original = Assert.Single(f.ExactIntents);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        f.RemoteHost.AfterReceive = null; f.Reopen(); f.Signed.Sample = 101;
        var recovered = await f.Coordinator.StoreClientAsync(client, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Equal(original, Assert.Single(f.ExactIntents)); Assert.Equal(2, f.AllHttpRequests);
        AssertQuorumDescriptorKeys(f, recovered.CanonicalMqr3.Span);
        await f.Sender.Node.Host.VerifyStoreSettlementAsync(original, recovered.CanonicalMqr3);
    }

    private static void AssertDescriptorKeys(Fixture f)
    {
        Assert.All(f.Sender.Node.Replicas, replica =>
        {
            Assert.False(replica.NodeId.Span.SequenceEqual(replica.SigningPublicKey.Span));
            Assert.Equal(f.Signed.Node(replica.NodeId.Span).Ed25519PublicKey.ToArray(), replica.SigningPublicKey.ToArray());
        });
    }

    private static void AssertQuorumDescriptorKeys(Fixture f, ReadOnlySpan<byte> encoded)
    {
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(encoded);
        var coordinatorKey = f.Signed.Node(quorum.CoordinatorId.Span).Ed25519PublicKey;
        var statement = MailboxReceiptV3Codec.GetQuorumSigningBytes(quorum);
        Assert.True(f.Sender.Crypto.Verify(coordinatorKey.Span, statement, quorum.Signature.Span));
        Assert.False(f.Sender.Crypto.Verify(quorum.CoordinatorId.Span, statement, quorum.Signature.Span));
        foreach (var replica in new[] { quorum.FirstReplica, quorum.SecondReplica })
        {
            var key = f.Signed.Node(replica.ReplicaId.Span).Ed25519PublicKey;
            var replicaStatement = MailboxReceiptV2Codec.GetReplicaSigningBytes(replica);
            Assert.True(f.Sender.Crypto.Verify(key.Span, replicaStatement, replica.Signature.Span));
            Assert.False(f.Sender.Crypto.Verify(replica.ReplicaId.Span, replicaStatement, replica.Signature.Span));
        }
    }

    private static void AssertNoPeerEffects(Fixture f)
    {
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Recipient.ReplayFiles);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests);
    }
}
