using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2PublicationFinalCommitterTests
{
    [Fact]
    public async Task RealDid2Authority_TerminalAndPeerCommitBothReceipts_ExactReplayAfterReopen()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var replicas = fixture.Placement.ReplicaIds;
            var fragments = Fragments(fixture);
            var receipts = new ParsedXic1V2[2];
            for (var i = 0; i < 2; i++)
            {
                var directory = Path.Combine(root, i.ToString());
                var receiver = Receiver(fixture, directory, replicas[i].Span);
                if (i == 0)
                {
                    foreach (var fragment in fragments.Take(fragments.Count - 1))
                        Assert.Equal(new byte[] { 1 }, (await receiver.ReceiveTerminalAsync(
                            fragment, default)).ToArray());
                    receipts[i] = DeepIdV2PreKeyCommitReceiptCodec.Decode(
                        (await receiver.ReceiveTerminalAsync(fragments[^1], default)).Span);
                }
                else
                {
                    var peer = RouterId.FromHex(Convert.ToHexString(replicas[0].Span));
                    foreach (var fragment in fragments)
                    {
                        // Exercise the actual wire projection, not the in-process
                        // verified capability as a stand-in for an authenticated RPC.
                        var command = ContactReplicaWireCodec.DecodeRequest(ContactReplicaWireCodec.Encode(
                            Command(fixture, fragment, ContactReplicaRpcOperation.StageDid2PreKeyPublication)));
                        Assert.Single((await receiver.ReceiveAsync(command, peer, default)).Payload.ToArray());
                    }
                    var commit = ContactReplicaWireCodec.DecodeRequest(ContactReplicaWireCodec.Encode(
                        Command(fixture, fragments[^1], ContactReplicaRpcOperation.CommitDid2PreKeyPublication)));
                    receipts[i] = DeepIdV2PreKeyCommitReceiptCodec.Decode(
                        (await receiver.ReceiveAsync(commit, peer, default)).Payload.Span);
                }
                using (var store = new DeepIdV2InventoryCommitStore(directory,
                           DeepIdV2PublicationAuthorityFixture.Network,
                           DeepIdV2PublicationAuthorityFixture.Service, replicas[i].Span))
                    Assert.Equal(fixture.Publication.CanonicalBytes.ToArray(),
                        store.ReadCurrentPublication()!.CanonicalBytes.ToArray());

                // A new receiver/committer reopens durable state and still verifies
                // current authority before returning the exact original receipt.
                var reopened = Receiver(fixture, directory, replicas[i].Span);
                fixture.RejectProof = true;
                await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                    await reopened.ReceiveTerminalAsync(fragments[^1], default));
                fixture.RejectProof = false;
                var replay = await reopened.ReceiveTerminalAsync(fragments[^1], default);
                Assert.Equal(receipts[i].CanonicalBytes.ToArray(), replay.ToArray());
            }
            DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(fixture.Publication,
                fixture.Placement.VerifiedPlacement, receipts[0], receipts[1]);
            Assert.Throws<ApplicationCoreFormatException>(() =>
                DeepIdV2PreKeyCommitReceiptVerifier.VerifyPair(fixture.Publication,
                    fixture.Placement.VerifiedPlacement, receipts[0], receipts[0]));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompleteStagedInventory_MissingOrExpiredCurrentProof_CannotActivate(bool expired)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var local = fixture.Placement.ReplicaIds[0];
            var receiver = Receiver(fixture, root, local.Span);
            var peer = RouterId.FromHex(Convert.ToHexString(fixture.Placement.ReplicaIds[1].Span));
            var fragments = Fragments(fixture);
            foreach (var fragment in fragments)
                await receiver.ReceiveAsync(Command(fixture, fragment,
                    ContactReplicaRpcOperation.StageDid2PreKeyPublication), peer, default);
            if (expired) fixture.Sample = fixture.Freshness.FreshnessDeadlineMonotonicSeconds;
            else fixture.RejectProof = true;
            await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
                await receiver.ReceiveAsync(Command(fixture, fragments[^1],
                    ContactReplicaRpcOperation.CommitDid2PreKeyPublication), peer, default));
            Assert.False(Directory.Exists(Path.Combine(root, "did2-prekey-commits")));
            fixture.Sample = 100;
            fixture.RejectProof = false;
            var receipt = await receiver.ReceiveAsync(Command(fixture, fragments[^1],
                ContactReplicaRpcOperation.CommitDid2PreKeyPublication), peer, default);
            Assert.Equal(local.ToArray(),
                DeepIdV2PreKeyCommitReceiptCodec.Decode(receipt.Payload.Span).Field(5).ToArray());
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task CompleteStagedInventory_AlteredPublicServiceSignature_CannotActivate()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = TemporaryRoot();
        try
        {
            var damaged = fixture.Xps.ToArray();
            damaged[^1] ^= 1;
            var fragments = Fragments(fixture, damaged);
            var local = fixture.Placement.ReplicaIds[0];
            var receiver = Receiver(fixture, root, local.Span);
            var peer = RouterId.FromHex(Convert.ToHexString(fixture.Placement.ReplicaIds[1].Span));
            foreach (var fragment in fragments)
                await receiver.ReceiveAsync(Command(fixture, fragment,
                    ContactReplicaRpcOperation.StageDid2PreKeyPublication), peer, default);
            await Assert.ThrowsAsync<ApplicationCoreFormatException>(async () =>
                await receiver.ReceiveAsync(Command(fixture, fragments[^1],
                    ContactReplicaRpcOperation.CommitDid2PreKeyPublication), peer, default));
            Assert.False(Directory.Exists(Path.Combine(root, "did2-prekey-commits")));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static IReadOnlyList<byte[]> Fragments(DeepIdV2PublicationAuthorityFixture fixture,
        byte[]? xps = null) => DeepIdV2BoundedPreKeyPublicationCodec.CreateSequence(
        fixture.Publication.CanonicalBytes.Span, fixture.Placement.ViewHash.Span,
        fixture.Publisher.CanonicalBytes.Span, fixture.Dca, xps ?? fixture.Xps);

    private static DeepIdV2ReplicaStageReceiver Receiver(DeepIdV2PublicationAuthorityFixture fixture,
        string root, ReadOnlySpan<byte> local)
    {
        var node = new RouterNodeOptions
        {
            DataDirectory = root,
            RouterId = Convert.ToHexString(local),
            Ed25519PrivateKey = Convert.ToHexString(fixture.Node(local).Seed)
        };
        var security = new MailboxStorageSecurity();
        var durability = new MailboxDurabilityBarrier();
        var committer = new DeepIdV2PublicationFinalCommitter(node,
            new(fixture, fixture), fixture, fixture, security, durability);
        return new(node, fixture, security, durability, committer);
    }

    private static ContactReplicaRpcCommand Command(DeepIdV2PublicationAuthorityFixture fixture,
        byte[] fragment, ContactReplicaRpcOperation operation) => new(fixture.Placement,
        operation, DeepIdV2PublicationAuthorityFixture.Bytes(32, 0x75),
        DeepIdV2ReplicaStagePayloadCodec.Encode(fixture.Publisher, fragment));

    private static string TemporaryRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "xnode-did2-final-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
