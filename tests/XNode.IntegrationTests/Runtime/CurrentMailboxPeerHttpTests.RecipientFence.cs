using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task RecipientFence_RealHttpStoreAndAckReleaseOnlyCommittedRepliesAndColdReplayIsExact()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var observed = new List<byte[]>();
        f.RemoteHost.AfterReceive = response =>
        {
            var document = JsonNode.Parse(File.ReadAllBytes(Path.Combine(f.Recipient.Node.DataRoot,
                "mailbox-client-intent", "operations.json")))!;
            var digest = Convert.ToHexString(SHA256.HashData(response.Span)).ToLowerInvariant();
            var fact = Assert.Single(document["peerReplayFloors"]!.AsObject().Select(pair => pair.Value!),
                row => row["responseDigest"]!.GetValue<string>() == digest);
            Assert.True(fact["mutationCompleted"]!.GetValue<bool>());
            Assert.All(f.Recipient.ReplayFiles,
                path => Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(path)));
            observed.Add(response.ToArray());
            return response;
        };
        var storeRequest = f.ClientStoreFrame();
        var stored = await f.Coordinator.StoreClientAsync(storeRequest, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, stored.Status);
        Assert.Equal(1, f.AllHttpRequests); Assert.Single(observed);
        Assert.Equal(MailboxReplicaDisposition.Stored, MailboxReceiptV2Codec.DecodeReplica(observed[0]).Disposition);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var ackRequest = AckFrame(f, page);
        var acknowledged = (await f.Coordinator.AcknowledgeClientAsync(ackRequest, f.AckLedger)).ToArray();
        AssertAck(acknowledged, page, 0x74);
        Assert.Equal(2, f.AllHttpRequests); Assert.Equal(2, observed.Count);
        Assert.Equal(MailboxReplicaDisposition.Tombstone, MailboxReceiptV2Codec.DecodeReplica(observed[1]).Disposition);
        AssertTombstones(f, 1); Assert.False(File.Exists(BlobPath(f)));
        f.Reopen(); f.Signed.Sample = 101;
        var replay = await f.Coordinator.StoreClientAsync(storeRequest, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, replay.Status);
        Assert.Equal(stored.CanonicalMqr3.ToArray(), replay.CanonicalMqr3.ToArray());
        Assert.Equal(acknowledged, (await f.Coordinator.AcknowledgeClientAsync(ackRequest, f.AckLedger)).ToArray());
        Assert.Equal(2, f.AllHttpRequests); Assert.Equal(2, observed.Count); AssertTombstones(f, 1);
    }

    [Theory]
    [InlineData("mutation")]
    [InlineData("protected-document")]
    [InlineData("authority")]
    public async Task RecipientFence_GenericPostActionJoinStillRejectsChangesAfterPrivateRecipientCommit(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var completedInsideCallback = false;
        var released = false;
        async Task Invoke()
        {
            _ = await f.Recipient.Receiver.WithPeerAsync(exact, MailboxPeerReplicationOperation.Store,
                MailboxPeerWireResponseReplicaV2.Recipient, async (operation, token) =>
                {
                    var response = await operation.ApplySignAndCommitRecipientAsync(token);
                    Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Recipient.ReplayFiles)));
                    completedInsideCallback = true;
                    if (defect == "mutation")
                    {
                        var path = Assert.Single(f.Recipient.MutationFiles);
                        var document = JsonNode.Parse(File.ReadAllBytes(path))!;
                        document["cursor"] = 2UL; File.WriteAllText(path, document.ToJsonString());
                    }
                    else if (defect == "protected-document")
                        File.Delete(Path.Combine(f.Recipient.Node.DataRoot, "mailbox-client-intent", "operations.json"));
                    else f.Signed.RejectProof = true;
                    return response;
                });
            released = true;
        }
        if (defect == "authority") await Assert.ThrowsAsync<CryptographicException>(Invoke);
        else await Assert.ThrowsAsync<InvalidDataException>(Invoke);
        Assert.True(completedInsideCallback); Assert.False(released); Assert.Equal(0, f.AllHttpRequests);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Recipient.ReplayFiles)));
        Assert.Single(f.Recipient.MutationFiles);
    }
}
