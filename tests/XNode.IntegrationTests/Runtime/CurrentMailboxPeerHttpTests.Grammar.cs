using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task BoundedOperationGrammarKeepsTheExistingStreamUtf8BomSemantics()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var original = File.ReadAllBytes(f.LedgerFile);
        await f.InstallTestOwnedDocumentAsync([0xef, 0xbb, 0xbf, .. original]);
        await f.Sender.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            await f.Ledger!.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            var decoded = f.Ledger.GrammarDecodeCount;
            await f.Ledger.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            Assert.Equal(decoded, f.Ledger.GrammarDecodeCount);
            return 0;
        });
        Assert.Equal(new byte[] { 0xef, 0xbb, 0xbf }, File.ReadAllBytes(f.LedgerFile)[..3]);
        Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public async Task GrammarMemoBudgetDoesNotRejectAValidLargerAuthenticatedDocument()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var original = File.ReadAllBytes(f.LedgerFile);
        var larger = new byte[8 * 1024 * 1024 + original.Length];
        larger.AsSpan().Fill((byte)' '); original.CopyTo(larger, 0);
        await f.InstallTestOwnedDocumentAsync(larger);
        await f.Sender.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            var before = f.Ledger!.GrammarDecodeCount;
            await f.Ledger.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            await f.Ledger.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            Assert.Equal(before + 2, f.Ledger.GrammarDecodeCount);
            return 0;
        });
        Assert.Equal(larger.Length, new FileInfo(f.LedgerFile).Length);
        Assert.Equal(0, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WarmOperationGrammarStillAuthenticatesActualBytesAfterEveryCustodyCallback(bool tamper)
    {
        await using var f = await Fixture.CreateAsync();
        var callbacks = 0; var damage = false;
        f.OpenLedger(afterVerifiedRead: () =>
        {
            callbacks++;
            if (!damage) return;
            var encoded = File.ReadAllBytes(f.LedgerFile); encoded[0] ^= 1;
            File.WriteAllBytes(f.LedgerFile, encoded);
        });
        await f.Sender.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            Task<ulong> Read() => f.Ledger!.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            await Read(); var decoded = f.Ledger!.GrammarDecodeCount;
            await Read();
            Assert.Equal(decoded, f.Ledger.GrammarDecodeCount);
            damage = tamper;
            if (tamper) await Assert.ThrowsAsync<InvalidDataException>(Read);
            else await Read();
            Assert.Equal(decoded, f.Ledger.GrammarDecodeCount);
            return 0;
        });
        Assert.Equal(3, callbacks);
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public async Task WarmOperationGrammarReparsesAnActualAuthenticatedNewNativeIntent()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var client = MailboxAuthenticatedClientRequestCodec.Decode(f.ClientStoreFrame());
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(client.Binding.CanonicalRequest.Span);
        await f.Sender.Node.Admission.WithGrantAsync(
            MailboxAuthenticatedCapabilityCodec.EncodeGrant(client.Presentation.Grant), MailboxCapabilityDomain.Deposit,
            async (scope, token) =>
            {
                Task<ulong> Read() => f.Ledger!.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
                await Read(); var before = f.Ledger!.GrammarDecodeCount;
                await Read(); Assert.Equal(before, f.Ledger.GrammarDecodeCount);
                var oldBytes = File.ReadAllBytes(f.LedgerFile);
                var intent = await f.Ledger.ReserveCurrentStoreAsync(envelope, scope.Grant.MembershipCommitment,
                    scope.Replicas.Select(replica => replica.NodeId).ToArray(), scope.Lease,
                    (cursor, upper) => f.Sender.Receiver.AuthorStoreRequest(scope,
                        client.Binding.CanonicalRequest, cursor, upper), scope.Host, token);
                Assert.False(oldBytes.AsSpan().SequenceEqual(File.ReadAllBytes(f.LedgerFile)));
                await Read(); Assert.True(f.Ledger.GrammarDecodeCount > before);
                var after = f.Ledger.GrammarDecodeCount;
                await Read(); Assert.Equal(after, f.Ledger.GrammarDecodeCount);
                Assert.Equal(intent.CanonicalPeerRequest.ToArray(), Assert.Single(f.ExactIntents));
                return 0;
            });
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public async Task AClosedActualLeaseCannotUseItsWarmOperationGrammar()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        MailboxCurrentOperationLease? closed = null;
        Deep.Protocol.XPointNetworkV1.VerifiedMailboxHostAuthorityV2? host = null;
        await f.Sender.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            closed = scope.Lease; host = scope.Host;
            await f.Ledger!.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            await f.Ledger.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token);
            return 0;
        });
        var before = f.Ledger!.GrammarDecodeCount;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            f.Ledger.InitializeCurrentAsync(f.Sender.Node.Node, host!, closed!, default));
        Assert.Equal(before, f.Ledger.GrammarDecodeCount);
        Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public void OperationGrammarCopiesAllMutableDictionaryAndNestedArrayOwners()
    {
        var store = new MailboxClientLedgerOperation(1, "m", "o", "r", "e", "b", "p", "v", ["first", "second"],
            1, 100, "reserved", "", 0, "", 0, "", "", "", false, 0, false, "request");
        var item = new MailboxClientLedgerAckItem(1, "e", 100, "reserved", "", 0, "", "", "", "request");
        var ack = new MailboxClientLedgerAckOperation(1, "m", "o", "r", "p", "v", ["first", "second"], 1, 100, [item]);
        var source = new MailboxClientLedgerDocument(8, 0, 0, new() { ["cursor"] = 1 },
            new() { ["store"] = store }, new() { ["ack"] = ack },
            new() { ["client"] = new(1, "claim", "outcome") },
            new() { ["peer"] = new("replay", "target", "store", "", false, "", 100) });
        var memo = MailboxClientOperationLedger.CopyGrammarDocument(source);
        source.NextCursorByMailbox.Clear(); source.Operations["store"].ExpectedReplicaIds[0] = "changed";
        source.AckOperations["ack"].ExpectedReplicaIds[0] = "changed";
        source.AckOperations["ack"].Items[0] = item with { PeerRequest = "changed" };
        source.Operations.Clear(); source.AckOperations.Clear(); source.ClientReplayFloors.Clear(); source.PeerReplayFloors.Clear();
        var borrowed = MailboxClientOperationLedger.CopyGrammarDocument(memo);
        borrowed.Operations["store"].ExpectedReplicaIds[1] = "borrowed-change";
        borrowed.AckOperations["ack"].Items[0] = item with { PeerRequest = "borrowed-change" };
        Assert.Single(memo.NextCursorByMailbox); Assert.Single(memo.ClientReplayFloors); Assert.Single(memo.PeerReplayFloors);
        Assert.Equal(new[] { "first", "second" }, memo.Operations["store"].ExpectedReplicaIds);
        Assert.Equal(new[] { "first", "second" }, memo.AckOperations["ack"].ExpectedReplicaIds);
        Assert.Equal("request", memo.AckOperations["ack"].Items[0].PeerRequest);
    }
}
