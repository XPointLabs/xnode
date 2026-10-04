using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.PrivacyRouting;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task NativeOnionThreeDistinctHostsCompleteCurrentStoreRetrieveAckAndReplayReconciliation()
    {
        await using var f = await Fixture.CreateAsync(); AssertDescriptorKeys(f);
        var candidates = OnionPathCandidateSnapshotFactory.Create(f.Signed.NetworkContext).Candidates;
        var writer = candidates.Single(node => node.NodeId.Span.SequenceEqual(f.Sender.Node.Node));
        var forward = candidates.Where(node => !node.NodeId.Span.SequenceEqual(writer.NodeId.Span)).ToArray();
        Assert.Equal(2, forward.Length);
        var root = Path.Combine(Path.GetTempPath(), "xnode-current-native-onion-" + Guid.NewGuid().ToString("N"));
        var security = new MailboxStorageSecurity(); security.SecureDirectory(root);
        var clientKey = Path.Combine(root, "client.key");
        File.WriteAllBytes(clientKey, RandomNumberGenerator.GetBytes(32)); security.SecureFile(clientKey);
        var hosts = new List<Did2SignedMultiRoleHostTests.Host>();
        using var services = NativeServices(f);
        var terminal = new NativeMailboxExitDispatcher(services);
        var peers = new Did2SignedMultiRoleHostTests.Peers();
        try
        {
            using var entropy = new DurableOnionEntropyUniquenessLedger(Path.Combine(root, "client.entropy"), clientKey);
            using var vault = new FileOnionKeyAgreementVault(Path.Combine(root, "client.vault"), clientKey);
            var client = new PrivacyRoutingCodec(new(entropy), new(vault));
            foreach (var candidate in candidates)
            {
                var host = new Did2SignedMultiRoleHostTests.Host(Path.Combine(root, "node-" + hosts.Count),
                    f.Signed, candidate, peers, terminal);
                hosts.Add(host); peers.Hosts.Add(Convert.ToHexString(candidate.NodeId.Span), host);
                await host.Capability.StartAsync(default);
            }
            var entry = peers.Hosts[Convert.ToHexString(forward[0].NodeId.Span)];
            async Task<byte[]> Dispatch(OnionOperation operation, byte[] exact)
            {
                var path = OnionPathContextFactory.CreateMailbox(f.Signed.NetworkContext, operation,
                    f.Sender.Node.Replicas[0].NodeId, f.Sender.Node.Replicas[1].NodeId,
                    forward[0].NodeId, forward[1].NodeId, writer.NodeId);
                var request = OnionTerminalPayloadVerifierV1.VerifyRequest(f.Signed.NetworkContext, operation, exact);
                using var built = await client.BuildAsync(path, request, default);
                var result = await entry.Runtime.ProcessAsync(built.Frame, default);
                Assert.Equal(PrivacyRuntimeOutcome.Completed, result.Outcome);
                var opened = await client.OpenResponseAsync(result.OpaqueReply, built.ReplyContext, default);
                Assert.Equal(OnionTerminalResultKind.Success, opened.Result.Kind);
                Assert.Null(opened.Result.FailureCode);
                var beforeReplay = peers.Calls; var mailboxHttp = f.AllHttpRequests;
                entry.RestartReplay();
                Assert.Equal(PrivacyRuntimeOutcome.ReplayedBeforeForward,
                    (await entry.Runtime.ProcessAsync(built.Frame, default)).Outcome);
                Assert.Equal(beforeReplay, peers.Calls); Assert.Equal(mailboxHttp, f.AllHttpRequests);
                return opened.Result.Body.ToArray();
            }
            var store = f.ClientStoreFrame(); var stored = await Dispatch(OnionOperation.Store, store);
            AssertQuorumDescriptorKeys(f, stored);
            var retrieve = RetrieveFrame(f); var retrieved = await Dispatch(OnionOperation.Retrieve, retrieve);
            var page = DecodePage(retrieved, f); var item = Assert.Single(page.Items);
            Assert.Equal(f.Recipient.Envelope, Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope));
            var ack = AckFrame(f, page); var acked = await Dispatch(OnionOperation.Acknowledge, ack);
            AssertAck(acked, page, 0x74); AssertTombstones(f, 1);
            Assert.Equal(6, peers.Calls); Assert.Equal(2, f.AllHttpRequests);
            // New sealed frames may carry the same exact native operation. No
            // rewrite, resurrection or additional mailbox peer effect occurs.
            Assert.Equal(stored, await Dispatch(OnionOperation.Store, store));
            Assert.Equal(retrieved, await Dispatch(OnionOperation.Retrieve, retrieve));
            Assert.Equal(acked, await Dispatch(OnionOperation.Acknowledge, ack));
            Assert.Equal(12, peers.Calls); Assert.Equal(2, f.AllHttpRequests);
            Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
        }
        finally
        {
            foreach (var host in hosts) host.Dispose();
            var resolved = Path.GetFullPath(root);
            var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!resolved.StartsWith(temp, StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFileName(resolved).StartsWith("xnode-current-native-onion-", StringComparison.Ordinal))
                throw new InvalidOperationException("Unexpected test-owned onion cleanup target.");
            Directory.Delete(resolved, recursive: true);
        }
    }
}
