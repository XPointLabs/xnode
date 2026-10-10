using System.Text;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false, "missing-blob")]
    [InlineData(true, "missing-blob")]
    [InlineData(false, "corrupt-blob")]
    [InlineData(true, "corrupt-blob")]
    [InlineData(false, "missing-mutation")]
    [InlineData(true, "missing-mutation")]
    [InlineData(false, "corrupt-mutation")]
    [InlineData(true, "corrupt-mutation")]
    [InlineData(false, "missing-peer-replay")]
    [InlineData(true, "missing-peer-replay")]
    [InlineData(false, "corrupt-peer-replay")]
    [InlineData(true, "corrupt-peer-replay")]
    public async Task CurrentHostNativeRecoveryRejectsDamagedReplicaWithoutRepairOrHttp(bool recipient, string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        var peer = recipient ? f.Recipient : f.Sender;
        using var host = RecoveryHost(f, recipient); await host.StartAsync();
        var recovery = host.Services.GetRequiredService<CurrentMailboxHostRecovery>();
        Assert.True((await recovery.CheckAsync()).Recovered);
        var path = defect.EndsWith("blob", StringComparison.Ordinal) ? NativeBlob(peer.Node.DataRoot) :
            defect.EndsWith("mutation", StringComparison.Ordinal) ? Assert.Single(peer.MutationFiles) : Assert.Single(peer.ReplayFiles);
        var original = File.ReadAllBytes(path);
        var protectedIntent = File.ReadAllBytes(f.LedgerFile);
        var requests = f.AllHttpRequests;
        if (defect.StartsWith("missing", StringComparison.Ordinal)) File.Delete(path);
        else File.WriteAllBytes(path, "{"u8.ToArray());
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var status = await recovery.CheckAsync();
            Assert.False(status.Recovered); Assert.Equal("unavailable", status.State);
            if (defect.StartsWith("missing", StringComparison.Ordinal)) Assert.False(File.Exists(path));
            else Assert.Equal("{"u8.ToArray(), File.ReadAllBytes(path));
            Assert.Equal(protectedIntent, File.ReadAllBytes(f.LedgerFile));
            Assert.Equal(requests, f.AllHttpRequests);
        }
        File.WriteAllBytes(path, original); new MailboxStorageSecurity().SecureFile(path);
        Assert.True((await recovery.CheckAsync()).Recovered);
        Assert.Equal(original, File.ReadAllBytes(path)); Assert.Equal(requests, f.AllHttpRequests);
        await host.StopAsync();
    }

    [Theory]
    [InlineData("missing-outcome")]
    [InlineData("corrupt-outcome")]
    [InlineData("missing-client-replay")]
    [InlineData("changed-client-replay")]
    public async Task CurrentHostNativeRecoveryRejectsDamagedClientCompletionWithoutRepair(string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        using var host = RecoveryHost(f); await host.StartAsync();
        var recovery = host.Services.GetRequiredService<CurrentMailboxHostRecovery>();
        Assert.True((await recovery.CheckAsync()).Recovered);
        var path = defect.EndsWith("outcome", StringComparison.Ordinal) ?
            Assert.Single(Directory.GetFiles(Path.Combine(f.Sender.Node.DataRoot, "mailbox-client-canonical-outcomes-v1"), "*.outcome")) :
            Path.Combine(f.Sender.Node.DataRoot, "mailbox-capability-replay-v3", "replay.json");
        var original = File.ReadAllBytes(path);
        var intent = File.ReadAllBytes(f.LedgerFile); var requests = f.AllHttpRequests;
        if (defect.StartsWith("missing", StringComparison.Ordinal)) File.Delete(path);
        else if (defect.StartsWith("corrupt", StringComparison.Ordinal)) File.WriteAllBytes(path, [1]);
        else
        {
            var json = JsonNode.Parse(original)!;
            json["records"]!.AsObject().Single().Value!["highestCounter"] = 2UL;
            File.WriteAllBytes(path, Encoding.UTF8.GetBytes(json.ToJsonString()));
        }
        var damaged = File.Exists(path) ? File.ReadAllBytes(path) : null;
        Assert.False((await recovery.CheckAsync()).Recovered);
        if (damaged is null) Assert.False(File.Exists(path)); else Assert.Equal(damaged, File.ReadAllBytes(path));
        Assert.Equal(intent, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(requests, f.AllHttpRequests);
        File.WriteAllBytes(path, original); new MailboxStorageSecurity().SecureFile(path);
        Assert.True((await recovery.CheckAsync()).Recovered);
        Assert.Equal(original, File.ReadAllBytes(path)); Assert.Equal(requests, f.AllHttpRequests);
        await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostNativeRecoveryColdOpenRejectsMissingBlobOrOrphan(bool orphan)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        var path = orphan ? Assert.Single(f.Sender.MutationFiles) : NativeBlob(f.Sender.Node.DataRoot);
        File.Delete(path); f.Reopen(); var requests = f.AllHttpRequests;
        using var host = RecoveryHost(f); await host.StartAsync();
        Assert.False((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.False(File.Exists(path)); Assert.Equal(requests, f.AllHttpRequests); await host.StopAsync();
    }

    [Fact]
    public async Task CurrentHostNativeRecoveryColdOpenJoinsExactCompletedReplayDigest()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        var path = Path.Combine(f.Sender.Node.DataRoot, "mailbox-capability-replay-v3", "replay.json");
        var json = JsonNode.Parse(File.ReadAllBytes(path))!;
        json["records"]!.AsObject().Single().Value!["canonicalOutcome"] = Convert.ToBase64String(Enumerable.Repeat((byte)0x71, 32).ToArray());
        var damaged = Encoding.UTF8.GetBytes(json.ToJsonString()); File.WriteAllBytes(path, damaged);
        f.Reopen(); var requests = f.AllHttpRequests;
        using var host = RecoveryHost(f); await host.StartAsync();
        Assert.False((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.Equal(damaged, File.ReadAllBytes(path)); Assert.Equal(requests, f.AllHttpRequests); await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostNativeRecoveryColdPendingLostReplyRemainsReadyForExactRetry(bool recipient)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var request = f.ClientStoreFrame(); f.RemoteHost.DropNext = true;
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, (await f.Coordinator.StoreClientAsync(request)).Status);
        f.Reopen(); var requests = f.AllHttpRequests;
        var intent = Assert.Single(f.ExactIntents);
        using var host = RecoveryHost(f, recipient); await host.StartAsync();
        Assert.True((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.Equal(requests, f.AllHttpRequests); Assert.Equal(intent, Assert.Single(f.ExactIntents));
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(request)).Status);
        Assert.Equal(intent, Assert.Single(f.ExactIntents)); Assert.Equal(requests + 1, f.AllHttpRequests);
        Assert.True((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        await host.StopAsync();
    }

    [Fact]
    public async Task CurrentHostNativeRecoveryRejectsTombstonedBlobResurrectionWithoutDeletingIt()
    {
        await using var f = await Fixture.CreateAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store)).Status);
        var path = NativeBlob(f.Sender.Node.DataRoot); var original = File.ReadAllBytes(path);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone), MailboxPeerReplicationOperation.Tombstone)).Status);
        File.WriteAllBytes(path, original); new MailboxStorageSecurity().SecureFile(path);
        f.Reopen(); var requests = f.AllHttpRequests;
        using var host = RecoveryHost(f); await host.StartAsync();
        Assert.False((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.Equal(original, File.ReadAllBytes(path)); Assert.Equal(requests, f.AllHttpRequests); await host.StopAsync();
    }

    private static string NativeBlob(string dataRoot) =>
        Assert.Single(Directory.GetFiles(Path.Combine(dataRoot, "mailbox-v1"), "*.json", SearchOption.AllDirectories));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostNativeRecoveryColdCompletedStateDoesNotRequireLiveClientGrant(bool tombstoned)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        if (tombstoned)
        {
            var page = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
            AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger)).Span, page, 0x74);
        }
        f.Reopen(); f.Signed.Sample = 105; var requests = f.AllHttpRequests;
        var intent = File.ReadAllBytes(f.LedgerFile);
        foreach (var recipient in new[] { false, true })
        {
            using var host = RecoveryHost(f, recipient); await host.StartAsync();
            Assert.True((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
            Assert.Equal(intent, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(requests, f.AllHttpRequests);
            await host.StopAsync();
        }
    }
}
