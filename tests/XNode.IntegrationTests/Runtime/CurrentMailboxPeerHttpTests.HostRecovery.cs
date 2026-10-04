using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostRecoveryStartsBothActualOwnersWithoutClientGrantOrReplay(bool recipient)
    {
        await using var f = await Fixture.CreateAsync();
        var peer = recipient ? f.Recipient : f.Sender;
        var path = Path.Combine(peer.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var before = File.ReadAllBytes(path);
        // This expires the fixture's client grant, not the independently current
        // host/MGR authority. Startup must not manufacture a replacement grant.
        f.Signed.Sample = 105;
        using var host = RecoveryHost(f, recipient);
        await host.StartAsync();
        var recovery = host.Services.GetRequiredService<CurrentMailboxHostRecovery>();
        var status = await recovery.CheckAsync();
        Assert.True(status.Recovered); Assert.Equal("recovered", status.State);
        Assert.True(CryptographicOperations.FixedTimeEquals(before, File.ReadAllBytes(path)));
        Assert.Equal(0, peer.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, peer.Node.OutcomeCount);
        Assert.Empty(peer.ReplayFiles); Assert.Empty(peer.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
        await host.StopAsync();
        Assert.False((await recovery.CheckAsync()).Recovered);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostRecoveryMissingOrSplitCompositionCannotUseRetiredOwners(bool split)
    {
        await using var f = await Fixture.CreateAsync();
        using var host = RecoveryHost(f, missing: !split, split: split);
        var reads = f.Signed.PublicationReads;
        await host.StartAsync();
        var status = await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync();
        Assert.False(status.Recovered); Assert.Equal(split ? "unavailable" : "unconfigured", status.State);
        Assert.Equal(reads, f.Signed.PublicationReads);
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostRecoveryLostDocumentOrProtectionStaysUnreadyWithoutEnrollment(bool checkpoint)
    {
        await using var f = await Fixture.CreateAsync();
        var path = checkpoint ? Assert.Single(Directory.GetFiles(f.Sender.Node.OperationCustodyRoot,
            "checkpoint.bin", SearchOption.AllDirectories)) : f.LedgerFile;
        var original = File.ReadAllBytes(path); File.Delete(path);
        using var host = RecoveryHost(f);
        await host.StartAsync();
        var recovery = host.Services.GetRequiredService<CurrentMailboxHostRecovery>();
        Assert.False((await recovery.CheckAsync()).Recovered); Assert.False(File.Exists(path));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles);
        File.WriteAllBytes(path, original); new MailboxStorageSecurity().SecureFile(path);
        Assert.True((await recovery.CheckAsync()).Recovered);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, File.ReadAllBytes(path)));
        await host.StopAsync();
    }

    [Fact]
    public async Task CurrentHostRecoveryWrongDescriptorKeyRejectsBeforeDocumentRecovery()
    {
        await using var f = await Fixture.CreateAsync();
        var original = File.ReadAllBytes(f.LedgerFile);
        f.Sender.Reopen(signingSeed: f.Sender.Node.Node); f.Bind();
        using var host = RecoveryHost(f);
        await host.StartAsync();
        Assert.False((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, File.ReadAllBytes(f.LedgerFile)));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); await host.StopAsync();
    }

    [Fact]
    public async Task CurrentHostRecoveryFreshCheckCannotReuseEarlierSuccessfulStatus()
    {
        await using var f = await Fixture.CreateAsync();
        using var host = RecoveryHost(f);
        await host.StartAsync();
        var recovery = host.Services.GetRequiredService<CurrentMailboxHostRecovery>();
        Assert.True((await recovery.CheckAsync()).Recovered);
        var original = File.ReadAllBytes(f.LedgerFile);
        f.Signed.RejectProof = true;
        Assert.False((await recovery.CheckAsync()).Recovered);
        f.Signed.RejectProof = false; f.Signed.Sample = 500;
        Assert.False((await recovery.CheckAsync()).Recovered);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, File.ReadAllBytes(f.LedgerFile)));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        var reads = f.Signed.PublicationReads;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => recovery.CheckAsync(cancelled.Token).AsTask());
        Assert.Equal(reads, f.Signed.PublicationReads); await host.StopAsync();
    }

    [Fact]
    public async Task CurrentHostRecoveryRejectsSnapshotChangedInsideRealProtectedRead()
    {
        await using var f = await Fixture.CreateAsync(); var original = File.ReadAllBytes(f.LedgerFile);
        f.OpenLedger(afterVerifiedRead: () => File.AppendAllText(f.LedgerFile, " "));
        using var host = RecoveryHost(f);
        await host.StartAsync();
        Assert.False((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.Equal(original.Length + 1, new FileInfo(f.LedgerFile).Length);
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostRecoveryNeedsBothProtectedRoleFloorsAndNeverReEnrolls(bool retrieve)
    {
        await using var f = await Fixture.CreateAsync();
        var path = retrieve ? f.Sender.Node.RetrieveFloorFile : f.Sender.Node.DepositFloorFile;
        var original = File.ReadAllBytes(f.LedgerFile); File.Delete(path);
        using var host = RecoveryHost(f); await host.StartAsync();
        Assert.False((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.False(File.Exists(path));
        Assert.True(CryptographicOperations.FixedTimeEquals(original, File.ReadAllBytes(f.LedgerFile)));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostRecoveryFinishesOnlyAnchoredPendingReplacementBeforeAnyPeerHttp(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        f.OpenLedger(new IntentWriteFault(beforeReplace)); var request = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(request, f.Ledger!).AsTask());
        byte[] original;
        if (beforeReplace)
        {
            var temporary = Assert.Single(Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp"));
            using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(temporary));
            original = Convert.FromBase64String(document.RootElement.GetProperty("operations").EnumerateObject()
                .Single().Value.GetProperty("peerRequest").GetString()!);
        }
        else original = Assert.Single(f.ExactIntents);
        f.Reopen(); using var host = RecoveryHost(f); await host.StartAsync();
        Assert.True((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, Assert.Single(f.ExactIntents)));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp"));
        Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(request)).Status);
        Assert.True(CryptographicOperations.FixedTimeEquals(original, Assert.Single(f.ExactIntents)));
        Assert.Equal(1, f.AllHttpRequests); await host.StopAsync();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentHostRecoveryBusyOrStoppingCannotReportCachedSuccess(bool stop)
    {
        await using var f = await Fixture.CreateAsync();
        CurrentMailboxHostRecovery? recovery = null; CurrentMailboxHostRecoveryStatus? nested = null;
        f.OpenLedger(afterVerifiedRead: () =>
        {
            if (stop) recovery!.StopAsync(default).GetAwaiter().GetResult();
            nested = recovery!.CheckAsync().AsTask().GetAwaiter().GetResult();
        });
        using var host = RecoveryHost(f); recovery = host.Services.GetRequiredService<CurrentMailboxHostRecovery>();
        await host.StartAsync();
        Assert.NotNull(nested); Assert.False(nested.Recovered);
        Assert.Equal(stop ? "not-running" : "checking", nested.State);
        if (stop) Assert.False((await recovery.CheckAsync()).Recovered);
        else Assert.True((await recovery.CheckAsync()).Recovered);
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); await host.StopAsync();
    }

    private static IHost RecoveryHost(Fixture fixture, bool recipient = false, bool missing = false, bool split = false)
    {
        var builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(new ReplicatedMailboxOptions { Enabled = true });
        if (!missing)
        {
            builder.Services.AddSingleton(recipient ? fixture.Recipient.Receiver : fixture.Sender.Receiver);
            builder.Services.AddSingleton(split ? new CurrentMailboxReplicationCoordinator(fixture.Recipient.Receiver,
                fixture.PeerClient, new ReplicatedMailboxOptions { Enabled = true }) :
                recipient ? new CurrentMailboxReplicationCoordinator(fixture.Recipient.Receiver, fixture.PeerClient,
                    new ReplicatedMailboxOptions { Enabled = true }) : fixture.Coordinator);
        }
        builder.Services.AddCurrentMailboxHostRecovery();
        return builder.Build();
    }
}
