using System.Diagnostics;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task NativeStoreCompositeBudgetIncludesBothValidLocalAndPeerWork()
    {
        // Real native owners and pinned TLS. The controlled disk stalls test
        // resource scheduling only; this is not physical trusted-time evidence.
        await using var f = await Fixture.CreateAsync();
        var logger = new NativeFailureLogger();
        using var services = NativeServices(f, logger: logger);
        var local = 0; var remote = 0;
        f.Sender.Fault.Action = point =>
        {
            if (point == MailboxPeerMutationFaultPoint.StoreReserved && Interlocked.Increment(ref local) == 1)
                Thread.Sleep(TimeSpan.FromSeconds(8));
        };
        f.Recipient.Fault.Action = point =>
        {
            if (point == MailboxPeerMutationFaultPoint.StoreReserved && Interlocked.Increment(ref remote) == 1)
                Thread.Sleep(TimeSpan.FromSeconds(8));
        };
        var elapsed = Stopwatch.StartNew();
        var result = await NativeDispatcher(services).DispatchAsync(OnionOperation.Store,
            NativeFrame(f, MailboxAuthenticatedOperation.Store), default);
        Assert.True(result.Success, $"status={result.StatusCode}; local={local}; remote={remote}; elapsedMs={elapsed.ElapsedMilliseconds}; " + string.Join(" | ", logger.Messages));
        Assert.Equal(1, local); Assert.Equal(1, remote);
        Assert.True(elapsed.Elapsed > TimeSpan.FromSeconds(MailboxWireHttpContract.PeerStore.RequestTimeoutSeconds));
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
        // The remote owner receives a PRQ2 peer request, not a second MAU3
        // client request: check its actual peer journal, not client counters.
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed,
            Status(Assert.Single(f.Recipient.ReplayFiles)));
        var stored = await f.Recipient.ReadBlobAsync();
        Assert.NotNull(stored);
        Assert.True(f.Recipient.Envelope.AsSpan().SequenceEqual(stored));
    }
}
