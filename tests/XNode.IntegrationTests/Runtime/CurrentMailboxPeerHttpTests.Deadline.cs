using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task PeerDeadlineCannotMintQuorumAndExactColdRetryResumesPendingNativeStore()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var exactClient = f.ClientStoreFrame();
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        f.RemoteHost.RequestCompleted = completed;
        f.Recipient.Fault.Action = point =>
        {
            if (point != MailboxPeerMutationFaultPoint.StoreReserved) return;
            reached.TrySetResult();
            if (!release.Wait(TimeSpan.FromSeconds(15)))
                throw new IOException("Test-owned native barrier was not released.");
        };
        byte[] exactIntent;
        try
        {
            var attempt = f.Coordinator.StoreClientAsync(exactClient, f.Ledger!).AsTask();
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var partial = await attempt.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, partial.Status);
            Assert.Equal(1, partial.DurableReplicaCount); Assert.True(partial.CanonicalMqr3.IsEmpty);
            Assert.True(f.PeerClient.Cancelled);
            Assert.Equal(0, f.Sender.Node.OutcomeCount);
            Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
            exactIntent = Assert.Single(f.ExactIntents);
            Assert.True(exactIntent.AsSpan().SequenceEqual(Assert.Single(f.PeerClient.ExactRequests)));
        }
        finally { release.Set(); }
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(15));
        f.Recipient.Fault.Action = null;
        Assert.Equal(exactIntent.Length, f.RemoteHost.BodyBytes); Assert.Equal(1, f.RemoteHost.EndReads);
        Assert.True(f.RemoteHost.RequestCancelled);
        Assert.Equal("OperationCanceledException", f.RemoteHost.HandlerFailure);
        Assert.Null(await f.Recipient.ReadBlobAsync());
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Recipient.ReplayFiles)));

        f.Reopen();
        var recovered = await f.Coordinator.StoreClientAsync(exactClient, f.Ledger!);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Equal(2, recovered.DurableReplicaCount); Assert.False(recovered.CanonicalMqr3.IsEmpty);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal(2, f.PeerClient.ExactRequests.Count); Assert.Equal(2, f.RemoteHost.Requests);
        Assert.True(exactIntent.AsSpan().SequenceEqual(f.PeerClient.ExactRequests[1]));
        Assert.True(exactIntent.AsSpan().SequenceEqual(Assert.Single(f.ExactIntents)));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.PendingCount);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.CompletedCount);
    }
}
