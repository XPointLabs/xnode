using System.Text.Json.Nodes;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task PendingCurrentMauBeforeFirstStoreIntentColdResumesExactlyOnce()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var exact = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Sender.Receiver.WithClientRequestAsync<int>(exact,
            Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxAuthenticatedOperation.Store,
            (_, _) => throw new IOException("Interrupted after replay join, before first Store intent."),
            default, storeLedger: f.Ledger).AsTask());
        Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests); Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        f.Reopen(); await f.InitializeLedgerAsync();
        var stored = await f.Coordinator.StoreClientAsync(exact);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, stored.Status);
        var original = Assert.Single(f.ExactIntents).ToArray();
        Assert.Equal(1, f.AllHttpRequests); Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        f.Reopen(); await f.InitializeLedgerAsync();
        var replay = await f.Coordinator.StoreClientAsync(exact);
        Assert.Equal(stored.CanonicalMqr3.ToArray(), replay.CanonicalMqr3.ToArray());
        Assert.Equal(original, Assert.Single(f.ExactIntents)); Assert.Equal(1, f.AllHttpRequests);
    }
    // These existing seams target Store/ACK intent/settlement transitions, not
    // the independent client/peer replay-floor writes in the same document.
    // Every write still uses the real barrier; only fault selection is semantic.
    private static bool IsBusinessWrite(string temporary, string current)
    {
        static JsonNode Read(string path)
        {
            var document = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
            Assert.True(document.Remove("clientReplayFloors"));
            Assert.True(document.Remove("peerReplayFloors"));
            return document;
        }
        return !JsonNode.DeepEquals(Read(temporary), Read(current));
    }

    private sealed class BusinessWriteFaultBoundary(IMailboxDurabilityBarrier fault) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        private bool business;
        public void ReplaceFile(string temporary, string final)
        {
            business = IsBusinessWrite(temporary, final);
            (business ? fault : native).ReplaceFile(temporary, final);
        }
        public void FlushFileAndParentDirectory(string path) =>
            (business ? fault : native).FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
    }

    // Deliberately NOT wrapped in BusinessWriteFaultBoundary: verifies the new
    // floor's own before/after-replacement failure rather than hiding that seam.
    private sealed class ReplayFloorWriteFault(bool beforeReplace) : IMailboxDurabilityBarrier
    {
        private readonly IntentWriteFault fault = new(beforeReplace);
        public void ReplaceFile(string temporary, string final) => fault.ReplaceFile(temporary, final);
        public void FlushFileAndParentDirectory(string path) => fault.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => fault.FlushParentDirectory(path);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentReplayFloorWriteFailureColdJoinsBeforeFirstIntentAndResumesExactlyOnce(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        f.OpenLedger(new ReplayFloorWriteFault(beforeReplace));
        var exact = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(exact).AsTask());
        Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests); Assert.Equal(0, f.Sender.Node.OutcomeCount);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        f.Reopen(); await f.InitializeLedgerAsync();
        var result = await f.Coordinator.StoreClientAsync(exact);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
        var first = Assert.Single(f.ExactIntents).ToArray();
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal(1, f.AllHttpRequests); Assert.Equal(1, f.Sender.Node.OutcomeCount);
        f.Reopen(); await f.InitializeLedgerAsync();
        var replay = await f.Coordinator.StoreClientAsync(exact);
        Assert.Equal(result.CanonicalMqr3.ToArray(), replay.CanonicalMqr3.ToArray());
        Assert.Equal(first, Assert.Single(f.ExactIntents)); Assert.Equal(1, f.AllHttpRequests);
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp"));
    }
}
