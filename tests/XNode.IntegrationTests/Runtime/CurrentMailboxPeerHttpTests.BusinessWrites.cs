using System.Text.Json.Nodes;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
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
    public async Task CurrentReplayFloorWriteFailureCannotDispatchOrRemintMissingExactIntent(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        f.OpenLedger(new ReplayFloorWriteFault(beforeReplace));
        var exact = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(exact).AsTask());
        Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests); Assert.Equal(0, f.Sender.Node.OutcomeCount);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount);
        f.Reopen(); await f.InitializeLedgerAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(exact).AsTask());
        Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.AllHttpRequests); Assert.Equal(0, f.Sender.Node.OutcomeCount);
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp"));
    }
}
