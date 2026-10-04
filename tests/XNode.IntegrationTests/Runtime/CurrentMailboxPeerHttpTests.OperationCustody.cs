using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task CurrentReadAuthenticatesActualSnapshotAfterVerifiedReadCallback()
    {
        await using var f = await Fixture.CreateAsync(); var prior = File.ReadAllBytes(f.LedgerFile);
        f.OpenLedger(afterVerifiedRead: () => File.AppendAllText(f.LedgerFile, " "));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!).AsTask());
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(prior.Length + 1, new FileInfo(f.LedgerFile).Length);
        File.WriteAllBytes(f.LedgerFile, prior); f.Reopen(); await f.InitializeLedgerAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
    }

    [Fact]
    public async Task OperationStartupNeedsNoClientGrantOrReplayAndCannotReEnrollMissingData()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var empty = File.ReadAllBytes(f.LedgerFile);
        await f.InitializeLedgerAsync();
        Assert.Equal(empty, File.ReadAllBytes(f.LedgerFile));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
        File.Delete(f.LedgerFile);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.InitializeLedgerAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Node.Admission.EnrollNewOperationsAsync(f.Ledger!).AsTask());
        Assert.False(File.Exists(f.LedgerFile)); Assert.Empty(f.ExactIntents);
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LostOrRolledBackIntentBeforeAnyNativeMutationRejectsNewGrantAndKnownReplay(bool delete)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); var initial = File.ReadAllBytes(f.LedgerFile);
        f.OpenLedger(new IntentWriteFault(beforeReplace: false)); var original = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(original, f.Ledger!).AsTask());
        Assert.Single(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Sender.ReplayFiles);
        var exactDocument = File.ReadAllBytes(f.LedgerFile);
        if (delete) File.Delete(f.LedgerFile); else File.WriteAllBytes(f.LedgerFile, initial);
        f.Reopen();
        var before = delete ? null : File.ReadAllBytes(f.LedgerFile); var replay = f.Sender.Node.Replay.Diagnostics;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.InitializeLedgerAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(DifferentGrantStore(f), f.Ledger!).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(original, f.Ledger!).AsTask());
        Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        if (delete) Assert.False(File.Exists(f.LedgerFile)); else Assert.Equal(before, File.ReadAllBytes(f.LedgerFile));
        // Exact backup plus intact independent plan recovers; no recreation.
        File.WriteAllBytes(f.LedgerFile, exactDocument); new MailboxStorageSecurity().SecureFile(f.LedgerFile);
        await f.InitializeLedgerAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(original, f.Ledger!)).Status);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(DifferentGrantStore(f), f.Ledger!)).Status);
        Assert.Equal(new ulong[] { 1, 2 }, f.ExactIntents.Select(bytes => MailboxPeerWireV2Codec.Decode(bytes).Cursor).Order());
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    [InlineData(2, false)]
    [InlineData(3, true)]
    [InlineData(3, false)]
    [InlineData(4, true)]
    [InlineData(4, false)]
    public async Task OperationCheckpointCrashBoundaryNeverRemintsOrAddsPeerHttp(int write, bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync(); var fault = new OperationCheckpointFault(write, beforeReplace);
        f.OpenLedger(custodyDurability: fault); var request = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(request, f.Ledger!).AsTask());
        Assert.True(fault.Reached);
        var files = Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp");
        var exact = f.ExactIntents.FirstOrDefault();
        if (exact is null)
        {
            var encoded = JsonNode.Parse(File.ReadAllBytes(Assert.Single(files)))!["operations"]!.AsObject().Single().Value!["peerRequest"]!.GetValue<string>();
            exact = Convert.FromBase64String(encoded);
        }
        var http = f.AllHttpRequests; f.Reopen();
        await f.InitializeLedgerAsync();
        if (write == 1 && beforeReplace)
        {
            // An unanchored temporary is not authority. It is not adopted; a
            // previously reserved client request cannot mint another peer nonce.
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(request, f.Ledger!).AsTask());
            Assert.Empty(f.ExactIntents); Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
        }
        else
        {
            var result = await f.Coordinator.StoreClientAsync(request, f.Ledger!);
            Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status); Assert.Equal(exact, Assert.Single(f.ExactIntents));
            Assert.Equal(write <= 2 ? 1 : http, f.AllHttpRequests);
            var preserved = result.CanonicalMqr3.ToArray(); f.Reopen();
            Assert.Equal(preserved, (await f.Coordinator.StoreClientAsync(request, f.Ledger!)).CanonicalMqr3.ToArray());
            Assert.Equal(1, f.AllHttpRequests);
        }
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MissingOrCorruptAnchoredTemporaryCannotRepairOrReserveReplay(bool delete)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(new IntentWriteFault(beforeReplace: true));
        var request = f.ClientStoreFrame();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(request, f.Ledger!).AsTask());
        var temporary = Assert.Single(Directory.GetFiles(Path.GetDirectoryName(f.LedgerFile)!, "operations.json.*.tmp"));
        if (delete) File.Delete(temporary); else File.WriteAllText(temporary, "{}");
        var prior = File.ReadAllBytes(f.LedgerFile); var replay = f.Sender.Node.Replay.Diagnostics; f.Reopen();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.InitializeLedgerAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(request, f.Ledger!).AsTask());
        Assert.Equal(prior, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics);
        Assert.Equal(0, f.AllHttpRequests); Assert.Empty(f.Sender.MutationFiles);
        if (!delete) Assert.Equal("{}", File.ReadAllText(temporary));
    }

    [Theory]
    [InlineData("checkpoint.bin", false)]
    [InlineData("enrollment.bin", false)]
    [InlineData("checkpoint.bin", true)]
    [InlineData("enrollment.bin", true)]
    public async Task MissingOrForeignOperationCustodyRejectsBeforeReplay(string part, bool foreign)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var scope = Directory.GetDirectories(f.Sender.Node.OperationCustodyRoot).Single();
        var target = Path.Combine(scope, part); var original = File.ReadAllBytes(target);
        if (foreign)
            File.Copy(Path.Combine(Directory.GetDirectories(f.Recipient.Node.OperationCustodyRoot).Single(), part), target, overwrite: true);
        else File.Delete(target);
        var prior = File.ReadAllBytes(f.LedgerFile); f.Reopen();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.InitializeLedgerAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!).AsTask());
        Assert.Equal(prior, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount);
        Assert.Equal(0, f.AllHttpRequests); Assert.Empty(f.Sender.MutationFiles);
        File.WriteAllBytes(target, original); new MailboxStorageSecurity().SecureFile(target);
        await f.InitializeLedgerAsync();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
    }

    private sealed class OperationCheckpointFault(int target, bool beforeReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new(); private int writes;
        internal bool Reached;
        public void ReplaceFile(string temporary, string final)
        {
            var fail = Path.GetFileName(final) == "checkpoint.bin" && ++writes == target;
            if (fail && beforeReplace) { Reached = true; throw new IOException("Test-owned pre-checkpoint replacement interruption."); }
            native.ReplaceFile(temporary, final);
            if (fail) { Reached = true; throw new IOException("Test-owned post-checkpoint replacement interruption."); }
        }
        public void FlushFileAndParentDirectory(string path) => native.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
    }

    // Invoke a hostile storage callback only after the real protected owner
    // verified its snapshot. All protection/lease checks remain native.
    private sealed class CustodyReadCallback(XNode.Core.Mailbox.Client.IMailboxOperationCustody inner, Action callback)
        : XNode.Core.Mailbox.Client.IMailboxOperationCustody
    {
        public void RequireScope(ReadOnlySpan<byte> node, ReadOnlySpan<byte> network) => inner.RequireScope(node, network);
        public void RequireNewScope(string path) => inner.RequireNewScope(path);
        public void RequireDocumentSnapshot(string path, ReadOnlySpan<byte> hash, long length) => inner.RequireDocumentSnapshot(path, hash, length);
        public ValueTask EnrollAsync(string path, MailboxCurrentOperationLease lease, CancellationToken token) => inner.EnrollAsync(path, lease, token);
        public ValueTask PrepareAsync(string path, string temporary, MailboxCurrentOperationLease lease, CancellationToken token) => inner.PrepareAsync(path, temporary, lease, token);
        public ValueTask CommitAsync(string path, MailboxCurrentOperationLease lease, CancellationToken token) => inner.CommitAsync(path, lease, token);
        public async ValueTask VerifyAsync(string path, MailboxCurrentOperationLease lease,
            Func<string, CancellationToken, Task> validate, CancellationToken token)
        { await inner.VerifyAsync(path, lease, validate, token); callback(); }
    }
}
