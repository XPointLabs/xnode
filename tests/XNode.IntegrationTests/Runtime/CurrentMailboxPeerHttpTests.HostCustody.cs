using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task HostCustodyLossInsideCompletedPeerCallbackCannotReleaseCachedReceipt()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var original = (await f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store)).ToArray();
        var path = Path.Combine(f.Recipient.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var backup = File.ReadAllBytes(path); var priorReplay = File.ReadAllBytes(Assert.Single(f.Recipient.ReplayFiles));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.WithPeerAsync(
            exact, MailboxPeerReplicationOperation.Store, MailboxPeerWireResponseReplicaV2.Recipient,
            (operation, _) =>
            {
                Assert.Equal(MailboxPeerReplayDisposition.IdempotentCompleted, operation.Verified.ReplayDisposition);
                File.Delete(path); return ValueTask.FromResult(operation.Verified.CachedResponse);
            }).AsTask());
        Assert.False(File.Exists(path)); Assert.Equal(priorReplay, File.ReadAllBytes(Assert.Single(f.Recipient.ReplayFiles)));
        Assert.Single(f.Recipient.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
        File.WriteAllBytes(path, backup); new MailboxStorageSecurity().SecureFile(path);
        Assert.Equal(original, (await f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store)).ToArray());
    }

    [Fact]
    public async Task HostCustodyCannotBeReplacedByNeutralLedgerOnRetrieveOrPeer()
    {
        await using var f = await Fixture.CreateAsync();
        var prior = File.ReadAllBytes(f.LedgerFile);
        f.Sender.CloseOperations();
        var neutral = new MailboxClientOperationLedger(f.Sender.Node.DataRoot,
            new MailboxClientAdapterOptions { DirectoryName = "mailbox-client-intent" });
        f.Sender.AttachOperations(neutral); f.Bind();
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f)).AsTask());
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Equal(prior, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(0, f.AllHttpRequests);
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Empty(f.Sender.ReplayFiles);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
    }

    [Fact]
    public async Task HostCustodyLossDuringPeerMutationReleasesNoReceiptAndExactRestoreResumes()
    {
        await using var f = await Fixture.CreateAsync();
        var path = Path.Combine(f.Recipient.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var staleBackup = File.ReadAllBytes(path); byte[]? backup = null; var mutations = 0;
        f.Recipient.Fault.Action = point =>
        {
            if (point == MailboxPeerMutationFaultPoint.StoreReserved)
            {
                mutations++; backup = File.ReadAllBytes(path); File.Delete(path);
            }
        };
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Equal(1, mutations); Assert.False(File.Exists(path));
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Recipient.ReplayFiles)));
        Assert.Single(f.Recipient.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
        Assert.NotNull(backup);
        f.Recipient.Fault.Action = null;
        // The peer fact was committed before the mutation callback. Restoring
        // the older authentic document must fail, not repair the protected root.
        File.WriteAllBytes(path, staleBackup); new MailboxStorageSecurity().SecureFile(path); f.Reopen();
        var unchanged = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        var protection = PeerProtectionDigest(f.Recipient);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.ReceiveAsync(
            exact, MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Equal(unchanged, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Equal(protection, PeerProtectionDigest(f.Recipient));
        File.WriteAllBytes(path, backup); new MailboxStorageSecurity().SecureFile(path); f.Reopen();
        _ = await f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(Assert.Single(f.Recipient.ReplayFiles)));
        Assert.Single(f.Recipient.MutationFiles); Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task HostCustodyLossBlocksFreshAndCompletedRetrieveWithoutReplayOrRepair(bool recipient, bool checkpoint)
    {
        await using var f = await Fixture.CreateAsync();
        await StoreItem(f, 1);
        var peer = recipient ? f.Recipient : f.Sender;
        var exact = RetrieveFrame(f);
        var originalPage = (await peer.Receiver.RetrieveClientAsync(exact)).ToArray();
        var path = checkpoint ? Assert.Single(Directory.GetFiles(peer.Node.OperationCustodyRoot, "checkpoint.bin", SearchOption.AllDirectories))
            : Path.Combine(peer.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var backup = File.ReadAllBytes(path);
        var before = peer.Node.Replay.Diagnostics; var outcomes = peer.Node.OutcomeCount;
        File.Delete(path); f.Reopen(); peer = recipient ? f.Recipient : f.Sender;
        foreach (var request in new[] { exact, RetrieveFrame(f, counter: 2, operation: 0x72) })
            await Assert.ThrowsAsync<InvalidDataException>(() => peer.Receiver.RetrieveClientAsync(request).AsTask());
        Assert.False(File.Exists(path)); Assert.Equal(before, peer.Node.Replay.Diagnostics);
        Assert.Equal(outcomes, peer.Node.OutcomeCount); Assert.Equal(1, f.AllHttpRequests);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        File.WriteAllBytes(path, backup); new MailboxStorageSecurity().SecureFile(path);
        Assert.Equal(originalPage, (await peer.Receiver.RetrieveClientAsync(exact)).ToArray());
        Assert.Single(DecodePage((await peer.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2, operation: 0x72))).Span, f).Items);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HostCustodyLossRejectsFreshAndCompletedPeerBeforeReservationAndHttpReturnsUnavailable(bool completed)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        byte[]? original = null;
        if (completed) original = (await f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store)).ToArray();
        var replayFiles = f.Recipient.ReplayFiles.Select(File.ReadAllBytes).ToArray();
        var mutationFiles = f.Recipient.MutationFiles.Select(File.ReadAllBytes).ToArray();
        var path = Path.Combine(f.Recipient.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var backup = File.ReadAllBytes(path); File.Delete(path); f.Reopen();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store).AsTask());
        using var handler = HttpPrivacyPeerClient.CreatePinnedHandler(f.Recipient.Node.Replicas.Single(replica =>
            replica.NodeId.Span.SequenceEqual(f.Recipient.Node.Node)).Transport);
        using var client = new HttpClient(handler);
        using var content = new ByteArrayContent(exact);
        content.Headers.ContentType = new(MailboxWireHttpContract.Prq2ContentType);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{f.RemoteHost.Port}{MailboxWireHttpContract.PeerStoreRoute}")
        { Content = content, Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync()); Assert.False(File.Exists(path));
        Assert.Equal(replayFiles, f.Recipient.ReplayFiles.Select(File.ReadAllBytes).ToArray());
        Assert.Equal(mutationFiles, f.Recipient.MutationFiles.Select(File.ReadAllBytes).ToArray());
        File.WriteAllBytes(path, backup); new MailboxStorageSecurity().SecureFile(path);
        var restored = (await f.Recipient.Receiver.ReceiveAsync(exact, MailboxPeerReplicationOperation.Store)).ToArray();
        if (original is not null) Assert.Equal(original, restored);
        Assert.Single(f.Recipient.ReplayFiles); Assert.Single(f.Recipient.MutationFiles);
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public async Task HostSigningCustodyMismatchRejectsAllClientOperationsBeforeReplay(MailboxAuthenticatedOperation operation)
    {
        await using var f = await Fixture.CreateAsync(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).Span, f);
        var before = f.Sender.Node.Replay.Diagnostics; var outcomes = f.Sender.Node.OutcomeCount;
        var ledger = File.ReadAllBytes(f.LedgerFile);
        f.Sender.Reopen(signingSeed: f.Sender.Node.Node); f.Bind();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
        {
            switch (operation)
            {
                case MailboxAuthenticatedOperation.Store:
                    _ = await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(counter: 2), f.Ledger!); break;
                case MailboxAuthenticatedOperation.Retrieve:
                    _ = await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f)); break;
                case MailboxAuthenticatedOperation.Ack:
                    _ = await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.Ledger!); break;
            }
        });
        Assert.Equal(before, f.Sender.Node.Replay.Diagnostics); Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
        Assert.Equal(ledger, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(1, f.AllHttpRequests);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
    }

    [Fact]
    public async Task HostCustodyLossInsideRetrieveCallbackCannotPersistOrReleasePageAndExactRestoreResumes()
    {
        await using var f = await Fixture.CreateAsync(); await StoreItem(f, 1);
        var path = Path.Combine(f.Recipient.Node.DataRoot, "mailbox-client-intent", "operations.json");
        byte[]? backup = null; var reads = 0;
        f.Recipient.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.RetrieveBlobRead) { reads++; backup = File.ReadAllBytes(path); File.Delete(path); } };
        var exact = RetrieveFrame(f);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.RetrieveClientAsync(exact).AsTask());
        Assert.Equal(1, reads); Assert.Equal(0, f.Recipient.Node.OutcomeCount); Assert.False(File.Exists(path));
        Assert.Equal(1, f.Recipient.Node.Replay.Diagnostics.PendingCount);
        Assert.NotNull(backup);
        f.Recipient.Fault.Action = null; File.WriteAllBytes(path, backup); new MailboxStorageSecurity().SecureFile(path);
        Assert.Single(DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(exact)).Span, f).Items);
        Assert.Equal(1, f.Recipient.Node.OutcomeCount); Assert.Equal(1, f.AllHttpRequests);
    }
}
