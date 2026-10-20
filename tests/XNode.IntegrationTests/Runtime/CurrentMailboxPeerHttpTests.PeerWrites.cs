using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task CurrentPeerFirstReservationRechecksFreshnessAfterNativeCustodyRecovery()
    {
        await using var f = await Fixture.CreateAsync();
        var created = f.Signed.Freshness.TrustedUpperUnixSeconds - MailboxPeerWireV2Limits.MaximumPastAgeSeconds;
        f.Recipient.Envelope = MailboxClientCodec.EncodeEncryptedEnvelope(
            MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with { CreatedAtUnixSeconds = created });
        var candidate = MailboxPeerWireV2Codec.Decode(f.Recipient.Frame(MailboxPeerReplicationOperation.Store)) with
        { CreatedAtUnixSeconds = created };
        var exact = MailboxPeerWireV2Codec.Encode(f.Recipient.Crypto.SignRequest(candidate, f.Recipient.SenderSeed));
        var changed = false;
        f.OpenLedger(afterVerifiedRead: () => { if (!changed) { changed = true; f.Signed.Sample++; } });
        var before = File.ReadAllBytes(f.LedgerFile);
        var error = await Assert.ThrowsAsync<MailboxPeerReplicationException>(() =>
            f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store).AsTask());
        Assert.True(changed); Assert.Equal(MailboxPeerReplicationError.ExpiredOrStale, error.Error);
        Assert.Equal(before, File.ReadAllBytes(f.LedgerFile));
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
    }

    // Select actual peer-floor transitions, not Store/ACK intent or client-floor
    // writes. Every non-selected write still uses the genuine native barrier.
    private sealed class PeerFloorWriteFault(int write, bool beforeReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        private readonly IntentWriteFault fault = new(beforeReplace);
        private int writes;
        private bool selected;
        private string? transition;
        internal bool Reached;
        public void ReplaceFile(string temporary, string final)
        {
            // All four native Windows attempts belong to one exact temporary.
            // Keep the selected failure armed across retries of that transition.
            if (transition != temporary)
            {
                transition = temporary;
                var prior = JsonNode.Parse(File.ReadAllBytes(final))!["peerReplayFloors"];
                var next = JsonNode.Parse(File.ReadAllBytes(temporary))!["peerReplayFloors"];
                selected = !JsonNode.DeepEquals(prior, next) && ++writes == write;
            }
            Reached |= selected;
            (selected ? (IMailboxDurabilityBarrier)fault : native).ReplaceFile(temporary, final);
        }
        public void FlushFileAndParentDirectory(string path) =>
            (selected ? (IMailboxDurabilityBarrier)fault : native).FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
    }

    [Theory]
    [InlineData(false, 1, false)]
    [InlineData(false, 1, true)]
    [InlineData(false, 2, false)]
    [InlineData(false, 2, true)]
    [InlineData(false, 3, false)]
    [InlineData(false, 3, true)]
    [InlineData(true, 1, false)]
    [InlineData(true, 1, true)]
    [InlineData(true, 2, false)]
    [InlineData(true, 2, true)]
    [InlineData(true, 3, false)]
    [InlineData(true, 3, true)]
    public async Task CurrentPeerFloorCrashRecoversExactStoreAcrossEitherReplica(
        bool recipient, int write, bool beforeReplace) =>
        await CheckPeerFloorCrashAsync(recipient, write, beforeReplace, tombstone: false);

    [Theory]
    [InlineData(false, 1, false)]
    [InlineData(false, 1, true)]
    [InlineData(false, 2, false)]
    [InlineData(false, 2, true)]
    [InlineData(false, 3, false)]
    [InlineData(false, 3, true)]
    [InlineData(true, 1, false)]
    [InlineData(true, 1, true)]
    [InlineData(true, 2, false)]
    [InlineData(true, 2, true)]
    [InlineData(true, 3, false)]
    [InlineData(true, 3, true)]
    public async Task CurrentPeerFloorCrashRecoversExactTombstoneAcrossEitherReplica(
        bool recipient, int write, bool beforeReplace) =>
        await CheckPeerFloorCrashAsync(recipient, write, beforeReplace, tombstone: true);

    private static async Task CheckPeerFloorCrashAsync(bool recipient, int write, bool beforeReplace, bool tombstone)
    {
        await using var f = await Fixture.CreateAsync(); AssertDescriptorKeys(f);
        if (tombstone)
            Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
                f.Recipient.Frame(MailboxPeerReplicationOperation.Store), MailboxPeerReplicationOperation.Store)).Status);
        var operation = tombstone ? MailboxPeerReplicationOperation.Tombstone : MailboxPeerReplicationOperation.Store;
        var fault = new PeerFloorWriteFault(write, beforeReplace);
        if (recipient) f.OpenRecipientLedger(durability: fault); else f.OpenLedger(fault);
        var exact = f.Recipient.Frame(operation);
        if (recipient)
        {
            var unknown = await f.Coordinator.ReplicateAsync(exact, operation);
            Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, unknown.Status);
            Assert.True(unknown.CanonicalMqr3.IsEmpty);
        }
        else
            await Assert.ThrowsAsync<IOException>(() => f.Coordinator.ReplicateAsync(
                exact, operation).AsTask());
        Assert.True(fault.Reached);
        if (write == 1 && !tombstone)
        {
            Assert.Empty((recipient ? f.Recipient : f.Sender).MutationFiles);
            Assert.Empty((recipient ? f.Recipient : f.Sender).ReplayFiles);
        }
        f.Reopen();
        using var host = RecoveryHost(f, recipient);
        await host.StartAsync();
        Assert.True((await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
        var requests = f.AllHttpRequests;
        var recovered = await f.Coordinator.ReplicateAsync(exact, operation);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, recovered.Status);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        foreach (var peer in new[] { f.Sender, f.Recipient })
        {
            Assert.Equal(tombstone ? 2 : 1, peer.ReplayFiles.Length);
            Assert.All(peer.ReplayFiles, path => Assert.Equal((byte)MailboxPeerReplayRecordStatus.Completed, Status(path)));
        }
        if (tombstone) AssertTombstones(f, 1);
        Assert.Equal(requests + (recipient || write < 3 ? 1 : 0), f.AllHttpRequests);
        await host.StopAsync();
        var exactResult = recovered.CanonicalMqr3.ToArray();
        var completedRequests = f.AllHttpRequests;
        f.Reopen();
        Assert.Equal(exactResult, (await f.Coordinator.ReplicateAsync(exact, operation)).CanonicalMqr3.ToArray());
        Assert.Equal(completedRequests, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentPeerAuthorityLossAfterProtectedPreparationLeavesNoOrphanAndColdResumesOriginal(bool recipient)
    {
        await using var f = await Fixture.CreateAsync();
        var fault = new PeerPreparationAuthorityLoss(() => f.Signed.RejectProof = true);
        if (recipient) f.OpenRecipientLedger(durability: fault); else f.OpenLedger(fault);
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        _ = await Record.ExceptionAsync(() => f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store).AsTask());
        Assert.True(fault.Reached);
        var interrupted = recipient ? f.Recipient : f.Sender;
        Assert.Empty(interrupted.ReplayFiles); Assert.Empty(interrupted.MutationFiles);
        f.Signed.RejectProof = false; f.Reopen(); f.Signed.Sample = 101;
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        Assert.Single(f.Sender.ReplayFiles); Assert.Single(f.Recipient.ReplayFiles);
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles);
        var requests = f.AllHttpRequests;
        f.Reopen();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        Assert.Equal(requests, f.AllHttpRequests);
    }

    private sealed class PeerPreparationAuthorityLoss(Action loseAuthority) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new();
        private bool selected;
        internal bool Reached;
        public void ReplaceFile(string temporary, string final)
        {
            var document = JsonNode.Parse(File.ReadAllBytes(temporary))!;
            selected = !Reached && document["peerReplayFloors"]!.AsObject().Count > 0;
            native.ReplaceFile(temporary, final);
        }
        public void FlushFileAndParentDirectory(string path)
        {
            native.FlushFileAndParentDirectory(path);
            if (selected) { Reached = true; selected = false; loseAuthority(); }
        }
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
    }

    [Fact]
    public async Task CurrentPeerFloorNativeHistoryRejectsNeutralCollectionAndReaderMutation()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        foreach (var peer in new[] { f.Sender, f.Recipient })
        {
            var before = AdmissionOwnerDigest(peer.Node.DataRoot); var independent = PeerProtectionDigest(peer);
            Assert.Throws<InvalidOperationException>(() => peer.CollectNeutralPeerReplay());
            await Assert.ThrowsAsync<InvalidOperationException>(() => peer.CollectNeutralPeerMutations());
            await Assert.ThrowsAsync<InvalidOperationException>(() => peer.InitializeNeutralPeerMutations());
            Assert.Equal(before, AdmissionOwnerDigest(peer.Node.DataRoot));
            Assert.Equal(independent, PeerProtectionDigest(peer));
        }
        f.Reopen();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        Assert.Equal(1, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentPeerFloorCapacityRejectsBeforeReservationWithoutEvictingHistory()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(maximumEntries: 1);
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        var before = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var independent = PeerProtectionDigest(f.Sender);
        var requests = f.AllHttpRequests;
        var request = MailboxPeerWireV2Codec.Decode(exact) with
        { ReplayNonce = Enumerable.Repeat((byte)0x39, 32).ToArray(), Signature = ReadOnlyMemory<byte>.Empty };
        var different = MailboxPeerWireV2Codec.Encode(f.Recipient.Crypto.SignRequest(request, f.Recipient.SenderSeed));
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Coordinator.ReplicateAsync(different,
            MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Equal(before, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(independent, PeerProtectionDigest(f.Sender)); Assert.Equal(requests, f.AllHttpRequests);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        Assert.Equal(requests, f.AllHttpRequests);
    }

    [Theory]
    [InlineData("missing-map")]
    [InlineData("missing-field")]
    [InlineData("unknown-field")]
    public async Task CurrentPeerFactsRejectIncompleteOrUnknownProtectedMetadata(string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store)).Status);
        var document = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!.AsObject();
        if (defect == "missing-map") Assert.True(document.Remove("peerReplayFloors"));
        else
        {
            var floor = document["peerReplayFloors"]!.AsObject().Single().Value!.AsObject();
            if (defect == "missing-field") Assert.True(floor.Remove("mutationCompleted"));
            else floor["unknown"] = true;
        }
        await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        f.Reopen(); var before = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var independent = PeerProtectionDigest(f.Sender); var requests = f.AllHttpRequests;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.ReplicateAsync(exact,
            MailboxPeerReplicationOperation.Store).AsTask());
        Assert.Equal(before, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(independent, PeerProtectionDigest(f.Sender)); Assert.Equal(requests, f.AllHttpRequests);
    }
}
