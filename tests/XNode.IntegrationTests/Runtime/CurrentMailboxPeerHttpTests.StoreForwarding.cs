using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task HistoricalSourceCannotExportAbsentOrAlreadyTombstonedStore()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.ExportHistoricalStoreRecoveryAsync(exact).AsTask());
        Assert.Empty(f.Sender.ReplayFiles); Assert.Empty(f.Sender.MutationFiles);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(exact, MailboxPeerReplicationOperation.Store)).Status);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.ReplicateAsync(
            f.Recipient.Frame(MailboxPeerReplicationOperation.Tombstone), MailboxPeerReplicationOperation.Tombstone)).Status);
        var before = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Sender.Receiver.ExportHistoricalStoreRecoveryAsync(exact).AsTask()));
        Assert.Equal(before, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
    }

    [Fact]
    public async Task HistoricalRepairAfterGrantExpiryChangesOnlyPendingMetadataNeverStoreOrReceipt()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var first = await CaptureStoreForwardingAsync(f, exact);
        f.Recipient.InjectUnpairedPending(first.Claim with { ReservedAtUnixSeconds = first.Claim.ReservedAtUnixSeconds + 1 });
        await f.Signed.RefreshNetworkProofAsync(101, 1111); // Original grant expires1110; host/MGR remain current.
        await Assert.ThrowsAnyAsync<System.Security.Cryptography.CryptographicException>(() =>
            f.Recipient.Receiver.ReceiveForwardedStoreAsync(first.Forwarding).AsTask());
        var sourceFiles = f.Sender.ReplayFiles.Concat(f.Sender.MutationFiles).Select(File.ReadAllBytes).ToArray();
        var proof = await f.Sender.Receiver.ExportHistoricalStoreRecoveryAsync(exact);
        Assert.Equal(sourceFiles, f.Sender.ReplayFiles.Concat(f.Sender.MutationFiles).Select(File.ReadAllBytes).ToArray());
        await f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(proof);
        Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Recipient.ReplayFiles)));
        Assert.Equal(0, f.Recipient.Node.OutcomeCount); Assert.Equal(0, f.AllHttpRequests);
        f.Reopen(); await f.Recipient.Receiver.InitializeHostAsync();
        var before = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        await f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(proof);
        Assert.Equal(before, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        await Assert.ThrowsAnyAsync<System.Security.Cryptography.CryptographicException>(() =>
            f.Recipient.Receiver.ReceiveForwardedStoreAsync(proof).AsTask());
        Assert.Empty(f.Recipient.MutationFiles); // Historical fact never became current effect authority.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HistoricalRepairProtectedWriteCrashResumesMetadataWithoutCreatingStore(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var first = await CaptureStoreForwardingAsync(f, exact);
        f.Recipient.InjectUnpairedPending(first.Claim with { ReservedAtUnixSeconds = first.Claim.ReservedAtUnixSeconds + 1 });
        await f.Signed.RefreshNetworkProofAsync(101, 1111);
        var proof = await f.Sender.Receiver.ExportHistoricalStoreRecoveryAsync(exact);
        var fault = new PeerFloorWriteFault(1, beforeReplace); f.OpenRecipientLedger(durability: fault);
        await Assert.ThrowsAsync<IOException>(() => f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(proof).AsTask());
        Assert.True(fault.Reached); Assert.Empty(f.Recipient.MutationFiles);
        f.Reopen(); await f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(proof);
        await f.Recipient.Receiver.InitializeHostAsync();
        Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal((byte)MailboxPeerReplayRecordStatus.Pending, Status(Assert.Single(f.Recipient.ReplayFiles)));
    }

    [Theory]
    [InlineData("mutation")]
    [InlineData("extra-orphan")]
    [InlineData("signature")]
    [InlineData("missing-pending")]
    public async Task HistoricalRepairRejectsUnownedEffectsOtherHistoryAndInvalidProof(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var first = await CaptureStoreForwardingAsync(f, exact);
        if (defect != "missing-pending") f.Recipient.InjectUnpairedPending(first.Claim);
        if (defect == "mutation") await f.Recipient.InjectUnpairedMutationAsync(first.Verified);
        if (defect == "extra-orphan")
        {
            var nonce = Enumerable.Repeat((byte)0x79, 32).ToArray();
            f.Recipient.InjectUnpairedPending(first.Claim with { ReplayNonce = nonce,
                ScopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(first.Claim.SenderRouterId.Span,
                    first.Claim.RecipientRouterId.Span, first.Claim.Epoch, nonce) });
        }
        await f.Signed.RefreshNetworkProofAsync(101, 1111);
        var proof = (await f.Sender.Receiver.ExportHistoricalStoreRecoveryAsync(exact)).ToArray();
        if (defect == "signature") proof[^1] ^= 1;
        var before = AdmissionOwnerDigest(f.Recipient.Node.DataRoot); var independent = PeerProtectionDigest(f.Recipient);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.ReconcileHistoricalStoreCustodyAsync(proof).AsTask()));
        Assert.Equal(before, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Equal(independent, PeerProtectionDigest(f.Recipient));
    }

    private static ValueTask<(ReadOnlyMemory<byte> Forwarding, MailboxPeerReplayClaim Claim, VerifiedMailboxPeerWireRequestV2 Verified)>
        CaptureStoreForwardingAsync(Fixture f, ReadOnlyMemory<byte> exact) =>
        f.Sender.Receiver.WithPeerAsync(exact, MailboxPeerReplicationOperation.Store,
            MailboxPeerWireResponseReplicaV2.Sender, async (operation, token) =>
            {
                var receipt = await operation.ApplyAndSignLocalAsync(token);
                return (operation.CreateForwarding(receipt), operation.Verified.ReplayClaim, operation.Verified);
            });

    [Fact]
    public async Task SourceProvenStoreReconcilesOnlyOriginalUnpairedPendingWithoutReplacingRequest()
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var source = await CaptureStoreForwardingAsync(f, exact);
        f.Recipient.InjectUnpairedPending(source.Claim with { ReservedAtUnixSeconds = source.Claim.ReservedAtUnixSeconds + 1 });
        f.Signed.Sample = 101; f.Reopen();
        Assert.Empty(f.Recipient.MutationFiles);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.InitializeHostAsync().AsTask());
        // An unaided exact request cannot import native history.
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Recipient.Receiver.ReceiveAsync(exact,
            MailboxPeerReplicationOperation.Store).AsTask());
        var response = await f.Recipient.Receiver.ReceiveForwardedStoreAsync(source.Forwarding);
        Assert.Equal(source.Claim.ReservedAtUnixSeconds, MailboxReceiptV2Codec.DecodeReplica(response.Span).AcceptedAtUnixSeconds);
        Assert.Equal(exact, MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(source.Forwarding.Span));
        Assert.Single(f.Recipient.ReplayFiles); Assert.Single(f.Recipient.MutationFiles);
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync());
        f.Reopen(); await f.Recipient.Receiver.InitializeHostAsync();
        Assert.Equal(response.ToArray(), (await f.Recipient.Receiver.ReceiveForwardedStoreAsync(source.Forwarding)).ToArray());
    }

    [Theory]
    [InlineData("mutation")]
    [InlineData("extra-orphan")]
    [InlineData("signature")]
    public async Task SourceProvenStoreCannotAdoptNativeEffectsOtherHistoryOrForgedEvidence(string defect)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var source = await CaptureStoreForwardingAsync(f, exact);
        f.Recipient.InjectUnpairedPending(source.Claim);
        if (defect == "mutation") await f.Recipient.InjectUnpairedMutationAsync(source.Verified);
        if (defect == "extra-orphan")
        {
            var nonce = Enumerable.Repeat((byte)0x79, 32).ToArray();
            f.Recipient.InjectUnpairedPending(source.Claim with { ReplayNonce = nonce,
                ScopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(source.Claim.SenderRouterId.Span,
                    source.Claim.RecipientRouterId.Span, source.Claim.Epoch, nonce) });
        }
        var forwarding = source.Forwarding.ToArray();
        if (defect == "signature") forwarding[^1] ^= 1;
        f.Reopen();
        var before = AdmissionOwnerDigest(f.Recipient.Node.DataRoot);
        var independent = PeerProtectionDigest(f.Recipient);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.ReceiveForwardedStoreAsync(forwarding).AsTask()));
        Assert.Equal(before, AdmissionOwnerDigest(f.Recipient.Node.DataRoot));
        Assert.Equal(independent, PeerProtectionDigest(f.Recipient));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SourceProvenUnpairedStoreProtectedWriteCrashRetainsExactRecoveryPrefix(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync();
        var exact = f.Recipient.Frame(MailboxPeerReplicationOperation.Store);
        var source = await CaptureStoreForwardingAsync(f, exact);
        f.Recipient.InjectUnpairedPending(source.Claim with { ReservedAtUnixSeconds = source.Claim.ReservedAtUnixSeconds + 1 });
        f.Signed.Sample = 101;
        var fault = new PeerFloorWriteFault(1, beforeReplace);
        f.OpenRecipientLedger(durability: fault);
        await Assert.ThrowsAsync<IOException>(() => f.Recipient.Receiver.ReceiveForwardedStoreAsync(source.Forwarding).AsTask());
        Assert.True(fault.Reached); Assert.Empty(f.Recipient.MutationFiles);
        f.Reopen();
        var result = await f.Recipient.Receiver.ReceiveForwardedStoreAsync(source.Forwarding);
        Assert.Equal(source.Claim.ReservedAtUnixSeconds, MailboxReceiptV2Codec.DecodeReplica(result.Span).AcceptedAtUnixSeconds);
        Assert.Single(f.Recipient.ReplayFiles); Assert.Single(f.Recipient.MutationFiles);
    }
}
