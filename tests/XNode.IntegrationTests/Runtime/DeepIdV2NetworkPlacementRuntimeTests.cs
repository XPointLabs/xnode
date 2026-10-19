using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Sodium;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Actual file source/floor/runtime with real signed proof; no HTTP or device claim.</summary>
public sealed class DeepIdV2NetworkPlacementRuntimeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PublicPolicyMemoRequiresExactActualTimeAndSignedBytes(bool atomic)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var source = files.Source(floor, atomic: atomic);
        await RefreshAsync(source, signed);
        var first = await source.ReadPublicationAuthorityAsync(default);
        Assert.Equal(1L, source.MailboxPolicySignatureVerifications);
        var same = await source.ReadPublicationAuthorityAsync(default);
        Assert.Same(first.MailboxAuthority, same.MailboxAuthority);
        Assert.Equal(1L, source.MailboxPolicySignatureVerifications);
        signed.Sample++;
        var next = await source.ReadPublicationAuthorityAsync(default);
        Assert.NotSame(first.MailboxAuthority, next.MailboxAuthority);
        Assert.Equal(2L, source.MailboxPolicySignatureVerifications);
        Assert.Equal(1L, source.MailboxInputDecodes);
        var retained = await floor.ReadAsync(default);
        files.CorruptIssuerSignature();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => source.ReadPublicationAuthorityAsync(default).AsTask());
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        Assert.Equal(2L, source.MailboxPolicySignatureVerifications);
        Assert.Equal(1L, source.MailboxInputDecodes); // Changed raw source is rejected before any re-decoding.
    }

    [Fact]
    public async Task BriefVerifiedContextReuseDoesNotRenewProofOrProtectedFloors()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var resources = new ResourceClock();
        var source = files.Source(floor, resourceTimeProvider: resources);
        var acquired = await RefreshAsync(source, signed); var retained = await floor.ReadAsync(default);
        var reused = await source.ReadPublicationAuthorityAsync(default);
        Assert.Same(acquired, reused.Network); Assert.Same(signed.Freshness, reused.Freshness);
        Assert.Equal(1, signed.ProofReads); Assert.Equal(1, signed.ObservationChecks);
        resources.Timestamp = resources.TimestampFrequency * 2;
        var stillReused = await source.ReadPublicationAuthorityAsync(default);
        Assert.Same(acquired, stillReused.Network); Assert.Same(signed.Freshness, stillReused.Freshness);
        Assert.Equal(1, signed.ProofReads); Assert.Equal(2, signed.ObservationChecks);
        resources.Timestamp = resources.TimestampFrequency * 11;
        var reverified = await source.ReadPublicationAuthorityAsync(default);
        Assert.Same(acquired, reverified.Network); Assert.Same(signed.Freshness, reverified.Freshness);
        Assert.Equal(1, signed.ProofReads); Assert.Equal(3, signed.ObservationChecks);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        signed.RejectProof = true;
        await Assert.ThrowsAsync<CryptographicException>(() => source.ReadPublicationAuthorityAsync(default).AsTask());
        signed.RejectProof = false;
        await Assert.ThrowsAsync<CryptographicException>(() => source.ReadPublicationAuthorityAsync(default).AsTask());
        Assert.Equal(1, signed.ProofReads);
    }

    [Fact]
    public async Task ReusedContextStillRejectsActualProofExpiryWithoutChangingProtectedFloor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var resources = new ResourceClock(); var source = files.Source(floor, resourceTimeProvider: resources);
        _ = await RefreshAsync(source, signed); var retained = await floor.ReadAsync(default);
        resources.Timestamp = resources.TimestampFrequency * 60;
        Assert.NotNull(await source.ReadPublicationAuthorityAsync(default));
        signed.Sample = signed.Freshness.FreshnessDeadlineMonotonicSeconds;
        var error = await Assert.ThrowsAsync<CryptographicException>(() => source.ReadPublicationAuthorityAsync(default).AsTask());
        Assert.Equal("DID2 mailbox issuer needs the current independent proof.", error.Message);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        Assert.Equal(1, signed.ProofReads);
    }

    private sealed class ResourceClock : TimeProvider
    {
        internal long Timestamp { get; set; }
        public override long GetTimestamp() => Timestamp;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ChangedPublicViewCanJoinOnlyBeforeAdmissionNotInsideEffect(bool insideEffect)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var source = files.Source(floor, atomic: true); var prior = await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        files.InstallSuccessor(await signed.AdvancePublicNetworkAsync());
        if (insideEffect)
        {
            await Assert.ThrowsAsync<DeepIdV2NetworkObservationChangedException>(() => source.ReadPublicationAuthorityAsync(default).AsTask());
            Assert.Equal(1, signed.ProofReads);
            Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        }
        else
        {
            var admitted = await source.ReadAdmissionAuthorityAsync(default);
            Assert.Equal(prior.ProtectedLkg!.ViewGeneration + 1, admitted.Network.ProtectedLkg!.ViewGeneration);
            Assert.Equal(2, signed.ProofReads);
            Assert.Same(admitted.Network, (await source.ReadPublicationAuthorityAsync(default)).Network);
        }
    }

    [Fact]
    public async Task ReceiveObservationRejoinsActualCustodyAndSchedulesRefreshWithoutMintingProofs()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var source = files.Source(floor); var network = await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        for (var i = 0; i < 12; i++) Assert.True(await source.ObserveReceiveNetworkAsync(network, default));
        Assert.Equal(1, signed.ProofReads);
        var fresh = signed.Freshness;
        var signedEndSample = checked(fresh.MonotonicSample + network.MaximumRecordExpiryUnixSeconds - fresh.TrustedUpperUnixSeconds);
        signed.Sample = Math.Min(fresh.FreshnessDeadlineMonotonicSeconds, signedEndSample) - 20;
        Assert.False(await source.ObserveReceiveNetworkAsync(network, default));
        Assert.Equal(1, signed.ProofReads);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        files.DeleteNetworkFloor();
        await Assert.ThrowsAsync<InvalidDataException>(() => source.ObserveReceiveNetworkAsync(network, default).AsTask());
        Assert.Equal(1, signed.ProofReads);
    }

    [Fact]
    public async Task ReceiveObservationCannotRepairChangedPublicSourceOrReacquireItself()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var source = files.Source(floor, atomic: true); var network = await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        files.InstallSuccessor(await signed.AdvancePublicNetworkAsync());
        Assert.False(await source.ObserveReceiveNetworkAsync(network, default));
        Assert.Equal(1, signed.ProofReads);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        await Assert.ThrowsAsync<CryptographicException>(() => source.ObserveReceiveNetworkAsync(network, default).AsTask());
        Assert.Equal(1, signed.ProofReads);
    }

    [Fact]
    public async Task InvalidChangedSourceCannotBeRepairedOrPromotedByAdmission()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed); using var floor = files.OpenFloor();
        var source = files.Source(floor); _ = await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default); files.CorruptIssuerSignature();
        await Assert.ThrowsAnyAsync<CryptographicException>(() => source.ReadAdmissionAuthorityAsync(default).AsTask());
        Assert.Equal(2, signed.ProofReads);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => source.ReadAdmissionAuthorityAsync(default).AsTask());
        Assert.Equal(2, signed.ProofReads); // No observation/readiness fallback.
    }

    [Fact]
    public async Task IndependentObserverFreshVerificationPersistsFloorAndSurvivesRestart()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        var candidate = OnionPathCandidateSnapshotFactory.Create(signed.NetworkContext).Candidates[0];
        var key = ScalarMult.Base(signed.TestOnionScalar(candidate.NodeId.Span));
        DeepIdV2NetworkFloor retained;
        using (var floor = files.OpenFloor())
        {
            var source = files.Source(floor);
            var initial = await source.ReadCurrentAsync(candidate.RouterOwnerId, key, default, default);
            Assert.Null(initial.PriorProtectedLkg);
            retained = (await floor.ReadAsync(default))!;
            var same = await source.ReadCurrentAsync(candidate.RouterOwnerId, key, default, default);
            Assert.NotNull(same.PriorProtectedLkg);
            Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        }
        using var restarted = files.OpenFloor();
        var current = await files.Source(restarted).ReadCurrentAsync(candidate.RouterOwnerId, key, default, default);
        Assert.NotNull(current.PriorProtectedLkg);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await restarted.ReadAsync(default)));
        Assert.Equal(3, signed.ProofReads);
    }

    [Fact]
    public async Task InstalledKeyMismatchCannotInitializeNetworkFloor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var candidate = OnionPathCandidateSnapshotFactory.Create(signed.NetworkContext).Candidates[0];
        var error = await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await files.Source(floor).ReadCurrentAsync(candidate.RouterOwnerId, ScalarMult.Base(new byte[32]), default, default));
        Assert.Equal("local-node-key-mismatch", error.Code);
        Assert.Null(await floor.ReadAsync(default));
    }

    [Fact]
    public async Task MissingObserverRejectsBeforeProofRequestOrFloorWrite()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var candidate = OnionPathCandidateSnapshotFactory.Create(signed.NetworkContext).Candidates[0];
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await files.Source(floor, observer: false).ReadCurrentAsync(candidate.RouterOwnerId,
                ScalarMult.Base(signed.TestOnionScalar(candidate.NodeId.Span)), default, default));
        Assert.Equal(0, signed.ProofReads);
        Assert.Null(await floor.ReadAsync(default));
    }

    [Fact]
    public async Task ExpiredProofCannotInitializeNetworkFloor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var candidate = OnionPathCandidateSnapshotFactory.Create(signed.NetworkContext).Candidates[0];
        signed.Sample = signed.Freshness.FreshnessDeadlineMonotonicSeconds;
        await Assert.ThrowsAsync<OnionBoundaryException>(async () =>
            await files.Source(floor).ReadCurrentAsync(candidate.RouterOwnerId,
                ScalarMult.Base(signed.TestOnionScalar(candidate.NodeId.Span)), default, default));
        Assert.Null(await floor.ReadAsync(default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualFileAndAtomicBundleRetainAndVerifyCurrentIssuer(bool atomic)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var source = files.Source(floor, atomic: atomic);
        await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        var current = await source.ReadPublicationAuthorityAsync(default);
        Assert.Equal(signed.MailboxAuthority.ToArray(), current.MailboxAuthority.ExactPma2.ToArray());
        Assert.True(current.MailboxAuthority.BindsProjection(signed.Projection.Span));
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        Assert.Equal(1, signed.ProofReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InvalidIssuerSignatureRejectsBeforeNetworkFloorPromotion(bool atomic)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        files.CorruptIssuerSignature();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await RefreshAsync(files.Source(floor, atomic: atomic), signed));
        Assert.Null(await floor.ReadAsync(default));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DuplicateCurrentIssuerRejectsBeforeNetworkFloorPromotion(bool atomic)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await RefreshAsync(files.Source(floor, atomic: atomic, duplicateIssuer: true), signed));
        Assert.Null(await floor.ReadAsync(default));
    }

    [Fact]
    public async Task IssuerChangedDuringFloorCommitCannotReleaseAuthority()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor(files.CorruptIssuerSignature);
        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await RefreshAsync(files.Source(floor), signed));
        Assert.Contains("changed before capability release", error.Message);
        // The independently valid NET floor remains committed; no issuer
        // capability was released, no repair/reset to empty occurred.
        Assert.NotNull(await floor.ReadAsync(default));
    }

    [Fact]
    public async Task MonotonicRollbackDuringFloorCommitCannotReleaseAuthority()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor(() => signed.Sample = 99);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await RefreshAsync(files.Source(floor), signed));
        Assert.NotNull(await floor.ReadAsync(default));
    }

    [Fact]
    public async Task ColdObservationCannotFetchProofOrInitializeFloor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await files.Source(floor).ReadPublicationAuthorityAsync(default));
        Assert.Equal(0, signed.ProofReads);
        Assert.Null(await floor.ReadAsync(default));
    }

    [Fact]
    public async Task RepeatedObservationsDoNotAcquireOrRewriteFloorAndStopFailsClosed()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        var writes = 0;
        using var floor = files.OpenFloor(() => writes++);
        var source = files.Source(floor);
        await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        var committedWrites = writes;
        for (var i = 0; i < 130; i++)
            Assert.NotNull((await source.ReadPublicationAuthorityAsync(default)).Freshness.CurrentCheckpoint);
        Assert.Equal(1, signed.ProofReads);
        Assert.Equal(130, signed.ObservationChecks);
        Assert.Equal(committedWrites, writes);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
        source.StopObservations();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await source.ReadPublicationAuthorityAsync(default));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await RefreshAsync(source, signed));
        Assert.Equal(1, signed.ProofReads);
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("missing-observer")]
    [InlineData("cancelled")]
    [InlineData("stopped")]
    public async Task ExplicitOperatorAcquisitionNeverBecomesReadinessFallback(string state)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var source = files.Source(floor, observer: state != "missing-observer");
        using var cancel = new CancellationTokenSource();
        if (state == "cancelled") cancel.Cancel();
        if (state == "stopped") source.StopObservations();
        if (state == "valid")
        {
            await Assert.ThrowsAsync<CryptographicException>(async () => await source.ReadPublicationAuthorityAsync(default));
            Assert.Null(await floor.ReadAsync(default));
            Assert.Equal(0, signed.ProofReads);
            await source.AcquireObservationAsync(cancel.Token);
            Assert.NotNull((await source.ReadPublicationAuthorityAsync(default)).Freshness.CurrentCheckpoint);
            Assert.NotNull(await floor.ReadAsync(default));
            Assert.Equal(1, signed.ProofReads);
        }
        else
        {
            if (state == "cancelled")
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await source.AcquireObservationAsync(cancel.Token));
            else await Assert.ThrowsAsync<InvalidOperationException>(async () => await source.AcquireObservationAsync(cancel.Token));
            Assert.Null(await floor.ReadAsync(default));
            Assert.Equal(0, signed.ProofReads);
        }
    }

    [Theory]
    [InlineData("expiry")]
    [InlineData("rollback")]
    [InlineData("issuer")]
    [InlineData("floor")]
    [InlineData("proof")]
    public async Task ObservationRejectsChangedSourceWithoutAcquisitionOrRepair(string fault)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var source = files.Source(floor);
        await RefreshAsync(source, signed);
        switch (fault)
        {
            case "expiry": signed.Sample = signed.Freshness.FreshnessDeadlineMonotonicSeconds; break;
            case "rollback": signed.Sample = 99; break;
            case "issuer": files.CorruptIssuerSignature(); break;
            case "floor": files.DeleteNetworkFloor(); break;
            case "proof": signed.RejectProof = true; break;
        }
        if (fault == "floor")
            await Assert.ThrowsAsync<InvalidDataException>(async () => await source.ReadPublicationAuthorityAsync(default));
        else
            await Assert.ThrowsAnyAsync<CryptographicException>(async () => await source.ReadPublicationAuthorityAsync(default));
        Assert.Equal(1, signed.ProofReads);
        if (fault == "floor") Assert.False(files.NetworkFloorExists);
        // Failure clears the observation; fixing files alone cannot revive it.
        signed.Sample = 100; signed.RejectProof = false;
        await Assert.ThrowsAsync<CryptographicException>(async () => await source.ReadPublicationAuthorityAsync(default));
        Assert.Equal(1, signed.ProofReads);
    }

    private static ValueTask<VerifiedOnionNetworkContext> RefreshAsync(
        DeepIdV2NetworkPlacementRuntime source, DeepIdV2PublicationAuthorityFixture signed)
    {
        var candidate = OnionPathCandidateSnapshotFactory.Create(signed.NetworkContext).Candidates[0];
        return source.ReadCurrentAsync(candidate.RouterOwnerId,
            ScalarMult.Base(signed.TestOnionScalar(candidate.NodeId.Span)), default, default);
    }

    [Fact]
    public async Task UnrelatedPublisherProofRejectionCannotInvalidateIndependentObserver()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var source = files.Source(floor);
        await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        var unrelated = DeepIdV2Codec.AuthorDid2(DeepIdV2PublicationAuthorityFixture.Bytes(32, 0x61),
            DeepIdV2PublicationAuthorityFixture.Bytes(1952, 0x62), DeepIdV2PublicationAuthorityFixture.Bytes(16, 0x63));
        await Assert.ThrowsAsync<CryptographicException>(async () => await source.MintPreKeyPublicationAsync(
            unrelated, DeepIdV2PublicationAuthorityFixture.Service, default));
        Assert.Equal(2, signed.ProofReads); // The unrelated proof request rejected.
        var current = await source.ReadPublicationAuthorityAsync(default);
        Assert.Same(signed.Freshness, current.Freshness);
        Assert.Equal(2, signed.ProofReads); // Observation did not acquire a replacement.
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
    }

    [Fact]
    public async Task RollbackWithinSignedHorizonStillRejectsObservedAuthority()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var source = files.Source(floor);
        await RefreshAsync(source, signed);
        signed.Sample = 105;
        await source.ReadPublicationAuthorityAsync(default);
        signed.Sample = 104;
        Assert.True(signed.Freshness.IsCurrentAtMonotonic(DeepIdV2PublicationAuthorityFixture.Boot, signed.Sample));
        await Assert.ThrowsAsync<CryptographicException>(async () => await source.ReadPublicationAuthorityAsync(default));
        Assert.Equal(1, signed.ProofReads);
    }

    [Fact]
    public async Task CancelledObservationCannotInvalidateHealthyIndependentProof()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Assets(signed);
        using var floor = files.OpenFloor();
        var source = files.Source(floor);
        await RefreshAsync(source, signed);
        var retained = await floor.ReadAsync(default);
        using var cancellation = new CancellationTokenSource();
        signed.OnObservationCheck = cancellation.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await source.ReadPublicationAuthorityAsync(cancellation.Token));
        signed.OnObservationCheck = null;
        Assert.Same(signed.Freshness, (await source.ReadPublicationAuthorityAsync(default)).Freshness);
        Assert.Equal(1, signed.ProofReads);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(retained, await floor.ReadAsync(default)));
    }

    internal sealed class Assets : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "did2-placement-source-" + Guid.NewGuid().ToString("N"));
        private readonly DeepIdV2PublicationAuthorityFixture signed;
        private readonly string policy, view, head, projection, mailboxAuthority, observer, authority, time;
        private readonly string[] nodes;
        private readonly IDataProtector protector = new EphemeralDataProtectionProvider().CreateProtector("test-network", "test-node");
        internal Assets(DeepIdV2PublicationAuthorityFixture signed)
        {
            this.signed = signed;
            Directory.CreateDirectory(root);
            policy = Write("policy.xvp1", signed.Policy); view = Write("view.xnv1", signed.View);
            head = Write("head.xnh1", signed.Head); projection = Write("projection.pmt2", signed.Projection);
            mailboxAuthority = Write("issuer.pma2", signed.MailboxAuthority);
            observer = Write("observer.did2", signed.Publisher.CanonicalBytes);
            authority = Write("authority.xna1", signed.ExactAuthority); time = Write("time.dts1", signed.ExactTimePolicy);
            nodes = signed.Descriptors.Select((bytes, index) => Write("node-" + index + ".xnd1", bytes)).ToArray();
        }
        private string Write(string name, ReadOnlyMemory<byte> bytes)
        { var path = Path.Combine(root, name); File.WriteAllBytes(path, bytes.ToArray()); return path; }
        internal void CorruptIssuerSignature()
        {
            var bytes = File.ReadAllBytes(mailboxAuthority);
            bytes[^1] ^= 1;
            File.WriteAllBytes(mailboxAuthority, bytes);
            // Atomic mode consumes the bundle, not the loose issuer file.
            // Fault the exact input the running source actually reads.
            if (File.Exists(Path.Combine(root, "network.ncp2")))
                Write("network.ncp2", XPointNetworkClosureWireCodec.EncodeResponse(DeepIdV2PublicationAuthorityFixture.Network,
                    [signed.ExactAuthority], [signed.ExactTimePolicy], [signed.Policy], [signed.View],
                    [signed.Head], signed.Descriptors, [signed.Projection], [bytes]));
        }
        internal void InstallSuccessor(AuthoredXPointNetworkOperationalSuccessor successor)
        {
            Write("network.ncp2", XPointNetworkClosureWireCodec.EncodeResponse(DeepIdV2PublicationAuthorityFixture.Network,
                [signed.ExactAuthority], [signed.ExactTimePolicy],
                [File.ReadAllBytes(policy), successor.ExactXvp1], [File.ReadAllBytes(view), successor.ExactXnv1],
                [File.ReadAllBytes(head), successor.ExactXnh1], successor.ExactXnd1,
                [File.ReadAllBytes(projection), successor.ExactPmt2],
                [File.ReadAllBytes(mailboxAuthority), successor.ExactPma2]));
            File.WriteAllBytes(policy, successor.ExactXvp1.ToArray());
            File.WriteAllBytes(view, successor.ExactXnv1.ToArray());
            File.WriteAllBytes(head, successor.ExactXnh1.ToArray());
            File.WriteAllBytes(projection, successor.ExactPmt2.ToArray());
            File.WriteAllBytes(mailboxAuthority, successor.ExactPma2.ToArray());
            for (var i = 0; i < nodes.Length; i++) File.WriteAllBytes(nodes[i], successor.ExactXnd1[i].ToArray());
        }
        internal bool NetworkFloorExists => File.Exists(Path.Combine(root, "node-state", "did2-network-state", "floor.bin"));
        internal void DeleteNetworkFloor() => File.Delete(Path.Combine(root, "node-state", "did2-network-state", "floor.bin"));
        internal FileDeepIdV2NetworkFloorStore OpenFloor(Action? afterFloorWrite = null) => new(Path.Combine(root, "node-state"),
            protector, new MailboxStorageSecurity(), new ObservedDurability(afterFloorWrite));
        internal DeepIdV2NetworkPlacementRuntime Source(FileDeepIdV2NetworkFloorStore floor,
            bool observer = true, bool atomic = false, bool duplicateIssuer = false, TimeProvider? resourceTimeProvider = null)
        {
            var issuerPaths = new[] { mailboxAuthority };
            if (duplicateIssuer)
            {
                var second = Write("duplicate.pma2", File.ReadAllBytes(mailboxAuthority));
                issuerPaths = [mailboxAuthority, second];
            }
            var source = atomic
                ? new DeepIdV2NetworkClosureFileSource(Write("network.ncp2",
                    XPointNetworkClosureWireCodec.EncodeResponse(DeepIdV2PublicationAuthorityFixture.Network,
                        [signed.ExactAuthority], [signed.ExactTimePolicy], [signed.Policy], [signed.View],
                        [signed.Head], signed.Descriptors, [signed.Projection],
                        issuerPaths.Select(path => (ReadOnlyMemory<byte>)File.ReadAllBytes(path)).ToArray())), this.observer)
                : new DeepIdV2NetworkClosureFileSource([policy], [view], [head], nodes, [projection],
                    issuerPaths, observer ? this.observer : "");
            return new(signed, new(signed.GenesisPin, [authority], [time]), source, floor, signed, resourceTimeProvider);
        }
        public void Dispose() => Directory.Delete(root, recursive: true);
    }

    private sealed class ObservedDurability(Action? afterFloorWrite) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier actual = new();
        public void FlushParentDirectory(string path) => actual.FlushParentDirectory(path);
        public void FlushFileAndParentDirectory(string path)
        {
            actual.FlushFileAndParentDirectory(path);
            if (Path.GetFileName(path) == "floor.bin") afterFloorWrite?.Invoke();
        }
    }
}
