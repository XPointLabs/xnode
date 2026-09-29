using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using Sodium;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Actual file source/floor/runtime with real signed proof; no HTTP or device claim.</summary>
public sealed class DeepIdV2NetworkPlacementRuntimeTests
{
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

    private sealed class Assets : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "did2-placement-source-" + Guid.NewGuid().ToString("N"));
        private readonly DeepIdV2PublicationAuthorityFixture signed;
        private readonly string policy, view, head, projection, observer, authority, time;
        private readonly string[] nodes;
        private readonly IDataProtector protector = new EphemeralDataProtectionProvider().CreateProtector("test-network", "test-node");
        internal Assets(DeepIdV2PublicationAuthorityFixture signed)
        {
            this.signed = signed;
            Directory.CreateDirectory(root);
            policy = Write("policy.xvp1", signed.Policy); view = Write("view.xnv1", signed.View);
            head = Write("head.xnh1", signed.Head); projection = Write("projection.pmt2", signed.Projection);
            observer = Write("observer.did2", signed.Publisher.CanonicalBytes);
            authority = Write("authority.xna1", signed.ExactAuthority); time = Write("time.dts1", signed.ExactTimePolicy);
            nodes = signed.Descriptors.Select((bytes, index) => Write("node-" + index + ".xnd1", bytes)).ToArray();
        }
        private string Write(string name, ReadOnlyMemory<byte> bytes)
        { var path = Path.Combine(root, name); File.WriteAllBytes(path, bytes.ToArray()); return path; }
        internal FileDeepIdV2NetworkFloorStore OpenFloor() => new(Path.Combine(root, "node-state"),
            protector, new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        internal DeepIdV2NetworkPlacementRuntime Source(FileDeepIdV2NetworkFloorStore floor, bool observer = true) =>
            new(signed, new(signed.GenesisPin, [authority], [time]),
                new([policy], [view], [head], nodes, [projection], observer ? this.observer : ""), floor, signed);
        public void Dispose() => Directory.Delete(root, recursive: true);
    }
}
