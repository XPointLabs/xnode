namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2NetworkPlacementOptionsTests
{
    [Fact]
    public void DisabledOptions_RejectAnyPartialArtifactConfiguration()
    {
        Assert.Null(new DeepIdV2NetworkPlacementOptions()
            .ValidateAndLoad(did2ProofEnabled: false,
                developmentOrUat: true));
        Assert.Throws<InvalidOperationException>(() =>
            new DeepIdV2NetworkPlacementOptions
            {
                ExactViewPaths = [Path.Combine(Path.GetTempPath(), "view.xnv1")]
            }.ValidateAndLoad(did2ProofEnabled: false,
                developmentOrUat: true));
    }

    [Fact]
    public void EnabledOptions_RequireIndependentProofAndUat()
    {
        var options = ValidOptions();
        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(
            did2ProofEnabled: false, developmentOrUat: true));
        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(
            did2ProofEnabled: true, developmentOrUat: false));
        Assert.NotNull(options.ValidateAndLoad(did2ProofEnabled: true,
            developmentOrUat: true));
    }

    [Fact]
    public void SignedArtifactInputs_AreBoundedAndCannotAliasEachOther()
    {
        var options = ValidOptions();
        options.ExactHeadPaths = options.ExactViewPaths.ToList();
        Assert.Throws<ArgumentException>(() => options.ValidateAndLoad(
            did2ProofEnabled: true, developmentOrUat: true));

        options = ValidOptions();
        options.ExactHeadPaths = [];
        Assert.Throws<ArgumentException>(() => options.ValidateAndLoad(
            did2ProofEnabled: true, developmentOrUat: true));

        options = ValidOptions();
        options.ExactActiveNodePaths = ["relative-node.xnd1"];
        Assert.Throws<ArgumentException>(() => options.ValidateAndLoad(
            did2ProofEnabled: true, developmentOrUat: true));
    }

    [Fact]
    public void FileSource_RejectsOversizedArtifactBeforePromotion()
    {
        var root = Path.Combine(Path.GetTempPath(),
            "xnode-did2-network-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var paths = Enumerable.Range(0, 5)
                .Select(index => Path.Combine(root, $"artifact-{index}.bin"))
                .ToArray();
            foreach (var path in paths) File.WriteAllBytes(path, [1, 2, 3]);
            var source = new DeepIdV2NetworkClosureFileSource(
                [paths[0]], [paths[1]], [paths[2]], [paths[3]], [paths[4]]);
            using (var artifacts = source.ReadCurrent())
            {
                Assert.Equal(new byte[] { 1, 2, 3 },
                    artifacts.Policies.Single().ToArray());
                Assert.Equal(new byte[] { 1, 2, 3 },
                    artifacts.Projections.Single().ToArray());
            }
            File.WriteAllBytes(paths[2], new byte[65_536]);
            Assert.Throws<InvalidDataException>(source.ReadCurrent);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static DeepIdV2NetworkPlacementOptions ValidOptions() => new()
    {
        Enabled = true,
        ExactPolicyPaths = [Path.Combine(Path.GetTempPath(), "policy.xvp1")],
        ExactViewPaths = [Path.Combine(Path.GetTempPath(), "view.xnv1")],
        ExactHeadPaths = [Path.Combine(Path.GetTempPath(), "head.xnh1")],
        ExactActiveNodePaths = [Path.Combine(Path.GetTempPath(), "node.xnd1")],
        ExactMailboxProjectionPaths = [Path.Combine(Path.GetTempPath(), "projection.pmt2")]
    };
}
