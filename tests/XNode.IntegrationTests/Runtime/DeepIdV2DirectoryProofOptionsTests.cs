using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2DirectoryProofOptionsTests
{
    [Fact]
    public void DisabledProof_RejectsPartialConfiguration()
    {
        var node = new RouterNodeOptions();
        Assert.Null(new DeepIdV2DirectoryProofOptions()
            .ValidateAndLoad(node, developmentOrUat: true));
        Assert.Throws<InvalidOperationException>(() =>
            new DeepIdV2DirectoryProofOptions { RegistryOrigin = "https://registry.example" }
                .ValidateAndLoad(node, developmentOrUat: true));
    }

    [Fact]
    public void EnabledProof_RequiresUat()
    {
        var options = ValidOptions();
        var node = new RouterNodeOptions
        {
            DataDirectory = Path.Combine(Path.GetTempPath(), "did2-proof-test")
        };
        Assert.Throws<InvalidOperationException>(() =>
            options.ValidateAndLoad(node, developmentOrUat: false));
        Assert.NotNull(options.ValidateAndLoad(node, developmentOrUat: true));
    }

    [Fact]
    public void EnabledProof_RejectsInsecureOriginAndOverlappingCustody()
    {
        var node = new RouterNodeOptions
        {
            DataDirectory = Path.Combine(Path.GetTempPath(), "did2-proof-test")
        };
        var options = ValidOptions();
        options.RegistryOrigin = "http://registry.example";
        Assert.Throws<ArgumentException>(() => options.ValidateAndLoad(node,
            developmentOrUat: true));

        options = ValidOptions();
        options.DataProtectionKeysRelativeDirectory = "did2-proof/state/keys";
        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(node,
            developmentOrUat: true));

        options = ValidOptions();
        options.StateRelativeDirectory = "../escaped";
        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(node,
            developmentOrUat: true));
    }

    private static DeepIdV2DirectoryProofOptions ValidOptions() => new()
    {
        Enabled = true,
        RegistryOrigin = "https://registry.example",
        NetworkIdHex = new string('A', 32),
        GenesisAuthorityCoreHashHex = new string('B', 64),
        ExactAuthorityPaths = [Path.Combine(Path.GetTempPath(), "authority.xna1")],
        ExactTimePolicyPaths = [Path.Combine(Path.GetTempPath(), "time.dts1")],
        GenesisHeadPath = Path.Combine(Path.GetTempPath(), "genesis.adh1"),
        GenesisHeadCoreHashHex = new string('C', 64),
        StateRelativeDirectory = "did2-proof/state",
        DataProtectionKeysRelativeDirectory = "did2-proof/keys",
        DeploymentProfileId = 1,
        RequestTimeoutSeconds = 5
    };
}
