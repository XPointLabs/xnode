using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2DirectoryProofOptionsTests
{
    [Fact]
    public void DisabledProof_RejectsPartialConfiguration()
    {
        var node = new RouterNodeOptions();
        Assert.Null(new DeepIdV2DirectoryProofOptions()
            .ValidateAndLoad(node, developmentOrUat: true,
                v1ContactAuthorityEnabled: false));
        Assert.Throws<InvalidOperationException>(() =>
            new DeepIdV2DirectoryProofOptions { RegistryOrigin = "https://registry.example" }
                .ValidateAndLoad(node, developmentOrUat: true,
                    v1ContactAuthorityEnabled: false));
    }

    [Fact]
    public void EnabledProof_RequiresUatAndIndependentV2Authority()
    {
        var options = ValidOptions();
        var node = new RouterNodeOptions
        {
            DataDirectory = Path.Combine(Path.GetTempPath(), "did2-proof-test")
        };
        Assert.Throws<InvalidOperationException>(() =>
            options.ValidateAndLoad(node, developmentOrUat: false,
                v1ContactAuthorityEnabled: false));
        Assert.Throws<InvalidOperationException>(() =>
            options.ValidateAndLoad(node, developmentOrUat: true,
                v1ContactAuthorityEnabled: true));
        Assert.NotNull(options.ValidateAndLoad(node, developmentOrUat: true,
            v1ContactAuthorityEnabled: false));
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
            developmentOrUat: true, v1ContactAuthorityEnabled: false));

        options = ValidOptions();
        options.DataProtectionKeysRelativeDirectory = "did2-proof/state/keys";
        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(node,
            developmentOrUat: true, v1ContactAuthorityEnabled: false));

        options = ValidOptions();
        options.StateRelativeDirectory = "../escaped";
        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(node,
            developmentOrUat: true, v1ContactAuthorityEnabled: false));
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
