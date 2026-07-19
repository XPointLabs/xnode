using System.Reflection;
using System.Text.Json;

namespace XNode.ProfileGenerator.Tests;

public sealed class PrivacyAndStaticGraphTests
{
    [Fact]
    public void PublicDebugJsonAndExceptionSurfacesDoNotDiscloseArtifacts()
    {
        var input = TestOnlyProfileFixture.Input();
        var document = DormantProfileComposer.Compose(
            input,
            TestOnlyProfileFixture.Options(),
            TestOnlyProfileFixture.SignatureScheme());
        var surfaces = new[]
        {
            input.ToString()!,
            input.GenesisSignatures[0].ToString()!,
            document.ToString()!,
            JsonSerializer.Serialize(input),
            JsonSerializer.Serialize(input.GenesisSignatures[0]),
            JsonSerializer.Serialize(document)
        };
        var forbidden = new[]
        {
            Convert.ToBase64String(input.CanonicalGenesis.ToArray()),
            Convert.ToHexString(input.GenesisSignatures[0].SignerId.Span),
            Convert.ToBase64String(input.GenesisSignatures[0].Signature.ToArray()),
            "bridge.example.invalid",
            Convert.ToHexString(
                Deep.Protocol.DeepExtension.Membership.MembershipContractCodec
                    .DecodeGenesis(input.CanonicalGenesis.Span).NetworkId.Span)
        };
        Assert.All(surfaces, surface =>
            Assert.All(forbidden, value => Assert.DoesNotContain(value, surface, StringComparison.OrdinalIgnoreCase)));

        var exception = Assert.Throws<ProfileContractException>(() =>
            DormantProfileInspector.Inspect(
                [1, 2, 3],
                TestOnlyProfileFixture.Options(),
                TestOnlyProfileFixture.SignatureScheme()));
        Assert.All(forbidden, value =>
            Assert.DoesNotContain(value, exception.ToString(), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ProductionApiHasNoPrivateKeySignerOrPublisherSurface()
    {
        var assembly = typeof(DormantProfileComposer).Assembly;
        var publicSurface = assembly.GetExportedTypes()
            .SelectMany(type => type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .Select(member => $"{type.FullName}.{member}"))
            .ToArray();
        var forbidden = new[]
        {
            "PrivateKey", "Seed", "RecoveryPhrase", "Mnemonic", "HardwareWallet",
            "SignAsync", "Publish", "Endpoint", "HttpClient", "FileStream"
        };
        Assert.All(publicSurface, member =>
            Assert.All(forbidden, value =>
                Assert.DoesNotContain(value, member, StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void RuntimeGraphAndProductionSourceRemainIsolated()
    {
        var root = RepositoryRoot();
        var generatorProject = File.ReadAllText(
            Path.Combine(root, "src", "XNode.ProfileGenerator", "XNode.ProfileGenerator.csproj"));
        Assert.Contains("Deep.Protocol", generatorProject, StringComparison.Ordinal);
        Assert.DoesNotContain("ProjectReference", generatorProject, StringComparison.Ordinal);
        Assert.DoesNotContain("Rebex", generatorProject, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Sodium", generatorProject, StringComparison.OrdinalIgnoreCase);

        var runtimeProjects = Directory.GetFiles(
                Path.Combine(root, "src"),
                "*.csproj",
                SearchOption.AllDirectories)
            .Where(path => !path.Contains("XNode.ProfileGenerator", StringComparison.Ordinal))
            .Select(File.ReadAllText);
        Assert.All(runtimeProjects, project =>
            Assert.DoesNotContain("XNode.ProfileGenerator", project, StringComparison.Ordinal));

        var productionSources = Directory.GetFiles(
                Path.Combine(root, "src", "XNode.ProfileGenerator"),
                "*.cs",
                SearchOption.AllDirectories)
            .Where(path =>
                !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
                !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(File.ReadAllText)
            .ToArray();
        var forbiddenSource = new[]
        {
            "Microsoft.Extensions", "System.Net", "HttpClient", "System.IO.File",
            "IServiceCollection", "WebApplication", "PrivateKey", "RecoveryPhrase"
        };
        Assert.All(productionSources, source =>
            Assert.All(forbiddenSource, value =>
                Assert.DoesNotContain(value, source, StringComparison.Ordinal)));
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            current = current.Parent;
        return current?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
