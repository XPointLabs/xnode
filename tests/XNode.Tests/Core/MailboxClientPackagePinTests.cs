using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.62fd84a.nupkg"] =
                "a1620cd62f12bcf62052c666445be46e453312d4a50d13d2dd44dff0594a0e51",
            ["Deep.Protocol.Abstractions.0.4.0-production.62fd84a.nupkg"] =
                "e0cffcf86d2340611a8c3fa68acb7d0d44f4cacd97be3c0059f528375108743c",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.62fd84a.nupkg"] =
                "e30511a9ec0541d957094a0be527c689cc6de4a7455bd81bd20b1bbb0082cafb",
            ["Deep.Protocol.Protobuf.0.4.0-production.62fd84a.nupkg"] =
                "e10b612ea9913e18ae1f059de37fe9c9a67aadfa6bd4b2cd219a74749d5d403e"
        };

    [Fact]
    public void ProductionAuthorityProtocolClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "production-successor-62fd84a",
            "packages");
        var files = Directory.GetFiles(packageDirectory, "*.nupkg")
            .ToDictionary(static path => Path.GetFileName(path)!, StringComparer.Ordinal);
        Assert.Equal(Expected.Keys.Order(), files.Keys.Order());
        Assert.DoesNotContain(
            files.Keys,
            static name => name!.Contains("p03b2", StringComparison.OrdinalIgnoreCase));

        foreach (var expected in Expected)
        {
            var actual = Convert.ToHexString(
                    SHA256.HashData(File.ReadAllBytes(files[expected.Key])))
                .ToLowerInvariant();
            Assert.Equal(expected.Value, actual);
        }

        var coreProject = File.ReadAllText(
            Path.Combine(root, "src", "XNode.Core", "XNode.Core.csproj"));
        Assert.Contains(
            "Version=\"[0.4.0-production.62fd84a]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.4.0-production.62fd84a]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.DoesNotContain("p03b2", coreProject, StringComparison.OrdinalIgnoreCase);

        var config = XDocument.Load(Path.Combine(root, "eng", "survival-beta.NuGet.Config"));
        var packageSources = config.Descendants("add")
            .ToDictionary(
                element => element.Attribute("key")!.Value,
                element => element.Attribute("value")!.Value,
                StringComparer.Ordinal);
        Assert.Equal(
            "../vendor/production-successor-62fd84a/packages",
            packageSources["production-successor-protocol"]);
        var sources = config.Descendants("packageSource")
            .ToDictionary(
                element => element.Attribute("key")!.Value,
                element => element.Elements("package")
                    .Select(package => package.Attribute("pattern")!.Value)
                    .ToArray(),
                StringComparer.Ordinal);
        Assert.Equal(
            new[] { "Deep.Protocol", "Deep.Protocol.*" },
            sources["production-successor-protocol"]);
        Assert.DoesNotContain(
            sources["nuget.org"],
            static pattern => pattern is "*" or "Deep.Protocol" or "Deep.Protocol.*");

        using var lockDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "src", "XNode.Core", "packages.lock.json")));
        var packages = lockDocument.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        Assert.Equal(
            "0.4.0-production.62fd84a",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "otJ40Z3g47L653ovTikPF4+mCFPbkuI+d0qj6A2oxLFy2js2r82P+JLRBdEqHQHepaXkM/BRPlvJdM649lJtOg==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.4.0-production.62fd84a",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Equal(
            "w2RWPi08pc2+jquhCGWp+v0v0+37JcBe80ClZVP1S7uvmpThjhgJuE4JnrpTHKStHHx1HYN79ZV0W24wiGUXQQ==",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("contentHash").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-successor-62fd84a", "package-manifest.json")));
        Assert.Equal(
            "62fd84a36580855a64307bf8020ce6a94d4ac741",
            manifest.RootElement.GetProperty("sourceCommit").GetString());
        Assert.Equal(
            "deep-local-package-closure.v1",
            manifest.RootElement.GetProperty("schema").GetString());
        Assert.Equal(
            "deep-protocol",
            manifest.RootElement.GetProperty("sourceRepository").GetString());
        Assert.True(
            manifest.RootElement.GetProperty("reproducibleNormalizedBuild").GetBoolean());
        Assert.Equal(
            Expected.Count,
            manifest.RootElement.GetProperty("packages").GetArrayLength());
        var manifestPackages = manifest.RootElement.GetProperty("packages")
            .EnumerateArray()
            .ToDictionary(
                element => Path.GetFileName(element.GetProperty("file").GetString()!),
                element => (
                    Bytes: element.GetProperty("bytes").GetInt64(),
                    Hash: element.GetProperty("sha256").GetString()!),
                StringComparer.Ordinal);
        Assert.Equal(Expected.Keys.Order(), manifestPackages.Keys.Order());
        foreach (var expected in Expected)
        {
            Assert.Equal(expected.Value, manifestPackages[expected.Key].Hash);
            Assert.Equal(
                new FileInfo(files[expected.Key]).Length,
                manifestPackages[expected.Key].Bytes);
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("XNode repository root was not found.");
    }
}
