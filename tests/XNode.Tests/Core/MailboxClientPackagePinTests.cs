using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.cc39def.nupkg"] =
                "6ae87c7b577b89aa42db9afdf41660c8ecd3ca5984c19b4290cb40fa53024f0d",
            ["Deep.Protocol.Abstractions.0.4.0-production.cc39def.nupkg"] =
                "e26432a477df59da31afc5dc8ab1b67cd828942c5095b56d568f6897abc08043",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.cc39def.nupkg"] =
                "7d6338ca8330b5db3db31f0cbe23aa38a4796f16bb7affbcc042c32b4ce1144a",
            ["Deep.Protocol.Protobuf.0.4.0-production.cc39def.nupkg"] =
                "999ff91b25a58662987c63824fcd4e0ce796ddc9de32c598efc22ce170c3bd25"
        };

    [Fact]
    public void ProductionAuthorityProtocolClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "production-successor-cc39def",
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
            "Version=\"[0.4.0-production.cc39def]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.4.0-production.cc39def]\"",
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
            "../vendor/production-successor-cc39def/packages",
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
            "0.4.0-production.cc39def",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "b0KwHBLTeNt9hI/UHckbVos6J4xOYkNl4DygB7b/8cFQv9nMB+9RcpAEJWAK5zi98BJUg2HANeWrL5Dzh2mLEQ==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.4.0-production.cc39def",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Equal(
            "Lszd79KT0K3ORoGiwEg/3azLCaVKHC4HWInrwrfEhWDqe7kCHcRYQ9YbB1zDCVXdM0Vr9X5JwQlppSWIXhK/zA==",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("contentHash").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-successor-cc39def", "package-manifest.json")));
        Assert.Equal(
            "cc39defbf9c24bf7d99f6346a86c7602379b62ea",
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
