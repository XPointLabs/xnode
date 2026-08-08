using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.32b4d14.nupkg"] =
                "9d49292fd16069dc13f4b669a8e17597eb38e533dbc2097905f4dc93a1d62b0b",
            ["Deep.Protocol.Abstractions.0.4.0-production.32b4d14.nupkg"] =
                "1af4fe4d305ab555790cd976ca1fea5f94db611a854c675a11b608991a3c25fd",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.32b4d14.nupkg"] =
                "e4d5feeb4e8b2634167f90634f76bc9d630087cf452876a48b6f3358f9b9e493",
            ["Deep.Protocol.Protobuf.0.4.0-production.32b4d14.nupkg"] =
                "f441a1875bc1d9a717e91dd2422bda1e9d08a7fa1eaeaa2b8024127689aca84e"
        };

    [Fact]
    public void ProductionAuthorityProtocolClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "production-successor-32b4d14",
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
            "Version=\"[0.4.0-production.32b4d14]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.4.0-production.32b4d14]\"",
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
            "../vendor/production-successor-32b4d14/packages",
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
            "0.4.0-production.32b4d14",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "X3vS74s4Pfu1tpG1LRuJORE8jOtZ6Gz5RlLSjh+VGa3YWagw92I4wXhcRTnBi9D7KEOdFTFLNMQyiRXMrwHSSQ==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.4.0-production.32b4d14",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Equal(
            "DhFDtQryAud5aanPnsC6YHArjxERk2AVtVbHlkimvQbStBIwWcwwARgzHa4I7GC+y+HfkNiT6r0fgKzPOYtbFQ==",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("contentHash").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-successor-32b4d14", "package-manifest.json")));
        Assert.Equal(
            "32b4d145de6d6b008e95b3cfc6ac2943de7f78fc",
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
