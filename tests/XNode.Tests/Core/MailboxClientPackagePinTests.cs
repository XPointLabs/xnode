using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.1059184.nupkg"] =
                "e4c29cd2de20d7863cdb7af993468953208e6a8097cee4de2a7cdfb468918c7f",
            ["Deep.Protocol.Abstractions.0.4.0-production.1059184.nupkg"] =
                "dcb00f2646b5a8bcf907f3936f761a00a6f0f360386e6631cd6e6513c711efe8",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.1059184.nupkg"] =
                "c2c1f3a5179cc10d32ed479225d730b9961fc7fbe7bd2e328b96f2a3fab1447b",
            ["Deep.Protocol.Protobuf.0.4.0-production.1059184.nupkg"] =
                "8912fa06c207bf48cddd251347ab7e7544c03485dff4222a3ec2fb86b8f13a56"
        };

    [Fact]
    public void ProductionAuthorityProtocolClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "production-successor-1059184",
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
            "Version=\"[0.4.0-production.1059184]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.4.0-production.1059184]\"",
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
            "../vendor/production-successor-1059184/packages",
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
            "0.4.0-production.1059184",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "6cpECaGXYofYPguIZsZZ0P3M5GwU8o4DSC7q+xa7jn54NznUZiqtILzeKdTsYiHP/iR4KsMEKct9k3+MCz1gnw==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.4.0-production.1059184",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Equal(
            "oUwiRYoKyfdMxKhkNk8IQ4ZDbbjdjUV+e8t/9hA2RU2dgObyBixltB3ZShdL/DhWZeXjBz3MdHLuNk6V2wIwvA==",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("contentHash").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-successor-1059184", "package-manifest.json")));
        Assert.Equal(
            "105918421eb5621bec86aeaac56013b269472aa7",
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
