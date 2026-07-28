using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.3.0-p10b3.60ce2e3.nupkg"] =
                "588a889f362a618bd06b8277fd4afc8b6c64ec37797f4cdf291af1865f0fd779",
            ["Deep.Protocol.Abstractions.0.3.0-p10b3.60ce2e3.nupkg"] =
                "af23f03aade18ee726d5a6345e2a613c91fbea0bf62d3d0431dd629062e603bd",
            ["Deep.Protocol.MembershipRoutes.0.3.0-p10b3.60ce2e3.nupkg"] =
                "16f4a0dd0c33461d85ed15bf69268e4b78b70617c059aa60d3b662d922155b96",
            ["Deep.Protocol.Protobuf.0.3.0-p10b3.60ce2e3.nupkg"] =
                "ec5478d4ebc03fba3a97a4e0675b0fbdac4bd43c4503ed39033e1b6e469f1250"
        };

    [Fact]
    public void P10b3PeerMailboxPackageClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "mailbox-peer-p10b3");
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
            "Version=\"[0.3.0-p10b3.60ce2e3]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.3.0-p10b3.60ce2e3]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.DoesNotContain("p03b2", coreProject, StringComparison.OrdinalIgnoreCase);

        var config = XDocument.Load(Path.Combine(root, "eng", "mailbox-client.NuGet.Config"));
        var sources = config.Descendants("packageSource")
            .ToDictionary(
                element => element.Attribute("key")!.Value,
                element => element.Elements("package")
                    .Select(package => package.Attribute("pattern")!.Value)
                    .ToArray(),
                StringComparer.Ordinal);
        Assert.Equal(
            new[] { "Deep.Protocol", "Deep.Protocol.*" },
            sources["mailbox-peer-p10b3"]);
        Assert.DoesNotContain(
            sources["nuget.org"],
            static pattern => pattern is "*" or "Deep.Protocol" or "Deep.Protocol.*");

        using var lockDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "src", "XNode.Core", "packages.lock.json")));
        var packages = lockDocument.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        Assert.Equal(
            "0.3.0-p10b3.60ce2e3",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "t9K7qzSWL63+qjkH0BH9Mz+6HEui6Dq6eV8FiaFhslGe5nFQcfjlQqWq5trTSXF4td4YLUCbtcz5TCyt2GeNcw==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.3.0-p10b3.60ce2e3",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(packageDirectory, "package-manifest.json")));
        Assert.Equal(
            "60ce2e3a5140f245d6bcfecf60fa456c26ffe730",
            manifest.RootElement.GetProperty("sourceCommit").GetString());
        Assert.Equal(
            Expected.Count,
            manifest.RootElement.GetProperty("packages").GetArrayLength());
        var manifestPackages = manifest.RootElement.GetProperty("packages")
            .EnumerateArray()
            .ToDictionary(
                element => element.GetProperty("file").GetString()!,
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
