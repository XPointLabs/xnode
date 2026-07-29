using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.3.0-p10j.2886880.nupkg"] =
                "a41c79124f1c62c2889e7b2ea4695956272aa16de1700206cade8993c1b44abe",
            ["Deep.Protocol.Abstractions.0.3.0-p10j.2886880.nupkg"] =
                "4508e67aba983e91c174c8ce796df654c06892680d65e14ff78bda4d553d542c",
            ["Deep.Protocol.MembershipRoutes.0.3.0-p10j.2886880.nupkg"] =
                "cdb3eb8a8b2889567a25e6db437a287fb12db86d29e0819c13c9adb5fbc02327",
            ["Deep.Protocol.Protobuf.0.3.0-p10j.2886880.nupkg"] =
                "c97025f5d1b44fd7a955e7b69614ea2c6cca499656ccf7930029cc740208eab7"
        };

    [Fact]
    public void P10jPeerMailboxPackageClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "mailbox-peer-p10j");
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
            "Version=\"[0.3.0-p10j.2886880]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.3.0-p10j.2886880]\"",
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
            sources["mailbox-peer-p10j"]);
        Assert.DoesNotContain(
            sources["nuget.org"],
            static pattern => pattern is "*" or "Deep.Protocol" or "Deep.Protocol.*");

        using var lockDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "src", "XNode.Core", "packages.lock.json")));
        var packages = lockDocument.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        Assert.Equal(
            "0.3.0-p10j.2886880",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "8nktp5tV9oPxOZbq9g9YDq0I8tmkkqY4mdXP9hZgBEnZi1xlfPq6j6I/s1xUFt0+4/ModMlGv9X/RU0iJ/vFbw==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.3.0-p10j.2886880",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(packageDirectory, "package-manifest.json")));
        Assert.Equal(
            "2886880d4c2060cd819765c53c77a02e1c475ea8",
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
