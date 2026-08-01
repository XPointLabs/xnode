using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.ff9f80f.nupkg"] =
                "feec9ded0d02c04fda2650bb45a0b550e97915df724e99fb56f1c1976508e154",
            ["Deep.Protocol.Abstractions.0.4.0-production.ff9f80f.nupkg"] =
                "86871905258af6b63e51b8231d35fb31ad51f45a3bccd3f2574716c7b7e60851",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.ff9f80f.nupkg"] =
                "a27f7d2a841ff3fb122d1d0767da2ee87b3e8b5f547b647600271d2ba54c2825",
            ["Deep.Protocol.Protobuf.0.4.0-production.ff9f80f.nupkg"] =
                "77bd88914a8e323c0b741664e2ff1431555311550edddc8f55f66ab287365416"
        };

    [Fact]
    public void ProductionAuthorityProtocolClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "production-topology-ff9f80f",
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
            "Version=\"[0.4.0-production.ff9f80f]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.4.0-production.ff9f80f]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.DoesNotContain("p03b2", coreProject, StringComparison.OrdinalIgnoreCase);

        var config = XDocument.Load(Path.Combine(root, "eng", "survival-beta.NuGet.Config"));
        var sources = config.Descendants("packageSource")
            .ToDictionary(
                element => element.Attribute("key")!.Value,
                element => element.Elements("package")
                    .Select(package => package.Attribute("pattern")!.Value)
                    .ToArray(),
                StringComparer.Ordinal);
        Assert.Equal(
            new[] { "Deep.Protocol", "Deep.Protocol.*" },
            sources["production-topology-protocol"]);
        Assert.DoesNotContain(
            sources["nuget.org"],
            static pattern => pattern is "*" or "Deep.Protocol" or "Deep.Protocol.*");

        using var lockDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "src", "XNode.Core", "packages.lock.json")));
        var packages = lockDocument.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        Assert.Equal(
            "0.4.0-production.ff9f80f",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "KEp7dKNCJcMoR04443k7XyC+HwztryAWL19B2P2hxFAKjCBdGRRz6yDCkWi2TeB69Bd9KsPBBvvD6AE5a4wcCg==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.4.0-production.ff9f80f",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-topology-ff9f80f", "package-manifest.json")));
        Assert.Equal(
            "ff9f80fb6c29e3ac0a725f9161ee477b658730e3",
            manifest.RootElement.GetProperty("sourceCommit").GetString());
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
