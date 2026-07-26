using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.3.0-p09c2.f1a93c9.nupkg"] =
                "6fb5c0f5e05ed5ef78e962c7ed515dec2656dd50f5f201fd68ff1cf29821ca23",
            ["Deep.Protocol.Abstractions.0.3.0-p09c2.f1a93c9.nupkg"] =
                "b48cfe11bc1481b1f210c25a02aa6f96c50937d79165fe76889b6564d2a91804",
            ["Deep.Protocol.Protobuf.0.3.0-p09c2.f1a93c9.nupkg"] =
                "8f27c94281ad70edd70f9e6c1876a9b9ec37abdc180a92eb7ea9009098cb3668"
        };

    [Fact]
    public void CorrectedMailboxPackageClosure_IsExactAndRejectsOldP09c()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "mailbox-client-package-corrected");
        var files = Directory.GetFiles(packageDirectory, "*.nupkg")
            .ToDictionary(static path => Path.GetFileName(path)!, StringComparer.Ordinal);
        Assert.Equal(Expected.Keys.Order(), files.Keys.Order());
        Assert.DoesNotContain(
            files.Keys,
            static name => name!.Contains("p09c.451f3dc", StringComparison.OrdinalIgnoreCase));

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
            "Version=\"[0.3.0-p09c2.f1a93c9]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.DoesNotContain("0.3.0-p09c.451f3dc", coreProject, StringComparison.Ordinal);

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
            sources["mailbox-corrected"]);
        Assert.DoesNotContain(
            sources["nuget.org"],
            static pattern => pattern is "*" or "Deep.Protocol" or "Deep.Protocol.*");

        using var lockDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "src", "XNode.Core", "packages.lock.json")));
        var packages = lockDocument.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        Assert.Equal(
            "0.3.0-p09c2.f1a93c9",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "l4hjLbU50YI+gCtnLKh3cEax+J5rS5lbHwL/ko2DT5AuVS5YfoVFjabOyDav8LVX2YoXEv8E0qXul0O2HgmG4w==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);
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
