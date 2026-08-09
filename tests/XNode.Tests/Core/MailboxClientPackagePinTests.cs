using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Deep.Protocol.0.4.0-production.588229f.nupkg"] =
                "026b63904f04bf841348d37732208cc52e13199f6483492eb652c85ae496e498",
            ["Deep.Protocol.Abstractions.0.4.0-production.588229f.nupkg"] =
                "1651c6b2bb84b8320fe795920d53cd64e9f0a8b684d97993739f9b107b0e1082",
            ["Deep.Protocol.MembershipRoutes.0.4.0-production.588229f.nupkg"] =
                "229a74b058be8a7a4278232833aa28b5afd56e2801f7e8ebef30173a676f8da3",
            ["Deep.Protocol.Protobuf.0.4.0-production.588229f.nupkg"] =
                "309ce298498311d2c3aa001f99a5a72c28fd687223c461402125c194dfe7e75b"
        };

    [Fact]
    public void ProductionAuthorityProtocolClosure_IsExactAndRejectsNetworkSubstitution()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root,
            "vendor",
            "production-successor-588229f",
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
            "Version=\"[0.4.0-production.588229f]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains(
            "Deep.Protocol.MembershipRoutes\" Version=\"[0.4.0-production.588229f]\"",
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
            "../vendor/production-successor-588229f/packages",
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
            "0.4.0-production.588229f",
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "4/DSNbwQtzdAo8iVDRX3Q/vmxMIH5GrScnME2iRndIjKTUqyrqA0J6V7nHGZPlQ+52LFfzvgB5ZVzaQSZG9tlA==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            "0.4.0-production.588229f",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("resolved").GetString());
        Assert.Equal(
            "Epe+Gs8QOErxGLQSeqhIAijtphPIknCQImQ7G6XdJMXXwjvsLZb6SbqXyW09+vXg2jwyBh+cwdLV+Sk6KnTulw==",
            packages.GetProperty("Deep.Protocol.MembershipRoutes").GetProperty("contentHash").GetString());
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "vendor", "production-successor-588229f", "package-manifest.json")));
        Assert.Equal(
            "588229f6beed9266382b17ce3c8b9303e3d36b2a",
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

        var packageDocumentation = new[]
        {
            File.ReadAllText(Path.Combine(root, "docs", "operator.md")),
            File.ReadAllText(Path.Combine(root, "docs", "adr",
                "0006-mailbox-client-activation-blocker.md"))
        };
        foreach (var document in packageDocumentation)
        {
            Assert.Contains(
                "588229f6beed9266382b17ce3c8b9303e3d36b2a",
                document,
                StringComparison.Ordinal);
            foreach (var expected in Expected)
                Assert.Contains(expected.Value, document, StringComparison.Ordinal);
        }
        foreach (var expected in Expected)
            Assert.Contains(expected.Key, packageDocumentation[0], StringComparison.Ordinal);
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
