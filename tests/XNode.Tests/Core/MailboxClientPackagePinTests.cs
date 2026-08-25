using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.Tests.Core;

public sealed class MailboxClientPackagePinTests
{
    private const string Version = "0.5.0-production.e75bfed";

    private static readonly IReadOnlyDictionary<string, string> Expected =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [$"Deep.Protocol.{Version}.nupkg"] =
                "69578c00c503383b149c4e9bccb3f14f87d3608c9781fe684710233059060098",
            [$"Deep.Protocol.MembershipRoutes.{Version}.nupkg"] =
                "5dacdef966835452ffa2c0a404dac72524b508ebeffa3f44b79d5d290c2de75e"
        };

    [Fact]
    public void ProductionPrivacyProtocolClosure_IsExactAndLocked()
    {
        var root = FindRepositoryRoot();
        var packageDirectory = Path.Combine(
            root, "vendor", "production-privacy-e75bfed", "packages");
        var files = Directory.GetFiles(packageDirectory, "*.nupkg")
            .ToDictionary(static path => Path.GetFileName(path)!, StringComparer.Ordinal);
        Assert.Equal(Expected.Keys.Order(), files.Keys.Order());

        foreach (var expected in Expected)
        {
            var actual = Convert.ToHexString(
                    SHA256.HashData(File.ReadAllBytes(files[expected.Key])))
                .ToLowerInvariant();
            Assert.Equal(expected.Value, actual);
        }

        var coreProject = File.ReadAllText(
            Path.Combine(root, "src", "XNode.Core", "XNode.Core.csproj"));
        Assert.Contains($"Version=\"[{Version}]\"", coreProject, StringComparison.Ordinal);
        Assert.Contains(
            $"Deep.Protocol.MembershipRoutes\" Version=\"[{Version}]\"",
            coreProject,
            StringComparison.Ordinal);
        Assert.Contains("<RestoreLockedMode>true</RestoreLockedMode>", coreProject);

        var config = XDocument.Load(Path.Combine(root, "eng", "survival-beta.NuGet.Config"));
        var packageSources = config.Descendants("add")
            .ToDictionary(
                element => element.Attribute("key")!.Value,
                element => element.Attribute("value")!.Value,
                StringComparer.Ordinal);
        Assert.Equal(
            "../vendor/production-privacy-e75bfed/packages",
            packageSources["production-successor-protocol"]);

        using var lockDocument = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(root, "src", "XNode.Core", "packages.lock.json")));
        var packages = lockDocument.RootElement.GetProperty("dependencies").GetProperty("net10.0");
        Assert.Equal(
            Version,
            packages.GetProperty("Deep.Protocol").GetProperty("resolved").GetString());
        Assert.Equal(
            "d554G0Upd8xsuRWoUGBh9bR33cu/9fpcDMEZ5ciTZ9OhLQahiuCgqkoukcMRUuJr2Sn6Nz/DaAk/m3buDq197A==",
            packages.GetProperty("Deep.Protocol").GetProperty("contentHash").GetString());
        Assert.Equal(
            Version,
            packages.GetProperty("Deep.Protocol.MembershipRoutes")
                .GetProperty("resolved").GetString());
        Assert.Equal(
            "6+TuQpHGiX+ekv0Cu5G+f1yEio/ZUP/hIdIX7X37hbrgIsIvwLItPLOEKXxRIRrXeEiyF1zun8QEnQiFLVS3Ug==",
            packages.GetProperty("Deep.Protocol.MembershipRoutes")
                .GetProperty("contentHash").GetString());

        var operatorDocument = File.ReadAllText(Path.Combine(root, "docs", "operator.md"));
        foreach (var expected in Expected)
        {
            Assert.Contains(expected.Key, operatorDocument, StringComparison.Ordinal);
            Assert.Contains(expected.Value, operatorDocument, StringComparison.Ordinal);
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("XNode repository root was not found.");
    }
}
