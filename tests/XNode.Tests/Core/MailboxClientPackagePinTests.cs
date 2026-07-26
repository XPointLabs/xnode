using System.Security.Cryptography;

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
