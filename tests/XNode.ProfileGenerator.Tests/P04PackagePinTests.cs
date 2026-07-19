using System.Security.Cryptography;
using System.Text.Json;

namespace XNode.ProfileGenerator.Tests;

public sealed class P04PackagePinTests
{
    [Theory]
    [InlineData("Deep.Protocol.0.3.0-p04.b887fa0.nupkg", "8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442")]
    [InlineData("Deep.Protocol.Abstractions.0.3.0-p04.b887fa0.nupkg", "fc1212a6765f5778188fcb3866ef923023c2253c3ead299a542271f4cc4f844f")]
    [InlineData("Deep.Protocol.Protobuf.0.3.0-p04.b887fa0.nupkg", "755a027c58be670151456cc0bca4764731f7c493932d9eedd00c02e704baf818")]
    public void AcceptedP04PackagesAreBytePinned(string file, string expectedSha256)
    {
        var path = Path.Combine(RepositoryRoot(), "vendor", "p04", file);
        using var stream = File.OpenRead(path);
        Assert.Equal(expectedSha256, Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant());
    }

    [Fact]
    public void ManifestAndGoldenFixtureArePinned()
    {
        var root = Path.Combine(RepositoryRoot(), "vendor", "p04");
        AssertHash(
            Path.Combine(root, "package-manifest.json"),
            "fd3ef27bf0b9272570d6c6e680a3c99e581f6220799d13ee3afbd86ea0e99298");
        AssertHash(
            Path.Combine(root, "membership-contract-v1.json"),
            "758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45");
        using var document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "package-manifest.json")));
        Assert.Equal(
            "b887fa088f486390be182cac4cbcb59b60ce8931",
            document.RootElement.GetProperty("sourceCommit").GetString());
        Assert.Equal(
            "0.3.0-p04.b887fa0",
            document.RootElement.GetProperty("packageVersion").GetString());
    }

    private static void AssertHash(string path, string expected)
    {
        using var stream = File.OpenRead(path);
        Assert.Equal(expected, Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant());
    }

    private static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            current = current.Parent;
        return current?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
