using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.ProfileGenerator.Tests;

public sealed class P04PackagePinTests
{
    [Fact]
    public void AcceptedP04ManifestEntriesResolveAndMatchTheirDeclaredArtifacts()
    {
        var vendorRoot = Path.Combine(RepositoryRoot(), "vendor", "p04");
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(Path.Combine(vendorRoot, "package-manifest.json")));
        var root = document.RootElement;
        Assert.Equal("deep-local-package-manifest.v1", root.GetProperty("schema").GetString());
        Assert.Equal("0.3.0-p04.b887fa0", root.GetProperty("packageVersion").GetString());
        Assert.Equal(
            "b887fa088f486390be182cac4cbcb59b60ce8931",
            root.GetProperty("sourceCommit").GetString());

        var entries = root.GetProperty("packages").EnumerateArray().ToArray();
        Assert.Equal(3, entries.Length);
        foreach (var entry in entries)
        {
            var relativeFile = entry.GetProperty("file").GetString();
            Assert.False(string.IsNullOrWhiteSpace(relativeFile));
            var path = Path.GetFullPath(Path.Combine(vendorRoot, relativeFile!));
            Assert.StartsWith(vendorRoot, path, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(path), $"Manifest artifact is missing: {relativeFile}");
            Assert.Equal(entry.GetProperty("bytes").GetInt64(), new FileInfo(path).Length);
            Assert.Equal(
                entry.GetProperty("sha256").GetString(),
                Sha256(path),
                ignoreCase: true);

            var identity = ReadIdentity(path);
            Assert.Equal(root.GetProperty("packageVersion").GetString(), identity.Version);
            Assert.StartsWith("Deep.Protocol", identity.Id, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void GoldenFixtureRemainsTheAcceptedP04Fixture()
    {
        Assert.Equal(
            "758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45",
            Sha256(Path.Combine(RepositoryRoot(), "vendor", "p04", "membership-contract-v1.json")));
    }

    internal static (string Id, string Version) ReadIdentity(string nupkg)
    {
        using var archive = ZipFile.OpenRead(nupkg);
        var nuspec = Assert.Single(
            archive.Entries,
            entry => entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
        using var stream = nuspec.Open();
        var metadata = XDocument.Load(stream).Root!
            .Elements().Single(element => element.Name.LocalName == "metadata");
        return (
            metadata.Elements().Single(element => element.Name.LocalName == "id").Value,
            metadata.Elements().Single(element => element.Name.LocalName == "version").Value);
    }

    internal static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    internal static string RepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            current = current.Parent;
        return current?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }
}
