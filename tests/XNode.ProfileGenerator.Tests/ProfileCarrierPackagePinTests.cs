using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.ProfileGenerator.Tests;

public sealed class ProfileCarrierPackagePinTests
{
    private const string ExpectedVersion = "0.2.0-p14.69a712a";
    private const string ExpectedSha256 =
        "fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498";
    private const string ExpectedSha512 =
        "x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==";
    private const string ExpectedSource =
        "69a712a894b024a09859096025c2bb8fe68a642e";
    private const string ExpectedNormalizedIdentity =
        "baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f";
    private const string ExpectedDllSha256 =
        "20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034";
    private const string ExpectedPdbSha256 =
        "80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a";

    [Fact]
    public void ExactProfileCarrierPackageIsPinnedWithoutRepacking()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var vendor = Path.Combine(root, "vendor", "p04");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "profile-carrier-manifest.json")));
        var value = manifest.RootElement;
        Assert.Equal("xnode-p14-profile-carrier-package.v2",
            value.GetProperty("schema").GetString());
        Assert.Equal("Deep.Protocol.ProfileCarrier", value.GetProperty("id").GetString());
        Assert.Equal(ExpectedVersion, value.GetProperty("version").GetString());
        Assert.Equal(29_399, value.GetProperty("bytes").GetInt64());
        Assert.Equal(ExpectedSha256, value.GetProperty("sha256").GetString());
        Assert.Equal(ExpectedSha512, value.GetProperty("nugetContentHash").GetString());
        Assert.Equal(ExpectedSource, value.GetProperty("sourceCommit").GetString());
        Assert.Equal(ExpectedNormalizedIdentity,
            value.GetProperty("normalizedIdentity").GetString());
        Assert.Equal(ExpectedDllSha256, value.GetProperty("dllSha256").GetString());
        Assert.Equal(ExpectedPdbSha256, value.GetProperty("pdbSha256").GetString());
        Assert.Equal(
            "packages/Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg",
            value.GetProperty("file").GetString());

        var package = Path.Combine(vendor, value.GetProperty("file").GetString()!);
        Assert.Equal(29_399, new FileInfo(package).Length);
        Assert.Equal(ExpectedSha256, P04PackagePinTests.Sha256(package), ignoreCase: true);
        using (var packageStream = File.OpenRead(package))
        {
            Assert.Equal(
                ExpectedSha512,
                Convert.ToBase64String(System.Security.Cryptography.SHA512.HashData(packageStream)));
        }
        var identity = P04PackagePinTests.ReadIdentity(package);
        Assert.Equal("Deep.Protocol.ProfileCarrier", identity.Id);
        Assert.Equal(ExpectedVersion, identity.Version);

        using var archive = ZipFile.OpenRead(package);
        var nuspec = Assert.Single(archive.Entries,
            entry => entry.FullName == "Deep.Protocol.ProfileCarrier.nuspec");
        using var stream = nuspec.Open();
        var document = XDocument.Load(stream);
        XNamespace ns = document.Root!.Name.Namespace;
        var metadata = document.Root.Element(ns + "metadata")!;
        Assert.Equal(ExpectedSource,
            metadata.Element(ns + "repository")!.Attribute("commit")!.Value);
        var dependency = Assert.Single(metadata.Descendants(ns + "dependency"));
        Assert.Equal("Deep.Protocol", dependency.Attribute("id")!.Value);
        Assert.Equal("[0.3.0-p04.b887fa0]", dependency.Attribute("version")!.Value);

        AssertEntryHash(archive, "lib/net10.0/Deep.Protocol.ProfileCarrier.dll",
            ExpectedDllSha256);
        AssertEntryHash(archive, "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb",
            ExpectedPdbSha256);

        Assert.False(File.Exists(Path.Combine(
            vendor,
            "packages",
            "Deep.Protocol.ProfileCarrier.0.1.0-p14.faa598f.nupkg")));
    }

    private static void AssertEntryHash(
        ZipArchive archive,
        string path,
        string expectedSha256)
    {
        var entry = Assert.Single(archive.Entries, value => value.FullName == path);
        using var stream = entry.Open();
        Assert.Equal(
            expectedSha256,
            Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(stream))
                .ToLowerInvariant());
    }
}
