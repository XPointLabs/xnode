using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.ProfileGenerator.Tests;

public sealed class ProfileCarrierPackagePinTests
{
    private const string ExpectedVersion = "0.1.0-p14.faa598f";
    private const string ExpectedSha256 =
        "5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e";
    private const string ExpectedSource =
        "faa598ff32913470cf85d6f2c8a8921cbf2aa287";

    [Fact]
    public void ExactProfileCarrierPackageIsPinnedWithoutRepacking()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var vendor = Path.Combine(root, "vendor", "p04");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(
            Path.Combine(vendor, "profile-carrier-manifest.json")));
        var value = manifest.RootElement;
        Assert.Equal("xnode-p14-profile-carrier-package.v1",
            value.GetProperty("schema").GetString());
        Assert.Equal("Deep.Protocol.ProfileCarrier", value.GetProperty("id").GetString());
        Assert.Equal(ExpectedVersion, value.GetProperty("version").GetString());
        Assert.Equal(24_597, value.GetProperty("bytes").GetInt64());
        Assert.Equal(ExpectedSha256, value.GetProperty("sha256").GetString());
        Assert.Equal(ExpectedSource, value.GetProperty("sourceCommit").GetString());
        Assert.Equal(
            "ab402ce9420ecb5f3f80a6fb9fd48b807a4bda96565c28f88f3c35ac860719ba",
            value.GetProperty("normalizedIdentity").GetString());

        var package = Path.Combine(vendor, value.GetProperty("file").GetString()!);
        Assert.Equal(24_597, new FileInfo(package).Length);
        Assert.Equal(ExpectedSha256, P04PackagePinTests.Sha256(package), ignoreCase: true);
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
    }
}
