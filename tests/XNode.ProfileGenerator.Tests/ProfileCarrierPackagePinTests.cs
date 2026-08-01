using System.IO.Compression;
using System.Text;
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
        Assert.Equal("d83bbdd001b723738357689bbb2150a51357cb3b",
            value.GetProperty("sourceTree").GetString());
        Assert.Equal("071b5b300bcba3796d621720fb8f21cfdd5eb882",
            value.GetProperty("evidenceCarrierCommit").GetString());
        Assert.Equal("ecbfc7747452709fb82aaf85fa912ba13b61d4ad",
            value.GetProperty("evidenceCarrierTree").GetString());
        Assert.Equal(ExpectedNormalizedIdentity,
            value.GetProperty("normalizedIdentity").GetString());
        Assert.Equal(ExpectedDllSha256, value.GetProperty("dllSha256").GetString());
        Assert.Equal(ExpectedPdbSha256, value.GetProperty("pdbSha256").GetString());
        Assert.Equal(
            "packages/Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg",
            value.GetProperty("file").GetString());
        Assert.Equal(
            new[]
            {
                "Deep.Protocol/[0.3.0-p04.b887fa0]",
                "Sodium.Core/[1.4.1]",
                "libsodium/[1.0.22]"
            },
            value.GetProperty("dependencies")
                .EnumerateArray()
                .Select(entry =>
                    $"{entry.GetProperty("id").GetString()}/{entry.GetProperty("version").GetString()}")
                .Order(StringComparer.Ordinal),
            StringComparer.Ordinal);

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
        var dependencies = metadata.Descendants(ns + "dependency")
            .Select(element =>
                $"{element.Attribute("id")!.Value}/{element.Attribute("version")!.Value}")
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(
            new[]
            {
                "Deep.Protocol/[0.3.0-p04.b887fa0]",
                "Sodium.Core/[1.4.1]",
                "libsodium/[1.0.22]"
            },
            dependencies,
            StringComparer.Ordinal);

        AssertEntryHash(archive, "lib/net10.0/Deep.Protocol.ProfileCarrier.dll",
            ExpectedDllSha256);
        AssertEntryHash(archive, "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb",
            ExpectedPdbSha256);

        Assert.False(File.Exists(Path.Combine(
            vendor,
            "packages",
            "Deep.Protocol.ProfileCarrier.0.1.0-p14.faa598f.nupkg")));
    }

    [Fact]
    public void HistoricalEvidenceRemainsPinnedWhileActiveConsumersUseSurvivalBeta()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var historicalConsumers = new[]
        {
            "eng/P14C3.Ed25519Probe/P14C3.Ed25519Probe.csproj",
            "eng/P14C3.Ed25519Probe/packages.lock.json",
            "vendor/p04/offline-closure-manifest.json",
            "vendor/p04/package-manifest.json",
            "vendor/p04/profile-carrier-manifest.json"
        };
        foreach (var relative in historicalConsumers)
        {
            var text = File.ReadAllText(Path.Combine(
                root,
                relative.Replace('/', Path.DirectorySeparatorChar)));
            Assert.DoesNotContain("0.1.0-p14.faa598f", text, StringComparison.Ordinal);
            Assert.DoesNotContain(
                "5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e",
                text,
                StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(
                "2a21902ff5a613242180fdd75233991da896f879",
                text,
                StringComparison.OrdinalIgnoreCase);
            Assert.Contains("0.2.0-p14.69a712a", text, StringComparison.Ordinal);
        }

        foreach (var relative in new[]
                 {
                     "src/XNode.ProfileGenerator/XNode.ProfileGenerator.csproj",
                     "src/XNode.ProfileGenerator/packages.lock.json",
                     "tests/XNode.ProfileGenerator.Tests/packages.lock.json"
                 })
        {
            var text = File.ReadAllText(Path.Combine(
                root,
                relative.Replace('/', Path.DirectorySeparatorChar)));
            Assert.Contains("0.4.0-survival.e570512", text, StringComparison.Ordinal);
            Assert.DoesNotContain(ExpectedVersion, text, StringComparison.Ordinal);
        }

        var packages = Directory.GetFiles(
            Path.Combine(root, "vendor", "p04", "packages"),
            "Deep.Protocol.ProfileCarrier.*.nupkg");
        Assert.Equal(
            "Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg",
            Path.GetFileName(Assert.Single(packages)));
    }

    [Fact]
    public void NormalizedVerifierIsTheExactSelfContainedAcceptedGate()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var verifier = Path.Combine(
            root,
            "eng",
            "Get-P14C3ProfileCarrierNormalizedIdentity.ps1");
        Assert.True(File.Exists(verifier));
        Assert.Equal(
            "8cb67b749e7df1641222b1a5a89cc9d3854a58942dcf67d205a757009d34a0a3",
            Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                    Encoding.UTF8.GetBytes(
                        File.ReadAllText(verifier)
                            .Replace("\r\n", "\n", StringComparison.Ordinal)
                            .Replace('\r', '\n'))))
                .ToLowerInvariant(),
            ignoreCase: true);
        var source = File.ReadAllText(verifier);
        Assert.Contains("deep-p14-profile-carrier-normalized-package-v2", source,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Invoke-WebRequest", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HttpClient", source, StringComparison.OrdinalIgnoreCase);
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
