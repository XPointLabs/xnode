using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;

namespace XNode.ProfileGenerator.Tests;

public sealed class OfflineClosureTests
{
    [Fact]
    public void ClosureManifestExactlyCoversBothLockedP14CGraphs()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var vendorRoot = Path.Combine(root, "vendor", "p04");
        using var manifest = JsonDocument.Parse(
            File.ReadAllBytes(Path.Combine(vendorRoot, "offline-closure-manifest.json")));
        Assert.Equal(
            "xnode-p14c-offline-closure.v1",
            manifest.RootElement.GetProperty("schema").GetString());
        var packages = manifest.RootElement.GetProperty("packages")
            .EnumerateArray()
            .Select(entry => new ManifestEntry(
                entry.GetProperty("id").GetString()!,
                entry.GetProperty("version").GetString()!,
                entry.GetProperty("file").GetString()!,
                entry.GetProperty("bytes").GetInt64(),
                entry.GetProperty("sha256").GetString()!,
                entry.GetProperty("role").GetString()!))
            .ToArray();
        Assert.Equal(packages.Length, packages
            .Select(static package => $"{package.Id}/{package.Version}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count());

        var locked = ReadLockedPackages(
                Path.Combine(root, "src", "XNode.ProfileGenerator", "packages.lock.json"))
            .Concat(ReadLockedPackages(
                Path.Combine(root, "tests", "XNode.ProfileGenerator.Tests", "packages.lock.json")))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var declared = packages
            .Where(static package => package.Role != "win-arm64-sdk-runtime-pack")
            .Select(static package => $"{package.Id}/{package.Version}")
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        Assert.Equal(locked, declared, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(
            new[]
            {
                "Microsoft.AspNetCore.App.Runtime.win-arm64/10.0.9",
                "Microsoft.NETCore.App.Runtime.win-arm64/10.0.9",
                "Microsoft.WindowsDesktop.App.Runtime.win-arm64/10.0.9"
            },
            packages
                .Where(static package => package.Role == "win-arm64-sdk-runtime-pack")
                .Select(static package => $"{package.Id}/{package.Version}")
                .Order(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

        foreach (var package in packages)
        {
            Assert.DoesNotContain('\\', package.File);
            var path = Path.GetFullPath(Path.Combine(vendorRoot, package.File));
            Assert.StartsWith(vendorRoot, path, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(path), $"Offline package is missing: {package.File}");
            Assert.Equal(package.Bytes, new FileInfo(path).Length);
            Assert.Equal(package.Sha256, P04PackagePinTests.Sha256(path), ignoreCase: true);
            var identity = P04PackagePinTests.ReadIdentity(path);
            Assert.Equal(package.Id, identity.Id, ignoreCase: true);
            Assert.Equal(package.Version, identity.Version);
            Assert.False(string.IsNullOrWhiteSpace(package.Role));
        }
    }

    [Fact]
    public void NuGetAndVerificationScriptAreLocalOnly()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        Assert.False(File.Exists(Path.Combine(root, "NuGet.Config")));
        var config = XDocument.Load(Path.Combine(
            root,
            "scripts",
            "p14c-offline.NuGet.Config"));
        var sources = config.Descendants("packageSources").Elements("add").ToArray();
        var source = Assert.Single(sources);
        Assert.Equal("../vendor/p04/packages", source.Attribute("value")?.Value);
        Assert.DoesNotContain(
            config.Descendants("add").Select(element => element.Attribute("value")?.Value ?? string.Empty),
            value => value.StartsWith("http:", StringComparison.OrdinalIgnoreCase) ||
                value.StartsWith("https:", StringComparison.OrdinalIgnoreCase) ||
                value.Contains("nuget.org", StringComparison.OrdinalIgnoreCase));

        var script = Path.Combine(root, "scripts", "verify-p14c-offline.ps1");
        Assert.True(File.Exists(script));
        var text = File.ReadAllText(script);
        Assert.Contains("--locked-mode", text, StringComparison.Ordinal);
        Assert.Contains("--no-http-cache", text, StringComparison.Ordinal);
        Assert.Contains("NUGET_PACKAGES", text, StringComparison.Ordinal);
        Assert.Contains("win-arm64", text, StringComparison.Ordinal);
    }

    [Fact]
    public void LibsodiumArchiveCarriesPortableAndWindowsArm64NativeAssets()
    {
        var closure = ReadClosure();
        var libsodium = Assert.Single(
            closure,
            package => package.Id.Equals("libsodium", StringComparison.OrdinalIgnoreCase));
        using var archive = ZipFile.OpenRead(Path.Combine(
            P04PackagePinTests.RepositoryRoot(),
            "vendor",
            "p04",
            libsodium.File));
        var paths = archive.Entries.Select(static entry => entry.FullName).ToHashSet(
            StringComparer.OrdinalIgnoreCase);
        Assert.Contains("runtimes/win-arm64/native/libsodium.dll", paths);
        Assert.Contains("runtimes/win-x64/native/libsodium.dll", paths);
        Assert.Contains("runtimes/linux-arm64/native/libsodium.so", paths);
        Assert.Contains("runtimes/linux-x64/native/libsodium.so", paths);
        Assert.Contains("runtimes/osx-arm64/native/libsodium.dylib", paths);
        Assert.Contains("runtimes/osx-x64/native/libsodium.dylib", paths);
    }

    private static IReadOnlyList<ManifestEntry> ReadClosure()
    {
        var path = Path.Combine(
            P04PackagePinTests.RepositoryRoot(),
            "vendor",
            "p04",
            "offline-closure-manifest.json");
        using var manifest = JsonDocument.Parse(File.ReadAllBytes(path));
        return manifest.RootElement.GetProperty("packages").EnumerateArray()
            .Select(entry => new ManifestEntry(
                entry.GetProperty("id").GetString()!,
                entry.GetProperty("version").GetString()!,
                entry.GetProperty("file").GetString()!,
                entry.GetProperty("bytes").GetInt64(),
                entry.GetProperty("sha256").GetString()!,
                entry.GetProperty("role").GetString()!))
            .ToArray();
    }

    private static IEnumerable<string> ReadLockedPackages(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        foreach (var framework in document.RootElement.GetProperty("dependencies").EnumerateObject())
        {
            foreach (var dependency in framework.Value.EnumerateObject())
            {
                if (dependency.Value.GetProperty("type").GetString() == "Project")
                    continue;
                yield return $"{dependency.Name}/{dependency.Value.GetProperty("resolved").GetString()}";
            }
        }
    }

    private sealed record ManifestEntry(
        string Id,
        string Version,
        string File,
        long Bytes,
        string Sha256,
        string Role);
}
