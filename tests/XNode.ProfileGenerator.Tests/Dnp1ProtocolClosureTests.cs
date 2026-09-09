using System.Diagnostics;
using System.IO.Compression;
using System.Xml.Linq;

namespace XNode.ProfileGenerator.Tests;

public sealed class Dnp1ProtocolClosureTests
{
    private const string Version = "0.5.0-survival.9a7eaed";

    [Fact]
    public void ExactThreeGatePassesForThePinnedRepository()
    {
        var result = RunGate(P04PackagePinTests.RepositoryRoot());

        Assert.Equal(0, result.ExitCode);
        Assert.Contains(
            "DNP1 exact-three protocol closure gate PASS",
            result.Output,
            StringComparison.Ordinal);
    }

    [Fact]
    public void VendoredNuspecsHaveOnlyTheExactAllowedDependencyGraph()
    {
        var packageRoot = Path.Combine(
            P04PackagePinTests.RepositoryRoot(),
            "vendor",
            "dnp1-survival-9a7eaed",
            "packages");
        var expected = new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["Deep.Protocol"] = ["Sodium.Core=[1.4.1]"],
            ["Deep.Protocol.MembershipRoutes"] =
                [$"Deep.Protocol=[{Version}]"],
            ["Deep.Protocol.ProfileCarrier"] =
            [
                $"Deep.Protocol=[{Version}]",
                "libsodium=[1.0.22]",
                "Sodium.Core=[1.4.1]"
            ]
        };

        var packages = Directory.GetFiles(packageRoot, "*.nupkg");
        Assert.Equal(3, packages.Length);
        foreach (var package in packages)
        {
            using var archive = ZipFile.OpenRead(package);
            var nuspecEntry = Assert.Single(
                archive.Entries,
                entry => entry.FullName.EndsWith(
                    ".nuspec",
                    StringComparison.OrdinalIgnoreCase));
            using var stream = nuspecEntry.Open();
            var document = XDocument.Load(stream, LoadOptions.None);
            var metadata = Assert.Single(document.Root!.Elements(),
                element => element.Name.LocalName == "metadata");
            var id = Assert.Single(metadata.Elements(),
                element => element.Name.LocalName == "id").Value;
            var dependencies = metadata.Descendants()
                .Where(element => element.Name.LocalName == "dependency")
                .Select(element =>
                    $"{element.Attribute("id")!.Value}={element.Attribute("version")!.Value}")
                .Order(StringComparer.Ordinal)
                .ToArray();

            Assert.True(expected.TryGetValue(id, out var wanted),
                $"Unexpected protocol package: {id}");
            Assert.Equal(wanted.Order(StringComparer.Ordinal), dependencies);
            Assert.All(dependencies, dependency =>
                Assert.Matches(@"^[^=]+=\[[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\]$", dependency));
        }
    }

    [Fact]
    public void GateFailsClosedForAnExpandedLegacyPackageInventory()
    {
        using var fixture = ClosureFixture.Create();
        var packages = Path.Combine(
            fixture.Root,
            "vendor",
            "dnp1-survival-9a7eaed",
            "packages");
        File.Copy(
            Path.Combine(packages, $"Deep.Protocol.{Version}.nupkg"),
            Path.Combine(packages, $"Deep.Protocol.Abstractions.{Version}.nupkg"));

        var result = RunGate(fixture.Root);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("inventory is not exact-three", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void GateFailsClosedForPackageByteMutation()
    {
        using var fixture = ClosureFixture.Create();
        var package = Path.Combine(
            fixture.Root,
            "vendor",
            "dnp1-survival-9a7eaed",
            "packages",
            $"Deep.Protocol.ProfileCarrier.{Version}.nupkg");
        using (var stream = new FileStream(package, FileMode.Append, FileAccess.Write, FileShare.None))
            stream.WriteByte(0);

        var result = RunGate(fixture.Root);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("byte length differs", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void GateFailsClosedForAStaleActivePin()
    {
        using var fixture = ClosureFixture.Create();
        var props = Path.Combine(
            fixture.Root,
            "Directory.Packages.props");
        File.WriteAllText(
            props,
            File.ReadAllText(props).Replace(
                Version,
                "0.4.0-survival.e570512",
                StringComparison.Ordinal));

        var result = RunGate(fixture.Root);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("central DNP1 version differs", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void GateFailsClosedWhenProtocolIdsCanResolveFromASecondSource()
    {
        using var fixture = ClosureFixture.Create();
        var config = Path.Combine(fixture.Root, "eng", "dnp1-survival.NuGet.Config");
        File.WriteAllText(
            config,
            File.ReadAllText(config).Replace(
                "<add key=\"nuget.org\"",
                "<add key=\"ambiguous-protocol\" value=\"../vendor/production\" />\n    <add key=\"nuget.org\"",
                StringComparison.Ordinal));

        var result = RunGate(fixture.Root);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("local NuGet source differs", result.Output, StringComparison.Ordinal);
    }

    [Fact]
    public void GateFailsClosedWhenNugetOrgAlsoMapsProtocolIds()
    {
        using var fixture = ClosureFixture.Create();
        var config = Path.Combine(fixture.Root, "eng", "dnp1-survival.NuGet.Config");
        File.WriteAllText(
            config,
            File.ReadAllText(config).Replace(
                "<package pattern=\"Microsoft.*\" />",
                "<package pattern=\"Deep.Protocol.*\" />\n      <package pattern=\"Microsoft.*\" />",
                StringComparison.Ordinal));

        var result = RunGate(fixture.Root);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("mapped outside the intended local feed", result.Output, StringComparison.Ordinal);
    }

    private static ProcessResult RunGate(string repositoryRoot)
    {
        var script = Path.Combine(
            P04PackagePinTests.RepositoryRoot(),
            "eng",
            "Verify-Dnp1ProtocolClosure.ps1");
        var startInfo = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-File");
        startInfo.ArgumentList.Add(script);
        startInfo.ArgumentList.Add("-RepositoryRoot");
        startInfo.ArgumentList.Add(repositoryRoot);
        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException("Unable to start the DNP1 closure gate.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ProcessResult(process.ExitCode, output);
    }

    private sealed record ProcessResult(int ExitCode, string Output);

    private sealed class ClosureFixture : IDisposable
    {
        private ClosureFixture(string root) => Root = root;

        public string Root { get; }

        public static ClosureFixture Create()
        {
            var source = P04PackagePinTests.RepositoryRoot();
            var fixture = new ClosureFixture(Path.Combine(
                Path.GetTempPath(),
                $"xnode-dnp1-closure-{Guid.NewGuid():N}"));
            foreach (var relative in new[]
            {
                "vendor/dnp1-survival-9a7eaed/package-provenance.json",
                $"vendor/dnp1-survival-9a7eaed/packages/Deep.Protocol.{Version}.nupkg",
                $"vendor/dnp1-survival-9a7eaed/packages/Deep.Protocol.MembershipRoutes.{Version}.nupkg",
                $"vendor/dnp1-survival-9a7eaed/packages/Deep.Protocol.ProfileCarrier.{Version}.nupkg",
                "Directory.Packages.props",
                "src/XNode.ProfileGenerator/XNode.ProfileGenerator.csproj",
                "src/XNode.ProfileGenerator/packages.lock.json",
                "tests/XNode.ProfileGenerator.Tests/packages.lock.json",
                "eng/dnp1-survival.NuGet.Config"
            })
            {
                var platformRelative = relative.Replace('/', Path.DirectorySeparatorChar);
                var destination = Path.Combine(fixture.Root, platformRelative);
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.Copy(Path.Combine(source, platformRelative), destination);
            }
            return fixture;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }
}
