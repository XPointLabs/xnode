using System.Text.Json;

namespace XNode.ProfileGenerator.Tests;

public sealed class RestoreIsolationTests
{
    [Fact]
    public void SdkAndArchitectureRestoreInputsAreExactlyPinned()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        using var global = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "global.json")));
        var sdk = global.RootElement.GetProperty("sdk");
        Assert.Equal("10.0.301", sdk.GetProperty("version").GetString());
        Assert.Equal("disable", sdk.GetProperty("rollForward").GetString());

        var project = File.ReadAllText(Path.Combine(
            root,
            "src",
            "XNode.ProfileGenerator",
            "XNode.ProfileGenerator.csproj"));
        Assert.Contains("<RuntimeIdentifiers>win-arm64</RuntimeIdentifiers>", project);
        Assert.Contains("<RestoreAdditionalProjectSources>", project);
        Assert.Contains("vendor\\p04\\packages", project);
    }

    [Fact]
    public void OfflineScriptUsesOnlyTemporarySourceIntermediateOutputAndPackageState()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var script = File.ReadAllText(Path.Combine(root, "scripts", "verify-p14c-offline.ps1"));
        Assert.Contains("$sourceRoot", script, StringComparison.Ordinal);
        Assert.Contains("Copy-TrackedSource", script, StringComparison.Ordinal);
        Assert.Contains("packageFolders", script, StringComparison.Ordinal);
        Assert.Contains(".nupkg.metadata", script, StringComparison.Ordinal);
        Assert.Contains("downloadDependencies", script, StringComparison.Ordinal);
        Assert.Contains("Get-RepositoryBuildSnapshot", script, StringComparison.Ordinal);
        Assert.Contains("--no-incremental", script, StringComparison.Ordinal);
        Assert.Contains("10.0.301", script, StringComparison.Ordinal);
        Assert.Contains("10.0.9", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "$tests = Join-Path $repositoryRoot 'tests\\XNode.ProfileGenerator.Tests",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void WholeSolutionHasASeparateCleanCacheRegressionGate()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var scriptPath = Path.Combine(root, "scripts", "verify-solution-clean-restore.ps1");
        Assert.True(File.Exists(scriptPath));
        var script = File.ReadAllText(scriptPath);
        Assert.Contains("XNode.slnx", script, StringComparison.Ordinal);
        Assert.Contains("Copy-TrackedSource", script, StringComparison.Ordinal);
        Assert.Contains("--no-http-cache", script, StringComparison.Ordinal);
        Assert.Contains("--no-incremental", script, StringComparison.Ordinal);
        Assert.Contains("NUGET_PACKAGES", script, StringComparison.Ordinal);
        Assert.Contains("SOLUTION_CLEAN_RESTORE=PASS", script, StringComparison.Ordinal);
    }
}
