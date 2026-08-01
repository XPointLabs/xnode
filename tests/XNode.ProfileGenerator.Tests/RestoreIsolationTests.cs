using System.Diagnostics;
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
        Assert.Contains("<RestoreConfigFile>", project);
        Assert.Contains("eng\\survival-beta.NuGet.Config", project);
    }

    [Fact]
    public void OfflineScriptUsesOnlyTemporarySourceIntermediateOutputAndPackageState()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var script = File.ReadAllText(Path.Combine(root, "scripts", "verify-p14c-offline.ps1"));
        Assert.Contains("$sourceRoot", script, StringComparison.Ordinal);
        Assert.Contains("New-ExactGitSourceSnapshot", script, StringComparison.Ordinal);
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
        Assert.Contains("New-ExactGitSourceSnapshot", script, StringComparison.Ordinal);
        Assert.Contains("--no-http-cache", script, StringComparison.Ordinal);
        Assert.Contains("--no-incremental", script, StringComparison.Ordinal);
        Assert.Contains("NUGET_PACKAGES", script, StringComparison.Ordinal);
        Assert.Contains("SOLUTION_CLEAN_RESTORE=PASS", script, StringComparison.Ordinal);
    }

    [Fact]
    public void ExactSnapshotUsesCommittedBytesAndIndependentObjects()
    {
        using var repository = TemporaryGitRepository.Create();
        repository.Write("tracked.txt", "tracked");
        repository.Write("nested/source.cs", "namespace Tracked;");
        repository.Write("vendor/p04/packages/dummy.nupkg", "package");
        repository.Git("add", "tracked.txt", "nested/source.cs", "vendor/p04/packages/dummy.nupkg");
        repository.Git(
            "-c", "user.name=P14C Test", "-c", "user.email=p14c@example.invalid",
            "commit", "-m", "fixture");
        var head = RunGit(repository.Root, "rev-parse", "HEAD").Output.Trim();
        var tree = RunGit(repository.Root, "rev-parse", "HEAD^{tree}").Output.Trim();
        using var destinationParent = TemporaryDirectory.Create();
        var destination = Path.Combine(destinationParent.Root, "snapshot");
        var result = RunPowerShell(
            $". '{Quote(HelperScript())}'; " +
            $"New-ExactGitSourceSnapshot -RepositoryRoot '{Quote(repository.Root)}' " +
            $"-DestinationRoot '{Quote(destination)}' -ExpectedHead '{head}' " +
            $"-ExpectedTree '{tree}'");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("tracked", File.ReadAllText(Path.Combine(destination, "tracked.txt")));
        Assert.Equal(
            "package",
            File.ReadAllText(Path.Combine(
                destination,
                "vendor",
                "p04",
                "packages",
                "dummy.nupkg")));
        Assert.False(File.Exists(Path.Combine(
            destination,
            ".git",
            "objects",
            "info",
            "alternates")));
        Assert.Empty(RunGit(destination, "remote").Output.Trim());
    }

    [Fact]
    public void DirtyWorktreePreflightRejectsUntrackedBuildInputs()
    {
        using var repository = TemporaryGitRepository.Create();
        repository.Write("tracked.txt", "tracked");
        repository.Git("add", "tracked.txt");
        repository.Git(
            "-c", "user.name=P14C Test", "-c", "user.email=p14c@example.invalid",
            "commit", "-m", "fixture");
        repository.Write("Directory.Build.props", "<Project />");

        var head = RunGit(repository.Root, "rev-parse", "HEAD").Output.Trim();
        var tree = RunGit(repository.Root, "rev-parse", "HEAD^{tree}").Output.Trim();

        var result = RunPowerShell(
            $". '{Quote(HelperScript())}'; " +
            $"Assert-ExactRepositoryAuthority -RepositoryRoot '{Quote(repository.Root)}' " +
            $"-ExpectedHead '{head}' -ExpectedTree '{tree}'");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(
            "worktree must be clean",
            result.Output,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsolationHelperUsesDetachedLocalObjectSnapshot()
    {
        var helper = File.ReadAllText(HelperScript());
        Assert.Contains("--no-hardlinks", helper, StringComparison.Ordinal);
        Assert.Contains("--no-checkout", helper, StringComparison.Ordinal);
        Assert.Contains("GIT_ALLOW_PROTOCOL", helper, StringComparison.Ordinal);
        Assert.Contains("hash-object --no-filters", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("Copy-TrackedSource", helper, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--skip-worktree")]
    [InlineData("--assume-unchanged")]
    public void ExactAuthorityRejectsHiddenIndexMutation(string flag)
    {
        using var repository = TemporaryGitRepository.Create();
        repository.Write("tracked.txt", "tracked");
        repository.Git("add", "tracked.txt");
        repository.Git(
            "-c", "user.name=P14C Test", "-c", "user.email=p14c@example.invalid",
            "commit", "-m", "fixture");
        var head = RunGit(repository.Root, "rev-parse", "HEAD").Output.Trim();
        var tree = RunGit(repository.Root, "rev-parse", "HEAD^{tree}").Output.Trim();
        repository.Git("update-index", flag, "--", "tracked.txt");
        repository.Write("tracked.txt", "hidden mutation");
        Assert.Empty(GitStatus(repository.Root));

        var result = RunPowerShell(
            $". '{Quote(HelperScript())}'; " +
            $"Assert-ExactRepositoryAuthority -RepositoryRoot '{Quote(repository.Root)}' " +
            $"-ExpectedHead '{head}' -ExpectedTree '{tree}'");

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("special index flags", result.Output, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildDiscoveryAnchorsAreTrackedAndNeutral()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var xmlAnchors = new[]
        {
            "Directory.Build.props",
            "Directory.Build.targets",
            "Directory.Solution.props",
            "Directory.Solution.targets",
            "Directory.Packages.props"
        };
        foreach (var relativePath in xmlAnchors)
        {
            var path = Path.Combine(root, relativePath);
            Assert.True(File.Exists(path), $"Missing build-discovery anchor: {relativePath}");
            Assert.Equal("<Project />", File.ReadAllText(path).Trim());
        }

        var response = Path.Combine(root, "Directory.Build.rsp");
        Assert.True(File.Exists(response), "Missing Directory.Build.rsp anchor.");
        Assert.StartsWith("#", File.ReadAllText(response).Trim(), StringComparison.Ordinal);

        if (IsGitRepository(root))
        {
            var tracked = TrackedFiles(root);
            Assert.All(xmlAnchors.Append("Directory.Build.rsp"), path => Assert.Contains(path, tracked));
        }
    }

    [Fact]
    public void BothGatesPinEveryBuildAndNuGetDiscoveryInput()
    {
        var root = P04PackagePinTests.RepositoryRoot();
        var helper = File.ReadAllText(HelperScript());
        Assert.Contains("-noAutoResponse", helper, StringComparison.Ordinal);
        Assert.Contains("DirectoryBuildPropsPath", helper, StringComparison.Ordinal);
        Assert.Contains("DirectoryBuildTargetsPath", helper, StringComparison.Ordinal);
        Assert.Contains("DirectorySolutionPropsPath", helper, StringComparison.Ordinal);
        Assert.Contains("DirectorySolutionTargetsPath", helper, StringComparison.Ordinal);
        Assert.Contains("DirectoryPackagesPropsPath", helper, StringComparison.Ordinal);

        foreach (var scriptName in new[]
                 {
                     "verify-p14c-offline.ps1",
                     "verify-solution-clean-restore.ps1"
                 })
        {
            var script = File.ReadAllText(Path.Combine(root, "scripts", scriptName));
            Assert.Contains("Assert-SafeWorkRootAncestors", script, StringComparison.Ordinal);
            Assert.Contains("Get-PinnedBuildArguments", script, StringComparison.Ordinal);
            Assert.Contains("--configfile", script, StringComparison.Ordinal);
            Assert.Contains("[IO.Path]::GetTempPath()", script, StringComparison.Ordinal);
            Assert.DoesNotContain(
                "Join-Path $repositoryRoot 'artifacts",
                script,
                StringComparison.Ordinal);
        }

        Assert.True(File.Exists(Path.Combine(
            root,
            "scripts",
            "solution-clean.NuGet.Config")));
    }

    [Theory]
    [InlineData("Directory.Build.props")]
    [InlineData("Directory.Build.targets")]
    [InlineData("Directory.Build.rsp")]
    [InlineData("Directory.Solution.props")]
    [InlineData("Directory.Solution.targets")]
    [InlineData("Directory.Packages.props")]
    [InlineData("NuGet.Config")]
    public void UserWorkRootRejectsMaliciousAncestorDiscoveryFile(string fileName)
    {
        using var directory = TemporaryDirectory.Create();
        var ancestor = Path.Combine(directory.Root, "ancestor");
        Directory.CreateDirectory(ancestor);
        File.WriteAllText(Path.Combine(ancestor, fileName), "malicious");
        var workRoot = Path.Combine(ancestor, "child", "work");

        foreach (var gate in GateScripts())
        {
            var result = RunPowerShell(
                $"& '{Quote(gate)}' -WorkRoot '{Quote(workRoot)}'");
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains(
                "Unsafe build customization file found above the verification work root.",
                result.Output,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void IgnoredRepositoryArtifactCannotBecomeAWorkRootAncestor()
    {
        var repositoryRoot = P04PackagePinTests.RepositoryRoot();
        var attackRoot = Path.Combine(
            repositoryRoot,
            "artifacts",
            $"p14c-c5-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(attackRoot);
            File.WriteAllText(Path.Combine(attackRoot, "Directory.Build.props"), "<Project />");
            File.WriteAllText(Path.Combine(attackRoot, "Directory.Build.targets"), "<Project />");
            File.WriteAllText(Path.Combine(attackRoot, "Directory.Build.rsp"), "-property:Injected=true");
            var workRoot = Path.Combine(attackRoot, "work");

            if (IsGitRepository(repositoryRoot))
            {
                Assert.DoesNotContain(
                    "artifacts/",
                    GitStatus(repositoryRoot),
                    StringComparison.OrdinalIgnoreCase);
            }
            foreach (var gate in GateScripts())
            {
                var result = RunPowerShell(
                    $"& '{Quote(gate)}' -WorkRoot '{Quote(workRoot)}'");
                Assert.NotEqual(0, result.ExitCode);
                Assert.Contains(
                    "Unsafe build customization file found above the verification work root.",
                    result.Output,
                    StringComparison.Ordinal);
            }
        }
        finally
        {
            if (Directory.Exists(attackRoot))
                Directory.Delete(attackRoot, recursive: true);
        }
    }

    private static string HelperScript() => Path.Combine(
        P04PackagePinTests.RepositoryRoot(),
        "scripts",
        "restore-isolation.ps1");

    private static IEnumerable<string> GateScripts()
    {
        var scripts = Path.Combine(P04PackagePinTests.RepositoryRoot(), "scripts");
        yield return Path.Combine(scripts, "verify-p14c-offline.ps1");
        yield return Path.Combine(scripts, "verify-solution-clean-restore.ps1");
    }

    private static ProcessResult RunPowerShell(string command)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -Command \"& {{ {command} }}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException("Unable to start PowerShell.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ProcessResult(process.ExitCode, output);
    }

    private static string Quote(string value) => value.Replace("'", "''", StringComparison.Ordinal);

    private static IReadOnlySet<string> TrackedFiles(string repositoryRoot)
    {
        var result = RunGit(repositoryRoot, "ls-files", "--cached");
        Assert.Equal(0, result.ExitCode);
        return result.Output
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.Ordinal);
    }

    private static bool IsGitRepository(string repositoryRoot)
    {
        var result = RunGit(repositoryRoot, "rev-parse", "--is-inside-work-tree");
        return result.ExitCode == 0 &&
            result.Output.Trim().Equals("true", StringComparison.OrdinalIgnoreCase);
    }

    private static string GitStatus(string repositoryRoot)
    {
        var result = RunGit(repositoryRoot, "status", "--porcelain=v1", "--untracked-files=all");
        Assert.Equal(0, result.ExitCode);
        return result.Output.Replace('\\', '/');
    }

    private static ProcessResult RunGit(string repositoryRoot, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "git.exe",
            WorkingDirectory = repositoryRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-C");
        startInfo.ArgumentList.Add(repositoryRoot);
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo) ??
            throw new InvalidOperationException("Unable to start git.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ProcessResult(process.ExitCode, output);
    }

    private sealed record ProcessResult(int ExitCode, string Output);

    private sealed class TemporaryDirectory : IDisposable
    {
        private TemporaryDirectory(string root)
        {
            Root = root;
            Directory.CreateDirectory(Root);
        }

        public string Root { get; }

        public static TemporaryDirectory Create() =>
            new(Path.Combine(Path.GetTempPath(), $"p14c-parent-{Guid.NewGuid():N}"));

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }

    private sealed class TemporaryGitRepository : IDisposable
    {
        private TemporaryGitRepository(string root)
        {
            Root = root;
            Directory.CreateDirectory(Root);
            Git("init", "--quiet");
            Directory.CreateDirectory(Path.Combine(Root, "vendor", "p04", "packages"));
        }

        public string Root { get; }

        public static TemporaryGitRepository Create() =>
            new(Path.Combine(Path.GetTempPath(), $"p14c-git-{Guid.NewGuid():N}"));

        public void Write(string relativePath, string content)
        {
            var path = Path.Combine(Root, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, content);
        }

        public void Git(params string[] arguments)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "git.exe",
                WorkingDirectory = Root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("-C");
            startInfo.ArgumentList.Add(Root);
            foreach (var argument in arguments)
                startInfo.ArgumentList.Add(argument);
            using var process = Process.Start(startInfo) ??
                throw new InvalidOperationException("Unable to start git.");
            process.WaitForExit();
            if (process.ExitCode != 0)
                throw new InvalidOperationException(process.StandardError.ReadToEnd());
        }

        public void Dispose()
        {
            if (!Directory.Exists(Root))
                return;
            foreach (var directory in Directory.EnumerateDirectories(
                         Root,
                         "*",
                         SearchOption.AllDirectories)
                     .Select(static path => new DirectoryInfo(path))
                     .Where(static value => value.Attributes.HasFlag(FileAttributes.ReparsePoint))
                     .OrderByDescending(static value => value.FullName.Length))
                directory.Delete();
            foreach (var file in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
                File.SetAttributes(file, FileAttributes.Normal);
            Directory.Delete(Root, recursive: true);
        }
    }
}
