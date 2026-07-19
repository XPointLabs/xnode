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

    [Fact]
    public void TrackedSourceCopyExcludesEveryUntrackedBuildInput()
    {
        using var repository = TemporaryGitRepository.Create();
        repository.Write("tracked.txt", "tracked");
        repository.Write("nested/source.cs", "namespace Tracked;");
        repository.Write("vendor/p04/packages/dummy.nupkg", "package");
        repository.Git("add", "tracked.txt", "nested/source.cs", "vendor/p04/packages/dummy.nupkg");

        repository.Write("Directory.Build.props", "<Project />");
        repository.Write("Directory.Build.targets", "<Project />");
        repository.Write("untracked/source.cs", "namespace Untracked;");

        var destination = Path.Combine(repository.Root, "copy");
        var result = RunPowerShell(
            $". '{Quote(HelperScript())}'; " +
            $"Copy-TrackedSource -RepositoryRoot '{Quote(repository.Root)}' " +
            $"-DestinationRoot '{Quote(destination)}'");
        Assert.Equal(0, result.ExitCode);

        var copied = Directory.GetFiles(destination, "*", SearchOption.AllDirectories)
            .Where(path => !path.Contains(
                $"{Path.DirectorySeparatorChar}vendor{Path.DirectorySeparatorChar}p04" +
                $"{Path.DirectorySeparatorChar}packages{Path.DirectorySeparatorChar}",
                StringComparison.OrdinalIgnoreCase))
            .Select(path => Path.GetRelativePath(destination, path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(["nested/source.cs", "tracked.txt"], copied);
        Assert.False(File.Exists(Path.Combine(destination, "Directory.Build.props")));
        Assert.False(File.Exists(Path.Combine(destination, "Directory.Build.targets")));
        Assert.False(File.Exists(Path.Combine(destination, "untracked", "source.cs")));
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

        var result = RunPowerShell(
            $". '{Quote(HelperScript())}'; " +
            $"Assert-CleanWorktree -RepositoryRoot '{Quote(repository.Root)}'");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(
            "Repository worktree must be clean before isolated verification.",
            result.Output,
            StringComparison.Ordinal);
    }

    [Fact]
    public void IsolationHelperNeverEnumeratesUntrackedFiles()
    {
        var helper = File.ReadAllText(HelperScript());
        Assert.Contains("git -C $RepositoryRoot ls-files --cached", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("--others", helper, StringComparison.Ordinal);
    }

    private static string HelperScript() => Path.Combine(
        P04PackagePinTests.RepositoryRoot(),
        "scripts",
        "restore-isolation.ps1");

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

    private sealed record ProcessResult(int ExitCode, string Output);

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
