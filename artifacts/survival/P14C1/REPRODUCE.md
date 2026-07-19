# P14C1 reproduction

All source verification targets the accepted source commit, not the later
evidence-carrier commit.

From a repository clone:

```powershell
$sourceCommit = 'eff452368fa4cb1324c5b3c8ee06e2f10e96b835'
git -c core.autocrlf=false worktree add ../p14c1-source $sourceCommit
Set-Location ../p14c1-source
git status --porcelain=v1 --untracked-files=all
```

The checkout option preserves the source tree bytes used by the pinned fixture
hashes. The status command must produce no output.

Run the isolated restore/build/test gates:

```powershell
$matrixRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'xnode-p14c1-matrix-' + [Guid]::NewGuid().ToString('N'))
powershell -NoProfile -NonInteractive -File scripts/verify-p14c-offline.ps1
powershell -NoProfile -NonInteractive `
    -File scripts/verify-solution-clean-restore.ps1 `
    -WorkRoot $matrixRoot
```

Expected sentinels:

```text
P14C_OFFLINE_VERIFICATION=PASS
SOLUTION_CLEAN_RESTORE=PASS
```

The explicit work root retains the clean-solution gate's isolated package
cache. Restore the fresh source worktree from that cache with network access
disabled, then run the full test matrix:

```powershell
$environmentNames = @(
    'NUGET_PACKAGES',
    'NUGET_HTTP_CACHE_PATH',
    'NUGET_FALLBACK_PACKAGES'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] =
        [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $sourceRoot = [IO.Path]::GetFullPath($PWD.Path)
    $retainedPackages = Join-Path $matrixRoot 'packages'
    $packages = Join-Path $matrixRoot 'matrix-packages'
    $httpCache = Join-Path $matrixRoot 'matrix-http-cache'
    $fallbackPackages = Join-Path $matrixRoot 'matrix-fallback-packages'
    New-Item -ItemType Directory -Force -Path `
        $packages, $httpCache, $fallbackPackages | Out-Null

    $escapedSource =
        [Security.SecurityElement]::Escape($retainedPackages)
    $matrixConfig = Join-Path $matrixRoot 'matrix.NuGet.Config'
    $matrixConfigText = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="retained-clean-gate-cache" value="$escapedSource" />
  </packageSources>
  <packageSourceMapping>
    <packageSource key="retained-clean-gate-cache">
      <package pattern="*" />
    </packageSource>
  </packageSourceMapping>
</configuration>
"@
    [IO.File]::WriteAllText(
        $matrixConfig,
        $matrixConfigText,
        [Text.UTF8Encoding]::new($false))

    $env:NUGET_PACKAGES = $packages
    $env:NUGET_HTTP_CACHE_PATH = $httpCache
    $env:NUGET_FALLBACK_PACKAGES = $fallbackPackages

    $buildIsolation = @(
        '-noAutoResponse',
        "-p:DirectoryBuildPropsPath=$(Join-Path $sourceRoot 'Directory.Build.props')",
        "-p:DirectoryBuildTargetsPath=$(Join-Path $sourceRoot 'Directory.Build.targets')",
        "-p:DirectorySolutionPropsPath=$(Join-Path $sourceRoot 'Directory.Solution.props')",
        "-p:DirectorySolutionTargetsPath=$(Join-Path $sourceRoot 'Directory.Solution.targets')",
        "-p:DirectoryPackagesPropsPath=$(Join-Path $sourceRoot 'Directory.Packages.props')"
    )
    dotnet restore XNode.slnx @buildIsolation `
        --configfile $matrixConfig `
        --packages $packages `
        --no-http-cache `
        -p:NuGetAudit=false `
        -p:DisableImplicitNuGetFallbackFolder=true `
        -p:RestoreIgnoreFailedSources=false
    if ($LASTEXITCODE -ne 0) {
        throw 'The deterministic matrix restore failed.'
    }

    dotnet test XNode.slnx --configuration Debug --no-restore
    if ($LASTEXITCODE -ne 0) {
        throw 'The Debug matrix failed.'
    }
    dotnet test XNode.slnx --configuration Release --no-restore
    if ($LASTEXITCODE -ne 0) {
        throw 'The Release matrix failed.'
    }
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $previousEnvironment[$name],
            'Process')
    }
    if (Test-Path -LiteralPath $matrixRoot) {
        Remove-Item -LiteralPath $matrixRoot -Recurse -Force
    }
}
```

Expected for each configuration:

- `XNode.ProfileGenerator.Tests`: 41 passed
- `XNode.Tests`: 48 passed
- `XNode.IntegrationTests`: 17 passed
- total: 106 passed, 0 failed, 0 skipped

Verify runtime isolation:

```powershell
$baseCommit = '2980c15c1901d7569f5ba025912ab019c1058407'
git diff --exit-code $baseCommit $sourceCommit -- src/XNode src/XNode.Core src/XNode.Registry src/XNode.Transport.Vless
rg -n -F -e Microsoft.Extensions -e System.Net -e HttpClient -e System.IO.File -e IServiceCollection -e WebApplication -e PrivateKey -e RecoveryPhrase src/XNode.ProfileGenerator -g *.cs
rg -n -F XNode.ProfileGenerator src -g *.csproj -g !src/XNode.ProfileGenerator/**
```

Expected exits:

- runtime diff: `0`, with no output
- private production API source scan: `1`, meaning no matches
- runtime project-reference scan: `1`, meaning no matches

Verify the source tree identity:

```powershell
git rev-parse "$sourceCommit^{tree}"
```

Expected:

```text
ee7a54e9eb0bc4c0803b9508627355eec75f0405
```

The package hashes and byte sizes to compare with
`vendor/p04/offline-closure-manifest.json` are recorded in
`closure-packages.json`.
