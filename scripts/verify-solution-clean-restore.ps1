param(
    [string]$WorkRoot,
    [string]$ExpectedHead,
    [string]$ExpectedTree
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'restore-isolation.ps1')

Assert-ExactSdk '10.0.301'

$artifactsRoot = [IO.Path]::GetFullPath(
    (Join-Path ([IO.Path]::GetTempPath()) 'xnode-solution-clean'))
$ownsWorkRoot = [string]::IsNullOrWhiteSpace($WorkRoot)
if ($ownsWorkRoot) {
    $WorkRoot = Join-Path $artifactsRoot ([Guid]::NewGuid().ToString('N'))
}
$WorkRoot = [IO.Path]::GetFullPath($WorkRoot)
if (Test-Path -LiteralPath $WorkRoot) {
    throw 'The clean solution work root must be new and empty.'
}
Assert-SafeWorkRootAncestors $WorkRoot
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Assert-NoGitAuthorityEnvironmentOverrides
if ([string]::IsNullOrWhiteSpace($ExpectedHead) -and
    [string]::IsNullOrWhiteSpace($ExpectedTree)) {
    $ExpectedHead = @(& git -C $repositoryRoot rev-parse HEAD)[0].Trim()
    $ExpectedTree = @(& git -C $repositoryRoot rev-parse 'HEAD^{tree}')[0].Trim()
}
elseif ([string]::IsNullOrWhiteSpace($ExpectedHead) -or
    [string]::IsNullOrWhiteSpace($ExpectedTree)) {
    throw 'Solution source HEAD and tree must be supplied together.'
}
Assert-ExactRepositoryAuthority `
    -RepositoryRoot $repositoryRoot `
    -ExpectedHead $ExpectedHead `
    -ExpectedTree $ExpectedTree `
    -Label 'Solution source'

$projectRoots = @(
    & git -C $repositoryRoot ls-files 'src/**/*.csproj' 'tests/**/*.csproj' |
        ForEach-Object { Split-Path -Parent $_ } |
        Sort-Object -Unique
)
if ($LASTEXITCODE -ne 0 -or $projectRoots.Count -eq 0) {
    throw 'Unable to enumerate solution project roots.'
}
$repositorySnapshot = Get-RepositoryBuildSnapshot $repositoryRoot $projectRoots
$sourceRoot = Join-Path $WorkRoot 'source'
$packages = Join-Path $WorkRoot 'packages'
$httpCache = Join-Path $WorkRoot 'http-cache'
$fallbackPackages = Join-Path $WorkRoot 'fallback-packages'
New-Item -ItemType Directory -Force -Path `
    $WorkRoot, $packages, $httpCache, $fallbackPackages | Out-Null
New-ExactGitSourceSnapshot `
    -RepositoryRoot $repositoryRoot `
    -DestinationRoot $sourceRoot `
    -ExpectedHead $ExpectedHead `
    -ExpectedTree $ExpectedTree | Out-Null

if (Test-Path -LiteralPath (Join-Path $sourceRoot 'NuGet.Config')) {
    throw 'The normal whole-solution gate must not inherit the dedicated P14C offline config.'
}

$previousPackages = $env:NUGET_PACKAGES
$previousHttpCache = $env:NUGET_HTTP_CACHE_PATH
$previousFallbackPackages = $env:NUGET_FALLBACK_PACKAGES
try {
    $env:NUGET_PACKAGES = $packages
    $env:NUGET_HTTP_CACHE_PATH = $httpCache
    $env:NUGET_FALLBACK_PACKAGES = $fallbackPackages
    $solution = Join-Path $sourceRoot 'XNode.slnx'
    $config = Join-Path $sourceRoot 'scripts\solution-clean.NuGet.Config'
    $buildIsolation = @(Get-PinnedBuildArguments $sourceRoot)

    Invoke-DotNet restore $solution @buildIsolation --configfile $config `
        --packages $packages --no-http-cache `
        -p:NuGetAudit=false -p:DisableImplicitNuGetFallbackFolder=true
    Invoke-DotNet build $solution @buildIsolation --no-restore --no-incremental `
        --configuration Release

    foreach ($assets in Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Filter 'project.assets.json') {
        Assert-AssetsPackageFoldersUnderRoot $assets.FullName $packages $WorkRoot
    }
    Assert-ArtifactsUnderRoot $sourceRoot $WorkRoot
    $afterSnapshot = Get-RepositoryBuildSnapshot $repositoryRoot $projectRoots
    Assert-SnapshotEqual $repositorySnapshot $afterSnapshot
    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $sourceRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Solution materialized snapshot'

    Write-Output 'SOLUTION_CLEAN_RESTORE=PASS'
    Write-Output "SOLUTION_CLEAN_SOURCE_SHA=$ExpectedHead"
    Write-Output "SOLUTION_CLEAN_SOURCE_TREE=$ExpectedTree"
    Write-Output "SOLUTION_CLEAN_PACKAGES=$packages"
}
finally {
    $env:NUGET_PACKAGES = $previousPackages
    $env:NUGET_HTTP_CACHE_PATH = $previousHttpCache
    $env:NUGET_FALLBACK_PACKAGES = $previousFallbackPackages
    $afterSnapshot = Get-RepositoryBuildSnapshot $repositoryRoot $projectRoots
    Assert-SnapshotEqual $repositorySnapshot $afterSnapshot
    Assert-RepositoryAssetsUsable $repositoryRoot $projectRoots
    if ($ownsWorkRoot -and (Test-Path -LiteralPath $WorkRoot)) {
        Remove-OwnedWorkRoot $WorkRoot $artifactsRoot
    }
}
