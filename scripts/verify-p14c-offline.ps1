param(
    [string]$WorkRoot,
    [string]$ExpectedHead,
    [string]$ExpectedTree
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'restore-isolation.ps1')

$requiredSdk = '10.0.301'
$runtimePackVersion = '10.0.9'
Assert-ExactSdk $requiredSdk

$artifactsRoot = [IO.Path]::GetFullPath(
    (Join-Path ([IO.Path]::GetTempPath()) 'xnode-p14c-offline'))
$ownsWorkRoot = [string]::IsNullOrWhiteSpace($WorkRoot)
if ($ownsWorkRoot) {
    $WorkRoot = Join-Path $artifactsRoot ([Guid]::NewGuid().ToString('N'))
}
$WorkRoot = [IO.Path]::GetFullPath($WorkRoot)
if (Test-Path -LiteralPath $WorkRoot) {
    throw 'The offline verification work root must be new and empty.'
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
    throw 'Offline source HEAD and tree must be supplied together.'
}
Assert-ExactRepositoryAuthority `
    -RepositoryRoot $repositoryRoot `
    -ExpectedHead $ExpectedHead `
    -ExpectedTree $ExpectedTree `
    -Label 'Offline source'

$projectRoots = @(
    'src\XNode.ProfileGenerator',
    'tests\XNode.ProfileGenerator.Tests'
)
$repositorySnapshot = Get-RepositoryBuildSnapshot $repositoryRoot $projectRoots

$sourceRoot = Join-Path $WorkRoot 'source'
$packages = Join-Path $WorkRoot 'packages'
$httpCache = Join-Path $WorkRoot 'http-cache'
New-Item -ItemType Directory -Force -Path $WorkRoot, $packages, $httpCache | Out-Null
New-ExactGitSourceSnapshot `
    -RepositoryRoot $repositoryRoot `
    -DestinationRoot $sourceRoot `
    -ExpectedHead $ExpectedHead `
    -ExpectedTree $ExpectedTree | Out-Null

$environmentNames = @(
    'NUGET_PACKAGES',
    'NUGET_HTTP_CACHE_PATH',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'ALL_PROXY',
    'NO_PROXY',
    'http_proxy',
    'https_proxy',
    'all_proxy',
    'no_proxy'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    $deadProxy = 'http://127.0.0.1:9'
    $env:NUGET_PACKAGES = $packages
    $env:NUGET_HTTP_CACHE_PATH = $httpCache
    $env:HTTP_PROXY = $deadProxy
    $env:HTTPS_PROXY = $deadProxy
    $env:ALL_PROXY = $deadProxy
    $env:NO_PROXY = ''
    $env:http_proxy = $deadProxy
    $env:https_proxy = $deadProxy
    $env:all_proxy = $deadProxy
    $env:no_proxy = ''

    $config = Join-Path $sourceRoot 'scripts\p14c-offline.NuGet.Config'
    $tests = Join-Path $sourceRoot 'tests\XNode.ProfileGenerator.Tests\XNode.ProfileGenerator.Tests.csproj'
    $generator = Join-Path $sourceRoot 'src\XNode.ProfileGenerator\XNode.ProfileGenerator.csproj'
    $manifest = Join-Path $sourceRoot 'vendor\p04\offline-closure-manifest.json'
    $vendorSource = Join-Path $sourceRoot 'vendor\p04\packages'
    $buildIsolation = @(Get-PinnedBuildArguments $sourceRoot)

    Invoke-DotNet restore $tests @buildIsolation --configfile $config --packages $packages `
        --no-http-cache --locked-mode -p:NuGetAudit=false -p:RestoreIgnoreFailedSources=false
    Assert-AssetsPackageFolder `
        (Join-Path $sourceRoot 'tests\XNode.ProfileGenerator.Tests\obj\project.assets.json') `
        $packages
    Assert-AssetsPackageFolder `
        (Join-Path $sourceRoot 'src\XNode.ProfileGenerator\obj\project.assets.json') `
        $packages

    Invoke-DotNet build $tests @buildIsolation --no-restore --no-incremental `
        --configuration Release
    Invoke-DotNet test $tests @buildIsolation --no-restore --no-build --configuration Release

    Invoke-DotNet restore $generator @buildIsolation --configfile $config --packages $packages `
        --no-http-cache --locked-mode --runtime win-arm64 `
        -p:NuGetAudit=false -p:RestoreIgnoreFailedSources=false
    Invoke-DotNet build $generator @buildIsolation --no-restore --no-incremental `
        --configuration Release --runtime win-arm64

    $generatorAssets = Join-Path $sourceRoot 'src\XNode.ProfileGenerator\obj\project.assets.json'
    Assert-AssetsPackageFolder $generatorAssets $packages
    Assert-DownloadDependencies $generatorAssets $manifest $runtimePackVersion
    Assert-MetadataSources $packages $vendorSource 23
    Assert-NoHttpCacheFiles $httpCache
    Assert-ArtifactsUnderRoot $sourceRoot $WorkRoot

    # These checks prove packageFolders, every .nupkg.metadata source, and
    # downloadDependencies are isolated and vendor-only.
    $afterSnapshot = Get-RepositoryBuildSnapshot $repositoryRoot $projectRoots
    Assert-SnapshotEqual $repositorySnapshot $afterSnapshot
    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $sourceRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Offline materialized snapshot'

    Write-Output 'P14C_OFFLINE_VERIFICATION=PASS'
    Write-Output "P14C_OFFLINE_SOURCE_SHA=$ExpectedHead"
    Write-Output "P14C_OFFLINE_SOURCE_TREE=$ExpectedTree"
    Write-Output "P14C_OFFLINE_PACKAGES=$packages"
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $previousEnvironment[$name],
            'Process')
    }
    $afterSnapshot = Get-RepositoryBuildSnapshot $repositoryRoot $projectRoots
    Assert-SnapshotEqual $repositorySnapshot $afterSnapshot
    Assert-RepositoryAssetsUsable $repositoryRoot $projectRoots
    if ($ownsWorkRoot -and (Test-Path -LiteralPath $WorkRoot)) {
        Remove-OwnedWorkRoot $WorkRoot $artifactsRoot
    }
}
