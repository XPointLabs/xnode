param(
    [string]$WorkRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactsRoot = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'artifacts\p14c-offline'))
$ownsWorkRoot = [string]::IsNullOrWhiteSpace($WorkRoot)
if ($ownsWorkRoot) {
    $WorkRoot = Join-Path $artifactsRoot ([Guid]::NewGuid().ToString('N'))
}
$WorkRoot = [IO.Path]::GetFullPath($WorkRoot)
if (Test-Path -LiteralPath $WorkRoot) {
    throw 'The offline verification work root must be new and empty.'
}

$packages = Join-Path $WorkRoot 'packages'
$httpCache = Join-Path $WorkRoot 'http-cache'
New-Item -ItemType Directory -Force -Path $packages, $httpCache | Out-Null

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

function Invoke-DotNet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet failed with exit code $LASTEXITCODE."
    }
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

    $config = Join-Path $repositoryRoot 'NuGet.Config'
    $tests = Join-Path $repositoryRoot 'tests\XNode.ProfileGenerator.Tests\XNode.ProfileGenerator.Tests.csproj'
    $generator = Join-Path $repositoryRoot 'src\XNode.ProfileGenerator\XNode.ProfileGenerator.csproj'

    Invoke-DotNet restore $tests --configfile $config --packages $packages `
        --no-http-cache --locked-mode -p:NuGetAudit=false -p:RestoreIgnoreFailedSources=false
    Invoke-DotNet build $tests --no-restore --configuration Release
    Invoke-DotNet test $tests --no-restore --configuration Release

    Invoke-DotNet restore $generator --configfile $config --packages $packages `
        --no-http-cache --locked-mode --runtime win-arm64 `
        -p:NuGetAudit=false -p:RestoreIgnoreFailedSources=false
    Invoke-DotNet build $generator --no-restore --configuration Release --runtime win-arm64

    Write-Output 'P14C_OFFLINE_VERIFICATION=PASS'
    Write-Output "P14C_OFFLINE_PACKAGES=$packages"
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $previousEnvironment[$name],
            'Process')
    }
    if ($ownsWorkRoot -and (Test-Path -LiteralPath $WorkRoot)) {
        $requiredPrefix = $artifactsRoot + [IO.Path]::DirectorySeparatorChar
        if (-not $WorkRoot.StartsWith($requiredPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an offline work root outside the repository artifacts directory.'
        }
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force
    }
}
