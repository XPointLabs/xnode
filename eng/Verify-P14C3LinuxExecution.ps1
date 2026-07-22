[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHead,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedTree,
    [ValidateSet('all', 'arm64', 'x64')]
    [string]$Architecture = 'all',
    [string]$EvidenceDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Join-Path $PSScriptRoot '..\scripts') 'restore-isolation.ps1')

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactsRoot = Join-Path ([IO.Path]::GetTempPath()) 'xnode-p14c3-linux-execution'
$workRoot = Join-Path $artifactsRoot ([Guid]::NewGuid().ToString('N'))
$sourceRoot = Join-Path $workRoot 'source'
$packagesRoot = Join-Path $workRoot 'packages'
$httpCache = Join-Path $workRoot 'http-cache'
$publishRoot = Join-Path $workRoot 'publish'
$probeRelative = 'eng/P14C3.Ed25519Probe/Program.cs'
$probeGitBlob = ''
$probeSha256 = ''
if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
    $EvidenceDirectory = Join-Path ([IO.Path]::GetTempPath()) `
        "xnode-p14c3-runtime-evidence-$([Guid]::NewGuid().ToString('N'))"
}
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
$repositoryPrefix = $repositoryRoot.TrimEnd('\') + '\'
if ($EvidenceDirectory.StartsWith(
    $repositoryPrefix,
    [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Runtime evidence must remain outside the Git worktree.'
}

$profiles = [ordered]@{
    arm64 = [ordered]@{
        platform = 'linux/arm64'
        dockerArchitecture = 'arm64'
        processArchitecture = 'arm64'
        image = 'mcr.microsoft.com/dotnet/aspnet@sha256:e3736b0d423db99c6988e1ddf5ea725c14b12579bb120024e5ff7ff204a14080'
        imageId = 'sha256:e3736b0d423db99c6988e1ddf5ea725c14b12579bb120024e5ff7ff204a14080'
        nativeSha256 = '54f416a70e0d982a63e7f2402ff6f2a8666bf0a430404a4205ed8eee1868b9db'
    }
    x64 = [ordered]@{
        platform = 'linux/amd64'
        dockerArchitecture = 'amd64'
        processArchitecture = 'x64'
        image = 'mcr.microsoft.com/dotnet/aspnet@sha256:1f51d2d65ace46d6395e773fb4cfc1c74d36fb4f08e5cf996e7f6961b45e9283'
        imageId = 'sha256:1f51d2d65ace46d6395e773fb4cfc1c74d36fb4f08e5cf996e7f6961b45e9283'
        nativeSha256 = '963416833246938fd6983e4aa96248dbccb2f95b30095c4a94678d6fb903404b'
    }
}

function Invoke-CheckedDotNet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet failed with exit code $LASTEXITCODE."
    }
}

function Invoke-DockerAllowFailure([string[]]$Arguments) {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $output = @(& docker @Arguments 2>$null)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [PSCustomObject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

function Assert-ExactSource {
    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $repositoryRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Linux execution source'
}

function Invoke-Architecture([string]$Name) {
    $profile = $profiles[$Name]
    $imageResult = Invoke-DockerAllowFailure @(
        'image', 'inspect', $profile.image,
        '--format', '{{.Id}}|{{.Os}}|{{.Architecture}}|{{index .RepoDigests 0}}')
    $imageInfo = @($imageResult.Output)
    if ($imageResult.ExitCode -ne 0 -or $imageInfo.Count -ne 1) {
        throw "LINUX-$($Name.ToUpperInvariant())-EXECUTION-BLOCKED: exact local image is absent."
    }
    $fields = $imageInfo[0].Split('|')
    if ($fields.Count -ne 4 -or
        $fields[0] -cne $profile.imageId -or
        $fields[1] -cne 'linux' -or
        $fields[2] -cne $profile.dockerArchitecture -or
        $fields[3] -cne $profile.image) {
        throw "LINUX-$($Name.ToUpperInvariant())-EXECUTION-BLOCKED: image identity mismatch."
    }

    $nonce = [Guid]::NewGuid().ToString('N')
    $containerName = "deep-p14c3-$Name-$nonce"
    $label = "deep.p14c3.owner=$nonce"
    $output = @()
    try {
        $runResult = Invoke-DockerAllowFailure @(
            'run',
            '--rm',
            '--pull', 'never',
            '--platform', $profile.platform,
            '--name', $containerName,
            '--label', $label,
            '--network', 'none',
            '--read-only',
            '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--pids-limit', '64',
            '--memory', '256m',
            '--cpus', '1',
            '--volume', "${publishRoot}:/probe:ro",
            '--workdir', '/probe',
            $profile.image,
            'dotnet', '/probe/P14C3.Ed25519Probe.dll')
        $output = @($runResult.Output)
        if ($runResult.ExitCode -ne 0) {
            throw "Linux $Name Ed25519 probe failed with exit code $($runResult.ExitCode)."
        }
    }
    finally {
        $inspectResult = Invoke-DockerAllowFailure @(
            'container', 'inspect', $containerName,
            '--format', '{{json .Config.Labels}}')
        $labels = @($inspectResult.Output)
        if ($inspectResult.ExitCode -eq 0) {
            if ($labels.Count -ne 1) {
                throw 'Refusing to clean a container without the exact owned nonce.'
            }
            $owner = ($labels[0] | ConvertFrom-Json).PSObject.Properties[
                'deep.p14c3.owner'].Value
            if ($owner -cne $nonce) {
                throw 'Refusing to clean a container without the exact owned nonce.'
            }
            $removeResult = Invoke-DockerAllowFailure @(
                'container', 'rm', '--force', $containerName)
            if ($removeResult.ExitCode -ne 0) {
                throw 'Unable to clean the exact owned P14C3 container.'
            }
        }
    }

    $expectedOutput = @(
        'P14C3_ED25519_PROBE=PASS',
        'OS=linux',
        "ARCH=$($profile.processArchitecture)",
        'NATIVE_FILE=libsodium.so',
        "NATIVE_SHA256=$($profile.nativeSha256)"
    )
    if (($output -join "`n") -cne ($expectedOutput -join "`n")) {
        throw "Linux $Name probe returned unexpected or unsanitized output."
    }

    $receipt = [ordered]@{
        schema = 'xnode-p14c3-linux-ed25519-execution.v1'
        sourceCommit = $ExpectedHead
        sourceTree = $ExpectedTree
        probeProgramGitBlob = $probeGitBlob
        probeProgramSha256 = $probeSha256
        os = 'linux'
        architecture = $profile.processArchitecture
        platform = $profile.platform
        image = $profile.image
        imageId = $profile.imageId
        nativeFile = 'libsodium.so'
        nativeSha256 = $profile.nativeSha256
        result = 'PASS'
    }
    $receiptPath = Join-Path $EvidenceDirectory "p14c3-linux-$Name.json"
    [IO.File]::WriteAllText(
        $receiptPath,
        ($receipt | ConvertTo-Json -Depth 5) + "`n",
        [Text.UTF8Encoding]::new($false))
    Write-Output "P14C3_LINUX_$($Name.ToUpperInvariant())_EXECUTION=PASS"
    Write-Output "P14C3_LINUX_$($Name.ToUpperInvariant())_NATIVE_SHA256=$($profile.nativeSha256)"
}

$environmentNames = @(
    'NUGET_PACKAGES', 'NUGET_HTTP_CACHE_PATH',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    Assert-ExactSdk '10.0.301'
    Assert-ExactSource
    Assert-SafeWorkRootAncestors $workRoot
    New-Item -ItemType Directory -Force -Path `
        $workRoot, $packagesRoot, $httpCache, $EvidenceDirectory | Out-Null
    New-ExactGitSourceSnapshot `
        -RepositoryRoot $repositoryRoot `
        -DestinationRoot $sourceRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree | Out-Null

    $probeGitBlob = @(& git -C $sourceRoot rev-parse "$ExpectedHead`:$probeRelative")[0].Trim()
    if ($LASTEXITCODE -ne 0 -or $probeGitBlob -notmatch '^[0-9a-f]{40,64}$') {
        throw 'Unable to bind the committed probe blob identity.'
    }
    $probeProgram = Join-Path $sourceRoot $probeRelative
    $materializedProbeBlob = @(& git -C $sourceRoot hash-object --no-filters -- $probeProgram)[0].Trim()
    if ($LASTEXITCODE -ne 0 -or $materializedProbeBlob -cne $probeGitBlob) {
        throw 'Materialized probe does not match the committed probe blob.'
    }
    $probeSha256 = (Get-FileHash -LiteralPath $probeProgram -Algorithm SHA256).Hash.ToLowerInvariant()

    $env:NUGET_PACKAGES = $packagesRoot
    $env:NUGET_HTTP_CACHE_PATH = $httpCache
    foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                         'http_proxy', 'https_proxy', 'all_proxy')) {
        [Environment]::SetEnvironmentVariable($name, 'http://127.0.0.1:9', 'Process')
    }
    $env:NO_PROXY = ''
    $env:no_proxy = ''

    $probe = Join-Path $sourceRoot 'eng\P14C3.Ed25519Probe\P14C3.Ed25519Probe.csproj'
    $config = Join-Path $sourceRoot 'scripts\p14c-offline.NuGet.Config'
    $buildIsolation = @(Get-PinnedBuildArguments $sourceRoot)
    Invoke-CheckedDotNet restore $probe @buildIsolation `
        --configfile $config --packages $packagesRoot --no-http-cache `
        --locked-mode -p:NuGetAudit=false -p:RestoreIgnoreFailedSources=false
    Invoke-CheckedDotNet publish $probe @buildIsolation `
        --configuration Release --no-restore --no-self-contained `
        -p:UseAppHost=false --output $publishRoot
    Assert-NoHttpCacheFiles $httpCache
    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $sourceRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Linux materialized snapshot'

    $targets = if ($Architecture -eq 'all') { @('arm64', 'x64') } else { @($Architecture) }
    foreach ($target in $targets) {
        Invoke-Architecture $target
    }
    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $sourceRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Linux materialized snapshot'
    Assert-ExactSource
    Write-Output "P14C3_PROBE_PROGRAM_GIT_BLOB=$probeGitBlob"
    Write-Output "P14C3_PROBE_PROGRAM_SHA256=$probeSha256"
    Write-Output "P14C3_RUNTIME_EVIDENCE=$EvidenceDirectory"
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable(
            $name,
            $previousEnvironment[$name],
            'Process')
    }
    if (Test-Path -LiteralPath $workRoot) {
        Remove-OwnedWorkRoot $workRoot $artifactsRoot
    }
}
