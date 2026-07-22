[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verify = Join-Path $PSScriptRoot 'Verify-P14C3Package.ps1'
$normalized = Join-Path $PSScriptRoot 'Get-P14C3ProfileCarrierNormalizedIdentity.ps1'
$version = '0.2.0-p14.69a712a'
$packageName = "Deep.Protocol.ProfileCarrier.$version.nupkg"
$testRoot = Join-Path ([IO.Path]::GetTempPath()) `
    "xnode-p14c3-package-gate-$([Guid]::NewGuid().ToString('N'))"

function New-Fixture([string]$Name) {
    $root = Join-Path $testRoot $Name
    foreach ($relative in @(
        'eng',
        'eng\P14C3.Ed25519Probe',
        'src\XNode.ProfileGenerator',
        'tests\XNode.ProfileGenerator.Tests',
        'vendor\p04\packages'
    )) {
        New-Item -ItemType Directory -Force -Path (Join-Path $root $relative) | Out-Null
    }
    foreach ($relative in @(
        'eng\Get-P14C3ProfileCarrierNormalizedIdentity.ps1',
        'eng\P14C3.Ed25519Probe\P14C3.Ed25519Probe.csproj',
        'eng\P14C3.Ed25519Probe\packages.lock.json',
        'src\XNode.ProfileGenerator\XNode.ProfileGenerator.csproj',
        'src\XNode.ProfileGenerator\packages.lock.json',
        'tests\XNode.ProfileGenerator.Tests\packages.lock.json',
        'vendor\p04\offline-closure-manifest.json',
        'vendor\p04\package-manifest.json',
        'vendor\p04\profile-carrier-manifest.json',
        "vendor\p04\packages\$packageName"
    )) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $relative) `
            -Destination (Join-Path $root $relative)
    }
    return $root
}

function Assert-Rejected([scriptblock]$Action, [string]$Label) {
    $rejected = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "$Label was accepted by the P14C3 gate."
    }
    Write-Output "PASS reject-$Label"
}

function Write-Utf8NoBom([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

try {
    & $verify -RepositoryRoot $repositoryRoot | Out-Null

    $pathDrift = New-Fixture 'path-drift'
    $outside = Join-Path $pathDrift $packageName
    Copy-Item -LiteralPath `
        (Join-Path $pathDrift "vendor\p04\packages\$packageName") `
        -Destination $outside
    Assert-Rejected {
        & $verify -RepositoryRoot $pathDrift -PackagePath $outside
    } 'path-drift'

    $substitution = New-Fixture 'substitution'
    $substitutionPackage = Join-Path $substitution "vendor\p04\packages\$packageName"
    $bytes = [IO.File]::ReadAllBytes($substitutionPackage)
    $bytes[0] = $bytes[0] -bxor 0x01
    [IO.File]::WriteAllBytes($substitutionPackage, $bytes)
    Assert-Rejected {
        & $verify -RepositoryRoot $substitution
    } 'package-substitution'

    $repack = New-Fixture 'repack'
    $repackPackage = Join-Path $repack "vendor\p04\packages\$packageName"
    $temporaryZip = Join-Path $repack 'repacked.nupkg'
    $sourceArchive = [IO.Compression.ZipFile]::OpenRead($repackPackage)
    try {
        $destinationArchive = [IO.Compression.ZipFile]::Open(
            $temporaryZip,
            [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($entry in $sourceArchive.Entries) {
                $created = $destinationArchive.CreateEntry(
                    $entry.FullName,
                    [IO.Compression.CompressionLevel]::Optimal)
                $input = $entry.Open()
                $output = $created.Open()
                try {
                    $input.CopyTo($output)
                }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        }
        finally {
            $destinationArchive.Dispose()
        }
    }
    finally {
        $sourceArchive.Dispose()
    }
    Copy-Item -LiteralPath $temporaryZip -Destination $repackPackage -Force
    $repackedIdentity = & $normalized `
        -PackagePath $repackPackage `
        -ExpectedRepositoryCommit '69a712a894b024a09859096025c2bb8fe68a642e'
    if ($repackedIdentity.Hash -cne `
        'baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f') {
        throw 'The controlled repack did not preserve normalized identity.'
    }
    Assert-Rejected {
        & $verify -RepositoryRoot $repack
    } 'raw-repack'

    Assert-Rejected {
        & $normalized `
            -PackagePath (Join-Path $repositoryRoot "vendor\p04\packages\$packageName") `
            -ExpectedRepositoryCommit '0000000000000000000000000000000000000000'
    } 'source-commit-drift'

    $dependency = New-Fixture 'dependency-expansion'
    $profilePath = Join-Path $dependency 'vendor\p04\profile-carrier-manifest.json'
    $profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
    $profile.dependencies = @($profile.dependencies) + [PSCustomObject]@{
        id = 'Unexpected.Dependency'
        version = '[1.0.0]'
    }
    Write-Utf8NoBom $profilePath ($profile | ConvertTo-Json -Depth 10)
    Assert-Rejected {
        & $verify -RepositoryRoot $dependency
    } 'dependency-expansion'

    $lockDrift = New-Fixture 'lock-drift'
    $lockPath = Join-Path $lockDrift 'src\XNode.ProfileGenerator\packages.lock.json'
    $lockText = Get-Content -LiteralPath $lockPath -Raw
    Write-Utf8NoBom $lockPath ($lockText.Replace($version, '0.1.0-p14.faa598f'))
    Assert-Rejected {
        & $verify -RepositoryRoot $lockDrift
    } 'lock-drift'

    $probeLockDrift = New-Fixture 'probe-lock-drift'
    $probeLockPath = Join-Path $probeLockDrift `
        'eng\P14C3.Ed25519Probe\packages.lock.json'
    $probeLockText = Get-Content -LiteralPath $probeLockPath -Raw
    Write-Utf8NoBom $probeLockPath `
        ($probeLockText.Replace($version, '0.1.0-p14.faa598f'))
    Assert-Rejected {
        & $verify -RepositoryRoot $probeLockDrift
    } 'probe-lock-drift'

    $evidenceDrift = New-Fixture 'evidence-carrier-drift'
    $evidencePath = Join-Path $evidenceDrift 'vendor\p04\profile-carrier-manifest.json'
    $evidenceProfile = Get-Content -LiteralPath $evidencePath -Raw | ConvertFrom-Json
    $evidenceProfile.evidenceCarrierCommit = '2a21902ff5a613242180fdd75233991da896f879'
    Write-Utf8NoBom $evidencePath ($evidenceProfile | ConvertTo-Json -Depth 10)
    Assert-Rejected {
        & $verify -RepositoryRoot $evidenceDrift
    } 'old-evidence-carrier'

    Write-Output 'P14C3_PACKAGE_MUTATION_TESTS=PASS'
}
finally {
    $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to clean a mutation root outside the system temp directory.'
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
