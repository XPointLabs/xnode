[CmdletBinding()]
param(
    [string]$RepositoryRoot,
    [string]$PackagePath,
    [string]$ExpectedPackagePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$version = '0.2.0-p14.69a712a'
$sourceCommit = '69a712a894b024a09859096025c2bb8fe68a642e'
$sourceTree = 'd83bbdd001b723738357689bbb2150a51357cb3b'
$evidenceCommit = '071b5b300bcba3796d621720fb8f21cfdd5eb882'
$evidenceTree = 'ecbfc7747452709fb82aaf85fa912ba13b61d4ad'
$expectedBytes = 29399
$expectedSha256 = 'fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498'
$expectedSha512 = 'x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw=='
$expectedNormalized = 'baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f'
$expectedDll = '20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034'
$expectedPdb = '80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a'
$expectedVerifier = '09eba1ae0a2376094e78478efc75595a385eff84be3f5cfc7c8bb492cb4a3bc3'
$oldValues = @(
    '0.1.0-p14.faa598f',
    '5b895ced820d678e6957482989f74621322a7bb0661ede13dcb3184e4f3e960e',
    '2a21902ff5a613242180fdd75233991da896f879'
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-Sha512Base64([string]$Path) {
    $hex = (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash
    $bytes = New-Object byte[] ($hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($hex.Substring($index * 2, 2), 16)
    }
    return [Convert]::ToBase64String($bytes)
}

function Get-ZipEntrySha256(
    [IO.Compression.ZipArchive]$Archive,
    [string]$Name
) {
    $entries = @($Archive.Entries | Where-Object FullName -eq $Name)
    if ($entries.Count -ne 1) {
        throw "Package entry '$Name' is absent or duplicated."
    }
    $stream = $entries[0].Open()
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-Equal($Expected, $Actual, [string]$Label) {
    if ([string]$Expected -cne [string]$Actual) {
        throw "$Label does not match the accepted P14E2 package."
    }
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
if ([string]::IsNullOrWhiteSpace($ExpectedPackagePath)) {
    $ExpectedPackagePath = Join-Path $RepositoryRoot `
        "vendor\p04\packages\Deep.Protocol.ProfileCarrier.$version.nupkg"
}
if ([string]::IsNullOrWhiteSpace($PackagePath)) {
    $PackagePath = $ExpectedPackagePath
}
$PackagePath = [IO.Path]::GetFullPath($PackagePath)
$ExpectedPackagePath = [IO.Path]::GetFullPath($ExpectedPackagePath)
Assert-Equal $ExpectedPackagePath $PackagePath 'Carrier package path'

$package = Get-Item -LiteralPath $PackagePath
Assert-Equal $expectedBytes $package.Length 'Carrier package byte length'
Assert-Equal $expectedSha256 (Get-Sha256 $PackagePath) 'Carrier package SHA-256'
Assert-Equal $expectedSha512 (Get-Sha512Base64 $PackagePath) 'Carrier package SHA-512'

$verifierPath = Join-Path $RepositoryRoot 'eng\Get-P14C3ProfileCarrierNormalizedIdentity.ps1'
Assert-Equal $expectedVerifier (Get-Sha256 $verifierPath) 'Normalized verifier SHA-256'
$identity = & $verifierPath `
    -PackagePath $PackagePath `
    -ExpectedRepositoryCommit $sourceCommit
Assert-Equal 'deep-p14-profile-carrier-normalized-package-v2' $identity.Schema 'Normalized schema'
Assert-Equal $version $identity.Version 'Normalized package version'
Assert-Equal $sourceCommit $identity.RepositoryCommit 'Normalized repository commit'
Assert-Equal $expectedNormalized $identity.Hash 'Normalized package identity'
Assert-Equal $expectedDll $identity.DllHash 'Carrier DLL SHA-256'
$normalizedManifest = $identity.Manifest | ConvertFrom-Json
$pdb = @($normalizedManifest.entries | Where-Object path -eq `
    'lib/net10.0/Deep.Protocol.ProfileCarrier.pdb')
if ($pdb.Count -ne 1) {
    throw 'Normalized package manifest has no exact PDB entry.'
}
Assert-Equal $expectedPdb $pdb[0].sha256 'Carrier PDB SHA-256'

$archive = [IO.Compression.ZipFile]::OpenRead($PackagePath)
try {
    Assert-Equal $expectedDll `
        (Get-ZipEntrySha256 $archive 'lib/net10.0/Deep.Protocol.ProfileCarrier.dll') `
        'Raw carrier DLL SHA-256'
    Assert-Equal $expectedPdb `
        (Get-ZipEntrySha256 $archive 'lib/net10.0/Deep.Protocol.ProfileCarrier.pdb') `
        'Raw carrier PDB SHA-256'

    $nuspecEntries = @($archive.Entries | Where-Object FullName -eq `
        'Deep.Protocol.ProfileCarrier.nuspec')
    if ($nuspecEntries.Count -ne 1) {
        throw 'Carrier nuspec is absent or duplicated.'
    }
    $stream = $nuspecEntries[0].Open()
    try {
        $nuspec = [xml](New-Object IO.StreamReader($stream)).ReadToEnd()
    }
    finally {
        $stream.Dispose()
    }
    $metadata = $nuspec.package.metadata
    Assert-Equal 'Deep.Protocol.ProfileCarrier' $metadata.id 'Carrier package id'
    Assert-Equal $version $metadata.version 'Carrier nuspec version'
    Assert-Equal $sourceCommit $metadata.repository.commit 'Carrier nuspec repository commit'
    $actualDependencies = @($metadata.dependencies.group.dependency |
        ForEach-Object { "$($_.id)/$($_.version)" } | Sort-Object)
    $expectedDependencies = @(
        'Deep.Protocol/[0.3.0-p04.b887fa0]',
        'Sodium.Core/[1.4.1]',
        'libsodium/[1.0.22]'
    ) | Sort-Object
    Assert-Equal ($expectedDependencies -join "`n") `
        ($actualDependencies -join "`n") 'Carrier dependency closure'
}
finally {
    $archive.Dispose()
}

$profilePath = Join-Path $RepositoryRoot 'vendor\p04\profile-carrier-manifest.json'
$profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
Assert-Equal 'xnode-p14-profile-carrier-package.v2' $profile.schema 'Profile manifest schema'
Assert-Equal $version $profile.version 'Profile manifest version'
Assert-Equal $expectedBytes $profile.bytes 'Profile manifest byte length'
Assert-Equal $expectedSha256 $profile.sha256 'Profile manifest SHA-256'
Assert-Equal $expectedSha512 $profile.nugetContentHash 'Profile manifest SHA-512'
Assert-Equal $expectedNormalized $profile.normalizedIdentity 'Profile manifest normalized identity'
Assert-Equal $expectedDll $profile.dllSha256 'Profile manifest DLL SHA-256'
Assert-Equal $expectedPdb $profile.pdbSha256 'Profile manifest PDB SHA-256'
Assert-Equal $sourceCommit $profile.sourceCommit 'Profile manifest source commit'
Assert-Equal $sourceTree $profile.sourceTree 'Profile manifest source tree'
Assert-Equal $evidenceCommit $profile.evidenceCarrierCommit 'Profile manifest evidence commit'
Assert-Equal $evidenceTree $profile.evidenceCarrierTree 'Profile manifest evidence tree'
$manifestDependencies = @($profile.dependencies |
    ForEach-Object { "$($_.id)/$($_.version)" } | Sort-Object)
Assert-Equal ($expectedDependencies -join "`n") `
    ($manifestDependencies -join "`n") 'Profile manifest dependency closure'

$consumerPaths = @(
    'src\XNode.ProfileGenerator\XNode.ProfileGenerator.csproj',
    'src\XNode.ProfileGenerator\packages.lock.json',
    'tests\XNode.ProfileGenerator.Tests\packages.lock.json',
    'vendor\p04\offline-closure-manifest.json',
    'vendor\p04\package-manifest.json',
    'vendor\p04\profile-carrier-manifest.json'
)
foreach ($relativePath in $consumerPaths) {
    $text = Get-Content -LiteralPath (Join-Path $RepositoryRoot $relativePath) -Raw
    foreach ($oldValue in $oldValues) {
        if ($text.IndexOf($oldValue, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "Old carrier identity remains in '$relativePath'."
        }
    }
    if ($text.IndexOf($version, [StringComparison]::Ordinal) -lt 0) {
        throw "Exact carrier version is absent from '$relativePath'."
    }
}

$carrierFiles = @(Get-ChildItem -LiteralPath `
    (Join-Path $RepositoryRoot 'vendor\p04\packages') `
    -File -Filter 'Deep.Protocol.ProfileCarrier.*.nupkg')
if ($carrierFiles.Count -ne 1 -or
    [IO.Path]::GetFullPath($carrierFiles[0].FullName) -cne $ExpectedPackagePath) {
    throw 'Vendored carrier set is not the exact singleton package.'
}

Write-Output 'P14C3_PACKAGE_VERIFICATION=PASS'
Write-Output "P14C3_PACKAGE_SHA256=$expectedSha256"
Write-Output "P14C3_NORMALIZED_IDENTITY=$expectedNormalized"
