[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHead,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedTree,
    [string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$baseCommit = 'cd9d20a8ec8346d171d4cd070dde170aa5f471d7'
$baseTree = 'e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

function Invoke-Git([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments) {
    $output = @(& git -C $RepositoryRoot @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "git failed: $($Arguments -join ' ')"
    }
    return $output
}

function Assert-Exact([string]$Expected, [string]$Actual, [string]$Label) {
    if ($Expected -cne $Actual.Trim()) {
        throw "$Label is not exact."
    }
}

Assert-Exact $ExpectedHead (Invoke-Git rev-parse HEAD)[0] 'P14C3 source HEAD'
Assert-Exact $ExpectedTree (Invoke-Git rev-parse 'HEAD^{tree}')[0] 'P14C3 source tree'
Assert-Exact $baseTree (Invoke-Git rev-parse "$baseCommit^{tree}")[0] 'P14C2 base tree'
Assert-Exact 'false' (Invoke-Git rev-parse --is-shallow-repository)[0] 'Shallow state'

$status = @(Invoke-Git status --porcelain=v1 --untracked-files=all)
if ($status.Count -ne 0) {
    throw 'P14C3 source worktree must be clean.'
}
if (@(Invoke-Git replace -l).Count -ne 0) {
    throw 'Git replace refs are forbidden.'
}
$alternatesConfig = @(& git -C $RepositoryRoot config --get-all objects.alternateObjectDirectories)
if ($LASTEXITCODE -notin @(0, 1) -or $alternatesConfig.Count -ne 0) {
    throw 'Git object alternates are forbidden.'
}
$common = (Invoke-Git rev-parse --git-common-dir)[0]
if (-not [IO.Path]::IsPathRooted($common)) {
    $common = Join-Path $RepositoryRoot $common
}
if (Test-Path -LiteralPath (Join-Path $common 'objects\info\alternates')) {
    throw 'Git alternates file is forbidden.'
}
if (Test-Path -LiteralPath (Join-Path $common 'info\grafts')) {
    throw 'Git grafts are forbidden.'
}

& git -C $RepositoryRoot merge-base --is-ancestor $baseCommit $ExpectedHead
if ($LASTEXITCODE -ne 0) {
    throw 'P14C3 HEAD does not descend from the exact accepted P14C2 source.'
}

$allowed = @(
    '^artifacts/survival/P14C3/',
    '^docs/P14C1_DORMANT_PROFILE_COMPOSER\.md$',
    '^docs/P14C3_XNODE_ACTIVATION_TRUST_REBIND\.md$',
    '^eng/Get-P14C3ProfileCarrierNormalizedIdentity\.ps1$',
    '^eng/P14C3\.Ed25519Probe/',
    '^eng/Test-P14C3PackageGate\.ps1$',
    '^eng/Verify-P14C3LinuxExecution\.ps1$',
    '^eng/Verify-P14C3Package\.ps1$',
    '^eng/Verify-P14C3Source\.ps1$',
    '^src/XNode\.ProfileGenerator/XNode\.ProfileGenerator\.csproj$',
    '^src/XNode\.ProfileGenerator/packages\.lock\.json$',
    '^tests/XNode\.ProfileGenerator\.Tests/P14C3ActivationTrustRebindTests\.cs$',
    '^tests/XNode\.ProfileGenerator\.Tests/ProfileCarrierPackagePinTests\.cs$',
    '^tests/XNode\.ProfileGenerator\.Tests/SharedCarrierAdoptionTests\.cs$',
    '^tests/XNode\.ProfileGenerator\.Tests/XNode\.ProfileGenerator\.Tests\.csproj$',
    '^tests/XNode\.ProfileGenerator\.Tests/packages\.lock\.json$',
    '^vendor/p04/offline-closure-manifest\.json$',
    '^vendor/p04/package-manifest\.json$',
    '^vendor/p04/packages/Deep\.Protocol\.ProfileCarrier\.[^/]+\.nupkg$',
    '^vendor/p04/profile-carrier-manifest\.json$'
)
$changed = @(Invoke-Git diff --name-only $baseCommit..$ExpectedHead -- |
    ForEach-Object { $_.Replace('\', '/') })
foreach ($path in $changed) {
    if (-not ($allowed | Where-Object { $path -match $_ })) {
        throw "P14C3 locked-file scope drift: '$path'."
    }
}

& git -C $RepositoryRoot diff --check $baseCommit..$ExpectedHead --
if ($LASTEXITCODE -ne 0) {
    throw 'git diff --check rejected the P14C3 source.'
}

$fixtureRoot = Join-Path $RepositoryRoot 'tests\XNode.ProfileGenerator.Tests\Fixtures'
$fixtures = [ordered]@{
    'accepted-eff4523-default.dpf' = '1359|cc8df0559b033ad7c70aa5d19134c06c58fb2dd6cfc10449525e1fb919679dbe'
    'accepted-eff4523-max-49152.dpf' = '49152|554f63afd6da4ecdde2c66732c9e4daf28391f796d26e949eb41ca3e95c74441'
    'accepted-eff4523-qr-1524.dpf' = '1524|0a1708d4fdf65ad0e72904867857973191ecb291bed379c6d728a5a56e0c497f'
    'accepted-eff4523-qr-1525.dpf' = '1525|854f4f73f304bc1cbf95be7a48231b7a1549079ea456a7eb2b06e763d8f70894'
    'accepted-eff4523-two-bridges.dpf' = '1726|05549533056af9a7f6d1cfb779e336fec3ac40395bcd9512ca953d1fe7795385'
    'accepted-eff4523-vectors.json' = '1222|7ce68a2884d2debb13c40b2019f73746d70e957a6738e8e0a52d0ea4ab91897e'
}
foreach ($name in $fixtures.Keys) {
    $path = Join-Path $fixtureRoot $name
    $file = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $actual = "$($file.Length)|$hash"
    Assert-Exact $fixtures[$name] $actual "DPF1 fixture $name"
}

$runtimeProjects = Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') `
    -File -Filter '*.csproj' -Recurse |
    Where-Object FullName -notmatch '[\\/]XNode\.ProfileGenerator[\\/]'
foreach ($project in $runtimeProjects) {
    $text = Get-Content -LiteralPath $project.FullName -Raw
    if ($text.Contains('Deep.Protocol.ProfileCarrier') -or
        $text.Contains('XNode.ProfileGenerator')) {
        throw "Runtime project references the dormant profile surface: '$($project.FullName)'."
    }
}
$runtimeSources = Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'src') `
    -File -Filter '*.cs' -Recurse |
    Where-Object FullName -notmatch '[\\/]XNode\.ProfileGenerator[\\/]'
foreach ($source in $runtimeSources) {
    $text = Get-Content -LiteralPath $source.FullName -Raw
    if ($text.Contains('SodiumEd25519MembershipSignatureVerifier') -or
        $text.Contains('ProfileCarrierTransitionVerifier')) {
        throw "Runtime source constructs the dormant activation-trust surface: '$($source.FullName)'."
    }
}

$diff = (Invoke-Git diff --unified=0 $baseCommit..$ExpectedHead --) -join "`n"
foreach ($forbidden in @(
    'BEGIN PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY',
    'UAT_SEED',
    'UAT_MNEMONIC',
    'Ed25519PrivateKeyPath'
)) {
    if ($diff.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "Static privacy scan rejected '$forbidden'."
    }
}

& (Join-Path $PSScriptRoot 'Verify-P14C3Package.ps1') `
    -RepositoryRoot $RepositoryRoot | Out-Null

Write-Output 'P14C3_SOURCE_VERIFICATION=PASS'
Write-Output "P14C3_SOURCE_SHA=$ExpectedHead"
Write-Output "P14C3_SOURCE_TREE=$ExpectedTree"
Write-Output 'P14C3_DPF1_BYTE_IDENTITY=PASS'
Write-Output 'P14C3_RUNTIME_REGISTRATION=NO-GO'
