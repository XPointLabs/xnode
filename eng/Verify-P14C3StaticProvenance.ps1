[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHead,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedTree,
    [Parameter(Mandatory = $true)]
    [string]$P14E2SourceRepositoryRoot,
    [Parameter(Mandatory = $true)]
    [string]$P14E2EvidenceRepositoryRoot,
    [string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Join-Path $PSScriptRoot '..\scripts') 'restore-isolation.ps1')

$p14e2SourceHead = '69a712a894b024a09859096025c2bb8fe68a642e'
$p14e2SourceTree = 'd83bbdd001b723738357689bbb2150a51357cb3b'
$p14e2EvidenceHead = '071b5b300bcba3796d621720fb8f21cfdd5eb882'
$p14e2EvidenceTree = 'ecbfc7747452709fb82aaf85fa912ba13b61d4ad'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$P14E2SourceRepositoryRoot = [IO.Path]::GetFullPath($P14E2SourceRepositoryRoot)
$P14E2EvidenceRepositoryRoot = [IO.Path]::GetFullPath($P14E2EvidenceRepositoryRoot)

Assert-ExactRepositoryAuthority `
    -RepositoryRoot $P14E2SourceRepositoryRoot `
    -ExpectedHead $p14e2SourceHead `
    -ExpectedTree $p14e2SourceTree `
    -Label 'P14E2 source'
Assert-ExactRepositoryAuthority `
    -RepositoryRoot $P14E2EvidenceRepositoryRoot `
    -ExpectedHead $p14e2EvidenceHead `
    -ExpectedTree $p14e2EvidenceTree `
    -Label 'P14E2 evidence'

& (Join-Path $PSScriptRoot 'Verify-P14C3Source.ps1') `
    -ExpectedHead $ExpectedHead `
    -ExpectedTree $ExpectedTree `
    -RepositoryRoot $RepositoryRoot

$packagePath = Join-Path $RepositoryRoot `
    'vendor\p04\packages\Deep.Protocol.ProfileCarrier.0.2.0-p14.69a712a.nupkg'
& (Join-Path $P14E2EvidenceRepositoryRoot 'eng\verify-p14e2-evidence.ps1') `
    -RepositoryRoot $P14E2EvidenceRepositoryRoot `
    -PackagePath $packagePath

Write-Output 'P14C3_P14E2_PROVENANCE_STATIC_GATE=PASS'
Write-Output "P14C3_ACCEPTED_P14E2_SOURCE=$p14e2SourceHead"
Write-Output "P14C3_ACCEPTED_P14E2_EVIDENCE=$p14e2EvidenceHead"
Write-Output 'P14C3_RUNTIME_REGISTRATION=NO-GO'
Write-Output 'P14C3_PRODUCTION_SIGNER=NO-GO'
Write-Output 'P14C3_PROFILE_ACTIVATION=NO-GO'
Write-Output 'P14C3_CANONICAL_ACCEPTANCE=PENDING'
