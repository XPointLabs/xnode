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

function Invoke-Git(
    [string]$Root,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
) {
    $output = @(& git -C $Root @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "git failed in '$Root': $($Arguments -join ' ')"
    }
    return $output
}

function Assert-ExactRepository(
    [string]$Root,
    [string]$ExpectedRepositoryHead,
    [string]$ExpectedRepositoryTree,
    [string]$Label
) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "$Label worktree is absent."
    }
    if (@(Invoke-Git $Root status --porcelain=v1 --untracked-files=all).Count -ne 0) {
        throw "$Label worktree is not clean."
    }
    if (@(Invoke-Git $Root rev-parse HEAD)[0].Trim() -cne $ExpectedRepositoryHead) {
        throw "$Label HEAD is not exact."
    }
    if (@(Invoke-Git $Root rev-parse 'HEAD^{tree}')[0].Trim() -cne $ExpectedRepositoryTree) {
        throw "$Label tree is not exact."
    }
    if (@(Invoke-Git $Root rev-parse --is-shallow-repository)[0].Trim() -cne 'false') {
        throw "$Label repository is shallow."
    }
    if (@(Invoke-Git $Root replace -l).Count -ne 0) {
        throw "$Label repository has replace refs."
    }
    $alternates = @(& git -C $Root config --get-all objects.alternateObjectDirectories)
    if ($LASTEXITCODE -notin @(0, 1) -or $alternates.Count -ne 0) {
        throw "$Label repository has object alternates."
    }
    $common = @(Invoke-Git $Root rev-parse --git-common-dir)[0]
    if (-not [IO.Path]::IsPathRooted($common)) {
        $common = Join-Path $Root $common
    }
    if (Test-Path -LiteralPath (Join-Path $common 'objects\info\alternates')) {
        throw "$Label repository has an alternates file."
    }
    if (Test-Path -LiteralPath (Join-Path $common 'info\grafts')) {
        throw "$Label repository has grafts."
    }
    if (@(Invoke-Git $Root ls-files -v | Where-Object { $_ -cmatch '^[a-z] ' }).Count -ne 0 -or
        @(Invoke-Git $Root ls-files -t | Where-Object { $_ -cmatch '^S ' }).Count -ne 0) {
        throw "$Label repository has special index flags."
    }
    $sparse = @(& git -C $Root config --bool core.sparseCheckout)
    if ($LASTEXITCODE -notin @(0, 1) -or ($sparse.Count -ne 0 -and $sparse[0] -ceq 'true')) {
        throw "$Label repository uses sparse checkout."
    }
}

Assert-ExactRepository $P14E2SourceRepositoryRoot `
    $p14e2SourceHead $p14e2SourceTree 'P14E2 source'
Assert-ExactRepository $P14E2EvidenceRepositoryRoot `
    $p14e2EvidenceHead $p14e2EvidenceTree 'P14E2 evidence'

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
