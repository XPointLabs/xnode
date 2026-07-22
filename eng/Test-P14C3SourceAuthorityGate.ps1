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

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$testRoot = Join-Path ([IO.Path]::GetTempPath()) `
    "xnode-p14c3-authority-$([Guid]::NewGuid().ToString('N'))"
$probeRelative = 'eng/P14C3.Ed25519Probe/Program.cs'
$unexpectedAcceptances = [Collections.Generic.List[string]]::new()

function New-Fixture([string]$Name) {
    $root = Join-Path $testRoot $Name
    & git -c core.autocrlf=true clone --no-hardlinks --no-checkout `
        $RepositoryRoot $root | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create authority fixture '$Name'."
    }
    & git -C $root -c core.autocrlf=true checkout --detach $ExpectedHead | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to materialize authority fixture '$Name'."
    }
    return $root
}

function Hide-Mutation([string]$Root, [ValidateSet('skip-worktree', 'assume-unchanged')][string]$Mode) {
    $flag = if ($Mode -eq 'skip-worktree') { '--skip-worktree' } else { '--assume-unchanged' }
    & git -C $Root update-index $flag -- $probeRelative
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to set $Mode."
    }
    $path = Join-Path $Root $probeRelative
    $text = [IO.File]::ReadAllText($path)
    if ($text.IndexOf('return 0;', [StringComparison]::Ordinal) -lt 0) {
        throw 'Probe mutation anchor is absent.'
    }
    $mutated = $text.Replace(
        'return 0;',
        'GC.KeepAlive("hidden-authority-mutation");' + "`n" + 'return 0;')
    [IO.File]::WriteAllText($path, $mutated, [Text.UTF8Encoding]::new($false))
    $status = @(& git -C $Root status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
        throw "$Mode fixture mutation is not hidden."
    }
}

function Assert-Rejected([string]$Label, [scriptblock]$Action) {
    $rejected = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $rejected = $true
    }
    if ($rejected) {
        Write-Output "PASS reject-$Label"
    }
    else {
        $unexpectedAcceptances.Add($Label)
        Write-Output "RED accepted-$Label"
    }
}

try {
    if (@(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all).Count -ne 0) {
        throw 'Authority test source must be clean.'
    }

    $skipSource = New-Fixture 'skip-source'
    Hide-Mutation $skipSource 'skip-worktree'
    Assert-Rejected 'source-skip-worktree' {
        & (Join-Path $skipSource 'eng\Verify-P14C3Source.ps1') `
            -ExpectedHead $ExpectedHead -ExpectedTree $ExpectedTree `
            -RepositoryRoot $skipSource
    }

    $assumeSource = New-Fixture 'assume-source'
    Hide-Mutation $assumeSource 'assume-unchanged'
    Assert-Rejected 'source-assume-unchanged' {
        & (Join-Path $assumeSource 'eng\Verify-P14C3Source.ps1') `
            -ExpectedHead $ExpectedHead -ExpectedTree $ExpectedTree `
            -RepositoryRoot $assumeSource
    }

    $skipStatic = New-Fixture 'skip-static'
    Hide-Mutation $skipStatic 'skip-worktree'
    Assert-Rejected 'static-provenance-skip-worktree' {
        & (Join-Path $skipStatic 'eng\Verify-P14C3StaticProvenance.ps1') `
            -ExpectedHead $ExpectedHead -ExpectedTree $ExpectedTree `
            -P14E2SourceRepositoryRoot $P14E2SourceRepositoryRoot `
            -P14E2EvidenceRepositoryRoot $P14E2EvidenceRepositoryRoot `
            -RepositoryRoot $skipStatic
    }

    $skipLinux = New-Fixture 'skip-linux'
    Hide-Mutation $skipLinux 'skip-worktree'
    Assert-Rejected 'linux-mutated-checkout' {
        & (Join-Path $skipLinux 'eng\Verify-P14C3LinuxExecution.ps1') `
            -ExpectedHead $ExpectedHead -ExpectedTree $ExpectedTree `
            -Architecture x64
    }

    if ($unexpectedAcceptances.Count -ne 0) {
        throw "Authority gates accepted hidden state: $($unexpectedAcceptances -join ', ')."
    }
    Write-Output 'P14C3_SOURCE_AUTHORITY_MUTATION_TESTS=PASS'
}
finally {
    $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to clean an authority root outside the system temp directory.'
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
