[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('true', 'false')]
    [string]$CoreAutoCrlf,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHead,
    [string]$RepositoryRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
$testRoot = Join-Path ([IO.Path]::GetTempPath()) `
    "xnode-p14c3-materialization-$CoreAutoCrlf-$([Guid]::NewGuid().ToString('N'))"

function Invoke-Git(
    [string]$WorkingDirectory,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
) {
    & git -C $WorkingDirectory @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed: $($Arguments -join ' ')"
    }
}

try {
    $actualHead = @(& git -C $RepositoryRoot rev-parse HEAD)[0]
    if ($LASTEXITCODE -ne 0 -or $actualHead.Trim() -cne $ExpectedHead) {
        throw 'Materialization source HEAD is not exact.'
    }
    if (@(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all).Count -ne 0) {
        throw 'Materialization source worktree must be clean.'
    }

    & git -c "core.autocrlf=$CoreAutoCrlf" clone --no-hardlinks --no-checkout `
        $RepositoryRoot $testRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to create the fresh local materialization.'
    }
    Invoke-Git $testRoot -c "core.autocrlf=$CoreAutoCrlf" checkout --detach $ExpectedHead

    $materializedHead = @(& git -C $testRoot rev-parse HEAD)[0]
    if ($LASTEXITCODE -ne 0 -or $materializedHead.Trim() -cne $ExpectedHead) {
        throw 'Fresh materialization HEAD is not exact.'
    }

    $project = Join-Path $testRoot `
        'tests\XNode.ProfileGenerator.Tests\XNode.ProfileGenerator.Tests.csproj'
    $config = Join-Path $testRoot 'scripts\p14c-offline.NuGet.Config'
    & dotnet restore $project --locked-mode --configfile $config `
        -p:NuGetAudit=false
    if ($LASTEXITCODE -ne 0) {
        throw 'Fresh materialization restore failed.'
    }
    & dotnet test $project -c Debug --no-restore `
        --filter 'FullyQualifiedName~GoldenFixtureRemainsTheAcceptedP04Fixture'
    if ($LASTEXITCODE -ne 0) {
        throw "Fresh core.autocrlf=$CoreAutoCrlf materialization test failed."
    }

    Write-Output "P14C3_WINDOWS_MATERIALIZATION_AUTOCRLF_$($CoreAutoCrlf.ToUpperInvariant())=PASS"
}
finally {
    $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to clean a materialization root outside the system temp directory.'
    }
    if (Test-Path -LiteralPath $resolved) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
