param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$resultsDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("xnode-p05-" + [guid]::NewGuid().ToString("N"))
$trxPath = Join-Path $resultsDirectory "p05.trx"

dotnet test (Join-Path $repositoryRoot "tests\XNode.Tests\XNode.Tests.csproj") `
    --configuration $Configuration `
    --filter "FullyQualifiedName~StorageReplicationProtocolCorrectiveTests" `
    --no-restore `
    --results-directory $resultsDirectory `
    --logger "trx;LogFileName=p05.trx"

if ($LASTEXITCODE -ne 0) {
    throw "P05 simulator tests failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path -LiteralPath $trxPath -PathType Leaf)) {
    throw "P05 simulator TRX result was not created."
}

[xml]$trx = Get-Content -Raw -LiteralPath $trxPath
$counters = $trx.TestRun.ResultSummary.Counters
$total = [int]$counters.total
$executed = [int]$counters.executed
$passed = [int]$counters.passed
$failed = [int]$counters.failed

if ($total -le 0 -or $executed -le 0) {
    throw "P05 simulator filter executed zero tests."
}

if ($failed -ne 0 -or $passed -ne $executed) {
    throw "P05 simulator summary is not clean: total=$total executed=$executed passed=$passed failed=$failed."
}

Write-Host "P05 simulator gate passed: total=$total executed=$executed passed=$passed failed=$failed."
