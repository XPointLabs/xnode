# P14C1 reproduction

All source verification targets the accepted source commit, not the later
evidence-carrier commit.

From a repository clone:

```powershell
$sourceCommit = 'eff452368fa4cb1324c5b3c8ee06e2f10e96b835'
git worktree add ../p14c1-source $sourceCommit
Set-Location ../p14c1-source
git status --porcelain=v1 --untracked-files=all
```

The status command must produce no output.

Run the isolated restore/build/test gates:

```powershell
powershell -NoProfile -NonInteractive -File scripts/verify-p14c-offline.ps1
powershell -NoProfile -NonInteractive -File scripts/verify-solution-clean-restore.ps1
```

Expected sentinels:

```text
P14C_OFFLINE_VERIFICATION=PASS
SOLUTION_CLEAN_RESTORE=PASS
```

Run the full test matrix:

```powershell
dotnet test XNode.slnx --configuration Debug --no-restore
dotnet test XNode.slnx --configuration Release --no-restore
```

Expected for each configuration:

- `XNode.ProfileGenerator.Tests`: 41 passed
- `XNode.Tests`: 48 passed
- `XNode.IntegrationTests`: 17 passed
- total: 106 passed, 0 failed, 0 skipped

Verify runtime isolation:

```powershell
$baseCommit = '2980c15c1901d7569f5ba025912ab019c1058407'
git diff --exit-code $baseCommit $sourceCommit -- src/XNode src/XNode.Core src/XNode.Registry src/XNode.Transport.Vless
rg -n -F -e Microsoft.Extensions -e System.Net -e HttpClient -e System.IO.File -e IServiceCollection -e WebApplication -e PrivateKey -e RecoveryPhrase src/XNode.ProfileGenerator -g *.cs
rg -n -F XNode.ProfileGenerator src -g *.csproj -g !src/XNode.ProfileGenerator/**
```

Expected exits:

- runtime diff: `0`, with no output
- private production API source scan: `1`, meaning no matches
- runtime project-reference scan: `1`, meaning no matches

Verify the source tree identity:

```powershell
git rev-parse "$sourceCommit^{tree}"
```

Expected:

```text
ee7a54e9eb0bc4c0803b9508627355eec75f0405
```

The package hashes and byte sizes to compare with
`vendor/p04/offline-closure-manifest.json` are recorded in
`closure-packages.json`.
