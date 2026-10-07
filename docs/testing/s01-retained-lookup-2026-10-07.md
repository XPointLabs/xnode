# S01 retained lookup: DCR garbage-collection consistency

This is a source checkpoint within the sole unfinished retained-read contract,
not acceptance of S01, renewed issuance, runtime activation or physical E2E.
Execution order remains owned by the workspace implementation plan.

## Reproduced defect and source change

Baseline: `4ec06aedf5a65d29e00f4aa9945f2a4014179bb0`.
Source fix: `27f8c5cf88ba1d48678353c7417f23f910e91f11`.

`ContactResolverOpaqueStore.CollectGarbage` previously pruned DCR predecessors
before validating the supplied XUR checkpoint against the existing stream.
A missing generation or mismatched event hash then returned without SaveState.
An exact DCR replay became StaleGeneration in memory, but reopened storage still
retained its operation. The checkpoint is now validated before either history
is changed. No public API, wire bytes, retention duration or state version changes.
The current-only mailbox grant lookup remains current-only; no expired grant
or historical route becomes admission authority.

## Focused evidence

From xnode:

```powershell
dotnet test tests/XNode.Tests/XNode.Tests.csproj -c Release `
  -p:DeepProtocolSourceCutover=true `
  --filter FullyQualifiedName~ContactResolverOpaqueStoreTests `
  --logger 'trx;LogFileName=gc-focused.trx' `
  --results-directory artifacts/s01-retained-lookup-gc/focused --verbosity quiet
```

Terminal0: 14 passed / 0 failed / 0 skipped; 14 results, definitions and distinct
execution IDs. Three new cases cover wrong hash and missing checkpoint generation
with unchanged durable bytes and exact replay before/after reopen; and valid GC
at 48h minus one second versus exactly 48h, durably retaining the successor.
The GC return count still counts XUR events, not DCR predecessors.

The initial targeted run finished terminal1 with three failures. Two reproduced
the product defect (ExactReplay expected, StaleGeneration returned). The positive
GC test initially expected Conflict after legitimate removal; the existing
PublishDcr implementation correctly returns StaleGeneration. That test expectation
was corrected; no production rejection was weakened. The original FAIL is kept.

| Receipt under artifacts/s01-retained-lookup-gc | SHA-256 |
| --- | --- |
| before/gc-before.trx | `DCF58AC18670B53F549F87DE0C37AC13A6F9D3A484E67F0AE19073D81A4FD2CD` |
| focused/gc-focused.trx | `0CEFB6AFA8751A82CB05CD6940B48CB373E9E7CE8E2402F1A8113D25C2F70A4E` |

## Mandatory qualification remains pending

The current source full run was started with:

```powershell
dotnet test XNode.slnx -c Release -m:1 `
  -p:DeepProtocolSourceCutover=true `
  -p:ShouldUnsetParentConfigurationAndPlatform=false -warnaserror `
  --logger trx --results-directory artifacts/s01-retained-lookup-gc/full `
  --verbosity quiet
```

No terminal result is available at this checkpoint; no full acceptance is claimed.
The required external/no-mock Docker smoke has not run: the Docker Desktop Linux
engine pipe is unavailable. A previous smoke receipt is not reused for this source.
Selected source secret scan passes (two files, zero findings); diff check passes.
The commit is local pending mandatory qualification. No deployment, account reset,
secret export, package pin, release publication or node identity change occurred.

This fixes only partial in-memory GC. Separate bounded retained-read custody,
current issuer authentication of that lookup, typed node Retrieve/ACK and the
accepted-object horizon remain the same unfinished S01 task.
