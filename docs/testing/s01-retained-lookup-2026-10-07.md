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

## Current source and mandatory smoke qualification

The current source full run was started with:

```powershell
dotnet test XNode.slnx -c Release -m:1 `
  -p:DeepProtocolSourceCutover=true `
  -p:ShouldUnsetParentConfigurationAndPlatform=false -warnaserror `
  --logger trx --results-directory artifacts/s01-retained-lookup-gc/full `
  --verbosity quiet
```

The original live process finished terminal0: **1,223 passed / 0 failed /
0 skipped** (Integration866, ProfileGenerator107, Unit250). The Integration suite
took44m55s. A three-second SampleProfiler-only trace during that suite showed
peer Store/commit/quorum calls; most CPU frames had no resolved symbols. This is
not proof of a particular performance cause. No deadline or assertion changed.

| Receipt under artifacts/s01-retained-lookup-gc/full | SHA-256 |
| --- | --- |
| nikit_SURFACE-LT_2026-10-07_09_29_54_net10.0.trx | `6DDE11A92EF0F25A71A612980E5BB6CFC53279524C691137641E9E0B9E533F3D` |
| nikit_SURFACE-LT_2026-10-07_10_14_57_net10.0.trx | `9708F02E21C03549DE9554B4664955BC4CF216C7EDBBB052C1DF3AFD2EF0E225` |
| nikit_SURFACE-LT_2026-10-07_10_15_23_net10.0.trx | `F4F9BF6A075F7B7E554CD6373B37D1DC251653EED0BD378DB568C8B010F1063D` |

Qualification preserves all1,220 prior exact case names and all14 required
focused cases; every current result has its exact execution entry and unique
method definition, with matching Passed counters. The three new cases explain
the increase from1,220 to1,223. All1,066 captured source/normative inputs are
unchanged. The expectations manifest was captured at09:47:44+05, during the live
run, not before launch; its original bytes remain unchanged, SHA-256
`77666039B3C1CC75046B4A00411B477D98CDCBC87D13AC0377F5E6FD9129A0A3`.

The first qualification returned1 because it incorrectly treated the not-yet-built
ProfileGenerator assembly as an already executing frozen binary. The solution
builds/tests sequentially: ProfileGenerator was built at10:14:54+05, before its
own suite started10:14:56+05. Its executed SHA-256 is
`0FB350EC6D783E423BF602AAA744CB49FC3F241EA193E6A6E40D4B7460EBCFC4`,
not the stale pre-build `7CBDA87E28D74A20FE41DDB3BD455A0240338D4482FF0E8F750280D41C2865A5`.
The corrected executed-matrix check finishes0, still verifying all1,066 inputs,
all case/entry/definition mappings, and both unchanged Integration/Unit binaries.
The ProfileGenerator binary is explicitly pinned post-terminal, not claimed to
have been frozen pre-run. No source change or second full run followed this
bookkeeping correction. Private qualifier SHA-256:
`0A2B8BB3BA3445020C01B8D62E1013754F1BA30F6E201C3FB1B0DFAA0D05FEB3`.

The first Desktop startup/status queries ended1 with its Linux engine unavailable.
After the operator restarted Desktop, engine28.3.3 became available. The required
smoke then completed terminal0, using a fresh artifact directory and the isolated
Compose project `deep-s01-gc-20261007`:

```powershell
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external `
  -ManagedExternalProfile backend-external -RequireRouterNoMock `
  -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
```

The process explicitly selected local external URLs and real Xray/Tcp in
Development. Node used the current Protocol source-cutover graph; Registry used
the existing local-cutover package lane. All seven managed services became
healthy. Fixture validation and10 infrastructure/harness tests passed; four hard
and five soft runtime checks passed, transportMode=running, mocked=false and no
runtime-gate warnings. Three existing Dockerfile InvalidDefaultArgInFrom warnings
were reported during the external-service build; no .NET build warning was shown.
Push provider delivery was not requested or proven. These are infrastructure
checks, not physical E2E or a uniform current issuer/Release package graph.

| Receipt under deep-devops/artifacts/s01-gc-smoke-20261007-01 | SHA-256 |
| --- | --- |
| runtime.gate.json | `2492AF432BF10A3893F37CC6D5F0845B1BB4E00004D27AD280B01447D3ECF1A7` |
| runtime.snapshot.json | `89F3B7AA064FE386D0EA8DC0D1D8D326AA3F2E2EEE71B555069D3EF07CE6E883` |
| compose.topology.redacted.json | `EAA6BC0B15065834262611B706DB2B1FC34203FC33D77FAEB1162B99BCDA6788` |

The script's evidence scan passed for its two selected files. An additional scan
initially inherited the whole historical artifacts root and failed on unrelated
old/private binary bundles; that FAIL summary remains private and ignored. The
explicitly scoped current four-receipt scan passes with zero findings; this does
not clear those historical findings or authorize uploading their bundles.
Selected source secret scan passes (two files, zero findings); diff check passes.
Cleanup removed only the temporary project's containers, seven volumes and network;
all six original deep-dev containers remained running. No WSL reset or old receipt
reuse occurred. The GC increment passes both mandatory XNode gates, not whole S01.
No production deployment, account reset, secret export, package pin, release
publication or node identity change occurred.

This fixes only partial in-memory GC. Separate bounded retained-read custody,
current issuer authentication of that lookup, typed node Retrieve/ACK and the
accepted-object horizon remain the same unfinished S01 task.
