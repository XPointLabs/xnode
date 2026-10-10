# S02 current consumer checkpoint — 2026-10-10

S02 is the sole active stage after the
[S01 contract/API review](../../../docs/S01-CONTRACT-REVIEW-2026-10-10.md).
This checkpoint is source/composition evidence, not runtime activation,
whole-stage acceptance or physical Windows/Android E2E.

## Current source build and focused result

Inputs: Node `c000dc1`, Protocol `9700e76`, Shared `c79c0a8` (documentation-only
successor of qualified Shared source `5057069`). No Node implementation or
fixture source was changed for this run.

Run from Windows PowerShell5.1:

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj --configuration Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxHostRecoveryReadinessTests|FullyQualifiedName~ActualRegisteredOwnersCompleteNative' --logger trx --results-directory artifacts/s02-current-consumer-20261010/focused-01 --verbosity minimal
```

Native exit0; build completed with warnings treated as errors. VSTest result:
**91 Passed /0 Failed /0 Skipped**, reported test duration37s. This duration is
not the build/wall-clock duration. The canonical root `Read-TestGateReceipt`
finds91 exact names,91 case identities and91 unique execution mappings:
85 composition cases,4 readiness cases and2 actual registered-native cases.

Receipt:
`artifacts/s02-current-consumer-20261010/focused-01/nikit_SURFACE-LT_2026-10-10_08_06_25_net10.0.trx`.
SHA256: `69001B184A3DF8C523F4538A6DC7D8EB4699F171E59BDF5849680AEC1167F7A1`.

This is not a canonical unfiltered full: there is no full gate terminal or
captured-input qualification for this focused run. The old Node full02 receipt
must not be relabelled a full on these newly compiled Protocol consumer inputs.

## Remaining S02 implementation boundary

Readiness invokes the actual current receiver under both restored role owners,
checks current descriptor signing custody and the anchored operation document.
The inspected `CurrentMailboxReplicaReceiver.InitializeHostAsync` does not itself
join all stored native blob/mutation/replay/outcome recovery dependencies.
Constructors and individual request guards are not proof of whole-host recovery.
The next coherent S02 unit is that native-state recovery/readiness boundary,
including retained work and fail-closed missing/corrupt custody. Do not replace
it with an extra Boolean, an empty store, host UTC, a synthetic client grant,
automatic enrollment or a new operation journal.

Enabled configured Program observer/provisioning, selected-exit/ONION boundaries
and the matching whole-host tests remain required. The existing positive Program
peer fixtures use explicitly enrolled native owners and test TLS endpoints;
they do not prove the production configuration or installed client composition.
No production machine/data/key, package, release or main branch was changed.

Implement this unit before another broad test cycle. Then run matching focused
fault/reopen checks, canonical Node full, and the separate required external
no-mock smoke/multi-node rehearsal. S04 renewal/cleanup and S07 scheduler/receipt
orchestration remain later stages; S02 is not accepted by91 focused passes.
