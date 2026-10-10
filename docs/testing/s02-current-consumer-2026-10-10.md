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

At the initial 91-case checkpoint, readiness invoked the actual current receiver under both restored role owners,
checks current descriptor signing custody and the anchored operation document.
That version of `CurrentMailboxReplicaReceiver.InitializeHostAsync` did not itself
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

The native recovery implementation below precedes another broad test cycle.
Run matching focused fault/reopen checks, canonical Node full, and the separate required external
no-mock smoke/multi-node rehearsal. S04 renewal/cleanup and S07 scheduler/receipt
orchestration remain later stages; S02 is not accepted by91 focused passes.

## Native recovery implementation batch

`InitializeHostAsync` now joins existing mutation/blob, peer replay and client
replay/canonical-outcome owners before reporting fresh readiness, while the two
current protected role owners remain held. No extra journal, grant, caller time,
GC, auto-enrollment or permissive reader is introduced. The operation ledger's
already anchored pending replacement recovery is unchanged.

The native read phase validates bounded file framing and names, mutation index
membership/cursor uniqueness, exact MEO1/blob linkage, absence of orphan or
tombstoned-resurrected blobs, peer replay inventory/partition counts, exact live
client replay readback and completed replay-to-outcome digests. Existing expired
blobs must still be structurally valid; absence of an expired blob is not treated
as loss of a live completed Store. Pending/tombstone-pending prefixes may have no
blob and are not completed by readiness. Native links reject before content read.

Fault/reopen fixtures use the existing signed distinct-ID/key peers and real
TLS/H2/native stores. They also exercise actual Store -> Retrieve -> ACK and
cold reopen after the original client grant expires, without new admission or
HTTP from readiness.

Independent protected cold anti-rollback/absence coverage for the client/peer
replay and mutation documents is still incomplete. Live cached-index/readback
comparison and cross-store consistency do not prove that coordinated cold loss
or rollback is impossible. Whole-host provisioning, retained-route/selected-exit
closure and sustained-capacity health remain explicit acceptance requirements.
This batch alone does not accept S02 or qualify shipping/device E2E.

## Native batch focused receipts

Windows PowerShell5.1, SDK10.0.301, warnings-as-errors, current Protocol source
cutover. Initial integration run `artifacts/s02-native-recovery-20261010/focused-01`
passed37/0/0/native0 (37 exact names/cases/executions). SHA256 of its TRX:
`EC22C7C2190DA6771A90FF5837697A65DE9EF8188F364864696783A178C5D2C2`.

The broader `focused-02` solution command exited1: integration38/1/0 plus
unit13/0/0. Its failure is retained, not relabelled PASS. The new tombstone fixture
used a fixed peer timestamp older than the server-authored Store; native mutation
validation correctly rejected it. The test now uses the actual Retrieve/ACK APIs
and keeps the same expiry and mutation bounds. Review also corrected the initial
native replay file bound to preserve the neutral primitive's maximum supported
cached outcome; a one-scope maximum-size cold-open regression passes.

Final matching command:

```powershell
dotnet test XNode.slnx --configuration Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentHostNativeRecovery|FullyQualifiedName~CurrentHostRecovery|FullyQualifiedName~DurableMailboxCapabilityReplayJournalTests' --logger trx --results-directory artifacts/s02-native-recovery-20261010/focused-03 --verbosity minimal
```

Terminal native0; **52/0/0**, with exact52 name/case/execution mappings. Integration
39/0/0 (reported3m7s) and unit13/0/0 (358ms); these are test durations, not total
build/wall-clock time. ProfileGenerator has an exact empty0/0/0 filtered receipt,
not a suite PASS. Node outputs are Release; the solution invocation builds its
Protocol project references as Debug. This is source evidence, not a shipping
package/configuration qualification.

All receipts under `artifacts/s02-native-recovery-20261010/focused-03`:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_08_43_14_net10.0.trx` | `8FBF26EAE66D6B446DB553ACA093B924D42AC749AE76346C28637D98539DF296` |
| `nikit_SURFACE-LT_2026-10-10_08_46_16_net10.0.trx` | `6FB82692575704948E89573EBCEFCA8072D87E494A3D1E8803D36448097A8C11` |
| `nikit_SURFACE-LT_2026-10-10_08_46_17_net10.0.trx` | `BED2946729BE13F9AE4B4E238D268A27A15E9649B2248C108A3C53A508F280E7` |

## Matching canonical Node full

`artifacts/test-gate-20261010/node-native-recovery-full-01` is terminal
Completed/native0, not a running observation. Windows PowerShell5.1.26100.9457,
SDK10.0.301; build/preflight/test/qualification all exit0. Started
`2026-10-10T03:50:16.2237011Z`, finished `2026-10-10T04:21:58.2511358Z`.

**1390/0/0**, exact1390 cases/executions and2130 unchanged captured inputs;
`FullAccepted=true`. Integration1028, ProfileGenerator107 and unit255 all pass.
The predeclared union contains the three previous Node full02 receipts, the
earlier91-case current-consumer receipt and all three final focused03 receipts.
The original focused02 fixture FAIL is preserved separately, not treated as a
passing reference or waived assertion.

Receipts under the run's `full` directory:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_08_51_07_net10.0.trx` | `49C864FFD0425DD6321121A4DAEF367EEB36975DAFDF4FB1E4A821918A7B4CF2` |
| `nikit_SURFACE-LT_2026-10-10_09_20_07_net10.0.trx` | `08A0EC8F191AC838BD0DAE696418AD15DB57231BD44A7417F8A07E60C9E6A145` |
| `nikit_SURFACE-LT_2026-10-10_09_20_33_net10.0.trx` | `B6448A37E7842A96CF9CD89659C762A5FBFA712E6497F64B38AB80754383BF2F` |

The separate external/no-mock smoke and multi-node rehearsal are both terminal
native0. The existing
Shared/Protocol full receipts are not rerun or relabelled by this Node batch.
This full qualifies the current implementation package, not the outstanding
independent cold-protection/provisioning boundaries or whole-stage acceptance.

## External/no-mock smoke

PowerShell7.5.4, `deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode
external -ManagedExternalProfile backend-external -RequireRouterNoMock`;
run `deep-devops/artifacts/s02-native-recovery-20261010/smoke-01`.
Terminal native0. Fixture validation and ten compatibility-runner tests pass;
these are not ten physical device scenarios. The runtime gate records no hard
or soft failures, no warnings, actual router transport `running` and
`routerTransportMocked=false`. The two selected runtime/topology files pass the
run's secret scan; this does not qualify other artifacts for upload.

This isolated Development transport lane uses external storage/file/push
services and real Xray. It does not provision current production mailbox
authority or prove contacts/messages/attachments/groups on installed devices.
Only its own `deep-integration` containers/volumes were removed by the script;
the existing `deep-dev` stack was preserved.
Runtime gate SHA256:
`1CCDE50A06ED3DB5CBC2498C28B7EC9CE18A759D600EBD57C3A2A9139AFD09C9`.

## Three-node no-mock rehearsal

PowerShell7.5.4, `deep-devops/scripts/multi-node-rehearsal.ps1` without
`-AllowMockRouter`. Terminal native0; run
`deep-devops/artifacts/rehearsals/multi-node/20261010T043622503Z-e8ad5309923d`.
The source-cutover image was rebuilt. All three distinct routers run real Xray,
register with the isolated Registry and have no reconciliation issues.
Each rejects privacy contact with503 without verified authority; this tests
honest unavailability, not successful current mailbox/onion delivery.
The script removed only its own `deep-multi-node-rehearsal` containers/volumes.
The pre-existing `deep-dev` stack was not restarted or reset.
Topology receipt SHA256:
`BB4BB981C3B946A2B510399C785793FCF0D056299C0E76AECC2D709E9C6506E4`.

This completes the required external transport/topology checks for Node source
commit `1c38f45`. It does not accept S02, qualify production authority or count
as any of the four required physical device flows.
