# S01 retained-read private forwarding candidate

Date: 2026-10-07. Sole semantics:
[CONTACT-RESOLVER §3.7.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md#373-current-retained-retrieve-issuance),
[DR-0104](../../../docs/survival-program/decisions/DR-0104-current-retained-retrieve-issuance.md).
Matched issuer/source and its preserved full FAIL are in the
[Registry receipt](../../../deep-registry-api/docs/testing/s01-retained-private-issuer-2026-10-07.md).

The actual HTTPS client verifies the holder signature, requires explicit private
kind/horizon, signs the independent retained purpose and preserves the exact
request deadline. The success still requires independent current authority
verification by its caller; parsing a response is not holder or issuer custody.
Unknown/cross-fed kind, horizon, role, result, disposition, deadline and holder
proof reject before HTTP. Standard HTTPS validation is unchanged. Existing
public AcquireMailboxGrant dispatch explicitly uses CurrentRoute/zero horizon;
there is no automatic current-miss fallback to retained reads.

Release source-cutover solution build completed terminal0, zero warnings/errors.
Final focused157/0/0 terminal0 includes all147 prior cases plus10 new executions.
Receipt `artifacts/s01-retained-private-forwarding/focused/retained-private-forwarding.trx`,
SHA256 `1FBED31E351C2129EBF52F4147FCC24ACED4B0C175BDFFA7BB833FEA9F7B6950`.
This is not qualification of the pinned shipping package graph.

## Original full launch and input custody

Shared prelaunch input custody is the original3703-input Registry manifest,
SHA256 `093A66A54320EEF80D6EC72207873F4EA56DC8BFAFD2A70F16B04907DC9F649D`,
captured at18:33:21.6441375 local time. A premature Node full started at18:32:39;
its exact verified test-process tree was stopped, terminal-1. Its incomplete
`artifacts/s01-retained-private-forwarding/full` is not acceptance evidence.
No unrelated application, device, container or data was stopped/reset.

The qualified original full started at18:34:57.638753, after capture, with:

```powershell
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --no-build --no-restore -m:1 --logger trx `
  --results-directory artifacts/s01-retained-private-forwarding/full-after-capture --verbosity quiet
```

Original full completed **terminal1:1339 Passed /1 Failed /0 Skipped**
(Integration981/1, ProfileGenerator107/0, Unit251/0). Existing
`CurrentMailboxRevocationRefreshTests.ActualHttpConsumerAndNativeRefreshResumeBeyondBudgetWithoutEnrollmentOrExpiredAdmission(observed: True)`
failed at line44: its first refresh hit the unchanged30-second deadline during
actual observed-source revalidation, yielding OperationCanceledException instead
of the expected exact IOException for the64-step catch-up budget. No timer,
assertion or authority check was changed. Cause of the elapsed-time increase is
not established. An isolated frozen-binary repeat of both theory cases passed
2/0/0 terminal0 in8 seconds; it does not fix or supersede the original full FAIL.
The full was launched alongside Registry and temporary Docker lanes; subsequent
complete qualification should avoid concurrent CPU-heavy lanes, not relax guards.

Post-terminal matrix verification preserves the exact1330 prior+10 new union,
all157 focused cases Passed in the original full, complete unique execution
mappings and all3703 original inputs unchanged. It reports FullAccepted=false
and terminal1, not green full acceptance. The separate helper was finalized
after terminal to pin all three original Node receipt hashes as well as the
already pinned Registry receipts; the original prelaunch manifest stayed intact.

| Original receipt below artifacts/s01-retained-private-forwarding | SHA256 |
| --- | --- |
| full-after-capture/nikit_SURFACE-LT_2026-10-07_18_35_02_net10.0.trx | `11F35EBC8F28B3AFD8E0DC59DEEA98238DCEDA8CE66FF5743890070ED3E06D2D` |
| full-after-capture/nikit_SURFACE-LT_2026-10-07_19_17_26_net10.0.trx | `395E31E5BB7FDBC8DE5B102F7CF195494D73B1BB2E9BB1FDD6249CA2E45B735C` |
| full-after-capture/nikit_SURFACE-LT_2026-10-07_19_17_52_net10.0.trx | `E89E1F6BE3E642603485D259CB32F61A0824A597F0C147D0D32B1D1CC883F1DF` |
| refresh-budget-frozen-triage/refresh-budget-frozen-triage.trx | `6421F076914CEED9B9CF85487049561AEA5887D61E4899DDEC73850712DC9E5B` |

## Mandatory isolated infrastructure evidence

External/no-mock smoke and multi-node rehearsal both completed terminal0.
They used their own temporary Compose projects and preserved the six original
dev containers/data. The original dev authority remains expired; no new genesis,
issuer keys, state reset or production mutation was used to make it ready.

| Receipt in DevOps | SHA256 |
| --- | --- |
| artifacts/s01-retained-private-smoke-20261007-01/runtime.gate.json | `A4AFA42A7D0002A35B997EE7683143D2CEFC736D4A2AC5A8D5AB3445D4558BC3` |
| artifacts/s01-retained-private-smoke-20261007-01/runtime.snapshot.json | `D9D252065EE60B445F1D56BBBFC55C3C81032FE66E1966C5DDF71C40FEB6E79C` |
| artifacts/rehearsals/multi-node/20261007T133852343Z-ebc75c7444bd/test-results/multi-node-topology.json | `0F09980D7E7207219C895B4CFCF493C968030ABEA89E8380264413D04F86A0BE` |

The multi-node lane proves three running real Xray nodes and intentional privacy
503 without verified authority, not actual private retained issuance or device
delivery. No production deploy/reset, registered identity change, GitHub Release
or main merge was performed.
Final selected changed source/fresh evidence secret scan passed11 files;
root documentation174 checks, contact-machine consistency and governance30/0/0
passed. Neither full FAIL is superseded by these checks.

## Same S01 residual work

Join actual protected two-store RPC18/receipt7 to private Registry issuance,
actual held Shared original-publication/holder/result installation, genuinely
elapsed original-route under current protected lineage, typed original-selection
Retrieve/ACK and matching object/tombstone/replay horizon. Full failures remain
open; source prerequisites do not close S01 or open S02/S04/files/groups.

## Coupled public Retrieve follow-up

The following working-tree increment is separate from the pushed8607c60
private-boundary checkpoint and its original frozen full input set above.
Public Retrieve now selects the original protected read path from the outset,
not on a current-route miss; Deposit is unchanged. The actual DID2 composition
supplies its protected current-source owner. Missing owner/custody fails closed.
Both stores must agree on exact route and horizon; their independently produced
receipts use the retained purpose. The local protected revision/current sources
are rechecked around the entire private issuer exchange. A final authenticated
remote read must still agree before releasing the exact Retrieve success.
Corrupt native state now maps to the existing forwarded unknown-outcome boundary,
without accepting, repairing or adopting it.

Release solution build0 warnings/errors. Corrected focused164/0/0 terminal0
preserves all157 prior case names and adds7 with complete unique execution
mappings. New cases use real independent native documents/roots and pinned
TLS/H2 peer reads/signatures, cold reopen, lost read/receipt/issuer responses,
wrong peer pin before issuer IO, and source/document/cancellation loss after
issuance. The fixture's role issuer/journal remains in-process, not actual
Registry PostgreSQL or device evidence. No elapsed original route is claimed.

Initial focused156/8/0 terminal1 is preserved. Six old consumers incorrectly
used the current-route result verifier for the new retained grant lifetime;
the current verifier's rejection remains explicitly asserted, followed by the
closed actual host retained verifier. One hostile-pin fixture changed a flag
after its HTTP client captured the pin: cold reopening captures the actual
hostile pin and now rejects before remote IO. One corrupt-document test exposed
an unhandled InvalidDataException at the public dispatch boundary; production
now preserves it as the inner cause of the standard unknown completion error.
No timeout, current-only Store check, signature or TLS assertion was relaxed.

| Receipt below artifacts/s01-retained-public-join | SHA256 |
| --- | --- |
| focused/retained-public-join-focused.trx | `B845C1E4DE2AF0334B27CE5F3CFA52789DD978BEB2254E6EFD1C368A7288C712` |
| focused-corrected/retained-public-join-focused-corrected.trx | `D12E81FB45292EE1DFFE21318DFE960DF5C4071CB3CB78F486D93BFE54BC0732` |

This is part of the still-open connected S01 source batch: Shared still expects
the old current-route result boundary. Complete source/case custody and required
full/Docker lanes will be qualified after connecting the owned/native vertical,
not relabelled from the previous private checkpoint. No deployment, release or
physical E2E is performed by this follow-up.

The next coupled working-tree increment changes native Retrieve/ACK admission
to the closed host's exact retained grant-selected pair and the actual protected
Retrieve MGR1 lease. Current Store still enters the current-selection verifier.
Current source/history/root/policy, local admitted node, descriptor custody,
holder, counters and full trusted interval remain independently checked.
The receiver's page/continuation/tombstone/peer proof scope now uses the exact
host-verified grant epoch/membership/reference, not the host's latest selection.
No fallback, reranking or expired grant admission is added. This increment has
now been rebuilt with0 warnings/errors after correcting a test-source build's
closed Protocol constructor and argument-order errors using the existing canonical
reference decoder. The164 receipt predates this native source and cannot qualify
it. A combined focused run now includes those original classes plus actual
admission, replica receiver, MGR1 store and peer-HTTP classes in a fresh
`artifacts/s01-retained-public-join/native-coupled-01` directory. It completed
terminal1:429 Passed/1 Failed/0 Skipped,430 executions,43m28s. The exact receipt
`retained-native-coupled.trx` has SHA256
`32A879C4691DB24AD817010D3C3B0A5F7B184B0C47E022F7D509A76753FAA79C`.
`ClientStoreLostRemoteResponseKeepsBothReplaysPendingUntilExactReopenRetry`
returned PartialFailure instead of Durable on exact recovery. Protocol/Shared
builds overlapped near this failure, but CPU/timeout causality is not established.
The test now records bounded failure/elapsed/cancel/status/count diagnostics
without changing its required Durable outcome. This remains the unfinished
connected owner/install/native Retrieve–ACK
batch, not full/physical qualification or deployment.

The native-coupled-01 binary predates the subsequent retention source
change. That source removes the sender/grant expiry cap, matches codec and native
blob limits to the product horizon, and makes Store/ACK private retention stable
across network-authority changes. New actual signed native Store/cold replay/
Tombstone/no-resurrection cases include objects beyond current authority lifetime
and the full horizon; native blob max/max+1 checks are also added. Current Protocol/Shared
Release builds and Node source-cutover
Release solution build completed terminal0,0 warnings/errors. The Node build
still composes external Protocol projects in Debug, not a uniformly Release
shipping matrix. The object-horizon/HTTP/exact-recovery run completed terminal0:
5/0/0 in1m28s. Receipt `object-horizon-01/retained-object-horizon.trx`, SHA256
`E85CB9EE3D1821056FFC879AB649442055B2DD10D4068D4302349473A8E790FE`.
Native blob exact maximum/maximum+1 completed terminal0:2/0/0; receipt
`object-horizon-01/native-blob-boundary.trx`, SHA256
`8E4F97ACD7014DDDCE55E5C641C4471AD86E666A13F2017DDE842A5640E2DCAC`.
Independent Protocol codec cases completed terminal0:50/0/0; receipt
`deep-protocol/artifacts/s01-object-horizon/focused/retained-object-codecs.trx`,
SHA256 `CE6F9942CA54DEA54ACCB86B91EBBCB8A7CE6923A87FD54D9C6C97008633336D`.
The previously failing recovery case passed in this current short run; no
causal fix for its original intermittent failure is proven. The older receipt cannot
qualify these changes or elapsed
operational history. No original failed full receipt is replaced or reclassified.

A further test-source increment now covers the missing cross-selection-epoch
scenario. It authors a genuinely threshold-signed short original PMT, then an
exact predecessor-bound PMT successor with a higher selection epoch under the
same live PMA policy. A fresh signed DID2 directory proof and the public
protected-history verifier mint the new network context. No raw verified
authority constructor, unsigned epoch override or current-Store fallback is
used. The original selected IDs/descriptor keys, accepted object expiry, native
revocation floors, peer Store/ACK replay and blob/mutation custody remain in the
connected test. Native peer and client replay stores are reopened; the fixture's
network history is in-process and this is not a whole-host DNH recovery,
operational policy renewal, HTTP/device or release claim.
The added scenario and fixture changes are not built or tested yet. The helper
used by the Registry's linked fixture stays in the shared fixture source; the
Node-only successor method is in its separate partial. Defaults for all existing
fixture callers remain unchanged. No heavy Node build/test is launched during
the still-running Shared full gate, whose captured source/binary inputs exclude
this Node-only test graph.

After that Shared full reached terminal, the Node integration project was built
in Release with source cutover: terminal0,0 warnings/errors; its observed external
Protocol dependency outputs were also Release. The first combined eight-case
repeat in `object-epoch-02` completed terminal1:7 Passed/1 Failed/0 Skipped.
Receipt `retained-object-epoch-coupled.trx`, SHA256
`01ED963BB6EBD53297ED4E2266AB690F1CC0E0613E561D66BC6E17BCAADD7C6B`.
The new cross-epoch fixture failed before native admission: it supplied only
generation1 to the public verifier, which correctly requires the full PMT chain
from generation0 before checking captured protected history. The fixture now
supplies the signed original and exact signed successor together; genesis,
lineage and protected-history verification are unchanged.

The corrected integration project build completed terminal0,0 warnings/errors.
One combined repeat of all the same eight cases in `object-epoch-03` completed
terminal0:8 Passed/0 Failed/0 Skipped in1m23s. Receipt
`retained-object-epoch-coupled.trx`, SHA256
`4EB6057123A0CA2184CA939389744A71A254B3B76D99A6E9F06AA8C7DCD071A7`.
Read-only qualification confirms the exact prior eight names and unique
result/definition/test/execution mappings. The cross-epoch native read/ACK,
original replica keys, hostile mixed-epoch rejection before reservation,
cold native peer/blob/replay/mutation reopening and no resurrection passed.
Both pinned-HTTPS horizon cases and lost-response exact recovery also passed.
The two revocation-refresh cases passed, but these isolated passes establish no
causal fix for the original full timeout. All original failed receipts remain.
Required current full, external/no-mock Docker and multi-node qualification,
whole-host recovery, shipping composition and physical E2E remain open.

The next whole-solution Node matrix is prepared under
`artifacts/s01-retained-public-join/full-02`, not launched or qualified yet.
Its reference union preserves all1340 original full executions (including the
refresh-budget FAIL), all430 native-coupled executions (including lost-response
recovery FAIL), the corrected eight-case repeat and both blob-boundary cases.
There are1354 exact unique required cases: Integration994, ProfileGenerator107,
Unit253. The reference reader has checked each result/definition/method/entry
mapping and rejects skips or incomplete counters; original receipt bytes remain
unchanged. The pending verifier requires all three actual assemblies, the exact
case/method/assembly union, unique full test/execution IDs, observed process exit
and unchanged prelaunch inputs. Capture is deliberately deferred until the next
Node build, after the still-active corrected Shared full; scripts and this
prepared matrix are not evidence of a passing Node gate.

The whole-solution runner is now queued, not executing a Node build/test yet.
At `2026-10-08T03:23:17.8318408Z` it started as process21720 and held the
actual live Shared full-03 runner9124. It waits for that process's observed exit0
and matching successful terminal/qualification receipt before building Node.
A failed/missing predecessor cannot launch the Node test gate. Build, test and
qualification exits are recorded separately; absent exits cannot pass. The
prelaunch manifest is captured only after the successful whole-solution build,
including all four runner/reference/capture/verification scripts. Syntax,
exact1354 reference mappings and selected script secret scan pass; this is
queue preparation, not a native full or Docker acceptance claim.

## Full-02 terminal and bounded fixture correction — 2026-10-08

The queued runner observed Shared exit0/qualification0, then built XNode.slnx
with source cutover and0 warnings/errors. It ended at
`2026-10-08T05:37:54.0111850Z`: actual test exit1, qualification exit1.
The whole matrix is1353 Passed/1 Failed/0 Skipped. Exact1354 required
case/method/assembly mappings and2183 captured inputs were unchanged;
manifest SHA256 `92AABECA373FBD2179E19AE0D93616AAE554D0809754A7139288F9311FE29A40`.

| Original full-02 receipt | SHA256 |
| --- | --- |
| Integration994: `nikit_SURFACE-LT_2026-10-08_09_50_19_net10.0.trx` | `138FD15102A9765DE7BE347C447C586B52EF3446984A260BBB865E84FF645C48` |
| Profile107: `nikit_SURFACE-LT_2026-10-08_10_36_00_net10.0.trx` | `D6F5958D15C0557B6EBD262E11699831EC48988D19969E89FA9687F6D73ECEF2` |
| Unit253: `nikit_SURFACE-LT_2026-10-08_10_36_21_net10.0.trx` | `B12CF3A61DCC9E9252D5A54964A0A34029B4540F2191451125C8AA6DC60901E9` |

The sole failed case is
`RetainedObjectReadAndAckUseOriginalEpochAfterSignedProjectionAdvanceAndNativePeerColdReopen`.
Its first Store threw `OnionBoundaryException`: the initial trusted-time lease
expired before any projection advance. The signed fixture's hard upper1110 and
trusted upper1105 give a5-second lease; native fixture setup consumed it under
the full run. Production correctly rejected the operation. The earlier full
refresh-budget failure and native-coupled lost-response failure passed in this
full matrix; those passes do not establish a causal fix for intermittency.

The Node-only helper now re-verifies the same signed generation0 protected
history immediately after native fixture setup, before the first Store. It is
restricted to the deliberately short initial fixture. The test asserts unchanged
projection bytes and trusted-time upper. It uses the existing full public
verifier, not a verified-authority constructor, lifetime increase, frozen system
clock or production renewal. Negative callback expiry checks remain unchanged.

Integration source-cutover Release rebuild completed terminal0,0 warnings/errors.
The combined corrected repeat completed terminal0:19 Passed/0 Failed/0 Skipped,
1m49s. `object-epoch-04/retained-epoch-lease-corrected.trx` SHA256:
`24019C311DC6E6C988D52E5A28492FCD7AB01CA957184C3414BF059C26589D99`.
Exact mapping preserves all eight prior coupled cases and the original failed
case, with the full replica-receiver negative expiry/mutation class included.

Fresh full-03 started at `2026-10-08T07:12:45.1541622Z`. Its required union
includes all1354 original cases, all prior FAILs and this corrected19-case
receipt. It first reran Shared's current full verifier, terminal0/all1795 inputs
unchanged. It then builds, captures current inputs and runs the whole Node
solution without a filter. No terminal or current full acceptance is claimed
until its own actual exits and post-terminal qualification complete. Required
Docker/multi-node, whole-host and shipping/device boundaries remain open.

Full-03 reached the same lease error at the subsequent exact Store replay after
native reopen (test line103), not at the first Store. It was stopped on this
observed failure rather than spend the remaining whole-suite time on known
invalid fixture timing. The original capture/console remain intact; its actual
test terminal is-1, qualification is null, FullAccepted=false, and there is no
complete TRX. Manifest SHA256:
`DD05B363530C329AD85C73943A086988AE6440EE4190B8B8E30C5A994C54F7F3`.
It is an aborted failed run, not1354 completed results or passing qualification.

The isolated signed original projection now ends1200 rather than1110, still
strictly before the unchanged1500 role policy. The existing signed directory
proof keeps its30-second freshness bound; neither production timeout nor lease
implementation changes. The successor begins exactly at1200 and uses new
independently signed directory evidence at1206/sample206. The test derives and
asserts the original epoch end, requires the new trusted lower beyond it, and
requires the renewed Retrieve not-before beyond it. Fresh current MGR1/grant
windows remain bounded. The original selected keys, hostile mixed-epoch-before-
reservation, expired old Store rejection, exact ACK/cold replay/no-resurrection
assertions are unchanged. Other fixture callers retain their default behavior.

Rebuild completed terminal0,0 warnings/errors. One repeat of all19 identical
case/method names completed terminal0:19 Passed/0 Failed/0 Skipped in57s.
`object-epoch-05/retained-epoch-window-corrected.trx` SHA256:
`AC02F6E5A280B2B4D75C17E6808E2D19F8B86F682FD932B13431AFC8D1BA9D96`.

Fresh full-04 started at `2026-10-08T07:22:16.9894229Z`; Shared's current verifier
again passed before Node build. Whole-solution build0 warnings/errors, prelaunch
capture2188 inputs/exact required1354 cases at `2026-10-08T07:22:29Z`.
Manifest SHA256:
`80DCC878B54B7E34DA2D7615D1D9DB853241FDB585B9FDCF810BCFE9CFF73C04`.
The run completed at `2026-10-08T08:00:36.0290222Z`: actual build/test/
qualification exits0, **1354 Passed/0 Failed/0 Skipped**. Exact result/definition/
execution-entry mappings preserve all1354 required cases, including every prior
failed case and the corrected19-case fixture. All2188 prelaunch inputs were
unchanged. This accepts this native source matrix, not all S01 or shipping.

| Current full-04 receipt | SHA256 |
| --- | --- |
| Integration994: `nikit_SURFACE-LT_2026-10-08_12_22_31_net10.0.trx` | `A7B4B43A773B142A429E815BC85AD01DB7348F1E70210D55D61450228E2A054B` |
| Profile107: `nikit_SURFACE-LT_2026-10-08_12_58_47_net10.0.trx` | `6FCFD073DC4717D00CD7B201BA2DF8035EDCDB30AC6309D7ECD4E9EF138C4373` |
| Unit253: `nikit_SURFACE-LT_2026-10-08_12_59_10_net10.0.trx` | `2F604435A15A44F15A79A4316CD25C8B1ED08B3EA350E9A6EAB589A40A74B0AB` |

Only after native acceptance, the queued isolated external/no-mock smoke and
multi-node rehearsal executed serially, both actual exits0. The Docker runner
finished `2026-10-08T08:02:17.0562728Z`, with original six dev container identities
preserved. The scripts removed their disposable project containers/volumes;
the retained original stack was not reset. Multi-node receipt directory:
`deep-devops/artifacts/rehearsals/multi-node/20261008T080153162Z-8080df71b67e`.
These infrastructure checks do not assert accepted-object delivery, current
authority readiness in the retained dev stack, production or physical E2E.

This checkpoint update is post-terminal documentation, not one of the unchanged
execution-input claims. Registry connected qualification, known-floor retirement,
whole-host shipping composition and installed/device boundaries remain open.
