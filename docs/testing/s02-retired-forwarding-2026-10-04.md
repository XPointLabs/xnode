# S02 retired authority forwarding removal — 2026-10-04

This is a bounded removal under the auditor's
[S02/S03 execution plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Input Node is `0ed0ccb11f80aabcef0373dabc4b03086c58935f`; Protocol remains
`8989ad6a787cdc8194106a5130fcfa832608e252`. Final pins belong to the root commit.

## Actual change

Remove the unreachable PMA1 authority forwarding client, HTTP handler,
authentication/replay/limiter/options and routed dispatcher: four production
files and eleven exported types. Program already uses the current native
dispatcher and never registered these types. No current admission, transport,
TLS, signature, replay, quota, persistence or receipt check is relaxed.

The six positive tests for the removed forwarding implementation are removed
with it. Contact/onion tests now use their recording `INativeMailboxExitDispatcher`
directly, retaining the same zero-effect assertions on peer/contact/mailbox
boundaries. Eleven negative cases inspect the actual Node assembly for the
removed types. Retired configuration still rejects, including empty objects.
Existing actual-Program TLS/H2 tests still reject all three retired forwarding
URLs before authority reads and exercise current two-store Store/Retrieve/ACK,
cold reopen and exact replay.

PMA1 provider/closure and Protocol DNP1 membership closure consumers are not
removed by this slice. They require a coordinated replacement of their actual
consumers and frozen evidence ownership; this is not full package cleanup.

## Terminal local evidence

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~ContactServiceTerminalDispatchTests|FullyQualifiedName~PrivacyRoutingRuntimeTests|FullyQualifiedName~CurrentMailboxHostCompositionTests.Retired|FullyQualifiedName~ActualRegisteredOwnersCompleteNativeStoreRetrieveAckAndColdExactRetryOverPinnedHttp' --logger trx --results-directory artifacts/s02-retired-forwarding/focused
dotnet test XNode.slnx -c Release -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --logger trx --results-directory artifacts/s02-retired-forwarding/full
```

Focused run exits0: **74 passed /0 failed /0 skipped**,32s. No integration-source
compile whitelist is used. Receipt:
`artifacts/s02-retired-forwarding/focused/nikit_SURFACE-LT_2026-10-04_22_20_49_net10.0.trx`,
SHA-256 `4050ec3fac378c95e25cc625f0ea7aa7c3996fad4d9abd76dee669a2752a6f7e`.
The required unfiltered full solution gate completes exit0 on product source
`8298161fb0a1afadf7eefff38ecffbfadd14a178`: **1243 passed /0 failed /0 skipped**
(integration864, profile107, unit272), integration25m1s. Every recorded result is
Passed; no filters or compile whitelist are used. Six removed legacy forwarding
cases and eleven new actual-assembly absence cases explain the net five-case
increase from the prior1238. Previous1238 qualifies the prior source, not this removal.
The full solution maps external Protocol references to Debug and Node to Release;
this is not a uniformly Release shipping package qualification.

Real-Xray Docker smoke exits0 on a fresh retry: ten fixture-runner contract tests
pass and runtime failed-check count is zero. The first attempt fails before
runtime because the MCR runtime-image metadata HEAD request returns EOF; its
failed receipt is retained. Both runs clean their disposable resources.
Smoke uses disabled-mailbox development composition, not positive current
enrollment or physical delivery. Required three-node rehearsal runs separately
after smoke cleanup and exits0: three registered nodes, real non-mocked Xray,
zero reconciliation issues. Contact503 remains fail-closed, not positive contact
or mailbox delivery evidence. Its disposable resources are cleaned; all six
existing deep-dev containers remain healthy and running.

| DevOps retry receipt | SHA-256 |
| --- | --- |
| `artifacts/s02-retired-forwarding/transport-smoke-retry/runtime.gate.json` | `f7c110c9026cd89332151d0eb6c3d6d578d0f1a436046e5a05df6fbe27d3e4a1` |
| `artifacts/s02-retired-forwarding/transport-smoke-retry/runtime.snapshot.json` | `24e2d0e8fe7d01103a09dfd8f03dffb7f6f4645442bad8dc6e39cc8d39e385aa` |
| `artifacts/rehearsals/multi-node/20261004T172528392Z-56c78ce0471b/test-results/multi-node-topology.json` | `5e3ddf7305c2e20368f7e9e8063154a3e511a8fd9613c11bd72f914d3bc7c339` |

| Node full receipt under `artifacts/s02-retired-forwarding/full/` | SHA-256 |
| --- | --- |
| Integration864 `nikit_SURFACE-LT_2026-10-04_22_21_55_net10.0.trx` | `403ef8dc7178f3fa43e397a49f2d88b7abbcc4b8a8ec83ab5a011adf283cfe89` |
| Profile107 `nikit_SURFACE-LT_2026-10-04_22_47_02_net10.0.trx` | `1f1d961848c9c99856aea60dabccdebc6e187ee3f4896010c82bc3d06259aa2f` |
| Unit272 `nikit_SURFACE-LT_2026-10-04_22_47_28_net10.0.trx` | `6d4b3730993591eaa074b53e90876f0fc915747fe36ecf13b55539f7e7bf4988` |

No production host, device, account or operator secret is changed. Current issuer,
renewal, sustained lifecycle, shipping composition and physical qualification
remain open. Contacts/messages/attachments/groups physical matrix remains0/4.

## S00 continuation: compiled PMA1 provider/cache removal (2026-10-05)

Input Node `f2ef177754369bc0da589c5f5db3e2f14c95fd9b`, Protocol
`78dc7a9ee6e94562a820ce7fa2a034aa5cff22ea` (documentation-only change from
`d1ccb573d552960f0c1cb21a655483f4065e74d5`). This continuation follows the
remaining compiled dependencies of the reproduced Protocol package blocker;
it does not activate another stage or repair that package gate by itself.

Remove `ProductionMailboxAuthorityRuntime`, `ProductionMailboxClosureRuntime`
and `ProductionMailboxTopologyRuntime`:29 provider/cache/fanout types.
Program already used current DID2/native owners and rejected the retired
configuration. The remaining development-only helper cannot accept a production
authority options object or activate a production topology. Its non-development
activation now rejects unconditionally. No current admission, TLS, time,
revocation, native peer/quorum, replay or custody body is changed.

The retired provider's89 cases were all Passed in the previous source's actual
922-case integration TRX recorded in the lifecycle checkpoint. Seven obsolete
closure cases and one PMA1 composition case are removed with their implementation;
three capacity codec cases are preserved verbatim in `MailboxCapacityCodecTests`.
New29 negative cases inspect the actual Node assembly for the removed public and
internal types. This is retired-runtime removal, not deletion of unexplained
failures or successful current coverage. The previous1301 full result belongs
to its unchanged earlier source, not this removal. The final full count1233
matches1301 minus89 provider cases,7 closure cases and1 composition case,
plus29 actual-assembly absence cases.

Whole solution source-cutover Release build completed exit0 with0 warnings and
0 errors (the solution maps external Protocol references to Debug). Focused
current host/admission/peer/activation/capacity verification completes terminal0:
287 passed,0 failed,0 skipped,28m53s. The mandatory unfiltered full completes
terminal0:1233 passed,0 failed,0 skipped (integration854, profile107, unit272).
No release claim is made. Protocol retains its
PMA1/PMR1 governance/membership consumers and the MAU2 source/MCG2 package gate
failures. No frozen bytes/API snapshots or package assertions were repinned.

The current-source real-Xray Docker smoke and three-node rehearsal each complete
terminal exit0. Smoke has zero failed runtime checks and no mocked router;
the fixture-runner's ten contract cases are not physical message tests. Rehearsal
has three registered nodes, zero reconciliation issues and real Xray on all
three. Contact503 on each node is the expected missing-authority rejection,
not contact or mailbox delivery. Both scripts clean only their owned disposable
projects; the six existing deep-dev containers remain healthy and untouched.

| Current removal DevOps receipt | SHA-256 |
| --- | --- |
| `artifacts/s00-retired-provider/transport-smoke/runtime.gate.json` | `d9cb18cc8401f4657c4e0777d0bc867fda4591cee2a057c38491091a957c00b3` |
| `artifacts/s00-retired-provider/transport-smoke/runtime.snapshot.json` | `b3d488f0ab99ded0315d2319060e6ac4400463a2565f55c9d02b6563da2278b3` |
| `artifacts/rehearsals/multi-node/20261005T020014332Z-04ccb2a38859/test-results/multi-node-topology.json` | `d134098e9d66b1e915b063b3fd48a6466b0250b05ea57e3efb3b5283764011c5` |

These artifact paths are relative to deep-devops. Focused discovery enumerated
287 cases; the final TRX independently records287 Passed results. Receipt:
`artifacts/s00-retired-provider/focused/nikit_SURFACE-LT_2026-10-05_06_44_31_net10.0.trx`,
SHA-256 `cf53d056920d51ecb9cf977e353edd00cdd9a570e84d8f50d73d7dbe381980c7`.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~MailboxClientActivationGuardTests|FullyQualifiedName~MailboxCapacityCodecTests' --logger trx --results-directory artifacts/s00-retired-provider/focused -m:1
dotnet test XNode.slnx -c Release -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --logger trx --results-directory artifacts/s00-retired-provider/full
```

The full gate uses the same source inputs with no filter or compile whitelist.
All three terminal Completed TRXs contain only Passed results. Integration
takes29m22s, profile21s and unit27s. The actual full-build Release Node assembly
SHA-256 is `26b34224c52d2a3778bea0de54e0dcfb79a2100cae931612fea1b945c0887672`.
The solution maps external Protocol references to Debug; this is not a uniformly
Release package or installed-client qualification. No source/test inputs are
changed while execution is live.

| Node receipt under `artifacts/s00-retired-provider/full/` | SHA-256 |
| --- | --- |
| Integration854 `nikit_SURFACE-LT_2026-10-05_07_14_08_net10.0.trx` | `c7e459b9612d47384f666a7b8453f6cb696d062b0560583d66ce3eb8a67fb3d2` |
| Profile107 `nikit_SURFACE-LT_2026-10-05_07_43_33_net10.0.trx` | `0bb2d4d88dced27e22a7af8026ef7c86440473529e8bb8b0eccf6983b32d04ff` |
| Unit272 `nikit_SURFACE-LT_2026-10-05_07_43_57_net10.0.trx` | `84dbad08d43719eca72d798dafff2c7a97c590017293cae4f53334a0a861fed3` |

Sequential downstream Registry solution build with both local/source cutover
properties and warnings-as-errors completes exit0 with0 warnings/errors.
Registry/test projects map to Release, linked Node/Protocol/Shared to Debug,
including the existing test-internals/recovery seam. The existing
`ActualPrivateIssuerHttpsForwarderClientVerifierAndConfiguredNativeMailboxCycle`
then passes1/0/0, terminal0,39s on that rebuilt graph using the approved
disposable PostgreSQL wrapper, lane `s00-retired-node-grant`. Its invocation-owned
container and tmpfs database are removed; the six deep-dev containers remain
healthy. Registry runtime/test sources are unchanged. Receipt, relative to
deep-registry-api:
`artifacts/s00/s00-retired-node-grant-8bcd868c509848089af4e7acb2a8d883/nikit_SURFACE-LT_2026-10-05_07_46_50_net10.0.trx`,
SHA-256 `632c56c06969cb9a698e4c9d30a3ca6f9257cdef7fd75492903369f6e60fd505`.
The previous Registry full348 is not a new full result on this Node graph.
This connected scope still uses synthetic resolver attestations, holder and
ciphertext; it is not owned Shared/E2EE, selected masked carrier or physical
delivery. Earlier unexplained HTTP503/native-access/ACK-setup failures remain
unclassified, not declared repaired by a later passing execution.

While the full gate runs, Protocol documentation-only commit
`981ab767a61c5b364eea7472fe623d12bc24750d` replaces the stale qualification
guide with links to current normative owners and the reproduced S00 blocker.
No Protocol runtime, project, registry, API/resource snapshot or test input is
changed. Its ten local links and selected one-file secret scan pass; this
documentation correction does not repair or requalify the package graph.
