# S02 — current native ONION terminal

Date: 2026-10-04. Source baseline: XNode `80b605e074a4125a27fff1cf2f47965ecc8b5494`,
Protocol `73f045491c7ca59dfcfdab21d161703e9df21238`,
root `5225d3906d18276edadf97b0ceada1a165ee3bf4`.
Sole current status remains [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
Admission/ordering contracts remain DR-0081/0083/0086/0087; no protocol byte,
public Protocol API, journal generation or authority activation was added.

## Connected implementation

The actual `NativeMailboxExitDispatcher` no longer uses the retired adapter,
raw `Verify` authority or old readiness DTO. All three binary operations call
the same current receiver/coordinator with the receiver's actual protected
operation owner. A split receiver/coordinator rejects before either owner can
mutate. Missing current composition remains unavailable, without a fallback.

Length bounds precede allocation. Bounded requests consume the existing ingress
budget before canonical operation/version checks and dependency resolution.
Captured bytes cannot change during a
dependency callback. Current admission authenticates the signed selected pair,
issuer and holder before the existing memory-only verified-holder budget; both
resource budgets use monotonic time, not host UTC or authorization time.
Existing protected interval, revocation, signing custody, native replay/outcome,
exact intent, writer, two-replica quorum and callback fences remain mandatory.

There is no second dispatcher-side outcome/journal. Success comes only from
the existing guarded native owner. Partial Store quorum or a failure after
current dispatch starts remains unknown with no success bytes. Exception types
cannot prove that neither store committed. Cancellation preserves existing
pending work, without replacement nonce/body or extended grant validity.

## Tests and diagnostic classification

The old `NativeMailboxIngressBindingTests` raw-source/ready-DTO fixture was
removed, not retained as an alternate positive path. Its 17 cases are mapped to
the signed current `CurrentMailboxPeerHttpTests.NativeIngress*` owners:

| Previous invariant | Current cases |
| --- | --- |
| six mismatched outer operations, no authority/replay | `NativeIngressWrongOuterOperationRejectsBeforeAuthorityOrDurableReplay` |
| three matching operations still require independent authority | `NativeIngressMatchingOperationStillRequiresCurrentAuthority` |
| six otherwise valid signed counters survive wrong outer operation | `NativeIngressWrongOuterOperationCannotReserveAnOtherwiseValidSignedRequest` |
| malformed input still consumes the ingress budget | `NativeIngressMalformedRequestsConsumeBudgetWithoutTouchingCurrentOwners` |
| own caller bytes before a dependency callback | `NativeIngressCapturesCallerBufferBeforeDependencyCallbacks` |

Current authority loss conservatively returns unknown after invoking the native
owner, not a fabricated terminal absence proof. Those cases additionally assert
no replay/intent/mutation/HTTP change. The real signed request then reaches its
actual operation, including durable exact outcome custody.

New cases cover Store/Retrieve/ACK -> exact cold reopen, both real stores,
lost Store/ACK response reconciliation, wrong holder before replay/intent,
callback expiry, missing current composition without resolving the retired
adapter, split owners, and retired/unknown outer request versions.

`NativeOnionThreeDistinctHostsCompleteCurrentStoreRetrieveAckAndReplayReconciliation`
uses three actual `PrivacyRoutingRuntime` instances, real signed DID2/NETCODEC,
encrypted key vaults and durable entropy/replay, sealed requests/replies and the
current terminal. Its mailbox replication uses actual loopback TLS/H2 and two
independent durable stores, with distinct node IDs/descriptor signing keys.
All three operations return verified onion success; restarting entry replay
rejects the old frame before forwarding. A newly sealed frame with the same
native operation returns the exact outcome without another mailbox write or
resurrection after ACK. The two onion peer calls are in-process, not a masked
carrier, deployed node, installed shipping client or physical device claim.

Initial focused diagnostic: 25 pass / 4 fail / 0 skips. All four failures were
the fixture assertion that accepting another counter must change replay scope
counts. A new counter correctly reuses one grant scope. The corrected assertion
checks the additional durable exact outcome, retaining all negative no-write
checks and positive actual-operation success. No runtime gate was weakened.
The earlier compile attempt failed on a missing exception namespace; fixed
before any executable result was claimed. The separate three-hop test passed
1/1 in 19 seconds. The final focused selection passes 30/30, no failures or
skips, in 2m41s. Full-suite/build terminal results are recorded below.

## Reproduction and final gates

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --no-restore --filter "FullyQualifiedName~CurrentMailboxPeerHttpTests.NativeIngress|FullyQualifiedName~CurrentMailboxPeerHttpTests.NativeOnion" --logger trx --results-directory artifacts/s02-native-ingress/final-focused
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore --logger trx --results-directory artifacts/s02-native-ingress/full
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore -m:1 -warnaserror
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<fresh absolute child of deep-devops/artifacts>'
../deep-devops/scripts/multi-node-rehearsal.ps1
```

| Final gate | Observed result |
| --- | --- |
| Focused native ingress + sealed three-hop | 30 pass / 0 fail / 0 skips; terminal exit 0 |
| Full XNode | 1142 pass / 0 fail / 0 skips; integration763 + unit272 + profile107; terminal exit 0; integration duration30m45s |
| Release build with warnings as errors | Terminal exit 0; zero warnings/errors |
| Docker external smoke, actual Xray | Terminal exit 0; no hard/soft failures or gate warnings; transport running, not mocked |
| Three-node rehearsal, actual Xray | Terminal exit 0; three healthy non-mocked routers, zero reconciliation issues |
| Public documentation | 174 checks pass |
| Selected source/docs/receipts secret scan | 18 selected files pass; not a scan of private operator inputs |

The unfiltered full suite compiles every integration test; no focused project
whitelist was used. The count changes by +13 from the prior 1129: 17 retired
fixture cases replaced by 29 current ingress cases and one sealed three-hop case.
XNode projects are Release; the solution's external Protocol project references
remain Debug in this source-cutover run, as shown by the build output. This is
not a claim about a uniformly Release-built published artifact matrix.

The Docker smoke builds XNode with source cutover, and Registry with its existing
local-cutover package graph. These health/transport checks do not qualify a
matched shipping matrix or current mailbox delivery. The three-node rehearsal
still reports contact 503 at the missing verified-authority boundary; that is not
a successful contact test. Its topology receipt contains only test-owned local
endpoints and identities. Temporary smoke/rehearsal resources were cleaned by
their scripts; the six existing `deep-dev` containers remain running.

Receipt SHA-256 (ignored local artifacts, not committed):

- Final focused `artifacts/s02-native-ingress/final-focused/nikit_SURFACE-LT_2026-10-04_10_32_19_net10.0.trx`:
  `4279f5bab67fc5d019606a32b7c63f21cd67123b4cf7dc885dd1ccebbaef7490`.
- Full profile107 `artifacts/s02-native-ingress/full/nikit_SURFACE-LT_2026-10-04_10_35_28_net10.0.trx`:
  `3cf902a6c02e7d0a9b94175de489a2fd5e9cbbf09db0a81caaabe045563cc1e5`.
- Full unit272 `artifacts/s02-native-ingress/full/nikit_SURFACE-LT_2026-10-04_10_35_34_net10.0.trx`:
  `66ffcd5643b1aca1d914ee2aa741dd1f04b1899071a7197ed5b6dfb1df11b974`.
- Full integration763 `artifacts/s02-native-ingress/full/nikit_SURFACE-LT_2026-10-04_10_35_36_net10.0.trx`:
  `177481776759152bfd943892064f1e2ace768a4d0619b28162f25cfa73aa584e`.
- DevOps `artifacts/s02-native-ingress-20261004/runtime.gate.json`:
  `95f6916d97162c48dd4a7e2de5439f3b0ea544184ea66bfc71c336746e6a726c`.
- DevOps `artifacts/rehearsals/multi-node/20261004T053504677Z-866f8f08a2b6/test-results/multi-node-topology.json`:
  `5c6d5afacf202f1903cab355a0b9223f212d9140ca846a5ee891a3b26b12647f`.

Source-cutover qualification is not a pinned package/installed matrix or release
approval. Unchanged Protocol/Registry/Shared gates retain the exact separate
matrix in the baseline publication checkpoint; this Node-only change does not
turn their previous package failure/skips into passes.

## Remaining activation requirements

Program still registers the old provider and does not register the current
receiver/coordinator. Its old readiness cannot enable this current terminal.
Whole-host startup/health/recovery/DI, retained-route/descriptor history,
signed retirement, object horizon and sustained quotas remain activation gates
under DR-0084/0086/0087. No production data, node identity, key, device/account,
floor or operator secret was changed for this local implementation.
