# S00 — XNode baseline and first fixture repair

This is test evidence, not a protocol specification or release qualification.
Execution order is owned by the workspace `docs/architecture/IMPLEMENTATION-PLAN-V1.md`.
No production deployment, device installation, account reset or physical E2E was performed.
No production runtime code, wire format or authority policy was changed.

## Source matrix

Branch: `release-candidate/prod-20260909`.

| Repository | Input HEAD |
| --- | --- |
| XPointLabs | `faeb267` |
| xnode | `b5899c90707c7c12b30849f05e0bb3ff9090217b` plus the test changes in this checkpoint |
| deep-protocol | `17a7c8be2b222eb0855d381b5040864dc14b4c9e` |
| deep-client-shared | `cba9f21fd15e33fb48fb3cdb71927cb7b0615053` |
| deep-client-maui | `11f1c8fb8a0d70178fa62ad78e69e93da1bb400a` |
| deep-registry-api | `5c79cb07620915769f673fd4b92624d774ad709e` |
| deep-devops | `af4f833787b2dcb41e8aac7ed8b54d69d4cbdfe3` |

The test graph uses `DeepProtocolSourceCutover=true`: current Protocol project
references, not a claim that frozen NuGet packages or installed clients match.

## Reproduction and results

Run from the xnode repository:

```powershell
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --logger trx --results-directory artifacts/s00/baseline --verbosity quiet

dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --filter "FullyQualifiedName~ContactReplicaTransportTests|FullyQualifiedName~ContactServiceTerminalDispatchTests|FullyQualifiedName~PublicVerifierContractIsPresentWithoutServerRawKeyInputs" `
  --logger trx --results-directory artifacts/s00/closed-boundaries --verbosity quiet

dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release `
  -p:DeepProtocolSourceCutover=true `
  --filter "FullyQualifiedName~ContactAuthorizedPublicationReplicaTests|FullyQualifiedName~ContactReplicaTransportTests|FullyQualifiedName~ContactServiceTerminalDispatchTests" `
  --logger trx --results-directory artifacts/s00/signed-publication --verbosity quiet

dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --logger trx --results-directory artifacts/s00/checkpoint-1 --verbosity quiet
```

Both full runs rebuilt current sources and exited **1**, not success.

| Assembly | Fresh baseline pass/fail | Checkpoint pass/fail |
| --- | --- | --- |
| ProfileGenerator | 107 / 0 | 107 / 0 |
| Unit | 281 / 16 | 282 / 13 |
| Integration | 445 / 3 | 452 / 0 |
| Total | 833 / 19 | 841 / 13 |

There were no skipped tests in either full run. The total increased from 852
to 854: two publication cases moved from Unit to Integration; one pre-HTTP
rejection case and one forged-witness/no-mutation case were added.
Focused results were 1 unit + 33 integration, then 36 integration, all passing.
These overlap the full run; do not add them to its unique-test count.
The final forged-witness test was added after the focused run and passed in
the final full Integration suite. No build warnings appeared in these commands.
After changing the restart test's cleanup to a scoped `using`, a final focused
`ContactAuthorizedPublicationReplicaTests` run rebuilt and passed all 3 cases
with TRX in `artifacts/s00/publication-final`; it is also overlapping evidence.

Local raw TRX files remain under ignored `artifacts/s00/`; they contain machine
paths and are not committed. Their SHA-256 digests identify the exact runs:

| Assembly | Baseline TRX SHA-256 | Checkpoint TRX SHA-256 |
| --- | --- | --- |
| ProfileGenerator | `12422e5b5ef9523340daccf82e32c441a560a279f9410ff5be06059cb9b8c4a1` | `65bfc6614d75dcb993b74face7d2baa3462c1884a06a95ff714b7c8a815efdf9` |
| Unit | `fc0f043e7c22faf8f8b71c96faca3d0c3624417bd91d7e6660022a3e89210ee7` | `e3e40175baa0e6d5d71b279974b4e2b007d6d57456f268226f1a83c45ac33983` |
| Integration | `e176b513f84272d4102d007e3e58eed4b6a268c418f437c01a2dbb659382ba72` | `db6b9d6de876366a1e6f14f3e2fb4520539565fe363e89e04000d5e6c9ea9e7f` |

## Classification of all 19 baseline failures

Six repaired failures were stale harness/contracts, not evidence of broken
HTTP timeout handling, peer-signature validation or durable publication:

| Baseline test | Cause and current check |
| --- | --- |
| `ContactReplicaTransportTests.HttpTransportTimeoutIsOutcomeUnknown` | Untrusted placement rejected before HTTP. Uses a genuinely signed DID2 network/placement; asserts exactly one handler call, cancellation and outcome-unknown deadline. |
| `ContactReplicaTransportTests.HttpTransportRejectsAResponseSignedByTheWrongPeer` | Same premature rejection. Uses signed placement and asserts the handler ran and peer/correlation rejection occurred. |
| `ContactServiceTerminalDispatchTests.ProductionCompositionKeepsContactRuntimeAndReplicaEndpointDormant` | Source-text assertion expected a retired composition method. Replaced by `ShippingDefaultsComposeDormantDid2ContactBoundary`: actual shipping JSON, current DI, unavailable dispatch and no mapped replica route. This is not full Program/Release composition qualification. |
| `ContactPreKeyXpc1ResponseTests.PublicVerifierContractIsPresentWithoutServerRawKeyInputs` | Reflection expected the removed V1 public verifier. Checks the compile-time current DID2 verifier signature and verified installation-plan boundary, private capability construction and null-plan rejection. |
| `ContactAuthorizedPublicationReplicaTests.ExactXpaReservationAndCommitSurviveReplicaRestart` | Synthetic V1 route failed current codec bounds before mutation. Moved to Integration and uses genuine DID2 authoring/verifier, durable stores and saga; replay after restart passes. |
| `ContactAuthorizedPublicationReplicaTests.SameAuthorizationWithChangedAuthorizedBodyFailsBeforeSecondMutation` | Same stale fixture and a capability-construction bypass. Current case uses two valid threshold witness sets for the same authorization/body with different exact requests; verifies permanent conflict and unchanged stored object. A separate forged-witness test proves no reservation/mutation and subsequent valid publication still commits. |

All 13 remaining failures are in `ContactServiceOpaqueFacadeTests`. The
immediate failing prerequisite is the same obsolete `Xpa1AuthorizationTestFixture`
request: current `Xpu1Codec.RequireBounds` rejects its route before the business
scenario. It also mints a sealed authority using uninitialized-object/unsafe
access rather than the public verifier. These tests are retained and failing,
not removed, skipped, or counted as product passes.

| Remaining scenario | Immediate classification |
| --- | --- |
| `CommittedFailpointReturnsUnknownWithoutReceiptsAndRestartExactReplays` | Stale signed-publication fixture; business outcome unverified |
| `PartialReplicaCommitStaysReservedWithoutReceiptsThenReconciles` | Same |
| `ContextMismatchDoesNotMutateAndAcceptedPublishDurablyExactReplays` | Same |
| `ReservedFailpointNeverReturnsCommittedAndRestartFinishesExactRequest` | Same |
| `SameAuthorizationChangedExactBodyPermanentlyLatchesConflict` | Same; rewrite with a genuinely valid exact-request conflict, not forged authority |
| `PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays` | Same; additionally current author/verifier supports permanent publication only, so a signed current invite prerequisite is absent |
| `ReceiptIssuanceHonorsCallerCancellationWithoutReturningAResponse` | Same; cancellation assertion receives fixture ArgumentException before dispatch |
| `PartialAuthorityFailureNeverEmitsTheSuccessfulPartialReceipt` | Same |
| `ResolveUsesPublishedRouteClosureWithoutExternalLocatorLookup` | Same |
| `InvalidSignatureSizeFailsClosedWithoutReceiptEmission` | Same |
| `ConcurrentExactAuthorizationIsConsumedOnceAndOnlyExactReplaysFollow` | Same |
| `RemoteShapedAuthoritiesAreDelegatedAndReceiptsStayCanonicallySorted` | Same |
| `CrossReplicaReceiptSubstitutionFailsClosedWithoutReceiptEmission` | Same |

The immediate harness classification does not prove those runtime scenarios
are correct. Repair them with current signed fixtures, then classify any newly
reached product failure separately. The current publication verifier explicitly
rejects nonzero usage limits/non-genesis publication; do not restore a V1
capability seam to make the invite case green. Reconcile its current contract
and missing producer/consumer under the unified plan.

## Limits and remaining S00 work

- HTTP tests use an injected handler: no socket/TLS, remote replica or device claim.
- The signed ceremony uses test-owned keys/native crypto; no production secrets.
- The two-replica placement fixture does not prove distinct node-ID/receipt-key
  support, node admission, revocation or grant-bound peer quorum.
- No removed admission/journal experiment was restored; DR-0082 remains the baseline.
- S00 is still open: 13 node cases, fresh Registry classification/isolated DB,
  current XPP fixtures and workspace governance drift remain to be completed.
- Release/physical E2E and the S01 admission/lifecycle decisions remain open.

## Checkpoint 2 — current facade inputs, unsafe fixture removed

Input xnode HEAD: `232de89e6fbf37bf9546b94aa73b43e00283c46e`; workspace HEAD:
`93f14532f2c1c57433d541d76cb5b65745591e1b`. Other source inputs above are unchanged.
The checkpoint-1 tables and its remaining-work list above are historical results.

All 15 `ContactServiceOpaqueFacadeTests` moved from Unit to Integration, retaining
their assertions and durable/fault scenarios. `CurrentContactPublicationFixture`
owns one class-scoped signed DID2 ceremony and disposes its test-owned keys.
Production `VerifiedContactPublicationAuthorizationVerifier` authenticates each
publication; normal context acceptance matches exact signed placement tuples.
The stale-view fault remains an explicitly injected test result, not authority.
Receipt keys are selected from the signed publication placement. Successful
publication/replay, reconciliation and restarted-saga results additionally pass
`DeepIdV2PublicationCommitVerifier`, including both current replica signatures.

Removed the unused 373-line `Xpa1AuthorizationTestFixture` (uninitialized-object
and unsafe private-field authority construction), the unused historical base64
route and manual legacy record writer. Removal is recoverable from Git. No
failed scenario was dropped or skipped. The exact-request conflict now uses
two genuinely signed witness sets for one body/authorization, as in checkpoint 1.

Cancellation waits for the actual receipt callback before cancelling the caller;
it no longer depends on a two-second timer. Focused facade runtime fell from
3 seconds to 811 milliseconds in these runs; this is a harness observation,
not a product performance SLO.

Commands (from xnode):

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release `
  -p:DeepProtocolSourceCutover=true --filter "FullyQualifiedName~ContactServiceOpaqueFacadeTests" `
  --logger trx --results-directory artifacts/s00/facade-verified-receipts --verbosity quiet

dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --logger trx --results-directory artifacts/s00/checkpoint-2 --verbosity quiet
```

Both commands exited **1**. Focused: **14 passed / 1 failed / 0 skipped**.
Fresh full source run: **853 passed / 1 failed / 0 skipped** out of 854, with
no build warnings. Moving cases between assemblies did not reduce test count.

| Assembly | Pass / fail | Checkpoint-2 TRX SHA-256 |
| --- | --- | --- |
| ProfileGenerator | 107 / 0 | `8821f26c6a5c216102806a30ba47b2398aa6dbc5dbfbd8f211b7b9ccb944b57b` |
| Unit | 280 / 0 | `835cd477ab6afc21db6ebfc5c366d7fc59d697235069db3825a74f37bcbfa9f9` |
| Integration | 466 / 1 | `c59e220c3ed85efd7add3e502e482991f30c8fcefa5a5de038bd5f30d2465fbd` |

The 12 previously failing reusable-publication scenarios now reach and pass
their intended runtime branches. The remaining case is still
`PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`. Its prerequisite
assertion explicitly rejects a reusable fixture where a one-time publication is
required. No one-time publication, consumption or receipt is claimed by this run.
Source inspection independently confirms the gap:

- `DeepIdV2PublicationAuthorityAuthor` emits publication kind 1 / usage limit 0.
- `Xpa1PublicationAuthorizationVerifier.VerifyAsync` rejects nonzero usage and
  non-genesis requests with `UnsupportedPublicationKind` before admission.
- The current codec's ability to parse kind 2 does not supply a signed current
  invite author/lineage/verifier. Do not bypass this check or reintroduce V1.

Classification is now a missing current producer/consumer prerequisite with
the positive scenario retained, not the old V1 bounds exception. Close the
current invitation contract and implement its actual author/consumer before
making that scenario green. S00 remains open for that prerequisite, signed
XPP/unit-fixture audit, fresh Registry/isolated DB classification and root drift.
Host UTC here is a persistence test clock, not protected-time admission evidence.
No Program/Release graph, socket/TLS, production deployment or physical E2E was
qualified by this fixture repair.

## Checkpoint 3 — current signed prekey exhaustion and recovery

The new actual DID2 claim scenario reproduces a product defect rather than a
V1 fixture exception: after 32 unique one-time claims and two signed permitted
last-resort claims, a fresh request returns `OutcomeUnknown` instead of the
existing `PreKeysUnavailable` / `None` result. The focused regression failed
at that exact status assertion before the fix (exit 1).

The local coordinator now emits a typed refusal only when selection proves
the signed last-resort limit exhausted **before** reservation/signing/peer
mutation. The runtime catches it only around that local selection, rechecks
current authority and returns the existing empty refusal. Pending reservations
are checked first; arbitrary errors, uncertain writes, peer loss and callbacks
cannot use this refusal to claim no mutation. No wire, configuration, public
Protocol API, state generation or signing key changed. Production candidate
activation remains disabled; [operator behavior](../operator.md) documents it.

The fixture authors matching signed XPS1/DPK2 reuse limits with the real current
device key, not reflection/uninitialized authority. The production final
committer verifies the complete DID2 public inventory; both selected stores
commit XIC1 before claims. Actual HTTP peer client/endpoint authentication and
the current claim codec/signature verifier execute through an in-process
handler. This proves neither actual socket TLS nor current-recipient DCR/DPH2
handshake, KEM decapsulation, shipping Release composition or physical devices.
The public KEM descriptors remain test-only bytes, not an exchange claim.

### Legacy scenario transfer

| Removed V1-capability Unit duplicate | Current signed replacement and preserved invariant |
| --- | --- |
| `ConcurrentOperationsNeverReceiveTheSameOneTimePreKey` | `ConcurrentExhaustionHonorsSignedLastResortLimitAndExactReplayAfterRestart`: all 32 concurrent anonymous-exit operations, distinct nonzero keys, counters zero, complete generations 1–32, current Merkle paths and both signatures |
| `ExhaustionUsesLastResortOnlyWithinSignedCounterLimit` | Same scenario: signed limit 2, counters 1/2, zero one-time IDs, refusal on next operation, identical durable claim snapshot hashes before/after refusal and reopen |
| `LastResortClaimPersistsCanonicalXpi1SentinelAcrossRestart` | Same scenario plus last-resort loss/recovery theory: exact embedded V2 manifest, index 0xffff, empty proof, exact whole-result replay after restart; limit-1 and limit-2 inventories |

The new prepare/complete response-loss theory reserves the final last-resort
key, loses the authenticated response, reopens and requires a new operation to
stay `OutcomeUnknown` without another reservation. Only original exact-operation
reconciliation completes generation 33/counter 1. Exact replay is retained;
after completion the new operation is correctly refused without mutation.
This exercises both peer prepare and peer complete loss boundaries.

Three old test cases were removed after their business assertions moved into
one new Fact and two new Theory cases. Counts are not a proof of semantic
equivalence; the table above is the mapping. The remaining unsafe inventory
fixture and rotation/quota/retention/XPC legacy scenarios are still open, not
silently accepted as current signed evidence. No scenario skip was introduced.

### Commands and evidence

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests --logger trx --results-directory artifacts/s00/current-prekey-after-fix --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests|FullyQualifiedName~DeepIdV2ClaimJournalTests|FullyQualifiedName~DeepIdV2PublicationFinalCommitterTests|FullyQualifiedName~DeepIdV2PublicationCandidateAuthorityTests' --logger trx --results-directory artifacts/s00/current-prekey-recovery --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter FullyQualifiedName~CrashAtCompletion_ReconcilesOnlyTheSameReservedTuple --logger trx --results-directory artifacts/s00/current-prekey-crash-isolated --verbosity quiet
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00/prekey-checkpoint-3-final --verbosity quiet
```

Initial runtime selection after the fix: 12/12, exit 0. Extended selection:
24 pass / 1 fail / 0 skip, exit 1. The extra failure is Windows native
`MoveFileEx` returning access denied in `CrashAtCompletion...afterReplace=true`
**during prerequisite reservation, before the injected crash**. Its cause is
unverified; it is not discarded as a test pass or fixed by this change. The
isolated crash theory passed 2/2 (exit 0), and both subsequent full runs passed
that case; filesystem nondeterminism remains an investigation item.

Before removal of migrated duplicates, full source: 856 pass / 1 fail / 0 skips
out of 857. Final full source: **853 pass / 1 fail / 0 skips out of 854**, exit 1,
no build warnings. ProfileGenerator 107/107, Unit 277/277, Integration 469 pass /
1 fail. The sole final failure is still the explicit signed one-time-invite
producer prerequisite from checkpoint 2; no invitation success is claimed.
All three new prekey cases passed in the final full run. Repetitions/subsets
are not additive unique coverage. Live external smoke/multi-node/device gates
were not run or qualified by this local business slice.

| Raw TRX (ignored, machine paths not committed) | SHA-256 |
| --- | --- |
| Regression before fix | `1f11140e572da0965437a349648f312d393409678c9e4a2ced37a7a851939c93` |
| Runtime selection after fix | `688d1f22be061695f8039d6073df4238ec52e79d996357d7fd0393dd99abba8b` |
| Extended selection including Windows failure | `886fb084ac6ccd548a6d74bcba5a2b66ed7b520b2f0fa91243f40b4d2d7f990e` |
| Isolated crash theory | `45dbba9cde0cac5696f986e71b21f8f4143405baff7d97dd936149d590971ec9` |
| Final ProfileGenerator | `3f567e3f97fc95a7b14bd530a3207f3651f719ba1a3a9505ff9b8f68f05bcba2` |
| Final Unit | `5b8bc213a23d240ed3c23dcdb4c4d9130fb6dea26a4ccfc80950e668696116d8` |
| Final Integration | `0fd10311292f7b96bd868fb0b373375bba27b4b47940c0d70e694b00a04a804d` |

## Checkpoint 4 — signed inventory lineage instead of V1 capabilities

Input xnode HEAD: `72fdc050027ccb4b025d7368e8e9eb375b8851d6`; workspace HEAD:
`0d60817aafdcc41b37677138c1b7440f463215cb`. Protocol input is unchanged.
This checkpoint changes test authoring/coverage only, not runtime behavior,
wire, public APIs, configuration, retention or production activation.

The fixture now authors public signed XPI1/DPK2/XPP1 successors for epochs
1–14 while its real device key is owned, then zeroes that key as before.
Each successor binds the exact domain-separated predecessor hash. One-time
IDs are canonical and sorted, and the complete Merkle root is re-signed.
No private-key export, retained authoring delegate, reflection or fabricated
verified capability was added. KEM descriptors remain test-only public bytes;
no KEM exchange or decapsulation is claimed.

Six new `DeepIdV2InventoryLineageTests` cases stage bounded candidates through
the actual journal and invoke the final committer's current-proof, device,
complete-inventory and selected-placement verification on both replicas:

- all 14 signed epochs commit, their XIC1 pair verifies, and current exact
  publication/manifest/receipt survive reopening;
- both retained epochs (13 and 14) return their exact original receipts without
  changing active-state hashes after the full rotation;
- signed skipped-epoch/wrong-predecessor candidates reject with cryptographic
  `InvalidLineage`, do not mutate/fork the service, and a valid successor still
  commits afterwards;
- authorized same-epoch and same-operation conflicts preserve active state,
  persist a fork marker and reject reopening/original-operation retries;
- an invalid device signature at the same epoch rejects with cryptographic
  `VerificationFailed` before service mutation or a fork marker.

| Removed V1-capability Unit scenario | Current signed replacement |
| --- | --- |
| `SuccessorRequiresMonotonicEpochAndExactXpi1Predecessor` | Valid succession through epoch 14, retained replay and both `SignedButUnacceptedLineage...` cases |
| `SameEpochOrPublicationOperationWithChangedInventoryForkLatches` | Both `AuthorizedInventoryConflict...` cases, plus unauthenticated same-epoch rejection |

The old wrong-predecessor assertion latched a service fork using an unsafe V1
capability. It is not imported into DID2: the current normative owner
`CONTACT-RESOLVER-V1` section 3.3.1 and current lineage verifier require the
exact accepted predecessor, and distinguish an unaccepted bad chain from an
authorized same-epoch/operation conflict. No verifier was weakened to perform
this transfer. Current forks remain durable and fail closed.

The CAS tests use independent test-owned staging journals per attempt to reach
the independently authorized service store. They do **not** exercise the
terminal's earlier same-operation fragment conflict guard, socket/TLS or a
physical endpoint. Existing terminal/peer commit tests passed in the combined
selection. Separate node-ID/receipt-key support, older-epoch claim settlement,
full service renewal/retention and shipping device composition remain open.
The remaining V1 fixture/quota/recovery scenarios were not silently deleted.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~DeepIdV2InventoryLineageTests|FullyQualifiedName~DeepIdV2PublicationFinalCommitterTests|FullyQualifiedName~DeepIdV2PublicationCandidateAuthorityTests|FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests' --logger trx --results-directory artifacts/s00/rotation-focused --verbosity quiet
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00/rotation-checkpoint-4 --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter FullyQualifiedName~DeepIdV2InventoryLineageTests --logger trx --results-directory artifacts/s00/rotation-final --verbosity quiet
```

First new selection: 0 pass / 6 fail because the new harness incorrectly
expected `Staged` from the final fragment instead of actual `CandidateReady`.
Those failures occurred before the final committer and are **not** product
regressions. The helper now asserts the exact phase-specific dispositions;
the corrected selection passed 6/6. Combined selection: **25 pass / 0 fail**,
exit 0. Final source full run: **857 pass / 1 fail / 0 skips** out of 858,
exit 1; ProfileGenerator 107, Unit 275, Integration 475 pass / 1 fail.
Build warnings: 0. The single full failure is the existing signed current
one-time-invite prerequisite, not a lineage failure. The post-full cleanup-safe
lineage selection had **5 pass / 1 fail / 0 skips**, exit 1: Windows native
`MoveFileEx` returned access denied while committing the valid successor in
the skipped-epoch case. This is a second observed atomic-replace failure,
now during final inventory commit instead of claim reservation (checkpoint 3).
Its cause remains unverified. Passing earlier selections/full run does not
fix or qualify that storage behavior; the final selection is not green.
Subsets are overlapping evidence, not additional unique tests. No
external/device/production gate ran.

| Raw TRX (ignored) | SHA-256 |
| --- | --- |
| Initial new harness failures | `9f68ef89d779dfbbba91a57949017e5ed77ff5c9e890f172b38f4f9465567bf1` |
| Corrected lineage selection | `eada7b479409d17225d5fc6b735a645ba43073ee6d3a8a9b57d8a6ca91eb5d99` |
| Combined current selection | `b628e0820adeeb4c5c28958b730e20ba63ae921e1e920bf632335937c4975760` |
| Full ProfileGenerator | `0f546c759de99e736cb3bdd7d6424e34adb17e76b15fdc9aef1e4d2b9929d34d` |
| Full Unit | `679d05a4e3b68b96082e7392bfb3a43296212f44a0abf0431f303992e055da79` |
| Full Integration | `9348fcc05b117452d7afcc1852a8ce38a51c9b0ad84b76d736e2fa63b06ab556` |
| Post-full lineage selection, Windows replace failure | `3128e3aadb01b2aa80179b38a01d7bda2c28c50f97780b6fb761148921eeff22` |

## Checkpoint 5 — current claim bindings and native I/O uncertainty

Inputs: xnode `e076f46d3e8940dfb9cf591b39a1b540e5bdcc01`, Protocol
`4af284766b1d9fdfb2a2e3285d248e4d30ca02e5`, workspace
`fbf9cd925e61db43bf1730bcf2ca00343f161487`. This is S00 source evidence,
not activation, a new protocol generation, or release qualification.

Three unsafe V1-capability tests were removed only after transferring their
business assertions to the existing signed DID2 runtime harness:

| Removed opaque-store scenario | Current signed replacement |
| --- | --- |
| `OneTimeClaimAndExactReplaySurviveRestart` | `BothAnonymousExitsCoordinateDistinctClaimsAndReplayAfterRestart`, with exact member/manifest, counter, Merkle proof, selected replica signatures and whole-wire replay |
| `SameOperationChangedRequestConflictsAndCannotConsumeAnotherPreKey` | Four `ChangedRequestForSameOperation...` cases: ephemeral, bundle, issued-at and expiry changes; unchanged operation ID, changed request hash, stable nonzero conflict evidence and state hashes across both exits/reopen; original replay and next key/generation retained |
| `ExactBundleHashesCannotBeReusedForAnotherNetworkDeviceOrSuite` | Five `SignedInventoryCannotAuthorizeAnotherRequestScope...` cases: network, device, service, wire suite and requested suite; reject before peer calls/claim state, retain inventory, then valid request obtains the first key |

Current malformed/unauthorized scope rejection is not the retired opaque
store's generic conflict disposition. No fabricated verified capability or
weakened verifier was introduced. Remaining unsafe fixture, quota, retention
and recovery scenarios are still open; their coverage was not deleted.

The new eight-case native-error regression first failed **0 pass / 8 fail**:
`Win32Exception` escaped both claim error handling and the peer endpoint.
The actual durability barrier can throw this type from native replacement,
independently of the intermittent failure's undiagnosed cause. The runtime
now includes it in existing I/O uncertainty handling; the peer endpoint
returns a bodyless, unsigned 503. No generic exception swallowing, retry,
permission changes or filesystem barrier replacement was added.

The deterministic test wraps the real barrier and throws native error 5 or
32 at completion, on either replica, before or after real replacement.
Reservation writes remain real. All eight cases now return `OutcomeUnknown`
without an offering; after reopen, exact reconciliation obtains the original
first key/generation, whole-wire replay is stable and a distinct next operation
gets the second key/generation. Peer failures assert empty unsigned 503.
This in-process authenticated HTTP harness is **not** socket/TLS/SPKI,
ONION, actual Windows lock diagnosis, or physical device evidence.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter FullyQualifiedName~NativeCompletionWriteFailure --logger trx --results-directory artifacts/s00/native-claim-errors-after --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests|FullyQualifiedName~DeepIdV2ClaimJournalTests|FullyQualifiedName~DeepIdV2InventoryLineageTests' --logger trx --results-directory artifacts/s00/native-claim-errors-focused --verbosity quiet
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00/native-claim-errors-full --verbosity quiet
```

Initial binding selection: **9/9**. Expanded pre-fix selection: **33 pass /
1 fail** (34): native access denied during last-resort exact reconciliation.
Pre-native-regression full suite: **862 pass / 1 invite fail** (863).
Native regression after fix: **8/8**. Combined post-fix selection:
**40 pass / 2 fail** (42). One is native access denied in
`TwoReplicaJournals_CommitTheSameVerifiedTupleAndReplayAfterRestart(lastResort=true)`
during reservation. The other is the concurrent exhaustion test's verifier
rejecting a non-success result as outside selected placement; its underlying
cause is not proven by that TRX. Neither is dismissed or counted as fixed.

Final full suite: **870 pass / 1 fail / 0 skips** (871), exit 1:
ProfileGenerator 107/107, Unit 272/272, Integration 491 pass / 1 fail.
Build warnings: 0. The sole full failure remains the current one-time-invite
producer prerequisite (B8). All new cases passed in this full run, but that
does not close the preceding selection failures or storage nondeterminism.
Overlapping selections are not additive unique coverage.

Mandatory local DevOps checks also ran on current sources:

```powershell
# Separate process: COMPOSE_PROJECT_NAME=deep-s00-claim-errors-20261003,
# managed URLs explicitly local, fresh per-run artifact directory.
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
../deep-devops/scripts/multi-node-rehearsal.ps1
```

External smoke exit 0: fixture validation and 10 runner/contract tests pass;
runtime gate has no failed hard/soft checks, Xray running/non-mocked and secret
scan passes. This smoke did **not** run physical business E2E. Multi-node
rehearsal exit 0: three real Xray processes, Registry count 3, no reconciliation
issues; all privacy contact endpoints return 503 without verified authority.
It does **not** prove current grant-bound peer mutation or successful contact
delivery. Docker builds also emitted three existing `InvalidDefaultArgInFrom`
warnings for external Node service images, not .NET compile warnings.
Only isolated temporary projects/volumes were cleaned; the existing `deep-dev`
stack, production, devices, production secrets and registered node keys were
not changed. Existing scripts generated isolated local test secrets.

| Raw evidence (ignored; machine paths not committed) | SHA-256 |
| --- | --- |
| Initial binding selection | `d475b45644ddd52523feb39ef7d05408e75211028034d64a56283dcb1e0ef07a` |
| Expanded pre-fix selection | `1ba005de56557ddc8fab779109792bf6550e05c8b660e9a32908882377e97a79` |
| Native regression before fix | `16e860310b3e941a97dc800a4bec4e19b6cea1f3963f57085ca89e3ae3492e6d` |
| Native regression after fix | `45edcf5732486c376692467da507e51e1b12fe24253994ef593cb7ff055be1c9` |
| Post-fix combined selection | `931578bcdf579b778c82aa5867a0f76d45b8713755bee8ed96a19e8032504810` |
| Final full ProfileGenerator | `844e589dbe38da33c0a8e84351c5c1cb81a5d05c668fcc8ee64d97cd2c9c7b67` |
| Final full Unit | `b30a6b74f899f078d867ac6a6b179ded282edec0b76b963f1cee26360f096e79` |
| Final full Integration | `91d117726e5b1a6dfdbd38ee3067fc4323a26d8c4c4d551d73ad2f3c2fffc1c2` |
| External smoke runtime gate | `aa1f6377a70fd6b79294907bf987ce9c3653020737478c4b55facf7273ab1b5c` |
| Multi-node topology rehearsal | `b1f4e50140bcba9b5ec8a64d1ec3a92652311a149451f890769dbf0d352d584c` |

S00 remains open: unsafe fixtures, B8 current one-time publication closure,
Windows availability, root machine-set and actual Protocol package/current
mailbox consumer. S01/S02 admission, shipping composition and physical full
contact/message/files/groups acceptance remain unqualified.

## Checkpoint 6 — current signed prekey negative paths, no legacy response fixture

Inputs: xnode `ace4f95692625e54718bf74939061392374cbe22`, Protocol
`4af284766b1d9fdfb2a2e3285d248e4d30ca02e5`, workspace
`86ca61379d3db990a3665df6b02bacf699708f8c`. Test-only changes; no runtime,
wire, authority policy, production or device state changed.

Removed `ContactPreKeyXpc1ResponseTests` and its fabricated-capability fixture
only after transferring all scenario assertions:

| Removed scenario | Current signed replacement |
| --- | --- |
| Two-replica success/restart replay | `BothAnonymousExits_UseOneCoordinatorAndDistinctDurableKeys_ThenRestartReplay`: exact offering/manifest, Merkle proof, both selected signatures and stable whole-wire replay |
| Three request-binding substitutions | `SignedInventoryCannotAuthorizeAnotherRequestScope_ValidRequestStillClaimsFirstKey`: network/device/service cases, reject before peer/state mutation and valid recovery |
| Receipt signer substitution after claim | Two `AuthenticatedPeerWithAnotherReplicasClaimSignature...` cases: prepare and complete; actual remote reservation/completion, incorrect inner signer, valid outer RPC authentication, Unknown without a key, blocked new operation, reopen/exact reconciliation and original first key/generation |
| XIC1 replica set substitution | `AuthenticatedPeerWithDuplicatedPublicationSigner...`: real selected peer returns an actual valid signature from the coordinator, not a second distinct signer; rejection now correctly precedes reservation, no claim snapshots, valid retry obtains key 0/generation 1 |
| Malformed DPK2 | `CompleteStagedInventory_SignedManifestWithInvalidMemberSignature...`: parsable bad bundle signature committed by a correctly signed manifest; real complete staging/current proof reaches the member-signature rejection before activation, including reopen |
| Public verification/custody boundary | `DeepIdV2PreKeyVerifierContractTests` checks current typed recipient/placement/time inputs and private claim capability; retained opaque-store installation-plan boundary moved intact to `ContactPreKeyOpaqueStoreTests` |

The inner proof attacks are injected **after** the real receiver returns and
**before** the normal endpoint signs the outer RPC. The tests independently
verify that outer authentication; transport rejection cannot stand in for the
intended inner-signature branch. No fake verified capability, no-op filesystem
security, AcceptAll authority or legacy success codec is used in these replacements.
In-process HTTP is not actual socket/TLS/SPKI, ONION or physical device evidence.
Other unsafe opaque-store fixtures remain open; their coverage is not deleted.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~AuthenticatedPeerWith|FullyQualifiedName~SignedManifestWithInvalidMemberSignature' --logger 'trx;LogFileName=s00-current-prekey-negative.trx' --results-directory artifacts/s00-current-prekey-negative
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00/current-prekey-proof-full --verbosity quiet
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror --verbosity minimal
```

Focused **4/4**; full **868 pass / 1 fail / 0 skips** (869), exit 1:
ProfileGenerator 107/107, Unit 266/266, Integration 495 pass / 1 B8 fail.
Count decreases by two: eight old cases removed, four signed integration cases
and two separated boundary cases added. This is mapped replacement, not removal
of an unexplained failure. All replacements passed in the full run. B8 still
requires the signed current one-time publication producer; no assertion bypass.
Earlier Windows native storage/selection failures remain unresolved despite
this full run not reproducing them.

The additional solution build uses the explicit parent-configuration property:
without it MSBuild builds the two out-of-solution Protocol references in Debug
despite `-c Release`. That mixed source graph is not a Release qualification.
The explicit source-only build preserves Release on those references; production
package/current consumer graph remains a separate open gate.
Explicit build: exit 0, zero warnings and zero errors.

Mandatory managed-external smoke ran with a fresh isolated project
`deep-s00-prekey-proof-20261003`, explicitly local URLs and fresh artifact directory:
`../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'`.
Exit 0; fixture validation, ten runner/contract tests, non-mocked Xray runtime
and secret scan pass. It does not exercise successful physical messaging.
Only that temporary project's containers/volumes were cleaned; existing six
`deep-dev` containers, production and devices preserved. Three existing external
Node Dockerfile `InvalidDefaultArgInFrom` warnings remain outside .NET compilation.
No multi-node rerun: production path/peer/transport sources unchanged.

| Raw evidence (ignored; machine paths not committed) | SHA-256 |
| --- | --- |
| Four focused negative cases | `68e4b294c437b1b0383ce15bbb4df93360f913d06940e3398088cc7db0826e15` |
| Full ProfileGenerator | `d13655976cc37078e54d0e19cec977012ef5bb1522f3395d88862bf79a06697f` |
| Full Unit | `eadb5fb8b0bbf9f90ed83053c0e94439a92992d06fb74deaf0df2be80c2c64b0` |
| Full Integration | `31e69e8832e83392fd12eca82682a1af0938d7bd7e0296b9c7fd2813af6f7227` |
| External smoke runtime gate | `0a34ee8db4ef9ddbcaa44976e419f5ac19017100e8b7c41d27d4a618acedebf6` |

## Checkpoint 7 — native read uncertainty preserves signed custody

Inputs: XNode `2843169d80c9f950173f834339b28aba526bcc9c`, Protocol
`149d689c86a73c2bbc47f028948c96f553680d32`, workspace
`700db07b9eb935783d8fcf67e14acaa5908eef82`.
The preceding intermittent Windows failures remain open. Fresh unmodified
claim/journal/lineage selection passes **45/45**, but one successful selection
does not prove their root cause or remediation.

A distinct defect was reproduced with native exclusive file handles over real
signed `active.state` and `claims.state`. Both readers previously treated the
native open failure as corrupt state and called `Fault`: active state attempted
quarantine and leaked a native sharing error; the claims reader persisted a
corruption marker despite no evidence of bad bytes. Regressions initially
failed **0 pass / 2 fail**, not at a synthetic signature/fixture prerequisite.

The readers now distinguish failure to capture the bounded snapshot from
validation of captured bytes. Native I/O/access failure before capture rethrows
without mutation/latch/quarantine. No cached state is returned, no operation is
authorized and no ACL or authority check is bypassed. After release, signature,
scope and reservation validation run normally. Exact completed bytes and
original reservations remain usable without a new signer, including cold reopen.
Captured corruption, wrong scope/signature and missing activated state retain
their persistent fault/recovery behavior.

Final new selection **4/4**: two native lock/unlock/restart cases and two actual
corrupt-signature cases. The latter require the durable fault marker, preserved
quarantine/damaged input and rejection after restart. No fake verified
capability, mocked filesystem/security or no-op durability barrier is used.
This fixes read-error misclassification, **not** the earlier intermittent
`MoveFileEx` access-denied on valid replacements, nor the unexplained concurrent
non-success result. Those two observations are not reclassified as fixed.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --filter 'FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests|FullyQualifiedName~DeepIdV2ClaimJournalTests|FullyQualifiedName~DeepIdV2InventoryLineageTests' --logger 'trx;LogFileName=windows-custody-recheck.trx' --results-directory artifacts/s00/windows-custody-recheck --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --filter 'FullyQualifiedName~NativeExclusiveReadFailure|FullyQualifiedName~CorruptSignedSnapshotStill' --logger 'trx;LogFileName=read-uncertainty-final.trx' --results-directory artifacts/s00/read-uncertainty-final --verbosity quiet
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror --verbosity minimal
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror --logger trx --results-directory artifacts/s00/read-uncertainty-full --verbosity quiet
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
```

Final Release source build: **0 warnings / 0 errors**. Full source solution:
**901 pass / 1 fail / 0 skips** (902): ProfileGenerator 107/107, Unit 266/266,
Integration 528 pass / 1 B8 fail. No other tests removed or assertions weakened.
Shipping package/current mailbox graph remains a separate open gate.

Isolated project `deep-s00-read-uncertainty-20261003` smoke exits 0: fixture
validation, ten runner/contract tests, real non-mocked Xray, all runtime hard/soft
checks and secret scan pass. Only its temporary containers/volumes were removed;
six existing deep-dev containers remain healthy. Three existing external Node
Dockerfile `InvalidDefaultArgInFrom` warnings remain outside .NET compilation.
No multi-node rerun: storage read classification changes, not path selection,
peer transport/framing or release transport composition. This is not physical
contact/message/attachment/group evidence. Production, devices, registered node
keys, operator secrets and signed source bytes were not changed.

### B8 investigation: real missing one-time producer contract

[DR-0037](../../../docs/survival-program/decisions/DR-0037-did2-owned-contact-object.md)
and [DR-0038](../../../docs/survival-program/decisions/DR-0038-did2-publication-coordination.md)
authorize reusable genesis, not one-time creation. The current object author
requires reusable XIR1/policy9 and encrypts with the permanent resolver derivation.
The threshold author uses permanent DID2-derived locator/kind1/usage0;
`ContactPublicationAuthorityWireCodec.RequireExactBody` enforces those same
values. Its current signed request has no one-time locator/expected-object/expiry
commitment for witnesses. Parsable XPA1 kind2 cannot supply that missing authority.

The sole [contact owner](../../../docs/architecture/CONTACT-AND-GROUP-PROTOCOL-V1.md#6-permanent-deep-id-resolution-and-one-time-invitation)
requires a separate opaque locator and exact bundle-bound invitation AEAD;
the [resolver owner](../../../docs/architecture/CONTACT-RESOLVER-V1.md#31-publish-xpu1)
requires witnesses to recompute the one-time locator commitment without receiving
the decryption key. A usage-limit toggle, unsigned fixture field or sending the
whole secret DIA1 to the threshold would not meet that contract. Close the
artifact-specific owned author and signed public commitment contract before
implementing matched producer/consumer and replacing the visibly failing fixture.
This investigation introduces no new wire/version/API or activation and does not
claim B8 fixed. Existing permanent-contact behavior is unchanged.

| Raw ignored evidence | SHA-256 |
| --- | --- |
| Unmodified Windows selection | `d7bdcbb1cbf181882436024eb8d8a9d505a995e6816cadb0bb7e1997d5bb4fd7` |
| Native read regression before fix | `b3a916e59f16b535026c6dd77325d41012929bc43efa15684ec05f47ba3bcc11` |
| Final four regressions | `e93fbbc9623bc3d302afbf3ce24de2a9cbf9e495346638161ce000d24be0b711` |
| Full ProfileGenerator | `d8615e6213ec830b79b1b97aec2171aade99c0852a346e63c2bceb0a7609209f` |
| Full Unit | `ed10c836b65493207cb138e05ae9d716ff3fe0343123aa06610eeac3e651f35f` |
| Full Integration | `671bf1dd14ae16dc408877ffc55401cc23767deae7dbf4c4743d38c12ca272ed` |
| External runtime gate | `c644f9fdf4ccbf66b6f5d0cde9e8c60be59cbcf8032117c2db780523beb1a2e9` |

Subsequent native replacement reproduction and bounded-retry evidence:
[S00 native replacement checkpoint](s00-native-replacement-2026-10-03.md).

## Current peer HTTPS setup investigation — 2026-10-05

Compiled baseline input: XNode `162ae3e10c8ca02faa2200302d1dc0e5befdb5cb`,
Protocol `ed7153e12cc0749e875a047705566bf0a99338b9`.

```powershell
dotnet build XNode.slnx -c Release -m:1 -warnaserror -p:DeepProtocolSourceCutover=true
dotnet test XNode.slnx -c Release --no-build -m:1 -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00-final-source/full
```

Build: terminal0, zero warnings/errors. External Protocol references build in
Debug; this is a source baseline, not a uniformly Release shipping matrix.
The full run terminates exit1: **1215 passed / 1 failed / 0 skipped** (1216).
Integration861/1/0, ProfileGenerator107/0/0, Unit247/0/0. It started without a
concurrent external build. A preceding successful matrix does not replace it.

Observed failure: `CurrentClientAckRevokedRoleCannotReleaseCachedAggregate`.
Its preparatory Store returned PartialFailure with one durable replica; the
peer threw TaskCanceledException, one HTTPS request reached the test host, and
no captured response/status was observed. The ACK/revocation assertion had not
been reached. This repeats the setup problem without the earlier concurrent
build, so build load is not an established explanation or remediation.

The test-only diagnostic patch records body byte/EOF counts, processing
phase, exception class and resource elapsed/cancellation values. The original
request stream remains the byte/error/cancellation source and is not owned by
the observer. Three focused observer cases preserve bytes/EOF, cancellation
and the exact I/O exception. The affected ACK test retains sanitized Store
observations in its TRX even on success; its security assertions are unchanged.
Only after that full terminated were its output assemblies rebuilt. Both
uniformly Release project build and the original solution's Debug/Release graph
compile with zero warnings/errors. Each isolated selection passes4/0/0;
Store peer timings1809ms and1773ms respectively, native handler1663ms/1669ms.
The configuration difference is not an established cause.

### Controlled reproduction and scoped fixture repair

Run the same ACK case and observer cases alongside the existing admission,
revocation/catch-up, prekey claim/journal/lineage and signed multi-role host
classes. The unchanged mixed build reproduces **129/1/0** (130), terminal1.
Exact observation: body1500 bytes plus EOF reached native receiver; client
budget cancelled at5054ms; server aborted during native work at4843ms with
OperationCanceledException. No MRR2/status/body was released. This identifies
parallel fixture resource competition exhausting the real five-second budget,
not a TLS/body framing defect or a false quorum. The budget fails closed.

`CurrentMailboxPeerHttpTests` alone now uses a non-parallel test collection.
Other test collections retain their default scheduling; concurrent requests
inside the TLS tests are unchanged. There is no assembly-wide serialization,
deadline increase, automatic retry of setup, deleted test or weakened assertion.
This follows [xUnit collection isolation](https://xunit.net/docs/running-tests-in-parallel#selectively-opting-out-of-parallelism).
It is functional fixture isolation, not production performance qualification.

A new controlled native StoreReserved barrier lasts through the same real peer
deadline, then releases in finally. It proves PartialFailure/one replica/no
quorum or success outcome; captured body/EOF and request cancellation; native
recipient replay stays Pending with no blob. After actual cold reopen the same
client bytes and server-authored peer intent complete2/2, preserving one intent,
one mutation per replica, the same request bytes and completed replay ownership.
No clock/authority or native persistence replacement is used.

Final focused selection **5/0/0**, terminal0: the three observer cases, original
ACK/revocation case and controlled timeout/exact cold recovery. The post-repair
loaded selection completes **131/0/0**, terminal0, with the same peer budget:
ACK Store1885ms, native handler1755ms, no cancellation. Other fixture collections
still run concurrently; the scoped TLS collection follows them. Required
isolated external smoke finishes terminal0: fixture validation, ten runner/
contract checks, actual non-mocked Xray and all runtime hard/soft checks pass.
Its two manifested artifacts pass secret scanning. Only its new project-owned
containers/volumes/network were removed; six existing dev containers remain.
Three pre-existing Dockerfile InvalidDefaultArgInFrom warnings are not .NET
build warnings. Registry in this smoke retains the local-cutover package lane;
this does not qualify its current issuer exchange or a uniform package matrix.
The final full run from the already-built corrected test assembly completes
**1220 passed / 0 failed / 0 skipped**, terminal0: Integration866, Profile107,
Unit247. Integration duration35m37s. Four added diagnostics/deadline cases
account for the increase from1216; no test was removed or skipped. The original
ACK/revocation case passes its full assertion, with preparatory Store2/2,
peer1794ms/native1766ms and no cancellation. The controlled timeout/exact cold
retry and all three transparent-observer cases also pass in the full run.
No concurrent Docker build or executable-source edit occurred during it.
The assembly SHA-256 remains
`0f0cc041194164aacdc8098c062413f1b4beb6116f9891fe2acdb508c606318e`.
This closes the Node source baseline, not a package, Release composition or
physical delivery claim. Overall stage acceptance belongs to
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md). Production, devices and secrets
are not changed.

The initial current full receipt also independently covers every one of the
original **19 failure scenario groups** listed above. The two exact-request
conflict replacements are
`SameAuthorizationWithDifferentValidWitnessSetLatchesExactRequestConflict` and
`SameAuthorizationDifferentValidWitnessSetPermanentlyLatchesConflict`; both
verify genuinely signed alternate witness sets for one authorization, not a
forged capability. `ForgedWitnessCannotReserveAuthorizationOrPreventValidPublication`
separately rejects a tampered witness before reservation. The public prekey
verifier maps to `PublicVerifierRequiresCurrentRecipientPlacementAndProtectedTime_NotRawServerKeys`
plus `RetainedOpaqueStoreRequiresVerifiedInstallationPlan_NotPublicCapabilityConstruction`.
All other original cases match their retained current names, including the
genuine one-time claim/replay and both invalid-signature theory arguments.
All these mapped results are independently Passed in the corrected final full,
including both replacement public-boundary checks. The initial full remains
recorded as FAIL; the corrected result does not rewrite its ACK setup failure.

| Ignored current receipts | SHA-256 |
| --- | --- |
| Initial full Integration861/1/0 | `433c918f335ac9b3dfd927cd782a3383f440181708069e44d307db95a5268053` |
| Initial full ProfileGenerator107/0/0 | `701e84337b60c97aa201eae3652b671be33c2fe60008a45188f3cb394b42cb51` |
| Initial full Unit247/0/0 | `9f3e11c216b06e742d8e03fe479152010e008ee6ed0ba7630c5d73989c8f69bb` |
| Release dependency isolated4/0/0 | `a01221bf2d2108edec522d491561f1a990a622633b48d848cda732ee46419614` |
| Original mixed dependency isolated4/0/0 | `09fdff4529dad46f1c6cd1344b7e24405df9c96c92fc963ae34977e76e5cad1c` |
| Original parallel loaded129/1/0 | `8c1bbb9b850070a89a803e38ec4396658c9b3619e915621863ba2773a90baa3f` |
| Scoped collection focused5/0/0 | `ec1068917ed5a29fe5b69ff850b6affd38d56a8d456159f7f542bc9f66924adb` |
| Scoped collection loaded131/0/0 | `c3dd7fbba36976e39f25f520f225e437292bb72cca1ac5f3cc9e23786e9cf5b8` |
| Isolated external smoke runtime gate | `7c0f58a02d3936a2bda826a42e242297fb0c32a0868f4e40b51ce0cce22d1d93` |
| Corrected final full Integration866/0/0 | `771f6348cd9d84d6a9821d8acb8530734e873f2a7b0a3f04afc37d844d76e268` |
| Corrected final full Profile107/0/0 | `ef654e454e6488e9d7149e2037abb43ea2a6a1153e88434ddab3c59af9eededc` |
| Corrected final full Unit247/0/0 | `d1107a6de3bd868ebe64383375068587128f29fc1a1e175af9a75360247feb2f` |

Exact scoped selections (source-cutover, no shipping qualification):

```powershell
$peerCases = 'FullyQualifiedName~RequestBodyObservation|FullyQualifiedName~CurrentClientAckRevokedRoleCannotReleaseCachedAggregate|FullyQualifiedName~PeerDeadlineCannotMintQuorum'
$nativeLoad = '|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocationStoreTests|FullyQualifiedName~MailboxGrantRevocationCatchUpTests|FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests|FullyQualifiedName~DeepIdV2ClaimJournalTests|FullyQualifiedName~DeepIdV2InventoryLineageTests|FullyQualifiedName~Did2SignedMultiRoleHostTests'
dotnet build XNode.slnx -c Release -m:1 -warnaserror -p:DeepProtocolSourceCutover=true --no-restore
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release --no-build -m:1 -p:DeepProtocolSourceCutover=true --filter $peerCases --logger 'trx;LogFileName=peer-setup-scoped-focused.trx' --results-directory artifacts/s00-final-source/peer-setup-scoped-focused
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release --no-build -m:1 -p:DeepProtocolSourceCutover=true --filter ($peerCases + $nativeLoad) --logger 'trx;LogFileName=peer-setup-scoped-loaded.trx' --results-directory artifacts/s00-final-source/peer-setup-scoped-loaded
dotnet test XNode.slnx -c Release --no-build -m:1 -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00-final-source/peer-setup-scoped-full
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
```
