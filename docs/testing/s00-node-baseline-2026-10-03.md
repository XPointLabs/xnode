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
