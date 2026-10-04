# S05 MGR1 lifecycle: explicit late first enrollment

Node product source: `200313a4f2c1c0c99d6770dc685fa95b7e157e89`.
Protocol product source: `d0c3f9d2dd053f9bb04411c41766e4e8b7098261`.
Normative owner: [DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md),
amended for genuinely new hosts joining an already renewed issuer chain.
This closes the late-initial-pin defect, not the complete S05 lifecycle.

## Verified change

The global issuer genesis expires within the snapshot interval. Two actual-role
Protocol cases and two native-store cases reproduced rejection of a fresh signed
generation 2 after that genesis expired: both selections completed exit1,
0 passed /2 failed /0 skipped, at the generation-1-only enrollment guard.
Those assertions were retained and pass after the coordinated correction.

The sole current API is `PlanInitialEnrollmentAsync`; the old API is absent,
not an alias or compatibility path. The new host pins a canonical fresh signed
snapshot under complete current authority. Native restore rejects a floor below
the immutable initial pin or different bytes at that generation. Existing-floor
advancement still requires its exact predecessor and cumulative serial retention.
Neither expiry, missing state nor a gap authorizes re-enrollment.

Real signed fixtures exercise both roles, revoked/unlisted grants, initial
generation 2, cold generation-3 advance, unchanged encrypted enrollment, and
rejection of independently protected lower/changed initial floors before a
callback. The actual DI factory also enrolls both fresh later snapshots and
recovers on cold reopen. Invalid or expired Retrieve input rejects before either
role's enrollment write. Existing key-ring and operation-custody assertions remain.

Wire bytes, signature/core domains, predecessor grammar, golden corpus and
activation flags are unchanged. Closed registry/schema metadata gained the
explicit initial-enrollment policy. Mechanical repin changed only three source
hashes; 175 anchors validated with zero anchor edits. Approved DNP1 blobs were
not changed. Downstream source consumers must use the new API and matching root
metadata; published packages/installed clients were not repinned or reset.

## Terminal local evidence

```powershell
# deep-protocol
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --filter 'FullyQualifiedName~MailboxGrantRevocationV1|FullyQualifiedName~DeepProtocolRegistryTests|FullyQualifiedName~XPointRegistryMachineParityTests' -warnaserror --logger trx --results-directory artifacts/s05-mgr1-lifecycle/bootstrap-after
# xnode
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~MailboxGrantRevocationStoreTests|FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxEnrollmentCommandTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~CurrentMailboxPeerHttpTests' -warnaserror --logger trx --results-directory artifacts/s05-mgr1-lifecycle/bootstrap-after
```

Protocol: **62 passed /0 failed /0 skipped**, terminal exit0.
Node: **286 passed /0 failed /0 skipped**, terminal exit0, 26m50s.
Actual TRX results contain zero non-passing cases, not just a console summary.
The Node selection is admission25, command6, actual factory/configuration40,
current peer HTTP180 and native revocation35. It includes the actual Program
pipeline with descriptor-pinned TLS/H2 Store/Retrieve/ACK/cold replay; signed
time/source/role authoring remains fixture-owned. This is not a real Registry
issuer, independent network observer, production provisioning or device test.

Warnings-as-errors builds completed. Protocol uses its test-seam output while
Node builds the normal source-cutover output. No compiler inputs changed during
either run. Product commits were made after the unchanged tested worktrees
completed; these are source-test receipts, not shipping artifact qualification.
Full Node/Protocol gates are not claimed for this new source. The earlier full
receipts remain evidence only for their recorded sources. No smoke/rehearsal,
production changes, device/account resets, Releases or main merges occurred.

| Receipt (relative to its repository) | SHA-256 |
| --- | --- |
| Protocol `artifacts/s05-mgr1-lifecycle/bootstrap-before/nikit_SURFACE-LT_2026-10-04_22_55_19_net10.0.trx` | `e43f27955c7008bc7d6d9e91c6e3090e175c96826fc10074d5a624ab3d1120af` |
| Node `artifacts/s05-mgr1-lifecycle/bootstrap-before/nikit_SURFACE-LT_2026-10-04_22_55_33_net10.0.trx` | `733df0ce18332860112f1eed3ba645b2a6c0e5b5cecc34b4e8488bdddd432fdbf` |
| Protocol `artifacts/s05-mgr1-lifecycle/bootstrap-after/nikit_SURFACE-LT_2026-10-04_23_06_10_net10.0.trx` | `59e0f6c52e26e2d120d5a769e5fb537ba2fb99c7cccefdda9edf4c8ff562a754` |
| Node `artifacts/s05-mgr1-lifecycle/bootstrap-after/nikit_SURFACE-LT_2026-10-04_23_06_27_net10.0.trx` | `56a1d402c2705e6a676e3fcb50109b5a297f1378e9777fcbc336f17ab0f047e3` |

Strict Protocol registry and documentation174 pass. Selected source16 and the
first three receipts pass secret scanning; the final receipt/checkpoint are
scanned separately before commit. No artifacts are added to Git.

## 2026-10-05: reserved authoring and historical native steps

Protocol product source: `a8690f7ef4a5cd09fbf1373f8050b8357281938c`.
Node product source: `2791642a365e38621eb0a854fd9acf055b42f103`.
The evidence above belongs to its earlier source, not this continuation.

DR-0083 freezes the same eleven-field SIGINPUT reservation before signing and
a separate historical floor-only transition. No wire magic, field, version,
signature/core domain, lifetime, golden corpus or activation flag changed.
Closed registry/schema metadata is coordinated with four mechanical source
hash changes; 175 anchors validate with zero edits. Approved DNP1 blobs are
unchanged. Matching source consumers must take the updated API/root metadata;
this does not repin installed clients, reset custody or activate production.

Protocol prepares owned canonical input, restores its exact reservation,
completes with the actual PMA2 role signer and verifies the retained signed
winner against that input. Expired completion is history only; a fresh successor
is required for current use. This API does not itself reserve durable issuer
state: the actual Registry journal still must do so. Actual-role tests cover
both roles, zero/4096 serials, cumulative retention, interrupted exact retry
after expiry, malformed input before callbacks, wrong/changing keys, invalid
signature, cancellation, foreign boot and exact read-back. No software signer
was added to production.

Native `CatchUpAsync` uses the actual protected floor/concurrency owner. Each
signed exact replay/sequential successor commits and reads back one bounded
record, without enrollment or an admission capability. Both-role tests cold-
reopen each of 69 expired successor steps, then accept fresh generation 71.
Every expired step rejects the operation callback; initial protected enrollment
remains byte-identical. Gap/rollback/signature-invalid inputs preserve the floor;
authenticated fork/removal alone latch. Missing floor, native replacement
interruption and cancellation fail closed.

Terminal local evidence:

```powershell
# deep-protocol
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --filter 'FullyQualifiedName~MailboxGrantRevocationV1|FullyQualifiedName~DeepProtocolRegistryTests|FullyQualifiedName~XPointRegistryMachineParityTests' -warnaserror --logger trx --results-directory artifacts/s05-mgr1-lifecycle/reserved-winner-final
# xnode: full test assembly compilation, selected execution
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~MailboxGrantRevocationStoreTests|FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxEnrollmentCommandTests|FullyQualifiedName~CurrentMailboxAdmissionTests' -warnaserror --logger trx --results-directory artifacts/s05-mgr1-lifecycle/reserved-winner-final
# unchanged binaries/source reproduction; all assertions retained
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --no-build --no-restore --filter 'FullyQualifiedName~MailboxGrantRevocationStoreTests|FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxEnrollmentCommandTests|FullyQualifiedName~CurrentMailboxAdmissionTests' --logger trx --results-directory artifacts/s05-mgr1-lifecycle/reserved-winner-reproduction
```

Protocol **83/0/0**, terminal0. Preliminary native selection **46/0/0** was
before the final reserved-winner helper, not final-source qualification.
Final-source expanded Node selection first returned **116/1/0**, terminal1:
Deposit's >64-step test exhausted the existing Windows native replacement
retry budget with `Win32Exception: Access is denied`. No assertion, barrier,
ACL, retry budget or product code was weakened. An unchanged-source/binary
repeat returned **117/0/0**, terminal0 (native46 + factory40 + command6 +
admission25). Original failure retained: its external/native cause is not
established or claimed fixed. Actual TRX non-passing counts are 0, 1 and 0.
No inputs were edited while these gates read them. These are source receipts,
not full Node/Protocol gates, peer HTTP requalification or shipping evidence.
The 26m50s peer selection was not rerun for this unfinished lifecycle business
batch; full/downstream gates remain required before its closure.

| Receipt (relative to its repository) | SHA-256 |
| --- | --- |
| Protocol `artifacts/s05-mgr1-lifecycle/reserved-winner-final/nikit_SURFACE-LT_2026-10-05_00_16_28_net10.0.trx` | `c7a15115094c55eb9e70e254d3a835ec20abccda20560619780a51ac3bd68f40` |
| Node preliminary `artifacts/s05-mgr1-lifecycle/author-history-final/nikit_SURFACE-LT_2026-10-05_00_12_37_net10.0.trx` | `4a64f1995d50495de48d91f83963995099d92187f43aa8b43ecf6f9f082218ff` |
| Node initial `artifacts/s05-mgr1-lifecycle/reserved-winner-final/nikit_SURFACE-LT_2026-10-05_00_17_15_net10.0.trx` | `48214305177eb7b7846a310e1acb36e64f8473c2d9ed6c3e5317a53a02de445d` |
| Node unchanged reproduction `artifacts/s05-mgr1-lifecycle/reserved-winner-reproduction/nikit_SURFACE-LT_2026-10-05_00_18_45_net10.0.trx` | `824287504ce70e30037a5068a383edab3b84080c47742047b43cd2e0a9917add` |

Strict Protocol registry, documentation174 and CONTACT consistency pass.
Selected source scan14 passed; receipts/checkpoint/NEXT are scanned separately
before documentation commits. Artifacts stay untracked. No Docker/production/
device changes, account resets, Releases or main merges occurred.

## Registry durable reservation continuation, 2026-10-05

Protocol product source: `666f0c4636e1ac988f7c003926d4bbeb7fd256d8`.
Registry product source: `76ebecdbe2694c8376097eee6395c82f8f93e28e`.
Node test-fixture source: `cfb607205a04f858ff9d3cf48e74e3d4a05ac956`;
its native product remains `2791642a365e38621eb0a854fd9acf055b42f103`.
Earlier receipts are not qualification of these new sources.

The actual PostgreSQL provider now commits the exact unsigned reservation and
cumulative ledger before calling the role signer. It resumes the same input
after a signer outage, verifies the actual signed predecessor before a new
callback, serializes competing writers through the explicit scope root, and
requires a separate verified database winner read-back. A new revocation while
pending is retained for the following generation without changing pending
bytes. Missing roots/history, invalid winners, lost ledger entries and exhausted
capacity reject without automatic repair, pruning or signing a replacement.
Expired completion remains history; a fresh successor is still necessary.

The operator DDL and restricted runtime privileges are in the sole Registry
[runbook](../../../deep-registry-api/docs/DID2_PRIVATE_MAILBOX_GRANTS.md#current-revocation-issuer-journal).
The journal uses the independently protected restore-authority database;
joint rollback of that database is outside its local detection guarantee.
There is no runtime DDL, new software signer, configuration/endpoint activation
or node auto-enrollment. The Registry test project links the actual existing
node DID2/network/PMA2 ceremony, excluding only native source/placement adapters
from that test compilation. No replacement proof constructor was introduced.

Terminal commands, run sequentially except the noted registry check:

```powershell
# deep-protocol
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --filter 'FullyQualifiedName~MailboxGrantRevocationV1|FullyQualifiedName~DeepProtocolRegistryTests|FullyQualifiedName~XPointRegistryMachineParityTests' -warnaserror --logger trx --results-directory artifacts/s05-mgr1-lifecycle/registry-journal-final
# deep-registry-api: unfiltered full solution, actual isolated PostgreSQL
../deep-devops/scripts/test-registry-postgres.ps1 -Lane s05-mgr1-journal-final
# xnode: full test source compilation, selected execution
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~MailboxGrantRevocationStoreTests|FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxEnrollmentCommandTests|FullyQualifiedName~CurrentMailboxAdmissionTests' -warnaserror --logger trx --results-directory artifacts/s05-mgr1-lifecycle/registry-fixture-final
# unchanged Registry source: isolate the failing route class, not a full-gate replacement
../deep-devops/scripts/test-registry-postgres.ps1 -Lane s05-route-replay-reproduction -Filter 'FullyQualifiedName~DeepIdV2RouteThresholdIssuerTests'
dotnet build Deep.Registry.Api.slnx -c Release -p:DeepProtocolLocalCutover=true -p:DeepProtocolSourceCutover=true -warnaserror --verbosity minimal
```

Protocol selected **89/0/0**, terminal0. Node selected **117/0/0**, terminal0,
including the original native fixture branch; no full Node/peer requalification.
Registry unfiltered full **344/1/7**, terminal1, includes all **14/0/0** new
provider cases. Both-role cases cover durable intent visible to another DB
connection before signing, cold retry, historical completion followed by a
fresh successor, exact winner write interruption/corruption, independent writers,
wrong predecessor/removal, lost pending ledger, foreign issuer, both capacity
limits and 70 retained generations read one record at a time.

The full Registry failure is the existing crash-mode1 route issuer case's exact
authenticated HTTP replay: expected200, actual503 at line228, before subsequent
publication assertions. Its assertion and product source were not changed.
Unchanged-source isolated repetition passes **3/0/0**, terminal0, but does not
establish or fix the original cause. This is not a green full Registry gate.
Seven skips remain actual Linux socket cases, not passing Windows evidence.
The concurrent strict Protocol registry command caused one MSB3026 dependency
copy retry warning during the full Registry build. The later sequential
warnings-as-errors solution build is terminal0 with zero warnings/errors;
it does not erase either the earlier warning or failed full test.

| Receipt (relative to its repository) | SHA-256 |
| --- | --- |
| Protocol `artifacts/s05-mgr1-lifecycle/registry-journal-final/nikit_SURFACE-LT_2026-10-05_00_56_21_net10.0.trx` | `8cefec284cfe5e61e9e4266646da38c7248a3d0ec558afdaae9ecd3ae4c8bce1` |
| Registry full `artifacts/s00/s05-mgr1-journal-final-6fd3a99007494038b17682ba8967c42e/nikit_SURFACE-LT_2026-10-05_00_57_58_net10.0.trx` | `59b869ebf3655d8fcde636605f20bdcbd0e8a61e64e8116d07b1bcf8626a135c` |
| Registry isolated repeat `artifacts/s00/s05-route-replay-reproduction-aae1f416183f41069a516e558ec99373/nikit_SURFACE-LT_2026-10-05_01_00_56_net10.0.trx` | `784bca4bb5c04443b4ce900b9766e8e63c9a532728b35a6b4e940b3881657927` |
| Node `artifacts/s05-mgr1-lifecycle/registry-fixture-final/nikit_SURFACE-LT_2026-10-05_00_59_29_net10.0.trx` | `d77e7bf52a2c89ce5d08c14d3294d1392a18fde248276ed0efd2b6225c9c8d1d` |

Strict registry and documentation174 pass; selected source scan9 has zero
findings. Receipts/docs are scanned separately before the documentation commit.
Disposable PostgreSQL containers/tmpfs were removed by their ownership-checking
wrapper. This is local provider integration, not PostgreSQL process restart,
configured external custody, deployed refresh or device qualification. There
were no production/device changes, new operational keys, Releases or main merges.

## Same delivery vertical, still open

At the provider checkpoint above, hosted Registry MGR1 current-context
composition/renewal and retained distribution were still open. The continuation
below implements the hosted producer; remaining work is wiring native historical steps into
actual bounded node refresh/readiness and configured observer;
matching deployed authority, full source/shipping gates and physical delivery.
The durable provider above does not close this lifecycle. The full Registry
HTTP503 and original native Windows denial remain unclassified.
The inspected Registry distributor currently serves only the existing signed
eight-chain network bundle. Its health or TLS success cannot supply MGR1 authority.
Physical contacts/messages/attachments/groups remain 0/4; S05 and the release
are not accepted by this checkpoint.

## Hosted Registry producer continuation — 2026-10-05

Registry `71129ad6a170cc4c507b03bc398a816278d3e081` registers current-context
MGR1 renewal only with the existing explicitly enabled private-grant composition.
It shares actual directory proof/floor, complete network/PMA2, protected time and
role custody with grant issuance. No new signed format, NCP2 chain, HTTP control
route or software production signer is introduced. Protocol and Node product
source are unchanged. The operator
[guide](../../../deep-registry-api/docs/DID2_PRIVATE_MAILBOX_GRANTS.md) owns
configuration, prerequisites and recovery consequences.

Refresh has one bounded flight and at most two generations per role: identical
pending completion, then a fresh cumulative successor if needed. Fresh unchanged
state does not sign or allocate a generation. Current source/floor/time is checked
around signing and release. HTTP readiness rechecks both actual signed DB winners
without acquiring a nonce-bound proof or signing. Cold, pending, corrupt and
stopped state remains unavailable. Internal historical reads release one actual
signed record, never a pending intent or admission token.

The initial selected run **30/1/0**, terminal1, exposed a real pre-existing
observer-query defect: the internal proof request expects a directory leaf key,
but the grant issuer supplied the distinct ADL1 lookup key. The shared current
context now uses `ComputeDirectoryLeafKey`; the checkpoint requirement remains
strict. Connected recovery test **1/0/0**, terminal0, then passed with real signed
DID2 admission/ADA2, independent PostgreSQL floor/journal and actual witnesses.

Adding HTTP readiness first produced **0/1/0**, terminal1: the TestServer omitted
the actual genesis interface/admission-gate registrations required by the other
mapped routes. Registering those existing services fixes the harness; no endpoint
or assertion was removed. The completed connected test **1/0/0**, terminal0,
covers expired pending completion then fresh renewal, source mutation during
signing, exact cold retry, cumulative revocation, corrupt winner rejection,
actual BackgroundService start/stop/restart and positive/negative HTTP readiness.
Repeated health calls leave actual nonce marker and signer-call counts unchanged.

Current unfiltered Registry **346/0/7**, terminal0, includes all provider14 cases,
the three unchanged route crash cases and the new connected lifecycle fact.
The seven actual Linux Unix-socket tests are skipped on Windows, not passing
production custody evidence. This green run does not establish or fix the earlier
intermittent route HTTP503 or original native Windows denial. Sequential
warnings-as-errors solution build: zero warnings/errors, terminal0.
Governance-contract tests22/0/0; selected source/runbook scan9: zero findings.

Commands, from Registry:

```powershell
../deep-devops/scripts/test-registry-postgres.ps1 -Lane s05-mgr1-hosted-full
dotnet build Deep.Registry.Api.slnx -c Release -p:DeepProtocolLocalCutover=true -p:DeepProtocolSourceCutover=true -warnaserror --verbosity minimal
```

| Registry receipt | SHA-256 |
| --- | --- |
| `artifacts/s00/s05-mgr1-hosted-focused-83f746ff3b304ebeac3b6ae5769e4dae/nikit_SURFACE-LT_2026-10-05_01_31_40_net10.0.trx` | `51736eed5587fd4101429230970b184b172c49407685f1ead9a6c9a0bdc5e71c` |
| `artifacts/s00/s05-mgr1-hosted-leaf-656aa6e70e0d4cf6a9fb31117b4bda7e/nikit_SURFACE-LT_2026-10-05_01_34_42_net10.0.trx` | `f2795d9d11c2f3d00a5e9c3367de072c9c5310a0ac5825a75483554338339019` |
| `artifacts/s00/s05-mgr1-hosted-http-efcd53d4ecb541a49666a6ea1f3fde43/nikit_SURFACE-LT_2026-10-05_01_35_46_net10.0.trx` | `bc90770b324ac0f698daae0fe493a3add6393ba5ca4a44987f525d8279bad9a7` |
| `artifacts/s00/s05-mgr1-hosted-http-final-9c61843de8984d4b85a7300868752636/nikit_SURFACE-LT_2026-10-05_01_37_04_net10.0.trx` | `35b647d78bb13a65b5fa08fdfe129f5ae966e5ca28b69fbc0b438637bb3d7e26` |
| `artifacts/s00/s05-mgr1-hosted-full-badfa7370d164d2ea1191f67535a5aaa/nikit_SURFACE-LT_2026-10-05_01_37_33_net10.0.trx` | `8103e84a34336dfa42a3e1dd7799cca52c2a89c9d93e81fc5e863f6ba2c4afc0` |

Disposable containers/tmpfs were removed by the ownership-checking wrapper.
No production/device data, node keys, releases or main branches were changed.
Worker cadence/resource bounds are documented, not sustained-load qualification.
PostgreSQL process-crash, configured Linux role custody, issuer→node→client
acceptance and deployed lifecycle remain open. Next in the **same** vertical:
freeze and implement bounded signed retained control distribution plus actual
node refresh/readiness, then remaining S01 retention/settlement and connected text.
Do not append MGR1 to the eight-chain NCP2 or use its health as authority.
S05/full release acceptance remains open: stages0/14 and physical matrix0/4.

## Bounded control transport and native refresh — 2026-10-05

DR-0083/CONTACT-RESOLVER §3.8 and their
closed machine inputs now freeze the raw read-only HTTP transport; MGR1 signed
bytes/domains, golden vectors and eight-chain NCP2 are unchanged. The primary
Protocol registry and generated source hashes are repinned, without activation.

The enabled Registry composition returns one actual retained signed record
under the independently current observed host. Numeric history and highest
signed `latest` never return an unsigned reservation; reads acquire no proof,
nonce or signature. The production XNode consumer checks exact request/scope,
bounded media/length/EOF and endpoint identity. Native refresh restores both
role floors before HTTP, verifies a fresh target, then commits exact sequential
history with native read-back, a 30-second budget and 64 steps per role. Restart
resumes beyond that budget; expired intermediates cannot admit an operation.
Both workers explicitly catch InvalidDataException (not an IOException).
The node worker also keeps running after an actual HttpRequestException;
the added hosted-worker test checks unchanged floors and cancellable backoff.

Node's first new focused run was **4/8/0**, terminal1: eight negative HTTP
cases correctly threw InvalidDataException but the harness incorrectly expected
IOException. Exact exception assertions were corrected, not rejection behavior.
The subsequent **129/0/0** passed before two additional generation bounds and
the network-failure fix. Current selected **133/0/0**, terminal0, covers those
changes, 70 sequential deposit successors across a native reopen, both roles,
missing-floor rejection before HTTP, bad signatures and nine framing failures.
Its HttpMessageHandler supplies genuine signed fixture records, not a live
Registry or TLS connection. Current unfiltered XNode is **1279/0/0**, terminal0:
integration900, profile107, unit272. Integration900 took29m11s. All production
and test sources remain included; warnings-as-errors is enabled. Older full
results do not qualify this source.

Registry's initial HTTP extension failed **0/1/0**, terminal1, because TestServer
omits RawTarget. A separate diagnostic **0/1/0** confirmed that fixture limitation.
Test-only middleware supplies the normal canonical raw target; the product
continues to reject missing or changed targets. Subsequent connected **1/0/0**
and unfiltered Registry **346/0/7** are terminal0. Seven Linux-only socket cases
remain NotExecuted on Windows. This is not real HTTPS/raw escaped-target evidence
or configured external signer custody. The earlier unexplained route HTTP503
and Windows native denial remain retained, not declared fixed.

| Current receipt | SHA-256 |
| --- | --- |
| Protocol `artifacts/s05-mgr1-lifecycle/control-contract-current/nikit_SURFACE-LT_2026-10-05_02_17_32_net10.0.trx` — selected111/0/0, Debug | `ace100096743ad567b4b5478ccaaaa05ebbfc81a73b9cde575c1339453d98749` |
| Node `artifacts/s05-mgr1-lifecycle/node-refresh-current/nikit_SURFACE-LT_2026-10-05_02_19_00_net10.0.trx` — selected133/0/0, Release | `eba354249d92ccf800ac64779ebdb9400d69f3e91e396d12c35d891ad56fc44f` |
| Registry `artifacts/s00/s05-mgr1-control-full-27b557854b3146688706b6ded7882948/nikit_SURFACE-LT_2026-10-05_02_09_20_net10.0.trx` — full346/0/7 | `bb98fe940672dda469c15025f37d8479de47d7774a674c225c6b07067290d997` |
| Node `artifacts/s05-mgr1-lifecycle/node-refresh-full/nikit_SURFACE-LT_2026-10-05_02_20_28_net10.0.trx` — integration900/0/0 | `5b446c7307f0f450239552034ec42e4ae096c16f7884b68012df7029e6fb7881` |
| Node `artifacts/s05-mgr1-lifecycle/node-refresh-full/nikit_SURFACE-LT_2026-10-05_02_49_46_net10.0.trx` — profile107/0/0 | `873562855bf3c076622a7a36a0c3551e1f1422380f873efe8968d5a439733e98` |
| Node `artifacts/s05-mgr1-lifecycle/node-refresh-full/nikit_SURFACE-LT_2026-10-05_02_50_13_net10.0.trx` — unit272/0/0 | `cbc1bb0dd9006b628e8da8c3171f235aeb389c262649452428db6beb5dc5cecf` |
| Registry `artifacts/s00/s05-mgr1-control-final-9e03f77550c54029931ceb2a613e6fdd/nikit_SURFACE-LT_2026-10-05_02_52_27_net10.0.trx` — final full346/0/7 | `3800bdaad21cb52265b0ac590ff6b911d1523f65d1d0c3becac157e8dc870728` |
| Registry `artifacts/s05-mgr1-lifecycle/linux-socket-current/_buildkitsandbox_2026-10-04_21_46_42_net10.0.trx` — Linux socket7/0/0 | `e0f7904a5d22cbb24f596efc3c8f0769d6af84a96306d4b1112f33d9410c8176` |
| Node initial `artifacts/s05-mgr1-lifecycle/node-refresh-first/nikit_SURFACE-LT_2026-10-05_01_59_49_net10.0.trx` — 4/8/0 | `0752c0d8133a8cea7e630fce5eb5ae5030c09dae247cc3a757f04fa349cb0f15` |
| Registry initial `artifacts/s00/s05-mgr1-control-focused-262404d7226d421aa0d893dfda2bd57b/nikit_SURFACE-LT_2026-10-05_02_03_03_net10.0.trx` — 0/1/0 | `3b7c9d4dab07935357a008c99f11a14a488f481898c3278041a8ec6db550166c` |
| Registry diagnostic `artifacts/s00/s05-mgr1-control-raw-target-82faa063425741da9ff969cb11a4862b/nikit_SURFACE-LT_2026-10-05_02_04_47_net10.0.trx` — 0/1/0 | `a55c5fea5755430e88ae9c78dac550943096d8e458ea18a0006e08875a9affd0` |

The Linux socket target initially failed compilation (CS2001): the linked
XNode signed fixture was included after the socket-only source selection,
although that target does not use it or copy the XNode context. The project now
excludes only that unneeded link when MailboxSignerFocused=true. Actual MSBuild
inventory retains44 default compile inputs, including the journal, connected
lifecycle and signed fixture, and exactly one socket-target input. Linux7/0/0
then passes against the actual adapter. The receipt is copied from the built
test image using an ownership-checked non-running temporary container, then that
helper is removed. This proves framing/cancellation, not external role custody.
After that harness fix, sequential full Registry build has zero warnings/errors;
final isolated PostgreSQL full346/0/7 is terminal0, including all fourteen provider
cases. The Windows skips and separate Linux result are not a combined deployed gate.

Strict Protocol registry, public documentation174 and governance-contract22
checks pass. Isolated external real-Xray smoke and three-node rehearsal exit0;
the latter still reports contact503 without verified authority. These transport
regressions are not current MGR1 configured issuer/node or client acceptance.
Their disposable resources were removed; the existing deep-dev stack is not
modified. No production, device, key, Release or main changes were made.

Remaining within this vertical: actual HTTPS producer-to-consumer qualification and configured node
observational authority/readiness. The inspected configured source reacquires
a nonce-bound directory proof on each check; it has not yet met observational
readiness or the catch-up acquisition budget. Registry control GET itself is
observational. PostgreSQL process-crash, independent deployment custody, remaining
S01 settlement/retention and connected/physical text acceptance remain open.
This checkpoint closes no additional stage or physical scenario.

## Continuation: observational node authority (2026-10-05)

One S05 dependency of the same contact/text vertical, not a new independent
stage. `ReadPublicationAuthorityAsync` and account-independent pre-key placement
now consume the observation acquired by the existing receive-network refresh.
Each observation independently rechecks the actual signed file/bundle closure,
PMA2, exact protected network history and instance/revision, retained directory
head and the signed monotonic horizon. A retained head read cannot bootstrap or
repair missing custody. The final source/floor/time fences remain; an observation
cannot advance a floor, request a nonce or extend the proof deadline. Cold,
changed, expired, failed or stopped source fails closed. Recipient-specific
publication still acquires its own proof; no fixture trust or wire is introduced.

Final focused selection **123/0/0**, terminal0, Release source-cutover and
warnings-as-errors. Genuine signed proof plus actual protected directory custody
checks current/expiry/boot/rollback/missing-index behavior without a fetch.
Actual network file/floor integration with an in-memory genuine proof source
checks 130 successive observations, one acquisition, no floor writes, source
faults, same-horizon rollback, cancellation and stop. A rejected unrelated
publisher and cancelled observation do not clear an independently healthy
observer. The same actual network-file/floor source is also connected to native
MGR admission/refresh, preserving all existing >64-step, expired admission and
restart assertions:71 deposit generations and2 retrieve generations recover
with one proof acquisition. The source fake is explicit: this is not
a configured HTTPS proof acquisition, deployed producer-to-consumer or device
result. Initial narrower selection23/0/0 was green; adding actual custody tests
first had compile-only CS0122 (test tried an internal Protocol hash helper),
corrected to the genuine signed predecessor hash, without changing Protocol.
Review found shared observation invalidation on unrelated recipient rejection;
the initial full run was intentionally terminated (exit1, no full receipt), not
reported as a pass. The correction has an explicit regression. Connected fixture
compilation first had CS0103 (missing namespace import); no tests executed in
that failed build. Final123 includes actual existing receive refresh/start/stop
and six signed in-process paths; no new independent slice was opened.

Receipt: `artifacts/s05-mgr1-lifecycle/observational-connected-final/nikit_SURFACE-LT_2026-10-05_03_38_31_net10.0.trx`,
SHA-256 `39f448db63e78c227e1d10f63fcc14ceae6b4ab07b3492cbcacac3f2bc3aa6e0`.
Final immutable-source smoke and three-node rehearsal are terminal0, real Xray
running/non-mocked. Smoke `failedHard`/`failedSoft` are empty; rehearsal still
reports contact503 without authority, not successful delivery. Owned disposable
resources were removed; deep-dev was not changed. Current full XNode is
**1297/0/0**, terminal0: integration918 (29m42s), profile107 (22s), unit272 (40s).
This is the current source-cutover matrix, not the previous1279 qualification.
No production/device/key/Release/main change. S05 and the
0/14 stage, 0/4 physical acceptance matrix remain open.

Transport receipts: DevOps `artifacts/s05-mgr1-observation-smoke-final/runtime.gate.json`
SHA-256 `80ead228cca4bfb007ad3ef6f8461c9251e92bb3f519a006ef852249e77d3cb0`,
and `artifacts/rehearsals/multi-node/20261004T224225078Z-bfd18eefceae/test-results/multi-node-topology.json`
SHA-256 `bc13cdd316b9292655e8d694807bbefe8d532f676348abd56480b0588ee97860`.
Public documentation174 and CONTACT/program governance22 are terminal0; these
are documentation/input-contract checks, not activation or package Release GO.

Full Node receipts under `artifacts/s05-mgr1-lifecycle/observational-full-final/`:

| Receipt | Pass/fail/skip | SHA-256 |
| --- | --- | --- |
| `nikit_SURFACE-LT_2026-10-05_03_40_34_net10.0.trx` | 918/0/0 | `c43fbc0491e0ee67661d4289fc497b7a66fea4d06af5f3e08c290ef1e8fcdb8b` |
| `nikit_SURFACE-LT_2026-10-05_04_10_22_net10.0.trx` | 107/0/0 | `2cd1a00536f4c53d21d65bb497abd2d231d29b2002890e38786526773ba94cc9` |
| `nikit_SURFACE-LT_2026-10-05_04_10_49_net10.0.trx` | 272/0/0 | `7c5946e50caecb7ae90d30b316632d14a74ce4a17347dcbf49365a2db418521f` |

Linked Registry sequential Release source/local-cutover build is terminal0,
zero warnings/errors. Approved isolated PostgreSQL default provider suite is
**346/0/7**, terminal0 on the final fixture source; owned tmpfs container was
removed. Windows skips remain Linux-specific, not converted to passes. Registry
and Protocol product inputs for the separately recorded Linux socket7 are
unchanged; that result remains adapter-only, not a deployed combined gate.
Registry receipt: `artifacts/s00/s05-observation-final-5584bec9b3cb493d97f8e928b3fb5e08/nikit_SURFACE-LT_2026-10-05_04_12_34_net10.0.trx`,
SHA-256 `2aefc8bf7737a7a1bad5d96a84c0d28508c020d21c1cb038568f40a66f4c96cb`.

This closes the locally verified observational node dependency, not all S05.
Configured live HTTPS proof acquisition and control producer→node consumer,
issuer→node→client, remaining S01 lifecycle and physical text remain open.
Earlier unexplained HTTP503/native-access failures are not classified by the
green current runs. No Release/main/prod/key/device changes or new wire.

## Continuation: actual TLS producer-to-consumer boundary (2026-10-05)

The existing Registry mailbox lifecycle ceremony now has an additional real
Kestrel HTTPS variant, retaining its PostgreSQL winner, source-change, stop and
restart assertions. Actual compiled XNode proof runtime uses its configuration
validator, native PQ verifier and protected head store to acquire the nonce-bound
proof from the actual Registry HTTP handler. It validates the resulting observation
130 times without issuing another nonce. The actual compiled signed-control HTTP
consumer reads both roles and retained generations from that producer.

The isolated client trusts only test-owned PKI, with normal chain/validity/EKU/name
validation and no permissive certificate callback or OS trust-store import. A
client without that root rejects TLS before proof issuance. Kestrel supplies its
own RawTarget: escaped generation is rejected400, plain HTTP403, missing/foreign
control503 and busy429. The hostile URI fixture explicitly preserves escaped
bytes instead of letting the client normalize them before sending.

Initial focused1/1/0 and diagnostic0/1/0 twice reproduced HTTP500 in the test
host: it omitted TimeProvider required by its real issuance gate. Actual Registry
Program already registers TimeProvider.System; this fixes the fixture, not a
claimed production defect. The next focused1/1/0 reached the escaped-target
assertion after successful proof acquisition: ordinary Uri normalized `%31` to1.
Preserving the actual hostile target corrected that fixture; focused2/0/0 is
terminal0. Final source additionally includes the untrusted-certificate rejection.
Sequential warnings-as-errors solution build is0 warnings/0 errors; approved
isolated PostgreSQL **unfiltered347/0/7** is terminal0,1m30s. Owned tmpfs DB was
removed. The seven Windows skips remain the unchanged Linux signer adapter cases.

| Registry receipt under `artifacts/s00/` | Outcome | SHA-256 |
| --- | --- | --- |
| `s05-control-tls-focused-374ec03270b54ee296566e9175a91808/nikit_SURFACE-LT_2026-10-05_04_26_37_net10.0.trx` | 1/1/0 | `4a32c30528652c23abbaf7291ddab0c6c748919945feb62d4f132e88fa0da74d` |
| `s05-control-tls-status-99a07e6df2284891b1f8b5948f8c26af/nikit_SURFACE-LT_2026-10-05_04_28_00_net10.0.trx` | 0/1/0 | `cd18cae768a036a8afe641c348ac2c0b809cc27107fbdf3bc97cdf030732089d` |
| `s05-control-tls-transport-e12fd48b7258479fa48f0b9390bc5cb4/nikit_SURFACE-LT_2026-10-05_04_29_06_net10.0.trx` | 0/1/0 | `296083b862a6ab2752a0eac84daa3bc23d72508207c018606df912662b13f73c` |
| `s05-control-tls-composition-8a292e3da50a436f92fb00a40402acb5/nikit_SURFACE-LT_2026-10-05_04_30_11_net10.0.trx` | 1/1/0 | `09e22ded04336ed7413bc820339dfb25efcf161e74638e29b77b965316fbd2f6` |
| `s05-control-tls-raw-09934555f86f4a7a8a7a0eff94bf5633/nikit_SURFACE-LT_2026-10-05_04_31_29_net10.0.trx` | 2/0/0 | `e8696a8afaa751f66c3e73583cee347a1a4753a2b48dab4d9577352ebbe1f703` |
| `s05-control-tls-final-e3426cc85ebc44ab8287ddc20eb56aa5/nikit_SURFACE-LT_2026-10-05_04_32_37_net10.0.trx` | 347/0/7 | `d9f92b21f8aea361a3e97e817e456012f767333fd32fb178f0c3d702565c2ad6` |

XNode exposes internals to the existing connected test assembly only under
source-cutover; default project evaluation excludes that friend. No runtime/test
method bodies changed since75b24f9 and its full1297 receipt; the later Node change
is test-access metadata, built by the connected solution, not a new full Node run.
This proves the actual HTTPS proof/control boundary with synthetic owned inputs
and test time, not the complete Program lifecycle/native control-admission chain,
shared443/proxy topology, deployed authority, three-hop delivery or device E2E.
Those remaining edges stay in the same contact/text vertical; stage0/14 and
physical0/4 remain. No production/key/device/Release/main changes.
