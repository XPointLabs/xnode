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

Actual hosted Registry MGR1 current-context composition, renewal and retained
distribution; wiring the implemented native historical steps into
actual bounded node refresh/readiness and configured observer;
matching deployed authority, full source/shipping gates and physical delivery.
The durable provider above does not close this lifecycle. The full Registry
HTTP503 and original native Windows denial remain unclassified.
The inspected Registry distributor currently serves only the existing signed
eight-chain network bundle. Its health or TLS success cannot supply MGR1 authority.
Physical contacts/messages/attachments/groups remain 0/4; S05 and the release
are not accepted by this checkpoint.
