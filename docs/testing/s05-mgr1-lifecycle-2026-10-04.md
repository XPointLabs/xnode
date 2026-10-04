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

## Same delivery vertical, still open

Actual Registry MGR1 durable signing intent/cumulative authoring, renewal and
retained distribution; bounded sequential historical catch-up without admission
from expired snapshots; actual node refresh/readiness and configured observer;
matching deployed authority, full source/shipping gates and physical delivery.
The inspected Registry distributor currently serves only the existing signed
eight-chain network bundle. Its health or TLS success cannot supply MGR1 authority.
Physical contacts/messages/attachments/groups remain 0/4; S05 and the release
are not accepted by this checkpoint.
