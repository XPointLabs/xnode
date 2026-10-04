# S02/S03 native distinct descriptor-key integration — 2026-10-04

Owner: Mr. X. Internal candidate; not Program/ONION or device E2E.
Input XNode: `a19fefb4f78176bf2f97d0edb4f7a40b6197ac5b`, plus this change.
Matching producer: [Protocol checkpoint](../../../deep-protocol/docs/testing/s03-descriptor-keys-2026-10-04.md).
Semantic owner: [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md)
and [XPOINT-NETWORK §7.2](../../../docs/architecture/XPOINT-NETWORK-V1.md#72-xnd1--node-descriptor).
Execution order: [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

All current native admission/receiver/peer HTTP fixtures now use node IDs
different from the immutable descriptor identity keys. The real public
operational author signs those independent fields, followed by actual DID2
directory proof/completion and the closed host verifier; no JSON authority,
raw-key adapter, fabricated key rotation or verification bypass is substituted.
The shared contact fixture keeps its existing default; this change does not
silently rewrite unrelated contact scenarios or weaken their assertions.

The first focused run failed all eight cases before admission because the
Protocol genesis author incorrectly required ID/key equality. The producer
now follows the existing independent-field contract. A second run passed
seven and failed one hostile sender-proof case in the safe test author, which
correctly refuses to sign a proof naming the wrong public key. That hostile
fixture now signs the genuine canonical digest directly with the original
test-owned sender key, allowing the native descriptor-binding rejection to
be tested. Neither consumer rejection nor its assertions were weakened.
Both initial TRX remain under `artifacts/s03-descriptor-keys/focused` and
`artifacts/s03-descriptor-keys/focused-final`.

## Verified scenario

Eight new connected cases use real pinned TLS/HTTP2 and two independent native
stores. Both Store/retrieve/ACK positive rows exercise loss of a real remote
Store response, exact PRQ2/nonce recovery after reopen, independently verified
MQR3 settlement, a later Store through the authenticated prefix, pagination
from writer to replica, ACK coordinated by either selected replica, cached ACK
after reopen, remaining-page retrieval and deletion without resurrection.
Each MRR2 and MQR3 signature is checked against the genuine descriptor key and
fails verification against its node ID bytes.

Negative rows replace either signed proof key with node ID, use node ID as
local signing custody at either replica, and return remote receipts signed
by the other replica or a node-ID-derived key. Invalid proofs/custody reject
before peer replay/mutation. Invalid remote receipts leave native Pending
and no terminal quorum; exact retry with the real descriptor signer succeeds
without replacing the original intent.

Fresh Release source-cutover build: **0 warnings / 0 errors**.
Focused gate: **8 pass / 0 fail / 0 skip**, 41 seconds.
TRX: `artifacts/s03-descriptor-keys/verified/descriptor-keys-verified.trx`.
SHA-256 `a8571dd6b5ff312404331573d87073848d67254c46b3a91cd0298c8577e757b9`.
Full XNode gate, once after the corrected batch: **1059 pass / 1 fail / 0 skip**
(1060 total): integration 680/1, unit 272/0, profile 107/0. All **164 current
admission/peer/Store/Retrieve/ACK/revocation cases pass** with the separate
descriptor-key fixtures. Integration duration: 9m53s. The only failure is the
existing B8 `PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`:
the signed one-time DID2 publication producer remains missing. No assertions
were removed, skipped or weakened. Full TRX: `artifacts/s03-descriptor-keys/full`.
SHA-256: integration `212ebfadc2c840b42cabd4031094a53c83c7a3cc55f227ffe1118c820df1f208`,
unit `a34bc24037470d7acb0865ab6f3710516b1c0ac378e77a0b900671e000fe64ce`,
profile `ddac235326ecaac66d54bc0481014a6a6ce4b0c382a37c5b4aefc7aa13d7d107`.

Matching Protocol full gate is recorded in its checkpoint: **2079 pass / 1
package-graph fail / 12 existing skips**. Shared source and the grant/request
grammar are unchanged; its full suite was not repeated for this producer/native
fixture batch. Published packages remain unqualified.

Managed-external real-Xray smoke passes with zero hard/soft failures:
`deep-devops/artifacts/s03-descriptor-keys-20261004/runtime.gate.json`, SHA-256
`6ab181b836da082462ffcaa1f82fbeb14c3b8e34a59496c4328738c7755b2f00`.
Three-node no-mock rehearsal passes:
`deep-devops/artifacts/rehearsals/multi-node/20261004T010052613Z-76574fa55207/test-results/multi-node-topology.json`,
SHA-256 `17f59c22f007df9f1e1c43d4ede7eef876b0b4c8455ebd2fe787cf584d801bd3`.
These are transport regressions, not current-mailbox activation. Both test
projects leave zero containers, volumes and networks; six deep-dev containers
are preserved. No production/device state changed.

Documentation gate: **174 checks**. Changed source/doc text passes strict UTF-8
and local-link validation; `git diff --check` passes. The scoped secret scan
covers **22 files**, zero findings: changed source/docs, both focused TRX,
six full-suite TRX and two sanitized transport results. Superproject summary:
`artifacts/s03-descriptor-keys-scan/selected-source-and-evidence.json`.
This is not a claim about every historical artifact in the workspace.

## Remaining activation boundaries

No wire, API, operation-ledger schema, limits, activation switch, production
identity/floor or device data changed. This qualifies the internal descriptor
binding, not shipping endpoints. Global protected startup/rollback, missing
intent before native mutation, retained projection/route history, object horizon,
retirement, signed provisioning/package repins and Program/DI remain required.
Store quorum and mailbox tombstone ACK are not application Delivered/Read.
