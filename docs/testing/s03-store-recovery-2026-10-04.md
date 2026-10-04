# S01/S03 native Store recovery fence — 2026-10-04

Owner: Mr. X. Internal candidate, not shipping endpoints or device evidence.
Input XNode: `fe190b00211d129890d07d5e9b74331e51ad5c2a`, plus this commit.
Semantic owner: [DR-0086](../../../docs/survival-program/decisions/DR-0086-current-mailbox-store-order.md).
Execution order: [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

The existing initialization called host UTC even for a current-only ledger.
The neutral ACK collector also lacked the current-intent exclusion already
applied to Store. Initialization now leaves current Store/ACK custody unchanged
without reading UTC, and neutral collection cannot retire current ACK intents.
No schema, wire, journal, limits, operator key or activation switch changes.

The old lost-intent check covered only the requested operation/deduplication
target. A new grant and different operation could therefore start allocation
against retained native effects after the producer ledger was lost or rewound.
Before client replay, after actual holder/current authority checks, the real
ledger owner now cross-checks the bounded native mutation index/files for that
exact epoch/mailbox/placement/membership before new allocation. Every retained native record must have
its matching exact intent, cursor, nonce and body in the ledger. Pending,
completed, expired and tombstoned records are all rejection fences. No native
record authorizes settlement, allocation, reconstruction or receipt; the existing
closed host verifier still authenticates saved MQR3 before prefix advancement.
An existing exact retry checks only its original native cursor and never
allocates another. It may reconcile while unrelated custody blocks new work;
the existing independent Retrieve/Pending test exercises that boundary.

Tests use the genuine current admission, two independent native stores and
pinned TLS/HTTP2 peer endpoints. They remove the test-owned ledger or clear its
operation entries while retaining cursor metadata, check rejection before new
client replay/outcome/peer effects, restore the preserved exact test custody,
and verify original reconciliation plus the next distinct cursor. Initialization
uses a clock that throws on UTC access. A separate neutral-primitive collection
test checks only preservation of a real current ACK; its raw neutral inputs are
not grant, admission or network evidence.

## Boundaries still open

This is a scoped recovery fence, not a fully guarded host startup. Loss before
any native mutation, coordinated rollback/loss of independent owners, signed
retirement/floor protection, retained descriptor/route history and long object
horizon remain required. Current-only initialization does not manufacture
readiness. Program/DI stays inactive; no production or device state changes.

## Verification

Fresh Release source-cutover build: **0 warnings / 0 errors**.
The initial connected selection was **153 pass / 2 fail / 0 skip** (155 total,
8m38s). The new fence initially rejected exact reconciliation in the existing
independent Retrieve/Pending fixture because of unrelated native records. This
was an implementation defect, not a weakened assertion or a fixture rewrite.
The fence now distinguishes original recovery from new allocation. Initial TRX
is retained locally at `artifacts/s03-recovery/focused/current-recovery.trx`.

Final focused gate: **10 pass / 0 fail / 0 skip**, 1m16s: eight new recovery/
initialization/collection cases plus both unchanged Retrieve/Pending rows.
TRX: `artifacts/s03-recovery/final-focused/recovery-final-focused.trx`;
SHA-256 `6548978cc10fc7cf214847191632e444b4f2e8c27b44070e75def58cc6f03622`.
Full XNode gate, once after the corrected batch: **1051 pass / 1 fail / 0 skip**
(1052 total): integration 672/1, unit 272/0, profile 107/0. All **156 current
admission/peer/Store/Retrieve/ACK/revocation cases pass**. The only failure is
the existing B8 `PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`:
the signed current DID2 one-time publication producer remains missing; reusable
genesis is insufficient. No assertion was removed, weakened or skipped.

Final TRX: `artifacts/s03-recovery/final`. SHA-256:
integration `1c49d30c5ed4b4d027a006271eda01f04727e787f8803a080c6f6c812feead5d`,
unit `1f1eec8130e0901a3d41d55dc320a914f1fcf6dc9c2233c181624c9a5a84fb04`,
profile `ab6249a38995ed758a6acd341431dfa3295b967d44cf78eb546107b9a8eebe5e`.
Integration duration: 9m16s. Matching Protocol/Shared sources are unchanged,
so their full suites were not repeated for this node-only persistence slice.

```powershell
dotnet test XNode.slnx -c Release --no-build -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --logger trx --results-directory artifacts/s03-recovery/final
```

Managed-external real-Xray smoke passes with zero hard/soft failures at
`deep-devops/artifacts/s03-current-recovery-20261004/runtime.gate.json`.
Three-node no-mock rehearsal passes at
`deep-devops/artifacts/rehearsals/multi-node/20261004T001327562Z-47499b439040/test-results/multi-node-topology.json`:
three routers, zero reconciliation issues, SHA-256
`548989cc217172a10c76b743dbdfeccce622bae00201728c26363ebf057b90b3`.
These are transport regression checks, not activation of this mailbox candidate.
Both temporary projects leave zero containers, networks or volumes; the six
existing deep-dev containers are preserved. No production/device state changed.

Documentation gate: 174 checks. Changed source/doc text passes strict UTF-8 and
local-link validation; `git diff --check` passes. The selected-source/evidence
secret scan covers 17 files (changed source/docs, four final TRX and two sanitized
Docker results), zero findings. Its local summary is
`artifacts/s03-recovery-scan/selected-source-and-final-evidence.json` in the
superproject. This is a scoped scan, not a claim about every historical artifact.
