# S05 replica service rollover checkpoint

Date: 2026-10-16. Owner: Mr. X. Source candidate, not release acceptance.
Semantics: [DR-0132](../../../docs/survival-program/decisions/DR-0132-replica-prekey-service-transition.md).
Operation: [operator](../operator.md).

The old CAS compared epoch numbers without service generation. A genuine signed
service2/epoch1 reached `CommitAuthorizedCore` and was incorrectly fork-latched
against service1/epoch1. The original red receipt is retained. This is an
independently reproduced defect, not proof that it caused every physical504.

The candidate scopes epoch conflict by service generation, retaining cross-slot
operation-ID conflict checks. The final committer verifies historical XPS support
against the exact reference in its node-signed durable inventory, then uses the
one signed transition predicate with independently current device authority.
Time and cancellation are checked after the historical read, before commit.
Snapshot version2, claim reservations, receipt bytes, limits and wire are unchanged.
No old fork marker is cleared or treated as evidence of its own cause.

Artifact prefix: `artifacts/s05-service-rollover-20261016/`.

| Receipt | Exact result |
| --- | --- |
| `red-01` | Native1,0 PASS/1 FAIL. Real signed next service incorrectly reaches old epoch-conflict/fork branch. |
| `node-02` | Native1,10 PASS/4 FAIL. Four fixture retry assertions expected first-stage responses instead of exact durable replay. |
| `node-03` | Native0,14 PASS/0 FAIL/0 skip after precise first-stage versus exact-replay fixture expectations. |
| `node-04` | Native1,15 PASS/1 FAIL. Injected post-read expiry correctly raises directory-freshness exception; fixture expected the wrong exception class. |
| `node-05` | Native0,90 PASS/0 FAIL/0 skip, no compiler warnings/errors. Includes lineage, final committer, candidate, staging, publication, claims and claim-journal families. |

The final positives verify both independent replica receipts, normal and genuinely
expired predecessor service succession, cold reopen and exact retained old/new
receipt replay. Signed wrong predecessor, skipped service generation, policy and
expiry reject without mutating or poisoning the original inventory. Missing or
substituted historical support rejects, then restoring the exact fixture support
allows the same staged successor. Actual storage validation injects cancellation
or stale monotonic time at the historical read; neither changes active state.
Existing same-service equivocation and operation-ID conflicts remain latched.
Fixture keys/clock/faults are test-owned; these are not physical transport tests.

Matching Protocol `artifacts/s05-service-rollover-20261016/protocol-07` passed36,
native0/no failures/skips/compiler warnings/errors. Protocol06 retained35 PASS/
1 fixture FAIL: epoch1 with a nonzero predecessor is rejected earlier by the
manifest codec's SemanticFields boundary, not the later lineage boundary.
The test now asserts that exact earlier rejection. Strict registry generation
and validation passed;178 normative anchors were unchanged and one normative
document source hash was mechanically repinned. No wire allocation was added.

Full canonical/package gates and retained-account device recovery remain open.
Before activation the local dev runtime had one pre-existing fork marker on one
node; read-only audit found none on the other two. Cause is not inferable from
that bare marker. Production, Releases and main were not changed.

Mr. X subsequently authorized a local-dev reset if `deep-dev` cannot supply a
compatible snapshot. Its network and both genesis anchors differ, so importing
that state is forbidden. After `image-08` completed native0 with no compiler
warnings/errors, `reset-09` stopped only the affected local node and moved its
one affected service directory (4 files, including the intact marker) into
recoverable quarantine on the same data volume. The first offline helper did
not run because the old container image was no longer locally available; its
exit125 is retained separately. The continuation used the newly built pinned
image with no network and only the exact data volume mounted. No keys, accounts,
other service directories or staging state were reset. This explicit local
operator reset is not retained-native-custody recovery acceptance and does not
authorize removing production latches.

Supported `up-10` completed native0 with all9 services running and exact matched
Registry, publisher and three-node images. All29 volume and25 bind identities
match before/after; bind comparison canonicalizes only Windows drive/separator
and equivalent Docker Desktop host-source representations. `smoke-11` completed
native0: current Registry proof,3 verified ONION nodes, recovery60s. This separate
readiness result is not sustained operation or business delivery. Android31 install
preflight passed against the attached physical device and exact APK/signer;
it was not installed by that preflight. Windows automation was stopped by a
physical Escape before opening the retained profile. No new device acceptance
is claimed; contacts, text, attachments and groups remain0/4.
