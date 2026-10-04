# S01/S03 current operation custody — 2026-10-04

Owner: Mr. X. Native integration candidate, not shipping Program/ONION or device evidence.
Input XNode: `74b22f743ae62a5147c76f9eccc6b6e3c2a37297`, plus this batch.
Local format/API owner: [operation custody](../mailbox-operation-custody.md).
Semantic owner: [DR-0087](../../../docs/survival-program/decisions/DR-0087-current-mailbox-operation-custody.md)
and [XPOINT-NETWORK §9.1](../../../docs/architecture/XPOINT-NETWORK-V1.md#91-current-two-replica-store-ordering).
Execution order remains [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

## Connected change

The current Store and ACK coordinator use the real independent Data Protection
owner for the existing schema-6 document, before client replay reservation and
across exact intent/quorum persistence. All current loads/saves require both
this owner and the actual current lease. Public neutral mutation/collection
cannot act on a protected current ledger. No second full journal, legacy reader,
wire/API change, account reset or node key regeneration was introduced.

Both replicas are explicitly provisioned in the connected fixture before client
requests. Readers do not provision. Host-only startup checks real membership,
source/time and both native MGR role owners without a client grant/replay.
Missing data cannot reset allocation before the first native mutation. A valid
anchored interrupted replacement recovers the exact same PRQ2 bytes/nonce;
unanchored or missing/hostile pending bytes cannot manufacture recovery.

Recovery tests cover both sides of four protected checkpoint replacement
boundaries (intent prepare/commit and quorum prepare/commit), both sides of
actual operation-file replacement for Store/ACK, independent root/enrollment
loss or substitution, exact backup restoration, both floor leases and escaped
lease rejection. A hostile callback changing bytes between verified path read
and actual deserialization is caught by authentication of the opened snapshot.

Existing peer-signature, saved Store-quorum and ACK-signature hostile tests
use the real protected owner to anchor their deliberately injected test-owned
documents. Thus they still reach independent PRQ2/MQR3 signature verification,
not merely the earlier storage hash rejection. No negative assertion was removed
or relaxed. The neutral collector runs on a separate test-owned copy, never
through a current-owned ledger.

## Diagnostic runs and scope

The first new 17-case run had 15 pass / 2 fail: after deliberate deletion, the
test backup restoration recreated files with inherited Windows ACL. The fixture
now restores required secure ACL; native validation was not weakened.
The first current 181-case run had 179 pass / 2 fail: ACK's old pre-replacement
expectation ignored the newly authenticated pending recovery, and its hostile
signature fixture lacked a matching protected root. Both scenarios are retained
with their original no-extra-effect/signature assertions and real native custody.
Initial TRX are retained locally under `artifacts/s03-operation-custody/focused`
and `current`; they are diagnostics, not passing qualification.

The final focused run passes 30 / 0 / 0 in 2m31s:
`artifacts/s03-operation-custody/verified/operation-custody-verified.trx`,
SHA-256 `912b0b2e3cc0735f455507ffc754eebc6b3c76c66f4d56ee2127b018727e3758`.
Fresh XNode Release build has 0 warnings / 0 errors.

## Terminal full gate

Fresh `dotnet test XNode.slnx -c Release --no-build` completes with **1080 pass /
1 fail / 0 skips** (1081 total). Integration: 701 pass / 1 fail, 702 total,
14m38s; all **185 current mailbox/MGR cases pass**. Unit: 272/272; profile:
107/107. Sole failure remains B8:
`ContactServiceOpaqueFacadeTests.PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`
needs the signed current DID2 one-time publication producer; reusable genesis
cannot substitute. It was not skipped, weakened or made green with a reusable flag.

Full TRX under `artifacts/s03-operation-custody/full`:

| File | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_06_57_07_net10.0.trx` (integration) | `78e9426edeb6ddd2f83203a0b9522f80c1c1c31c18fcd385a47687e0c7eb3a64` |
| `nikit_SURFACE-LT_2026-10-04_06_57_08_net10.0.trx` (profile) | `15d47e440416b32069830b30273f18853c262a1d372f5bb681d3c64078555f2c` |
| `nikit_SURFACE-LT_2026-10-04_06_57_09_net10.0.trx` (unit) | `6bf6c5cd5fc3c78c47d8cbb61dc7e1045b779f7e31cac23109e89b1923a5b9e9` |

The only Protocol delta is reviewed normative source-hash/derived registry
repinning: no wire, API, crypto or inventory change. Strict registry/175-anchor
consistency and fresh registry/parity tests pass 11/11. Final TRX:
`../../../deep-protocol/artifacts/s03-operation-custody/registry-final/registry-custody-final.trx`,
SHA-256 `28a09cb0fd913689b2a6a450100482e742e57d13a6341dadd9da64094cef6588`.
Full Protocol and unchanged Shared were not rerun in this native custody batch;
their previous dated results are not new installed-package qualification.

Fresh final-source real-Xray Docker regression checks pass:

- smoke `deep-devops/artifacts/s03-operation-custody-final-20261004/runtime.gate.json`,
  SHA-256 `4421cb3a34dc2e8be4b1f359a792ba2a32c7e925ef8e7f6c8aa59b78d8ecf35f`;
- three-node `deep-devops/artifacts/rehearsals/multi-node/20261004T021125182Z-d6ffca0b6745/test-results/multi-node-topology.json`,
  SHA-256 `d6e4f8e762e4e2f43f86e132b102647be47d23c59d09bfaafb4a45c68e450ea0`.

These compile/run the real transport but retain its intentional authority-unready
503 boundary. They are not activated current mailbox or device delivery evidence.
Both final private stacks were cleaned up; the six existing deep-dev containers
remain. Documentation gate: 174 pass. Changed files decode as strict UTF-8;
local links and scoped source/evidence secret scan are checked before commit.

Production state, credentials, node identities, device/account data and existing
deep-dev containers were not changed. Matching child commits are pinned in
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md), not inferred from focused success.
Whole-host readiness/Program, deployed provisioning, retained-route history,
retirement and object horizon remain activation blockers. Independent root and
matching data can be jointly rolled back undetected even with retained keys;
this is no hardware/external monotonic-store claim.
