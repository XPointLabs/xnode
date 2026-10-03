# S01/S03 authenticated Store prefix checkpoint — 2026-10-04

Owner: Mr. X. Candidate evidence, not activated Program or physical delivery.
Input XNode: `1d8de3090265390363dc9d9a3107d46b62bf26af`, plus this commit.
Single semantic owner: [DR-0086](../../../docs/survival-program/decisions/DR-0086-current-mailbox-store-order.md).
Execution order: [implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

The native Store producer persists exact authenticated MQR3 in its existing
operation ledger. Schema **6** rejects 3/4/5 without migration, repair or reset.
A later Store in the same epoch/mailbox/placement/membership checks the actual
signed PRQ2/MQR3 of every earlier intent, across different grants and including
intents persisted before the first mutation. An unsigned durable label cannot
advance the prefix. Current Store intents are excluded from host-UTC collection.

Prefix preflight occurs under actual current host/grant/revocation-floor leases,
after verifying the exact holder signature but before native client replay
reservation. The complete canonical current verifier still reserves afterwards.
This avoids trapping a blocked later request in a Pending claim without an
intent. Prefix verification repeats under the ledger lock before allocation.
There is no fake replay disposition, current-time override or provisional grant.

The native outcome commits before ledger settlement. If the settlement write
fails before replacement or after durable flush, original exact retry restores
the same signed request/quorum without another HTTP write. Two independent
stores and actual TLS/H2 peer receipts supply this evidence.

Focused matrix: **16 pass / 0 fail / 0 skip**. It covers pre-mutation and native
Pending intents, live/reopen, independent signed grants, hostile/missing quorum,
changed signed intent, expiry without restored grant authority, settlement write
failures, incompatible generations, native quota accounting and the lower-level
Retrieve guard. First implementation exposed a real preflight/replay ordering
defect (four retry failures); moving preflight before reservation fixes it.
The initial pre-revision run also reproduced expected older harness mismatches.
These negative TRX remain under `artifacts/s03-store-prefix/initial` and `focused`.

Existing native Retrieve/quota tests still reach their original branches through
the internal explicit signed producer, independently of the new ledger barrier.
They do not bypass a public shipping endpoint or weaken native mutation checks.
The unactivated explicit producer and per-coordinator counters are not the
single-writer/path solution: that integration remains an activation requirement.

Focused TRX: `artifacts/s03-store-prefix/after/store-prefix-focused.trx`, SHA-256
`1bb5c569771aad4bb0f3f358294f14ed7683e139faba35697a39af3e7c63b355`.
Release source-cutover build has **0 warnings / 0 errors**.
Final full XNode gate: **1038 pass / 1 fail / 0 skip** (1039 total):
integration 659/1, unit 272/0, profile 107/0. The one retained failure is B8's
missing signed DID2 one-time invitation producer; it is not skipped or weakened.
The final full gate contains **143/143** current admission/peer/Retrieve/ACK/
revocation tests, including the revised explicit-producer lower-level guards.
Final TRX directory: `artifacts/s03-store-prefix/final`; SHA-256:
integration `3af97d8b943f5705fc29660805ca873f9f7e9014f5e3ab0505508f2cfeb30f13`,
unit `5e506dc9b965d90fa7798e696a1527992b9a2017d0c3007c5aba6bf84253d6d8`,
profile `989eb09accca56f904c0c8f01b1d2332d44241f799625559ebc211d59a82ff21`.
Command from this repository:

```powershell
dotnet test XNode.slnx -c Release --no-build -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --logger trx --results-directory artifacts/s03-store-prefix/final
```

Matching [Protocol checkpoint](../../../deep-protocol/docs/testing/s03-store-settlement-2026-10-04.md)
records the separately frozen closed API, full suite and remaining package gate.

Managed-external Docker smoke with real Xray passes with zero hard/soft failures:
`deep-devops/artifacts/s03-store-settlement-20261004/runtime.gate.json`.
Three-node no-mock rehearsal passes in
`deep-devops/artifacts/rehearsals/multi-node/20261003T222715215Z-9bf07ecce78c`.
These validate the existing runtime transport lane, not activation of the new
mailbox candidate. Temporary stacks clean up; existing deep-dev is preserved.

Current writer/path, startup/retained-route and signed expiry retirement,
object horizon, distinct native node-ID/identity-key evidence and Program/DI
remain open. No production, device, account, key or secret was modified.
