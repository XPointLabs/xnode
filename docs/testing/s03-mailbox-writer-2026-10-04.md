# S01/S03 authenticated Store writer — 2026-10-04

Owner: Mr. X. Internal candidate evidence, not shipping endpoints or devices.
Input XNode: `6b6e37266d1a843cb0ce88fcbe6c1dcc6c750783`, plus this commit.
Single semantic owner: [DR-0086](../../../docs/survival-program/decisions/DR-0086-current-mailbox-store-order.md).
Execution owner: [implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

Client Store admission requires the local node to be first in the actual host
verifier's signed PMS2 ranking, before holder/prefix/replay work. The peer Store
producer enforces that same writer. Both sender and recipient consumers reject
a Store whose signed sender is not first, before native peer reservation,
rate accounting or mutation. Retrieve and ACK remain available on either replica.
XNode never chooses a client path or reroutes its sealed request.

Native fixtures now orient sender/recipient to the real ranked pair. Descriptor
transport selection uses the actual recipient ID, not an index accidentally
assuming that the receiving node is rank zero. Wrong TLS pin, signatures,
expiry, quota, lost responses, crash/reopen and existing Retrieve/ACK assertions
are preserved. Internal explicit peer producers still serve lower-level native
guard tests; they are not a shipping cursor allocation bypass.

New tests reject a genuine correctly signed non-writer peer after reopen,
reject non-writer client Store before replay/outcome/cursor allocation and
retain read/ACK admission at the second node. Actual pinned TLS/H2 returns 403
for the reversed signed Store without receipt or mutation. The original valid
Store subsequently receives two receipts at cursor 1 and can be retrieved.

Initial focused run: **118 pass / 1 fail / 0 skip** (119 total). The new HTTP
test mistakenly expected an exception for a bounded authorization failure;
the real peer client returns no receipt. The assertion was corrected to require
both no receipt and the actual HTTP 403, preserving all no-effect assertions.
The initial TRX remains in `artifacts/s03-writer/focused/current-writer.trx`.
Final Release source-cutover build: **0 warnings / 0 errors**.
Final full gate: **1043 pass / 1 fail / 0 skip** (1044 total): integration
664/1, unit 272/0, profile 107/0. All **148 current admission/peer/Store/
Retrieve/ACK/revocation tests pass**, including the corrected HTTP assertion.
The sole failure remains B8's missing signed DID2 one-time invitation producer;
no test is skipped or weakened to hide it.

Final TRX: `artifacts/s03-writer/final`. SHA-256:
integration `6cc34560a558aa2406f869735a4aac700690ee12d857baba0b9f7686a331bf9c`,
unit `b74fec1fc52dc06913963a7b6ad90fabf2ea885d95d43e9c9e5e5a345b9ebed4`,
profile `13d4b0277e41868639bad19110ccc8c09fe0d55ada207484bae6fb8ee176621a`.

```powershell
dotnet test XNode.slnx -c Release --no-build -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --logger trx --results-directory artifacts/s03-writer/final
```

The authenticated prefix from the
[previous checkpoint](s03-store-prefix-2026-10-04.md) remains in the existing
schema-6 ledger; no new journal, wire, legacy reader or activation flag is added.
Matching [Shared checkpoint](../../../deep-client-shared/docs/testing/s03-mailbox-writer-2026-10-04.md)
records actual installed rank preservation and the Store client exit rule.

Managed-external real-Xray smoke passes with zero hard/soft failures in
`deep-devops/artifacts/s03-current-writer-20261004/runtime.gate.json`.
Three-node no-mock rehearsal passes in
`deep-devops/artifacts/rehearsals/multi-node/20261003T231344753Z-999e62453e0c`:
status ok, three routers, zero reconciliation issues. These exercise the existing
transport composition, not activation of this mailbox candidate. Both temporary
projects clean up all containers, volumes and networks; six deep-dev containers
are preserved.

Program/DI, guarded startup, retained-route/projection/descriptor history,
unsettled signed expiry retirement, object horizon and genuine native distinct
ID/key evidence remain open. Current projection writer/prefix checks alone do
not qualify a global no-loss snapshot across route changes. No production,
device, account, custody or secret was modified.
