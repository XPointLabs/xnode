# S02/S03 native receiver custody — 2026-10-04

Owner: Mr. X. Input XNode `a731c12e829fa2455a09fea5af8ef91397423d3e`.
This is connected native request/peer integration, not Program activation,
installed-package, production or physical-device evidence. Execution order
remains [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Local mapping belongs to [operation custody](../mailbox-operation-custody.md);
network semantics remain [XPOINT §9.1](../../../docs/architecture/XPOINT-NETWORK-V1.md#91-current-two-replica-store-ordering).

## Connected change

The existing native receiver now requires its protected operation ledger.
Retrieve and peer Store/tombstone no longer bypass that owner. Client holder and
actual local descriptor signing custody are checked before recovery/client replay;
the full peer candidate is authenticated before recovery/rate/peer replay.
Recovery stays under the existing two native role leases. No synthetic grant,
second journal, wire/API extension, TLS downgrade, new crypto or legacy fallback.
The real peer HTTP endpoint maps missing/malformed operation data to bodyless 503.

Result checks also revalidate operation custody after callbacks, before outcome
persistence/receipt completion or release. Completed replay still requires the
same root. The receiver refuses a different producer ledger and neutral ledger.
The low-level admission-only fixture remains a primitive test, not an activated
endpoint or an alternate receiver composition.

The connected fixture explicitly provisions both real independent native ledgers
before requests; all native receiver tests now use that same owner. Reopen and
failure-injection replacement rebind the receiver, retaining the actual custody
directory/key ring. Existing explicit signed peer producer tests retain their
prefix/late-Store negative coverage; shipping Store uses the durable producer
overload. No assertion/negative scenario was removed or weakened.

## Qualification

Thirteen new cases cover both replicas' missing operation document/checkpoint,
fresh and completed Retrieve replay, fresh/completed peer replay through actual
pinned TLS/H2, neutral-owner substitution, signing custody mismatch for all
three client operations, and operation loss inside real Retrieve/peer mutation
callbacks, including cached peer receipt return. Exact secure backup restoration resumes the original request; no
missing root is recreated. Negative checks preserve replay/outcome/mutation/HTTP
counts or the actual interrupted Pending state as appropriate.

The initial focused run passes 13/13 in 2m05s (ten initial new cases plus three
existing Store/ACK regressions), at
`artifacts/s03-host-custody/focused/host-custody-focused.trx`.
SHA-256 `464e8514da7259cc96845d807d6877c6c7b08b6c324fc7c482e7586a6d4cc183`.
Three further cases, a post-recovery peer-time recheck and a final peer callback
custody check were added before the final build/full gate. The intermediate full
run under `artifacts/s03-host-custody/full` was intentionally stopped after that
last source correction; it is not terminal full-gate evidence. The initial focused
run is not evidence for those final changes.
Final fresh Release build: 0 warnings / 0 errors, source-cutover Protocol.

Final `dotnet test XNode.slnx -c Release --no-build
-p:DeepProtocolSourceCutover=true` completes with **1093 pass / 1 fail / 0 skips**
(1094 total). Integration: 714 pass / 1 fail, 715 total, **25m35s**;
all **198 current mailbox/MGR cases pass**, including all **13 new cases**.
Unit: 272/272; profile: 107/107. The sole failure is
`ContactServiceOpaqueFacadeTests.PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`:
the known signed one-time contact producer prerequisite B8 is not skipped or
replaced by reusable genesis. Unchanged Protocol/Shared full gates are not rerun
or promoted to new installed evidence by this native change. The full command
exits 1; this is not a green release gate or a production performance benchmark.

Final TRX under `artifacts/s03-host-custody/final-full`:

| File | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_07_41_58_net10.0.trx` (integration) | `fdb0626e5b1a99392d36d5c2cb31d41fb5017e25fedc8d87afa809c2a81d9f86` |
| `nikit_SURFACE-LT_2026-10-04_07_41_57_net10.0.trx` (profile) | `5afb0a860f854b1a4c2c07979173ff0a3e6f98a706011aa87695214161c5cd80` |
| `nikit_SURFACE-LT_2026-10-04_07_41_57_net10.0[1].trx` (unit) | `8570ef564f53fecd1553b8c9876d00829f58182bbbf8f4dec0e673b990685ab7` |

Fresh final-source real-Xray Docker checks pass:

- smoke: `deep-devops/artifacts/s03-host-custody-final-20261004/runtime.gate.json`,
  SHA-256 `81ebf58f5982aca24f04c340fe76162fa1385a51e0862d3f360140f1f1c4bf93`;
  zero hard/soft failures, mocked=false;
- three-node: `deep-devops/artifacts/rehearsals/multi-node/20261004T024331553Z-fa1afdc6827b/test-results/multi-node-topology.json`,
  SHA-256 `22bff23eb7f12ba6111e5debcfc3aa58e4f5c416643ea7a3f06867a8642bc497`;
  three actual running Xray nodes, no reconciliation issues.

These remain fail-closed 503 without ready current authority and do not prove
mailbox/physical delivery. Both private Docker projects and their volumes were
removed after the checks; the six existing deep-dev containers were retained.

## Activation boundary

Program/DI and whole-host startup/health composition remain unactivated, as do
deployed provisioning, retained-route/retirement/object-horizon qualification,
shipping clients and physical E2E. Protection's joint-root/data rollback limit
is unchanged. Production, node identities/secrets and device/account data were
not modified. Matching commits belong in
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
