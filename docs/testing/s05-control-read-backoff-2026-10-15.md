# S05 — bounded signed-control GET under runtime congestion

Date: 2026-10-15. Source candidate, not release/device acceptance.

After the operator restored Docker Desktop's Linux engine, actual current-dev
smoke01 failed native1: node mailbox readiness remained unavailable. Read-only
requests from the three node containers to the exact configured Registry
control endpoint returned HTTP429 (five of six sequential observations);
verified ONION privacy readiness remained available. This demonstrates real
control-read congestion, not a signing, enrollment or endpoint translation fix.

`HttpsMailboxGrantRevocationArtifactSource` now retries only its exact immutable
GET after HTTP429/503, at most four attempts under the existing five-second
whole-read deadline. It honors Retry-After; absent backoff uses bounded jitter.
The runtime contract is in [operator.md](../operator.md#bounded-current-revocation-refresh).
No quota, signed bytes, trust window, native floor or mutation retry changed.

## Source evidence

Focused03: **26/0/0**, native0, Windows PowerShell5.1, Release/source-cutover.
Receipt: `artifacts/s05-control-read-backoff-20261015/focused-03/control-read.trx`.
SHA256: `1CCCBE00FC90ECA4C4D227BD9D2368BF84FD75F8B165AA5EFE9E97FACD3B3BC6`.
It includes real native-owner verification after transient reads, unchanged
role floors on persistent congestion or bad signatures, exact request reuse,
redirect refusal, long backoff refusal, cancellation and whole-deadline closure.
Existing malformed framing, expired-floor catch-up and worker-survival cases
remain. Focused01 was an incorrect package-lane invocation and failed compilation;
it is retained. Focused02 passed24 before the final two hostile cases were added.

Canonical Node full is running at
`artifacts/test-gate-20261015/s05-control-read-full-01/`, using the three prior
accepted full receipts plus focused03. Its build passed with zero warnings/errors;
pending full/qualification must not be represented as accepted source.

## Actual local runtime evidence

DevOps receipts: `artifacts/s05-engine-resume-20261015-01/`.
Node image build02 passed native0. Supported retained `Up`03 recreated the three
nodes and reported observer admission accepted, but its whole-mount JSON
comparison wrapper failed (exit1). The child exit was not separately emitted;
this observation is retained and is not an upgrade/unchanged-mount qualification.
Read-only custody check05 separately passed native0: all eighteen expected
named state/key volumes and each node's identity/onion key matched the original
independent host custody. No hashes, keys or private paths were logged.

Post-upgrade smoke04 passed native0 after39 seconds: current Registry proof,
three verified ONION capabilities, native mailbox recovery and required contact
terminals. Log SHA256:
`DAD96A90EB7348AE32EC7947141F81DC07B45C5355DFE3B5E519FE76AE1D7979`.
Transient failures before recovery remain in the receipt; this is not a sustained
availability/SLO result or proof that congestion is eliminated.

No account, identity, journal, floor, old dev or production state was reset.
The Windows signed-endpoint transport boundary remains unresolved. Current
issuer-to-owned-client-to-node admission, S05 lifecycle matrix and physical
contacts/messages/attachments/groups remain unqualified. Queue/status owner:
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
