# ADR 0006: native MAU2 client ingress requires a complete verified production bundle

Status: accepted. Date: 2026-07-30. Human owner: **Mr. X**.

## Decision

XNode consumes the exact locked PMA1+PMR1+PMT1/PMS1 protocol closure built from `deep-protocol`
source `7c84e8b55a82797049d221264010e94af406a963`, version
`0.4.0-production.7c84e8b`, under `vendor/production-successor-7c84e8b`.

The peer listener remains native PRQ2 Store/Tombstone with signed MRR2 and exact 2-of-2 MQR3.
The client listener now exposes only the three P10J MAU2 routes from `MailboxWireHttpContract`.
MAU2 authenticates MEO1, MBR2, or MBA2; success returns MQR3, MRP1, or MAR1. No MST1/MRT1/MAK1
route, MCP1 compatibility envelope, translation, or fallback is present.

Route operation authority comes only from `AuthenticatedOperation`. Strict decoding, issuer and
holder Ed25519 verification, generation/lifecycle/revocation policy, replay reservation, verified
holder admission, placement authority, and pure validation precede mailbox-specific work.

Replay and exact outcomes are deliberately separate:

- the replay journal persists Pending and later only the SHA-256 outcome digest;
- the canonical outcome store persists exact MQR3/MRP1/MAR1 or coarse MTO1 terminal state;
- endpoint-maximum outcome capacity is reserved before ledger/blob/peer access;
- exact outcome persistence completes before replay digest completion;
- completed replay rereads the exact outcome and compares the digest in constant time.

One process execution owns an opaque outcome key. Concurrent exact InFlight requests do no work.
After an owner exits or the process restarts, only an exact durable PendingSame claim may acquire
the recovery worker. PendingPrior is never executable. Store/ACK operation journals make recovery
idempotent; Retrieve uses its fixed high-water snapshot. Pre-side-effect cancellation releases
only NewReserved. Post-side-effect cancellation preserves Pending and releases only ephemeral
execution/outcome-capacity ownership.

Pre-auth admission is host-global and independent per authenticated operation; it stores no
remote-IP partitions. Post-verify admission stores only a domain-separated hash of operation plus
holder public key and permits 120 requests per minute.

Production/default composition remains dormant. An explicitly enabled production loader now
verifies PMA1 and its hash-bound, issuer-signed complete PMR1 snapshot on the same clock observation,
then durably commits and publishes the immutable pair atomically. Only that verified full snapshot
may treat an unknown serial as non-revoked. Authority/revocation readiness is distinct from route
readiness, which remains false until a signed topology artifact supplies two replicas, MIP1 proofs,
and HTTPS/SPKI routing. PMT1/PMS1 now supplies and verifies that topology; production routes are
mapped only for the complete protected bundle and each request remains caller-bound to its own
verified PMS1. Development activation requires the
explicit pinned fixture: issuer, revocations, network, coordinator URL, E/E+1 commitments,
placement ids/commitments, exactly two distinct replica identities/keys, and canonical MIP1/RIP1
proofs. The node owns only its local replica private seed.

Because Deep is pre-production, replay and adapter persistence schemas are clean-break. Older
schemas are rejected unchanged; no migration or compatibility decoder is permitted. Smart
contract compatibility is outside this ADR and remains separately controlled.

## Exact dependency provenance

- Deep.Protocol:
  `2fb4dafdd659b0e8e9bdb5099280b57cc44ba5f56b2b380d2a869d187fb8641d`
- Deep.Protocol.Abstractions:
  `9d8f61674bd010126bfd4076525f7b9f9b6f3510847ea49d1777e355f910a17a`
- Deep.Protocol.MembershipRoutes:
  `826e4f7e1a2870afcef1479c296aef1f285e77423622e01288c57e6b9a48abc9`
- Deep.Protocol.Protobuf:
  `5d7326c2e8fe367cee0a321568a078e1fa98b77b01c86d7dea86c8295d218410`

## Remaining production blockers

1. production deployment key custody and signed artifact publication automation;
2. staging, mobile/Windows E2E, operational rehearsal, and independent security review.

Until these gates close, public client ingress remains Development-only.
