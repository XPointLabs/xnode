# ADR 0006: native MAU2 client ingress requires a complete verified production bundle

Status: accepted. Date: 2026-07-30. Human owner: **Mr. X**.

## Decision

XNode consumes the exact locked PMA1+PMR1+PMT1/PMS1 protocol closure built from `deep-protocol`
source `ff9f80fb6c29e3ac0a725f9161ee477b658730e3`, version
`0.4.0-production.ff9f80f`, under `vendor/production-topology-ff9f80f`.

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
  `feec9ded0d02c04fda2650bb45a0b550e97915df724e99fb56f1c1976508e154`
- Deep.Protocol.Abstractions:
  `86871905258af6b63e51b8231d35fb31ad51f45a3bccd3f2574716c7b7e60851`
- Deep.Protocol.MembershipRoutes:
  `a27f7d2a841ff3fb122d1d0767da2ee87b3e8b5f547b647600271d2ba54c2825`
- Deep.Protocol.Protobuf:
  `77bd88914a8e323c0b741664e2ff1431555311550edddc8f55f66ab287365416`

## Remaining production blockers

1. production deployment key custody and signed artifact publication automation;
2. staging, mobile/Windows E2E, operational rehearsal, and independent security review.

Until these gates close, public client ingress remains Development-only.
