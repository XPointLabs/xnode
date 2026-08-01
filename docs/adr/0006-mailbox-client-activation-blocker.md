# ADR 0006: native MAU2 client ingress is survival-development only

Status: accepted. Date: 2026-07-30. Human owner: **Mr. X**.

## Decision

XNode consumes the exact locked PMA1 protocol closure built from `deep-protocol` source
`fa314137d0ee97b62b77b00849ce030e273eec32`, version `0.4.0-production.fa31413`, under
`vendor/production-authority-fa31413`.

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

Production/default composition remains dormant and unmapped. A production-only PMA1 loader now
verifies and durably chains the public issuer/epoch/NodeIngress-SPKI substrate, while readiness
remains false because PMA1 commits only a revocation snapshot hash and cannot answer whether an
individual serial is revoked. Unknown serials are never treated as non-revoked. Development activation requires the
explicit pinned fixture: issuer, revocations, network, coordinator URL, E/E+1 commitments,
placement ids/commitments, exactly two distinct replica identities/keys, and canonical MIP1/RIP1
proofs. The node owns only its local replica private seed.

Because Deep is pre-production, replay and adapter persistence schemas are clean-break. Older
schemas are rejected unchanged; no migration or compatibility decoder is permitted. Smart
contract compatibility is outside this ADR and remains separately controlled.

## Exact dependency provenance

- Deep.Protocol:
  `4cc09868cf000091e3d9014ac426c23a1894f9dbd08e8b5aeaa298c0173f13aa`
- Deep.Protocol.Abstractions:
  `efdc2a5e4d1ec198c00f9f584684dfa20acf2ff62b9a8703fb32ac025f7a57f2`
- Deep.Protocol.MembershipRoutes:
  `98d177d71b53856773bc300e6ba0a2ba3d90622feeb271dd2a3229cf1c8b26d6`
- Deep.Protocol.Protobuf:
  `890d05366fbf9c24fb8fa828c7a591e40fbfe99b725ef499bcc5239537e7ee04`

## Remaining production blockers

1. reviewed production issuer distribution/rotation and grant generation (PMA1 consumption is present);
2. hash-bound public revocation artifact/proof and durable serial-level policy;
3. reviewed membership-bound placement and E/E+1 lifecycle;
4. production fanout composition and deployment key custody;
5. staging, mobile/Windows E2E, operational rehearsal, and independent security review.

Until these gates close, public client ingress remains Development-only.
