# ADR 0006: P10D client ingress is survival-development only

Status: accepted. Date: 2026-07-29. Human owner: **Mr. X**.

## Decision

XNode adopts the accepted P10I contract from `deep-protocol` source
`a9b7a10a555758d4b2e30707a70d271f010b6c30`, package
`0.3.0-p10i.a9b7a10`, for peer mailbox replication only.

The peer listener maps exact binary PRQ2 Store and Tombstone paths from
`MailboxWireHttpContract`. It verifies the configured authoritative epoch commitment, both
RIP1/MIP1 Storage proofs and independent RouterId/signing-key identities, the configured exact
two-router placement selection, exact sender/recipient/operation/placement/context binding,
zero future skew, expiry and durable replay. Local Store and logical Tombstone mutations are
crash-safe. Success returns only a native signed durable MRR2. The sender-side coordinator counts
exactly the selected local and recipient receipts, binds the recipient endpoint to its verified
RIP1 descriptor, and emits only native PRQ2-domain MQR3.

An exact persisted pending/completed PRQ2 scope may be recovered after the initial freshness
window while the request remains otherwise live. Lookup is read-only when the stale scope is
unknown, and a recovered scope retains its original effective reservation timestamp so restarted
replicas and coordinators reproduce the same MRR2/MQR3 bytes.

The legacy JSON `SignedMailboxReplicaRequest` path is removed. There is no JSON translation,
PRQ1 acceptance, or MQR2 acceptance.

Production and default builds keep client ingress dormant and unmapped. Enabling it outside the
Development environment still stops host construction because reviewed production authorities
do not exist. Development can activate only through the explicit
`MailboxClient:DevelopmentFixture:Enabled` composition. That fixture pins the issuer, revocations,
network, coordinator URL, E/E+1 membership commitments, placement ids and commitments, two
distinct replica identities and signing public keys, and canonical base64 MIP1/RIP1 proofs. The
issuer, local replica and remote replica keys must be distinct, and the node owns only its local
replica private seed. The origin-only coordinator URL is bound to the node's advertised
`PublicHost`/`PublicPort`, never its container listen address. Clients and operators never infer
or read node private seeds.

The Development public routes are the exact `MailboxWireHttpContract` MST1, MRT1 and MAK1 POST
routes. They require exact content types and Content-Length, forbid Content-Encoding, apply
protocol byte bounds, deadlines and pre-auth IP rate/concurrency admission, and return only
MQR3, MRP1 or ordered MQR3-in-MAR1 binary success bodies. Error bodies are empty. The MAU2
presentation carried by the MCP1 compatibility envelope is reconstructed over the canonical
operation transcript and verified by the pinned Ed25519 authority, revocation policy and durable
atomic replay journal.

Store and Tombstone fanout build signed canonical PRQ2 from the pinned MIP1/RIP1 evidence and call
the actual peer HTTP listener. The remote XNode persists and signs its own MRR2 with its own key.
No process owns both replica keys and a missing/invalid remote receipt is quorum-unavailable,
never durable. Replica accepted/durable timestamps are independently signed and bounded by the
persisted request acceptance and common expiry; cross-replica timestamp equality is not a quorum
condition. Only after the exact two verified MRR2 bytes are available does the client ledger
atomically persist those bytes and allocate the next monotonic global MQR3 coordinator sequence;
no request hash or external caller supplies sequence authority. Successful client
operations complete the MAU2 replay reservation with a bounded response digest; partial
operations remain pending for exact retry.

## Durability and limits

- The capability replay journal holds an exclusive process lease and atomically persists Pending
  before storage. Completion is represented by an opaque request-scoped handle, not an
  ever-growing process dictionary. A side-effect-free cancellation may durably move its exact
  new reservation to Released; Released preserves the counter and claim digest, permits only the
  exact claim to re-reserve at that counter, rejects lower/same-counter conflicts, and permits a
  higher counter only because no downstream side effect remains pending.
- Capability replay records retain through the later of grant expiry and authoritative epoch
  retirement plus the protocol-fixed seven-day retention interval. Collection removes only
  records beyond that boundary and runs before capacity admission, so capacity diagnostics and
  recovery are truthful. Issuer-key lifetime does not extend per-grant replay storage; serial
  reuse remains forbidden by the issuer authority.
- Replay schema v3 durably persists a monotonic accepted-time high-watermark before verification;
  collection and record transitions atomically preserve or advance that floor. Verification uses
  at least that time. Wall-clock rollback of at most 60 seconds is tolerated without moving the
  floor backward; a larger rollback fails authentication closed. V1/V2 migration atomically
  preserves every replay floor, assigns V1 infinite retention, and records the injected migration
  clock before the journal is usable. An interrupted migration restarts from either the intact
  legacy image or complete v3.
- MRT1/MAK1 capability verification precedes delivery admission, replica selection,
  continuation work and every mailbox-specific ledger/blob access. Clean failures before a
  durable side effect release only a newly-created replay reservation. After ledger, storage or
  peer work begins, cancellation/crash leaves Pending for exact restart recovery; a completed
  ledger statement is reverified and finishes replay completion without duplicate fanout.
- Replay scope and collection use the P10I state machine. Priority-ordered bounded collection runs
  before capacity at startup and on sender/receiver reserve/completion paths.
- Eager replay loading applies P10I semantic invariants to every record regardless of future
  retention and accepts cached completion bytes only as canonical MRR2-domain responses.
- A Store/Tombstone pair uses one durable expiry/retention record. Pending Store is exclusive to
  its exact replay identity; Tombstone is a recoverable state transition, not a two-file update.
  Expiry must remain within the epoch, retention is exactly the protocol-fixed interval, and
  state-specific timestamps/nonces cannot be populated in the wrong phase.
- Mutation GC is bounded and considers only records beyond their live/replay-retention boundary.
- The HTTP layer requires exact media type, no content encoding, bounded Content-Length, a
  protocol deadline no greater than 15 seconds, host-global and per-operation pre-auth
  rate/concurrency admission, and 120 requests/minute per verified sender.
- Durable leases and corruption validation run during hosted startup and gate readiness.
- Windows persistence uses write-through rename and crash-recoverable anonymous delete
  tombstones; Unix persistence fsyncs file and parent-directory metadata.
- Metrics and status expose aggregate counters only. No identities, capabilities, route/
  placement values, operation ids, mailbox ids, ciphertext or receipt bytes are labels or logs.

Ordinary onion peer replay remains volatile and is explicitly reported as debt. This ADR makes
no durable-onion claim.

## Exact dependency provenance

The four-package offline closure in `vendor/mailbox-peer-p10b3` is:

- Deep.Protocol:
  `588a889f362a618bd06b8277fd4afc8b6c64ec37797f4cdf291af1865f0fd779`;
- Deep.Protocol.Abstractions:
  `af23f03aade18ee726d5a6345e2a613c91fbea0bf62d3d0431dd629062e603bd`;
- Deep.Protocol.MembershipRoutes:
  `16f4a0dd0c33461d85ed15bf69268e4b78b70617c059aa60d3b662d922155b96`;
- Deep.Protocol.Protobuf:
  `ec5478d4ebc03fba3a97a4e0675b0fbdac4bd43c4503ed39033e1b6e469f1250`.

Core/runtime/test projects use locked local resolution. ProfileGenerator/ProfileCarrier projects
remain isolated on their exact older P04/P14 closure.

## Remaining production activation blockers

Activation needs all of the following, reviewed across protocol, client, node and operations:

1. production issuer key distribution, rotation/LKG/equivocation and grant generation;
2. durable revocation authority;
3. deterministic membership-bound placement authority and E/E+1 lifecycle;
4. production fanout and placement-provider composition equivalent to the Development proof path;
5. deployment key custody, staging evidence, mobile/Windows E2E and independent security review.

Until these exist, production public client ingress stays unmapped and reject-all.
