# ADR 0006: P10D client ingress is survival-development only

Status: accepted. Date: 2026-07-29. Human owner: **Mr. X**.

## Decision

XNode adopts the accepted P10B3 contract from `deep-protocol` source
`60ce2e3a5140f245d6bcfecf60fa456c26ffe730`, package
`0.3.0-p10b3.60ce2e3`, for peer mailbox replication only.

The peer listener maps exact binary PRQ2 Store and Tombstone paths from
`MailboxWireHttpContract`. It verifies the configured authoritative epoch commitment, both
RIP1/MIP1 Storage proofs and independent RouterId/signing-key identities, the configured exact
two-router placement selection, exact sender/recipient/operation/placement/context binding,
zero future skew, expiry and durable replay. Local Store and logical Tombstone mutations are
crash-safe. Success returns only a native signed durable MRR2. The sender-side coordinator counts
exactly the selected local and recipient receipts, binds the recipient endpoint to its verified
RIP1 descriptor, and emits only native PRQ2-domain MQR3.

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
never durable. The PRQ2 request digest supplies the MQR3 coordinator sequence. Successful client
operations complete the MAU2 replay reservation with a bounded response digest; partial
operations remain pending for exact retry.

## Durability and limits

- The replay journal holds an exclusive process lease, atomically persists Pending before storage,
  caches only verified exact MRR2 bytes after durable mutation, and recovers Pending after restart.
- Replay scope and collection use the P10B3 state machine. Priority-ordered bounded collection runs
  before capacity at startup and on sender/receiver reserve/completion paths.
- Eager replay loading applies P10B3 semantic invariants to every record regardless of future
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
