# ADR 0006: P10C peer runtime ready; client mailbox activation remains fail-closed

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
PRQ1 acceptance, MQR2 acceptance, or public client mailbox route.

`MailboxClient:Enabled=true` still stops host construction. Status says the P10B3 peer runtime is
ready, while client issuer, membership-bound placement, revocation and public ingress authority
remain dormant/reject-all. A configuration value is not activation authority.

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

## Remaining public-client activation blockers

Activation needs all of the following, reviewed across protocol, client, node and operations:

1. production issuer key distribution, rotation/LKG/equivocation and grant generation;
2. durable revocation authority;
3. deterministic membership-bound placement authority and E/E+1 lifecycle;
4. composition of the dormant MST1/MRT1/MAK1 adapters with PRQ2 Store/Tombstone fanout, native
   MQR3 and ordered MAK1-to-MAR1 aggregation;
5. reviewed public client paths, authentication/error/privacy contract and client conformance;
6. deployment key custody, staging evidence, mobile/Windows E2E and independent security review.

Until all six exist, public client ingress stays unmapped and reject-all.
