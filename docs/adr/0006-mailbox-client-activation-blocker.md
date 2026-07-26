# ADR 0006: Client mailbox activation remains fail-closed

Status: accepted blocker decision. Date: 2026-07-26. Human owner: **Mr. X**.

## Decision

The canonical XNode `MST1`/`MRT1`/`MAK1` adapter remains dormant. XNode does not
register `MailboxClientStoreAdapter`, map client mailbox HTTP routes, translate the legacy JSON
replica protocol to `MRR2`, or accept configuration as activation authority.

`MailboxClient:Enabled` is explicitly `false`. Any configuration provider, including environment
variables or command-line configuration, that sets it to `true` stops host construction with a
fail-closed error. `/status` and `/health/ready` expose only non-sensitive dormant readiness:
Store, Retrieve and Acknowledge are each `not-ready`; the verifier is `reject-all`; store and
tombstone fanouts are `disabled`. Because the feature is unavailable, its not-ready state does
not make the otherwise healthy legacy router unready.

The only mapped mailbox HTTP route remains `/api/peer/mailbox/replica` on the peer listener. It is
the existing authenticated legacy JSON store primitive and is not a client route or a canonical
V2 fanout.

## Evidence for the blocker

- P03B `MCP1` validates canonical structure, domain, lifecycle, time and replay-decision shape.
  Its domain bytes and optional admission authorization are opaque caller input. The contract
  explicitly provides no producer, derivation, authentication, key lifecycle or production
  replay implementation. A node therefore cannot distinguish an issued capability from
  attacker-chosen well-formed bytes.
- `deep-client-shared` exposes `IOpaqueMailboxCapabilityProvider` as a production trust boundary
  but ships no production implementation.
- P09C defines canonical `MEO1`/`MST1`/`MRT1`/`MRP1`/`MAK1` and native `MRR2`/`MQR2`, but no
  networking, DI or aggregate ACK response frame.
- XNode's P04 publisher returns an already-produced opaque artifact. XNode has no production P04
  verifier with durable last-known-good state and no commitment-bound deterministic
  placement-to-replica selector. `NodeDbMailboxPeerAuthorizer` proves only that a fresh,
  self-signed contact is currently registered in the local catalog.
- The legacy `SignedMailboxReplicaRequest`/`MailboxWriteReceipt` JSON transcript lacks epoch,
  operation ID, cursor, placement commitment, membership commitment and tombstone operation.
  Its in-memory replay guard and store-only response cannot produce a native `MRR2`.
- P14C3 explicitly remains `XNODE-RUNTIME-REGISTRATION-NO-GO`,
  `PRODUCTION-SIGNER-NO-GO` and `PROFILE-ACTIVATION-NO-GO`.
- No P10B contract, source package or acceptance artifact exists in the current XPointLabs
  checkout. Its semantics cannot be inferred from a sprint label.

## Required contracts before returning to XNode

### A. Capability issuer and verifier

A reviewed producer/verifier contract must select a cryptographic construction and canonical
transcript. Verification must bind the exact canonical `MCP1`, capability domain, outer operation
type and ID, epoch, blinded mailbox ID, placement commitment, canonical request digest, issuer/key
identifier, validity, lifecycle and revocation state. It must define deposit sharing without
revealing retrieve or master material and must prohibit raw Session/user identifiers.

The same contract must define a durable atomic replay/idempotency key, comparison statement,
cached-outcome rules, CAS/crash semantics, retention and epoch rollover. Parsing `MCP1` is not
authorization.

### B. Membership and placement authority

A pinned P04 successor contract must define production signature/key resolution, durable
delegation/revocation/LKG/equivocation state, and the exact canonical membership commitment used
by P09C. It must map one verified commitment to an ordered bounded replica set and define the
deterministic, domain-separated placement algorithm, role/capability filtering, E/E+1 overlap,
failover and unavailable-member behavior.

### C. Authenticated peer STORE and TOMBSTONE wire

A canonical peer request/response contract must bind sender and recipient router IDs, operation,
epoch, cursor, blinded mailbox, placement and membership commitments, envelope/digest, expiry,
freshness and durable replay nonce. It must define both Store and Tombstone, return native `MRR2`
bytes, require persistence before signing, bound request/response sizes and specify peer
authentication, replay, equivocation, retry and crash recovery. Legacy JSON must not be
implicitly translated.

### D. Public client ingress and response wire

The protocol owner must freeze route names, methods, content types, canonical raw body handling,
body/time/concurrency/rate limits, status/error mapping and privacy-safe observability for
`MST1`, `MRT1` and `MAK1`. P09C has no aggregate ACK response frame; the owner must either define
one canonically or explicitly standardize a bounded per-item `MQR2` response. No ad-hoc JSON is
permitted.

### E. Production crypto, key custody and conformance

The contracts must select receipt/peer signature and digest algorithms, router/coordinator key
resolution and rotation, custody, compromise recovery, failover and equivocation evidence.
Acceptance requires cross-language golden/negative vectors, crash/restart/replay/equivocation
tests, Android and Windows E2E, deployment key injection with no committed secrets, and
independent architecture/security review.

P10B must also be supplied as an exact source/package/ADR dependency with its relationship to
client ACK, durable outbox and delivered state stated explicitly.

## Current dependency pins

- XNode activation baseline:
  `c7d7462cf99f95e72d04072539232883ccea0ec4`.
- Runtime mailbox contract source:
  `deep-protocol` `f1a93c9460fa92bb6a1f514bb5266e45ee9c6ff2`.
- Runtime package closure:
  `Deep.Protocol`, `Deep.Protocol.Abstractions` and `Deep.Protocol.Protobuf`
  `0.3.0-p09c2.f1a93c9`.
- Package SHA-256:
  `6fb5c0f5e05ed5ef78e962c7ed515dec2656dd50f5f201fd68ff1cf29821ca23`,
  `b48cfe11bc1481b1f210c25a02aa6f96c50937d79165fe76889b6564d2a91804`,
  `8f27c94281ad70edd70f9e6c1876a9b9ec37abdc180a92eb7ea9009098cb3668`.
- P14C3 remains isolated in `XNode.ProfileGenerator`:
  `Deep.Protocol.ProfileCarrier 0.2.0-p14.69a712a`, source
  `69a712a894b024a09859096025c2bb8fe68a642e`, package SHA-256
  `fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498`,
  with `Deep.Protocol 0.3.0-p04.b887fa0`.

Any replacement or additional dependency requires a new exact version, source commit/tree,
package content hash, compatibility decision and review. A package name or sprint label is not an
activation authority.

## Exit criteria

Activation may be reconsidered only after contracts A-E and P10B are pinned, implemented and
independently reviewed. The next XNode iteration must then add real implementations behind the
existing interfaces, bounded client/peer ingress, per-operation health, failover and complete
crash/restart/replay/equivocation/HTTP/mobile/Windows evidence while keeping the feature flag off
until all gates pass.
