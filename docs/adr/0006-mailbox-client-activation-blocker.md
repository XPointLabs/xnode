# ADR 0006: Client mailbox activation remains fail-closed

Status: accepted blocker decision. Date: 2026-07-26. Human owner: **Mr. X**.

## Decision

The canonical XNode `MST1`/`MRT1`/`MAK1` adapter remains dormant. XNode does not
register `MailboxClientStoreAdapter`, map client mailbox HTTP routes, translate the legacy JSON
replica protocol to `MRR2`, or accept configuration as activation authority.

`MailboxClient:Enabled` is explicitly `false`. Any configuration provider, including environment
variables or command-line configuration, that sets it to `true` stops host construction with a
fail-closed error. `/status` and `/health/ready` expose only non-sensitive dormant readiness:
Store, Retrieve and Acknowledge are each `not-ready`; strict MAU2 and Ed25519 verification plus
the durable replay journal are registered internally, while issuer authority is `unconfigured`,
revocation is `reject-all`, and store/tombstone fanouts are `disabled`. Because the feature is
unavailable, its not-ready state does not make the otherwise healthy legacy router unready.

The only mapped mailbox HTTP route remains `/api/peer/mailbox/replica` on the peer listener. It is
the existing authenticated legacy JSON store primitive and is not a client route or a canonical
V2 fanout.

## Evidence for the blocker

- P03B2 now freezes Ed25519 issuer-signed MCG2 grants, holder-signed MCP2 presentations, strict
  MAU2 typed request binding and an atomic replay state machine. XNode vendors that exact closure,
  verifies the signatures through the protocol codec and durably implements the replay port.
  It still has no production issuer/key distribution, rotation/LKG or revocation source; the
  injected defaults therefore reject every grant.
- `deep-client-shared` exposes `IOpaqueMailboxCapabilityProvider` as a production trust boundary
  but ships no production implementation.
- P03B2 includes canonical client/peer frames and MAR1 aggregate ACK, but intentionally supplies
  no networking, runtime ingress, key custody, membership catalog acquisition or activation.
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

### A. Capability issuer and verifier (contract/runtime adapter delivered; authority blocked)

P03B2 selects Ed25519 and binds the exact MCG2/MCP2/MAU2 transcript, operation, request digest,
epoch, placement and membership commitments, issuer lifecycle/generation, validity, revocation
query and replay counter. XNode supplies a strict decoder/verifier adapter and a durable atomic
replay journal: exact completed retries return the cached canonical outcome; pending crash state
requires explicit exact recovery; conflict and stale replay fail closed.

The remaining blocker is the externally provisioned production authority: issuer key custody and
distribution, rotation/LKG/equivocation policy, durable revocation input and client grant
production. The runtime must not derive any of those from an untrusted grant.

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

- Runtime mailbox contract source:
  `deep-protocol` `a34e726bd60d762ac9f76c2ebf5456b266d8186e`.
- Runtime package closure:
  `Deep.Protocol`, `Deep.Protocol.Abstractions`, `Deep.Protocol.MembershipRoutes` and
  `Deep.Protocol.Protobuf` `0.3.0-p03b2.a34e726`.
- Package SHA-256:
  `fb98b4d3d65949d7dbf7e420031d06dd2a84cb377235ae5f02f15e0c35ab033e`,
  `8d2e17ed6c31144ed35e3ca0d3ad7a52ce90a0f5f4239a29213ebeca01c0613a`,
  `f2bc7b6fd105a5d89f4cf29d07dfda2975db62274e5dfa0021f7c45f8ded5491`,
  `59f844b747f82fec06e2ab84f89991ce42df52cdb110da04b58a185a218b845f`.
- P14C3 remains isolated in `XNode.ProfileGenerator`:
  `Deep.Protocol.ProfileCarrier 0.2.0-p14.69a712a`, source
  `69a712a894b024a09859096025c2bb8fe68a642e`, package SHA-256
  `fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498`,
  with `Deep.Protocol 0.3.0-p04.b887fa0`.

Any replacement or additional dependency requires a new exact version, source commit/tree,
package content hash, compatibility decision and review. A package name or sprint label is not an
activation authority.

## Exit criteria

Activation may be reconsidered only after the production authorities remaining in A, contracts
B-E and P10B are pinned, implemented and independently reviewed. A later XNode iteration must
then add bounded client/peer ingress, per-operation health, failover and complete
crash/restart/replay/equivocation/HTTP/mobile/Windows evidence while keeping the feature flag off
until all gates pass.
