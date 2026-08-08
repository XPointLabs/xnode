# ADR 0007: authenticated replica cache for production mailbox closure refresh

Status: accepted for implementation; managed-lane release remains gated. Date: 2026-08-08.
Human owner: **Mr. X**.

## Context

PMA1, PMR1, PMT1 and PMS1 intentionally have short live windows. A client that can still reach
its pinned mailbox replicas must not depend on Registry HTTP availability merely to obtain the
next signed closure. Extending artifact expiry would weaken revocation and incident rotation, and
a 365-day Offline PSS1 anchor does not make an expired PMT1/PMS1 usable by itself.

## Decision

Every selected XNode may retain the latest publisher-authorized forward closure for a route. The
cache is a distribution mechanism, not a trust root: clients verify exact PMA1/PMR1/PMT1/PMS1 and
PSS1 through their durable LKG/recovery anchor before atomic activation.

- `POST /api/production-mailbox/closure` has a constant path and an exact 176-byte PMQ1 body.
  PMQ1 binds timestamp, nonce, selection commitment and owner public key to an Ed25519 proof.
- `POST /api/peer/production-mailbox/closure` accepts PMP1 only on the peer listener. PMP1 binds
  timestamp, nonce, exact PMC1 SHA-256 and target replica id to a distinct signature domain and a
  pinned closure-publisher key. A copied PMC1/PSS1 is not an authenticated preposition command.
- PMC1 is canonical and bounded and always carries exact PMA1, PMR1, PMT1, PMS1 and PSS1. PSS1 is
  mandatory because this endpoint exists for forward LKG advancement, not ordinary bootstrap.
- The route file name is HMAC(selection commitment) under a protected node-local secret. Route,
  owner and mailbox identifiers are absent from URL/query/file names and logs. Request-body
  logging is not enabled; responses are `no-store`; metrics may expose sanitized counters only.
- An in-process gate plus a native cross-process store lock owns compare-and-swap, reconciliation
  and durable replacement. Every writer reconciles count/byte accounting from stable no-follow
  file handles while holding that lock. Exact bytes are idempotent. Replacement requires strictly
  higher PMA and PMT generations and a forward epoch/generation, while preserving exact network,
  owner, blinded route, selection and the original old PMS1/PMA1/PMT1 recovery anchor.
  Same-generation forks, rollback and anchor rebasing fail closed, including across two XNode
  processes sharing a state volume.
- Startup and every mutation revalidate the protected path ancestry, scan stable regular files and
  enforce both entry and byte caps. Ambiguous post-replace failures reconcile authoritative disk
  state before accepting a retry. An orphan atomic-write temporary makes startup fail closed and
  requires operator inspection/removal; it is never ignored or omitted from accounting. New routes
  fail closed at capacity; no silent eviction is permitted because eviction could strand an offline
  client. Reparse paths, identity swaps and unsafe files fail closed.

Short validity is not relaxed. A replica serves only a live PSS1 (with configured skew), so the
artifact publisher must continue prepositioning fresh closures or bounded future closures during
Registry outages. Long-offline recovery relies on an Offline PSS1 issued from the retained exact
old anchor; retired issuer private keys are not retained for this purpose.

## Publication invariant

Registry rotation is not publishable until the exact new PMC1/PSS1 has been acknowledged by both
old-current/old-next selected replicas and the new selected replicas required by policy. The
publisher must use PMP1 for each target. Failure or capacity rejection keeps the new managed lane
unpublished. Registry must retain an outbox and exact acknowledgements across restart.

## Release gates

This XNode cache alone does not close the availability requirement. Managed production remains
NO-GO until:

1. Registry implements the durable PMP1 outbox and pre-publication acknowledgement barrier;
2. mobile and Windows clients race Registry with both pinned replica origins and verify every
   candidate through the same importer/LKG/PSS path;
3. a fake-clock outage E2E exceeds 24 hours, uses an actual old pinned replica with a prepositioned
   exact closure, and resumes Store/Retrieve/Acknowledge while Registry is unavailable;
4. independent security review returns no P0/P1 findings.
