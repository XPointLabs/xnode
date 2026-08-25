# ADR 0006: native MAU2 activation boundary

- Original status: accepted on 2026-07-30
- Current status: superseded by the Deep-native privacy-routing clean break
- Human owner: **Mr. X**

## Preserved decision

The MAU2 verifier, durable replay/outcome journals, placement authority and PRQ2/MRR2/MQR3
replication runtime remain the authoritative mailbox implementation. Their validation,
idempotency, recovery and quorum invariants remain unchanged.

## Superseding transport decision

MAU2 Store, Retrieve and Acknowledge are no longer public HTTP routes. A client constructs an
exact three-XNode privacy route. Only the exit opens the final layer and invokes the native MAU2
dispatcher in process. The client receives a sealed DPR1 terminal result. Peer mailbox replication
continues on the authenticated PRQ2 surface as the survival layer.

The active protocol packages are exactly `0.5.0-production.e75bfed`, restored in locked mode from
`vendor/production-privacy-e75bfed/packages`. Production readiness is fail-closed unless privacy
routing, key independence, peer allowlisting/pins, mailbox authority and peer durability are ready.

This superseding decision is a clean break: no compatibility routes, decoder fallback or parallel
public mailbox ingress is retained.
