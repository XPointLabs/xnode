# ADR 0007: authenticated PMC2 replica cache

Status: accepted for implementation; managed-lane release remains gated. Date: 2026-08-09.
Human owner: **Mr. X**.

## Context

PMA1, PMR1, PMT1 and PMS1 intentionally have short live windows. A selected XNode may distribute
an already authorized route transition while Registry is unavailable, but it must not become a
client activation authority or accept route-continuity history and revocation capabilities.

## Decision

The cache is a clean-break PMC2-only distribution surface.

- PMC2 has a fixed 112-byte header: `PMC2`, version 2, authorization tag, zero reserved bytes,
  random non-zero 32-byte salt, 32-byte route-lineage commitment, and ten big-endian lengths for
  exact PMA1, PMR1, PMT1, current PMS1, next PMS1, PSS2, PRC1, RTC1, RCH1 and tagged
  authorization bytes. Owner mode carries no RCH1 and exactly one PRA2; delegated mode carries an
  active RCH1 and exactly one RCA1. Both PMS1 documents are mandatory. RCD1, RDA1, RCR1, RHB1,
  RHC1 and sealed route-history bytes are forbidden.
- PMP2/PMC2 perform their exact outer length/tag checks and allocation-free PMR1 count plus
  PMT1/PMS1/PSS2 structural framing walk before any multi-megabyte caller buffer is copied. The
  owned snapshot repeats all framing and canonical checks before Protocol verification.
- XNode passes the exact decoded aggregate to Protocol's public cache-only verifier. The sealed
  result proves canonicality, production signatures, live windows, exact duplicate bytes, mode and
  route/hash bindings. XNode retains its exact hard cache expiry (the minimum authenticated
  artifact deadline) for admission recheck, fetch, restart and GC. It cannot be converted to a
  full client activation capability.
- The lineage commitment is SHA-256 over the fixed v2 domain, network, owner, selection
  commitment, old-PMS hash, sealed old-route-origin hash, transition mode, authorization tag,
  RTC1 hash, PSS2 hash and fresh salt. It is recomputed before storage.
- Retrieval uses exact 272-byte PMQ2 at the constant public POST path. Its owner signature binds
  timestamp, nonce, selection commitment, durable old-PMS hash, lineage commitment, target replica
  and owner public key. A request for another target or commitment is a miss.
- Preposition uses PMP2 only at the peer listener. Its fixed 280-byte header retains a legacy-count
  byte and two legacy slots only as fixed zero fields, plus a capacity cohort. The publisher
  signature binds the exact PMC2 hash, target, zero count and slots, cohort, verified transition
  mode and lineage commitment. PMC2 is parsed before the signing transcript is constructed or
  verified, and the target must belong to the verified PSS2 old or new selections.
- Storage is cardinality one. The protected path is sharded by HMAC(selection commitment), then by
  HMAC(selection commitment || durable old-PMS hash || lineage commitment), and contains one
  `closure.pmcs2`. Exact byte replay is idempotent and conflicting bytes for the same full tuple fail
  closed. Distinct commitments for devices with the same durable old PMS are distinct lineages and
  coexist up to the per-selection lineage cap. There is no PMC1/PMQ1/PMP1 or schedule fallback.
- Count accounting charges one per `.pmcs2`; byte accounting charges the exact envelope bytes plus
  the configured conservative per-file overhead. Expiry GC, global capacity, per-selection lineage
  capacity and reservation consumption all use those same units.
- A cohort-bound insertion uses PBT2. The authenticated crash journal binds selection, old PMS,
  lineage commitment, old/new closure hashes, capacity floors and ledgers. Recovery follows
  journal → closure → floor → ledger, so a restart cannot recover another lineage or double-charge
  exact replay.
- Paths and logs contain only keyed digests. Request bodies are not logged, responses are
  `no-store`, stable reads reject reparse/identity swaps, and fetch and mutation both hold the
  native process lock plus bounded in-process gates. Fetch uses a cancellable five-second lock
  deadline only for PBT2 recovery and a stable owned byte snapshot, then releases the global lock
  before Protocol crypto so independent lineage verification overlaps. It rechecks request and
  hard-cache time after waiting and again before return;
  GC snapshots are bounded at the configured global/per-selection count plus one before traversal.

## Publication invariant

Registry may publish a route transition only after every required old/current/new selected replica
has acknowledged the exact target-bound PMP2 and required PMB2 capacity receipt. Partial
preposition never becomes a global cutover barrier. Clients still verify the returned closure
through their own protected LKG/import path; PMC2 is only cache evidence.

## Release gates

Managed production remains NO-GO until Registry and clients wire the frozen PMC2/PMQ2/PMP2 map,
the durable acknowledgement barrier survives restart, a Registry-outage E2E succeeds through an
old pinned replica, and independent security review reports no P0/P1 findings.
