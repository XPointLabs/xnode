# P05 handoff

P05 is ready for independent architecture review, not implementation approval.

- Status: **PROPOSED / NOT-APPROVED**
- Decision owner: Mr. X
- Decision deadline: 2026-07-21
- Approved ADR SHA: `NOT-APPROVED`
- Base: `8b19577ef00f2169116cc08da51e9592089289a9`
- Red tests: `5feb95ff44e2f70e3e1b23307271ea968716e4c4`
- Green simulator: `97281d55b32864c5c508abe7977a80d19b769d5f`
- ADR/API/estimate proposal: `9f5e658d7f86272a041ca4ba0faa4327dd348353`

Recommendation: one client request to an XNode-owned core/storage coordinator, independent HRW
storage placement, `N=3/W=2/R=2`, strict bounded E/E+1 rollback overlap and logical quota counted
once. Privacy route hops are never storage-replica evidence.

Important review focus:

1. P03B receipts lack an explicit P04 epoch; review the proposed domain-separated derivation of the
   P03B 16-byte `OperationId` before any implementation.
2. P04 commits an opaque membership leaf but does not define the full storage roster transport;
   P04D/canonical leaf ownership must be pinned.
3. Strict W2 in both E and E+1 is intentional while rollback is claimed.
4. The simulator excludes epoch and nonce from HRW scoring; epoch authenticates the roster and is
   bound into operation/receipt expectations.
5. The proposed product runtime owner is `xnode`; DevOps compatibility storage is not reused.

Full Release is green: 100 unit plus 30 integration tests. Focused P05 is 16/16. Only docs, tests
and local evidence changed. No Docker, network, production runtime, credential or Git remote was
accessed.

P08/P09 remain blocked until independent review and an explicit Mr. X decision record.

