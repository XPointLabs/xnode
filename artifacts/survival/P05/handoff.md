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
- Initial independent review: `NO-GO`, P0=0/P1=3/P2=1/P3=0
- Corrective red: `8c2156bd37d551da6ef4f1776679c4399e429101`
- Corrective binary/quorum model: `25cf55b26b7393b5abf654104fdc25fa790c5760`
- Corrective ADR/API/P05A design: `b131f853bf702d958d1552d3b6fa031837753c96`
- First corrective evidence: `30dc69fdc02feba2c9543b89e01511b30bcf3437`
- First corrective rereview: `NO-GO`, P0=0/P1=1/P2=2/P3=0
- Second corrective red: `f95452ec1499cd9bdc5ec5812dd5b87e82552e43`
- Second corrective log-freshness/pagination model: `86a4fd4fc9fe81d227c47b5266fd62628c7ac416`
- Second corrective evidence: `PENDING`

Recommendation: one client request to an XNode-owned core/storage coordinator, independent HRW
storage placement, `N=3/W=2/R=2`, strict bounded E/E+1 rollback overlap and logical quota counted
once. Privacy route hops are never storage-replica evidence.

Important review focus:

1. P05A is now an explicit `deep-protocol` predecessor for epoch/log/high-water/tombstone/legacy
   mirror bytes and vectors; P08 is only a pinned XNode consumer.
2. Cursor allocation is a quorum ballot/contiguous hash-chain design; client ack waits until the
   P03B/P05A final certificate is stored on W2.
3. Reads require two signed high-water statements plus per-record evidence and contiguous pages.
4. Membership E/E+1 and LegacySingleExit->ReplicatedV2 are separate state machines; a legacy gap
   removes the rollback claim.
5. The proposed product runtime owner remains `xnode`; DevOps compatibility storage is not reused.
6. Every receipt/high-water/record is scoped to a canonical storage log; fresh client challenges,
   issuance buckets and monotonic per-log client LKG reject stale or substituted heads.
7. Authenticated reads are bounded pages whose start/end cursor and continuation hash are verified
   across page boundaries.

Full Release is green: 96 unit plus 30 integration tests. Focused P05 is 12/12. Only docs, tests
and local evidence changed. No Docker, network, production runtime, credential or Git remote was
accessed.

P08/P09 remain blocked until independent review and an explicit Mr. X decision record.
