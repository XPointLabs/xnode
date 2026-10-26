# S05 Store native prefix read segment — 2026-10-26

This bounded P2 slice removes repeated current-authority acquisitions inside
`MailboxPeerMutationStore.RequireCurrentStoreIntentCustodyAsync`. Real fresh
Store admission invokes it through `EnsureCurrentStorePrefixAsync` before client
replay/reservation. The existing mutation owner keeps its semaphore and actual
entry/final lease checks. Every scanned native file is still opened, bounded,
read to EOF and hashed; index/path, PRQ2/body, nonce/hash and exact intent joins
remain. Each iteration checks lease lifetime and cancellation. No effect,
external callback, diagnostic or usable admission result occurs inside the loop.
The original-cursor recovery restriction is unchanged. Retrieve is unchanged.

## Scaling evidence

The isolated native-reader tests use actual files and the real admission lease.
One genuine Store supplies framing; synthetic canonical requests reuse its
signature bytes. These records do **not** prove valid PRQ2 signatures or full
host recovery/RPC acceptance. This avoids 10000 signers/fsync setup operations.
The cold native index and the measured walk still read the real bounded files;
the supplied synthetic intent map is only an internal denial-only fixture.

| Scanned records N | Prior source shape N+2 | Measured actual checks now |
| ---: | ---: | ---: |
| 0 | 2 | 2 |
| 1 | 3 | 2 |
| 100 | 102 | 2 |
| 1000 | 1002 | 2 |
| 10000 | 10002 | 2 |

Each case also measures exactly two actual publication-source reads. The old
column is derived from the previous loop source, not a separately timed baseline.
Real fresh Store invokes this owner once, removing N acquisitions from that RPC;
all other request/effect/callback fences remain. The separate genuine signed
Store with one prior native record measured116 sender lease checks in total,
confirmed two local mutations and both persisted peer mutation-completed floors
before actual pinned HTTP/2 dispatch, then obtained a two-replica durable quorum.
No all-RPC 209-to-2 or latency acceptance is claimed.

## Exact validation and retained failures

Windows PowerShell5.1.26100.9457 / SDK10.0.301 Release source-cutover build passed
native0 with zero warnings/errors. Canonical captures covered2351
source/binary/normative/tooling inputs, including XNode and Protocol and excluding
Shared; source was unchanged during builds and all inputs during tests.

`artifacts/s05-store-prefix-read-segment-20261026/` preserves every attempt:

- `focused-01`: build native1, zero warnings/two CS1503 errors in the new fixture's
  RecordKey call; no tests ran. Corrected string arguments to byte spans.
- `focused-02`: build native0,25 cases ran:24PASS/1FAIL/0skip/native1.
  All13 new native-scope cases and11 existing Store prefix/settlement/recovery
  cases passed. The new genuine Store test asserted client outcome count inside
  the server response callback; its assertion was masked by transport handling.
  The exact original callback expected/actual count was not retained. Client
  outcome timing is a source-derived explanation, not runtime-confirmed cause.
- `focused-03`: build native0; only that affected genuine Store case reran and
  passed1/0fail/0skip/native0. Its replacement witness uses the existing transparent
  before-send seam and actual persisted native mutation floors, retaining final
  two-replica quorum assertions. Assertion exceptions propagate directly.

The accepted focused union is25 distinct passing cases (24 unchanged cases from
02 plus1 corrected case from03), not a passing02 run. Native-scope negatives cover
missing/same-length changed middle records, missing exact intent, final changed
revocation floor, missing floor, cancellation and grant expiry. They check exact
failure types/reasons, unchanged native/intents, and owner release after failure.
Original-cursor recovery remains bounded while unrelated missing custody blocks
new allocation. Existing negatives cover different-grant pending intent, hostile
settlement, expired grant admission, final native rejoin and quorum-write recovery.
Independent source review found no code blocker. After these receipts, only a
fixture comment was clarified from authentication to native read/hash/grammar
validation; executable statements and assertions were unchanged.

No full gate, connected engineering/latency run, Docker or device acceptance was
run. Earlier interrupted regression/health history remains in the linked
[first custody segment checkpoint](s05-current-custody-read-scope-2026-10-26.md).
Actual retained inventory, two historical settlement-prefix walks, and whole
document rewrite/fsync remain scaling costs. P2 is incomplete.
