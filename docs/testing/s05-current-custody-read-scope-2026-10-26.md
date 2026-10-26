# S05 ordinary mailbox custody read segment — 2026-10-26

Scope: the first conservative P2 owner slice. No connected or latency acceptance
is claimed. Startup/readiness, first reservation and historical repair continue
through `InitializeCurrentAsync`. Ordinary client/peer currentness uses
`CheckCurrentOperationAsync` on the same protected ledger.

## Owner and callback map

1. The ledger holds its existing semaphore and authenticates actual operation
   bytes against independent enrollment/checkpoint custody. Interrupted
   checkpoint closure stays inside `LoadAsync`; its full current checks and the
   actual post-callback document re-read remain unchanged.
2. Only after that load, a disposable `MailboxCurrentCustodyReadScope` owns the
   denial-only client outcome/replay and peer replay/mutation/blob joins. All
   retained actual files, path/type guards, framing, hashes, index joins and
   independent floor comparisons remain mandatory on every invocation. No TTL,
   file metadata, watcher or positive authority result is reused.
3. The mutation owner lends its semaphore to this segment until the final
   actual current check. The blob owner still holds its existing semaphore
   during its inventory. The loan is released on success, cancellation or error,
   before returning to request work; it never spans peer HTTP dispatch.
4. Native validators and their diagnostics finish before the final source,
   protected role-floor/grant and same-boot trusted-time callback. Missing
   completed blobs must be expired at that exact final upper, using only a
   scalar maximum expiry collected during the read. The segment closes and
   cannot be reused after returning. No mutation, repair, reservation, receipt,
   network dispatch or externally usable admission result is exposed by it.

The redundant mutation pre-scan and post-scan source acquisitions are absorbed
by the enclosing read segment. The existing full recovery path uses four actual
lease checks for this join; the ordinary path requires two (ledger load and final
segment completion). Source/role callbacks at writes and network boundaries are
unchanged. Quorum still requires both independent durable receipts, with source
mutation durability before peer dispatch.

## Validation

Release source-cutover build passed with zero warnings/errors (native exit0),
under Windows PowerShell5.1.26100.9457 / SDK10.0.301. New focused cases passed
13/0fail/0skip/native0 in19s. They cover real client/peer `EnsureCurrent`, the
exact4→2 check-count comparison, closed-scope refusal and owner release,
missing/same-length damaged ledger/replay/mutation/blob custody, and final
source/expiry/floor/cancellation rejection. Receipts:
`artifacts/s05-current-custody-read-scope-20261026/focused-01/`.

The first regression selected224 methods before theory expansion and was too
broad for this partial owner slice. The coordinator stopped its owned process
tree before native completion to release the serial build slot. It is
**INTERRUPTED/UNQUALIFIED**, with no final TRX or native terminal; wrapper exit1
does not establish the test native exit. Original logs and the explicit
interruption record remain in `regression-01/` under the same artifact prefix.
Four observed failures remain unresolved: three theory cases of
`ActualProgramHealthCannotSubstituteDisabledOrMissingCompositionForRecovery`
and `ActualProgramDefaultRoutesHaveCurrentHealthAndNoRetiredMailboxFallback`
received a text/plain health response instead of the expected JSON. No cause or
pre-existing classification is established by that interrupted run. The later
[bounded Blob clock dependency fix](s05-blob-clock-health-2026-10-26.md) passed
the same four health cases and three clock lifecycle/guard cases; it does not
qualify the interrupted regression. No assertions were relaxed. Existing
targeted crash/rollback/revocation/quorum regressions and the required final
source gate still need qualification on coherent inputs.

## Remaining work

Actual inventory reads, replay joins and operation-document authentication remain
O(retained history) at each fence. Ledger writes still rewrite/fsync the complete
document. This slice reduces duplicated source acquisitions; it does not satisfy
the whole P2 redesign or the p95 1000ms target. A future affected-record design
must prove equivalent arbitrary retained-tamper detection with independently
protected aggregate custody, or obtain an explicit normative contract change
before changing detection semantics. The 100/1000/10000 scaling matrix, connected
engineering run, full source gates, package/device evidence and release gates
remain outstanding.
