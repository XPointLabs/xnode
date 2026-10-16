# S05 native original Store expiry exclusion — candidate

Owner: Mr. X. Branch: release-candidate/prod-20260909.
Contract: [DR-0134](../../../docs/survival-program/decisions/DR-0134-original-store-expiry-exclusion.md).
Native mapping: [operation custody](../mailbox-operation-custody.md#original-permission-expiry-exclusion-candidate).
Protocol source: `9d6df07`; [its affected checks](../../../deep-protocol/docs/testing/s05-store-expiry-exclusion-2026-10-17.md).

## Source and checks

The protected writer prefix verifies either original saved MQR3 or permanent
original-permission expiry before a later allocation. There is no fallback
from broken durable custody. The actual Retrieve path holds ledger -> mutation,
matches every native original request/blob/cursor binding, authenticates the
original permission and reloads protected custody after callbacks. All omitted
native Pending records are reread after later blob/time callbacks. Completed
objects are not hidden because of grant expiry. Pending cannot bypass these
checks through object upper-time overlap. Original bytes, unknown outcomes,
native records and protected/replay floors remain; no collection/reset/remint.

Native PowerShell5.1 / SDK10.0.301 / root Invoke-TestGateNative, fresh ignored
directories under artifacts/s05-store-expiry-20261017:

| Receipt | Native exit | Passed / failed / skipped | Scope |
| --- | --- | --- | --- |
| focused-01 | 1 | 27 / 7 / 0 | Existing affected cases passed; all seven initial new cases rejected during fixture setup |
| focused-02 | 0 | 9 / 0 / 0 | Corrected real signed windows; new expiry/native custody cases |
| focused-03 | 1 | 52 / 3 / 0 | Expanded55-case union; two existing rejection-type mismatches and one new TTL fixture setup failure |
| focused-04 | 0 | 12 / 0 / 0 | Final ten new rows and both unchanged existing warm/cold live-Pending cases |

The first failure was a test-input defect, not successful product reproduction:
its requested short grant already failed the genuine full trusted interval.
The corrected fixtures keep the existing signed time uncertainty, prove overlap
refusal and reach exact lower equality using the real clock projection. A
separate new current grant permits later work; original bytes are not resigned.
Production clock/grant checks and lifetimes were not relaxed. The first receipt
predates the final later-callback/object-overlap guards and is not final evidence.

The expanded run preserved live-Pending rejection but exposed two existing
exact exception contracts: expiry authentication escaped as CryptographicException
instead of the native reader's InvalidDataException. The consumer now wraps that
failure with its original native rejection type and retains the inner cause;
existing assertions were not weakened. The new object-overlap fixture initially
violated the canonical minimum60s TTL before reaching the tested path. Its
independently created object now spans the canonical60s interval; signed clock
uncertainty and production TTL/admission checks remain unchanged. Focused04
verifies all ten new rows plus both unchanged existing warm/cold cases. All
builds have no compiler diagnostics. The passing receipts overlap; they are
not an unfiltered55-case run or canonical full-source qualification.

Cases use real local TLS/H2 and two independent stores, before-mutation and
native-Pending interruption, warm/cold reopen, unchanged original row/request,
later cursor2, no late old client or peer completion, malformed durable quorum,
absent exact original at the non-writer, retained completed objects, and hostile
later blob callback. Test helpers only gained explicit new-grant expiry inputs;
their defaults and previous cases are unchanged. The affected scope is covered
by expanded03 plus final04; the original failed receipts remain unchanged.

## Activation and remaining scope

Matching local Build25/Up26/Verify27 completed with native0. Runtime code is
Node `3fe03ab` / Protocol `9d6df07`; all nine desired images match actual running
containers. All54 mounts (29 volumes/25 binds, including RW modes) are retained.
Raw representation comparison remains FAIL; a separate finite-equivalence proof
matches all originals and identifies one permitted path representation alias.
Ignored snapshots/comparison/proof are under
deep-devops/artifacts/s05-store-expiry-20261017. No signer/key/genesis/floor
ceremony, enrollment, account reset or production deployment occurred. Build's
first wrong-interpreter invocation rejected before launch; actual Build/Up/Verify
used the explicitly selected PowerShell7 wrapper. Native tests used5.1 as above.

Existing APK43 passed dry179, Refresh180 and independent Inspect182 with
SynchronizationCompleted=true, MessagingError=false, no busy control/reset.
Actual MailboxSyncTotal was68814ms,13 Protect/384 Unprotect, protection36851ms.
Windows26's first Refresh ended OutcomeUnknown after33095ms (9/267 operations,
protection9751ms); an uncorrelated node1 native-deadline observation was retained.
Its bounded ordinary UI retry completed synchronization without error on the
same account:24834ms,4 Protect/218 Unprotect, protection10742ms. Four existing
outgoing awaiting-acceptance rows remain; this is read recovery, not contact
delivery or a reason to delete their unknown intents. Both installed client
binaries are unchanged. Exact device evidence remains with the
[MAUI owner](../../../deep-client-maui/docs/S05-BUSINESS-WORK-2026-10-17.md#original-store-expiry-exclusion-retained-read-recovered).
The subsequent Android exact contact retry still rejects retained Initial draft
metadata before another Store. It does not undo the read result or qualify
contact delivery; resolve that actual owner boundary without discarding intent.

The original recovery worker still correctly refuses expired admission and
does not retry with fresh permission.
Missing original custody at a non-writer still fails closed: this increment
does not add a peer RPC or reconstruct a signed original. Original uncertainty
is not delivery or noncommit. S05 remains unaccepted; physical contacts, text,
attachments and groups remain0/4. Full source/package, external transport
smoke/rehearsal and Windows/Android business acceptance remain open.
