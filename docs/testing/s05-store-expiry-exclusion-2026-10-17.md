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

No matching activation or physical retest is claimed here yet. The old deployed
reader still refuses native Pending, and its original recovery worker correctly
refuses expired admission. The new worker does not retry with fresh permission.
Missing original custody at a non-writer still fails closed: this increment
does not add a peer RPC or reconstruct a signed original. Original uncertainty
is not delivery or noncommit. S05 remains unaccepted; physical contacts, text,
attachments and groups remain0/4. Full source/package, external transport
smoke/rehearsal and Windows/Android business acceptance remain open.
