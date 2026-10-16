# S05 — original native Store recovery candidate

Owner: Mr. X. Local current-dev only; not physical delivery or release acceptance.
The observed receive refusal is recorded in the
[device checkpoint](../../../deep-client-maui/docs/S05-BUSINESS-WORK-2026-10-17.md#retained-local-deployment-and-native-pending-store-diagnosis).
Network ordering and pending-prefix obligations remain solely in
[XPOINT-NETWORK section9.1](../../../docs/architecture/XPOINT-NETWORK-V1.md#91-current-two-replica-store-ordering).
Local scheduling/custody belongs to
[the native owner](../mailbox-operation-custody.md#original-store-settlement-worker-candidate).

## Source correction

Previously the node retained its exact signed peer intent but depended on a
client retry to finish it. The new configured-graph hosted worker selects one
active original reservation under actual host/key/native recovery, then
independently reopens its exact custody under the original current grant and
both role owners before peer effects. Closed/stale snapshots cannot dispatch.
It never issues a grant or authors a new nonce, cursor, request or ciphertext.
Two independent receipts precede protected quorum retention. No new journal,
local generation, wire/API allocation, signing tool or dependency is added.

Native settlement does not manufacture the client's canonical outcome. A later
independently current exact client retry verifies/adopts the same saved quorum,
without another peer request or coordinator receipt. Readiness remains
observational and does not drive this mutating worker. Normal cancellation,
fixed closed logging and bounded scheduling/backoff use the existing host.

An expired/revoked original grant still refuses. This does not close unsettled
expiry/retirement, historical issuer/cohort handover or sustained runtime load.
Do not replace those requirements with a new account or skip live Pending in a
Retrieve page. The original Store failure's cause has not been established by
the later pending-read observation.

## Exact focused receipts

All runs use Windows PowerShell5.1 and SDK10.0.301; native0, no FAIL/skip or
compiler diagnostics. These are focused scopes, not canonical full qualification.

| Run under `artifacts/s05-native-store-recovery-20261017/` | Passed | Scope |
| --- | ---: | --- |
| `focused-01` | 22 | Initial6 recovery cases plus actual host recovery regression |
| `focused-02` | 164 | Expanded12 recovery cases, native ingress/onion and host composition |
| `focused-03` | 23 | Final16 recovery cases,2 registration cases, original quorum-persistence2 and native authority-fence3 |
| `closed-observer-04` | 5 | Shared owned-code observer regression3 and recovery unreadable-exception/throwing-logger2 |

Positive cases use genuine signed fixture authority, two independent native
stores and actual TLS/H2. They cover interruption at Store reservation and
lost peer response, each with/without reopen; exact original peer bytes,
protected quorum and later identical client adoption; no fabricated client
completion. Pre/post-quorum replacement faults recover the sealed winner after
reopen without new peer HTTP. Negative cases cover expired/unavailable authority,
protected revocation, foreign/closed/settled snapshots before effects, missing
document/checkpoint, wrong TLS, cancellation and host stop/idle preservation.
Registration-only cases acquire no authority, clock, keys or files.

For the eventual full reference union, use the prior accepted full plus current
final new cases and the separately committed native-observer cases. Initial
uncommitted case shapes are not an accepted full baseline. Current full/package,
external transport rehearsal, matching retained local activation and physical
Windows/Android business acceptance remain required. No production change,
GitHub Release publication or main merge is claimed here.

## Retained runtime observation

Source `30cd519` was activated only in current-dev through supported Build16,
Up17 and Verify18, all native0. All9 services matched captured desired images;
all54 mounts/RW modes are preserved. Raw comparison did not pass because three
bind-source strings changed representation; a separate finite Windows/Docker
alias proof matched all54 original targets. Verify reported current Registry
proof and3 verified nodes, recovery24s. This is readiness, not messaging.

The first worker events are unavailable on all3 nodes. They do not identify the
failing guard and, because the initial observer deduplicated by state alone,
cannot establish whether a later failure has the same cause. Do not infer grant
expiry from these logs. Closed observer04 above adds code-location-sensitive
observation without changing recovery/currentness rules; matching activation
and cause inspection remain required.

Android43 Dry175/Inspect176/Refresh177/Inspect178 completed their scoped phases,
without reset or APK replacement. Actual receive remains OutcomeUnknown:
MailboxSyncTotal60611ms,10 Protect/345 Unprotect,32642ms protection. The closed
native log again observed ReadCurrentWindowAsync IL1074/live pending Store;
no identifier correlation with a particular old sender intent is asserted.
Physical business acceptance remains0/4. Current expired-original recovery,
canonical full/package and broader S05 gates remain open.
