# S05 — one current contact-replica endpoint

Date: 2026-10-15. Program previously registered competing replica handlers when
both current resolver and bounded inventory staging were enabled. The production
local contour reproduced `AmbiguousMatchException` on the receiving peer and an
unknown publication outcome with only one reported durable replica.

Program now calls one mapper for both activation flags, resolving the current
`IContactReplicaCommandReceiver`. The redundant mapper/plan wrapper is removed;
the common listener, TLS/H2, peer signature, replay, current placement and durable
handler are unchanged. No compatibility reader, route alias or new wire is added.
Closed optional publication logging uses the existing ILogger dependency to
separate reservation, write-quorum and receipt failures without private fields.

Focused02: **11/0/0/native0**, Release/source-cutover, receipt
`artifacts/s05-contact-diagnostic-20261015/focused-02/single-peer-endpoint.trx`.
Includes both-flags exact-one-route regression, enabled/disabled routing, dormant
composition, real TLS/H2 wrong-pin rejection and lost response/cold store recovery.
Focused01 previously passed7 for the diagnostics slice.

[Connected Windows owner](../../../deep-devops/docs/S05-CONTACT-TRANSPORT-2026-10-15.md)
then completed contact publication and an authenticated empty mailbox read on
the rebuilt real contour. This is not physical MAUI/message qualification.
Canonical `full-01` executed all1513 tests successfully (1145 integration,
107 profile,261 core; native0, no failures/skips). Its final qualification
rejected the DR-0121 retirement declaration: prose specified the replacement,
but the required exact arrow binding was absent. The original terminal remains
qualification1/FullAccepted=false. The decision now includes that same exact
binding; common gate reference validation runs before build and again at final
qualification (49 contract checks/native0). A fresh canonical run is required
for those changed captured inputs; neither the prior source full nor raw1513
passing executions is substituted for its acceptance.

Mandatory current-source managed-external no-mock smoke and three-node
infrastructure rehearsal both completed native0; scoped stacks cleaned up.
Receipts: DevOps `artifacts/s05-contact-diagnostic-20261015/infrastructure-01/`.
They do not extend the device/message evidence scope.
