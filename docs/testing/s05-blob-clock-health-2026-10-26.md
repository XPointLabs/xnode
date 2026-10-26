# S05 disabled Blob clock dependency — 2026-10-26

The four health failures observed in the interrupted custody regression remain
in their original logs. They are not reclassified as passing executions.

## Cause and change

Read-only source tracing found an eager dependency chain from `/health/ready`
through disabled `PrivacyRoutingRuntime`, `PrivacyTerminalExitDispatcher` and
`BlobChunkOnionDispatcher` to `LinuxBootOnionMonotonicClock`. Its constructor
rejects Windows, even when no Blob operation is being admitted. The eager Blob
clock dependency originated in `54a71c5`, before the custody read-segment slice.

`BlobChunkOnionDispatcher` now resolves the same required configured clock inside
its actual Blob currentness check, immediately before the existing clock read.
Construction/readiness creates no Blob custody and acquires no production time.
Actual Blob processing retains current network/selected local role, freshness,
expiry and before/after effect checks. The Linux-only production guard is
unchanged; no fake clock, UTC substitute or unsupported-host fallback exists.

## Exact evidence and limits

An attempt to inspect the old compiled health response using a bounded
PowerShell7 reflection helper failed tooling with native exit3 and closed error
type `System.Management.Automation.MethodInvocationException`. No response text
was emitted and no runtime prechange exception cause was established. That
attempt remains in `artifacts/s05-blob-clock-health-20261026/oldcompiled-01/`;
the helper was not repaired or retried.

Windows PowerShell5.1.26100.9457 / SDK10.0.301 Release source-cutover build passed
native0 with zero warnings/errors. Exactly seven native cases passed
7/0fail/0skip/native0: the same four existing health cases, dispatcher construction
without clock/custody acquisition, an actual signed current Blob request whose
configured clock rejects before mutation, and the real production clock's
unsupported-host guard. Canonical input capture found source unchanged through
build and all2350 source/binary/normative/tooling inputs unchanged during tests.
Receipts: `artifacts/s05-blob-clock-health-20261026/focused-01/`.

The source dependency chain and the minimal change followed by those same four
passing health cases support this diagnosis. They do not retroactively confirm
the old response's exact exception or qualify the interrupted broad regression.
No full gate, Linux connected Blob delivery, Docker, device or release acceptance
was run or claimed. The independent P1/P2 architecture and latency gates remain
open.
