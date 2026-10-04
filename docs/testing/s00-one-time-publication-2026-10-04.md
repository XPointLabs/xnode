# S00 / B8 — signed one-time publication integration

Owner: Mr. X. Baseline: Protocol `010b94a16d65e46af91a88ba9787ee92b39e513b`,
Shared `485c381280ca9b59d27eba12be43a7eb7d5f782f`,
Registry `2a78eb64713ef02b1400ff5a6c35a956a33f8fae`,
XNode `bf24f288d3a37f5e9f9568f54e5bfd0bf3958b08`, root `fb52c84`.
Current matrix/status belongs to [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
Execution follows the auditor's integration-first
[S00–S13 plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md), not a new roadmap.

## Connected change

[DR-0089](../../../docs/survival-program/decisions/DR-0089-did2-one-time-publication-coordination.md)
adds only public locator16 to the existing signed coordination envelope. Existing
signed kind/hash/expiry/usage fields are not duplicated. Both permanent and
one-time requests use sole V4; old envelopes/media reject. DIA1, its decryption
key and full invitation hash are never witness inputs. Existing DIA1/AEAD,
publisher domain, XPA/XPU and neutral node receipt grammars stay unchanged.

The real owned one-time candidate now feeds the typed request author and actual
witness threshold. Registry durably reserves by account leaf, kind, locator and
unsigned generation under its existing network lock/capacity budget. Independent
one-time genesis invitations coexist with permanent genesis; changing bytes or
nonce for one scope cannot sign, including after a pending callback failure.
Explicit operator provision retains opaque retired rows/counts and old permanent
fences without any old-envelope runtime reader. Actual production provision was
not performed. The reusable Shared journal9 merely repins the request/budget;
it does not gain a one-time secret slot or export permission.

Node admission accepts exact current kind2/usage1 genesis, retaining witness,
placement, protected time and replay checks. The formerly failing B8 claim case
now publishes a genuinely signed one-time object, durably claims once, exact
replays the successful response and rejects a competitor as `AlreadyClaimed`.
It no longer edits a permanent object's usage limit. Reusable scenarios keep
their quota/replay/crash assertions.

Closed metadata/schema and generated signed positive/hostile vector ownership:
[registry](../../../docs/survival-program/releases/v3.0.0/specs/contact-publication-v4.registry.json),
[vectors](../../../docs/survival-program/releases/v3.0.0/specs/contact-publication-v4.vectors.json).
The executable cases compare the independent unsigned signing-input assembly,
locator-domain result, publisher signature, exact response/XPA fields and absent
invitation/key. Hostile retired/unknown versions, flags, truncated/trailing/large
bodies and mixed kind/locator reject. A valid-width locator edit cannot invoke
witness signers. No generic trusted constructor or fake verifier capability is added.

## Focused and provider evidence

Final fresh connected Node selection: **53 passed / 0 failed / 0 skipped**:
24 existing object cases, 11 publication cases, 15 facade cases and 3 carrier cases.
TRX: `artifacts/s00-one-time-publication/final-vectors-connected/nikit_SURFACE-LT_2026-10-04_09_39_26_net10.0.trx`;
SHA-256 `67111f2c5e14a532557644c38fc3398d23efb67fbcc074b31e4e89757cebef01`.

Full Registry source-cutover: **331 passed / 0 failed / 6 skipped** in the
disposable pinned PostgreSQL lane; terminal exit0, container/tmpfs removed.
TRX: `deep-registry-api/artifacts/s00/one-time-publication-final-c848f308366f4f15a39d2045d3124159/nikit_SURFACE-LT_2026-10-04_09_35_23_net10.0.trx`;
SHA-256 `61e7cc005332052a5a7a9167a82b09d04b4b90b155832d94f85d711b08d2a3e2`.
The six Windows signer skips were rerun on fresh source through the existing
Linux Docker signer-only target: **6 passed / 0 failed / 0 skipped**, terminal0.
These six are the same cases, not additive unique coverage or device qualification.
The artifact-export container was never started and was removed after ownership
verification. Actual Unix socket framing remains synthetic-signature evidence,
not cryptographic issuance or production signer readiness.
Linux signer TRX: `deep-registry-api/artifacts/s00-one-time-publication/linux-signer/_buildkitsandbox_2026-10-04_04_50_13_net10.0.trx`;
SHA-256 `7fd13c77a0cc81283e7dbad7fb0adffbf1815c6f02361586ed61d7efb80c224b`.
Current tests exercise real PQ account/SQLCipher, file witness custody, PostgreSQL
transactions, authenticated TestServer HTTP lost response/restart, six concurrent
exact provider replays, corrupt locator projection and SQL half-null/duplicate/
unsigned-generation constraints. TestServer does not provide socket TLS or ONION evidence.

Initial diagnostics were retained/classified: node XPA genesis was permanent-only
and required the explicit kind2 admission change; Registry pending-header tests
expected journal8 and were repinned to9. Concurrent issuer calls correctly hit
its unchanged bounded source admission, so concurrency was moved to the actual
journal provider; sequential issuer/HTTP restart coverage remains. The final
Registry build found a shadowed local variable in a new corruption test; only
that variable was renamed. An initial Node full attempt found two stale carrier
version3 assertions and was explicitly interrupted, not reported as a full pass.
Only the publication version assertion changed to4; all carrier tamper/currentness
and unknown-after-forward assertions remain, and the final 53-case selection passes.

## Full gates

Final Node full suite: **1129 passed / 0 failed / 0 skipped**, terminal0.
Integration750, unit272, profile107; integration duration19m18s. All 198 current
mailbox/MGR cases and the original B8 claim/replay scenario pass. No tests were
removed or skipped. CI's integration job now checks out the four closed public
specification inputs from the matched root branch before the child checkouts;
their absence or drift rejects, with no fabricated fallback. This workflow-only
change follows the completed source gate and does not alter tested runtime code.
Final Shared production suite: **547 passed / 0 failed / 0 skipped**, terminal0,
duration27m16s. TRX:
`deep-client-shared/artifacts/s00-one-time-publication/full/nikit_SURFACE-LT_2026-10-04_09_36_50_net10.0.trx`;
SHA-256 `2ad1c4cfd75b6f6050fac41782cb55372b27258d30e8f9db8f0c0817475f0f59`.
Final Node/Protocol Release builds have zero warnings/errors. No full suite
is inferred from a focused selection, partial run or another source matrix.

| Node TRX under `artifacts/s00-one-time-publication/final-full` | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_09_39_43_net10.0.trx` (profile107) | `98cfc463f18f4b6fface160fddc93307861237bdfff23ff437c1e9346083e80e` |
| `nikit_SURFACE-LT_2026-10-04_09_39_43_net10.0[1].trx` (unit272) | `44392f91e1e7263d32853effc12f4ae1961858d812ec38d610a91df541b52ff0` |
| `nikit_SURFACE-LT_2026-10-04_09_39_43_net10.0[2].trx` (integration750) | `1098bf0c1915131850d81a6cd2e21102326414eb863d51772944173667587da0` |

Protocol Release build: **0 warnings / 0 errors**. Full Protocol:
**2079 passed / 1 failed / 12 skipped**, terminal exit1. The unchanged package
witness still finds retired MCG2 in assembly bytes; the graph script also rejects
retired MAU2 source. These failures remain release blockers, not waived exceptions.
Reviewed source/anchor repin covers the three edited normative sources, current
production inventory and 86 moved anchors; strict generator/check and registry
gate pass. DNP1 classification passes exact314/package219/final95 with mapped0,
packageMissing219: **not a package-complete ownership gate**.
Root CONTACT/crypto consistency checks pass on the current retained inputs.
The root ONION checker now follows the accepted DR89 width, preserving the exact
operation/magic pairing and all existing malformed/vector checks. It validates
the new publication registry/vector schemas and their outer-wrapper pairing;
2 valid schema documents and 8 expected extra/missing/activation/decision
rejections pass. Public documentation gate passes174; selected UTF-8/JSON/local
link checks pass. These are metadata gates, not executable delivery evidence.
Root `check-survival-program.ps1 -RequiredEvidenceClaim ClassificationOnly`
also passes on the current immutable twelve-input set. No approved digest/blob
was rewritten for this batch; the result still has mapped0 and cannot grant
ProtocolPackageGO or CutoverFinalReleaseGO.

| Protocol TRX under `artifacts/s00-one-time-publication/full` | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_09_36_37_net10.0.trx` (membership131) | `e0c6aceb67514f47e44aa5f62a2967a75db57c1247ace5bedf2cb20ed69df776` |
| `nikit_SURFACE-LT_2026-10-04_09_36_37_net10.0[1].trx` (carrier105) | `6b7a83d89da7fdc6d0fc5b3f0e824df705e48c72d2393b94d94dd600501a5222` |
| `nikit_SURFACE-LT_2026-10-04_09_36_37_net10.0[2].trx` (main1843/1/12) | `dfd63ef42f587875fe649d4216674b1feb784ee2ff75979ed94efbc8ac17b3bc` |

## Local transport and remaining limits

Final-source managed-external real-Xray smoke passes with failedHard0,
failedSoft0, mocked=false and no runtime warnings. Three unchanged Dockerfile
InvalidDefaultArgInFrom warnings are separate from .NET compilation.
Sequential three-node rehearsal passes: three actual running/non-mocked Xray
processes, no reconciliation issues. Privacy endpoints correctly return503 without
ready current authority; health does not prove publication or message delivery.
Both owned temporary projects/volumes were cleaned; six existing deep-dev
containers remain. No production, registered keys, device/account data or operator
secrets changed. No packages or GitHub Releases were published.

| Local environment receipt | SHA-256 |
| --- | --- |
| `deep-devops/artifacts/s00-one-time-publication-20261004/runtime.gate.json` | `129d4951eb3f02ca333791838cf77390f09223f2c4d0d643dbadee335c1af862` |
| `deep-devops/artifacts/rehearsals/multi-node/20261004T044146714Z-84c84218d440/test-results/multi-node-topology.json` | `4bb77ea89104f2bdee218b7d79a67aeeca352cba8489fca7534016013c4897ee` |

This closes the signed publication/Registry scope/node claim prerequisite, not
all B8. Account-owned one-time secret pending/winner custody, exact AEAD restoration
before shipping intent/export, client commit verification and QR remain open.
An incomplete intent crossing the short request/XPA expiry also needs the S01/S04
reconciliation lifecycle; exact replay must not extend validity or remint a nonce.
Installed matching packages/provisioning, Release composition and physical
Windows/Android contact/consent/text/receipts are still required. Full files,
groups and other release scope follow the auditor's plan after the text milestone.
