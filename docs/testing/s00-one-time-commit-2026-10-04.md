# S00 / B8 — owned one-time publication commit verification

Owner: Mr. X. Source baseline: Protocol
`73f045491c7ca59dfcfdab21d161703e9df21238`, XNode
`3ce981bb750b3465377a418c0d5ddf363343a19f`, Shared
`59eba8b7ddfd9090a99df51021c72e02b5da394c`, root `6217743`.
Current status belongs only to [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
Execution follows [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

## Connected change and limits

[DR-0090](../../../docs/survival-program/decisions/DR-0090-did2-one-time-publication-commit-verification.md)
closes the missing typed client verifier over the existing signed DR88/89
object/request/result. One-time and reusable entry points share verification,
but do not accept a public kind flag, raw key or clock. No wire, signature
domain, suite, journal or invitation export right changes. The sole normative
owner is [CONTACT-RESOLVER §7](../../../docs/architecture/CONTACT-RESOLVER-V1.md#7-owned-did2-one-time-publication-commitment).
The reviewed source repin uses the existing registry generator.

Both selected receipt keys are now resolved from the independently verified
descriptor lineage, not node-ID bytes. Distinct ID/key positives use actual
signed DID2/PQ/current-network ceremony with explicitly synthesized receipts:
this is cryptographic consumer evidence, not storage or host qualification.
The existing two-store opaque-facade scenario now verifies the actual one-time
publication result, then claims once, exact replays and rejects a competitor.
That separate storage scenario still uses its existing equal ID/key composition;
the real contact receipt producer/facade alias has **not** been fixed here.

The common verifier validates its initial protected sample and all subsequent
intervals. No discarded extra clock observation remains. Existing closed
freshness error codes are preserved. A past exact commit remains verifiable
after short request/XPA expiry only while the independent current object/route
is valid; it never authorizes another dispatch of the expired request.

## Verification

Final reviewed source focused Node selection: **27 passed / 0 failed / 0 skipped**.
Nineteen new typed/descriptor/time cases plus eight existing consumer/facade cases.
TRX `artifacts/s00-one-time-commit/final-reviewed-focused/one-time-commit.trx`;
SHA-256 `7c5949d5a1177578d6c7bc25d55a86a157ffbb0b125cbfb9806e047b0415bbd0`.

Checks include ID-derived signing keys, wrong signature/unselected replica,
changed signed request, initial/intermediate/release/final clock rollback,
boot discontinuity, authority expiry before release/final return, oversized
result, disposed candidate, cancellation and mixed reusable/one-time route.
Reusable initial-clock rejection and expired-XPA historical commit are explicit.

Initial diagnostics: the first compile referenced an internal Protocol signing
helper; tests now use the existing node receipt transcript. The initial tests
exposed an ignored first clock sample, and used an incorrect expiry boundary;
expiry now uses the actual freshness deadline. Exact freshness exception/code
assertions and a valid different boot ID replace erroneous harness assumptions.
The first full Node attempt was explicitly interrupted after final review found
the discarded clock callback; it is **not** full-suite evidence.

Final reviewed Protocol default Debug restore/build: terminal0, zero warnings
and errors. Full Protocol: **2079 passed / 1 failed / 12 skipped**, terminal1;
Protocol1843/1/12, MembershipRoutes131/0/0, ProfileCarrier105/0/0. The sole fail
is the unchanged actual package witness finding retired MCG2 in assembly bytes;
the production source graph separately rejects retired MAU2 in the old codec.
Neither gate was weakened. The initial API-surface expectation was updated to
the accepted DR90 typed method and exact parameter/return types; the final full
run has no new failure. Twelve existing native/operator-capture skips remain.

| Protocol TRX under `artifacts/s00-one-time-commit/final-reviewed-full` | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_11_47_47_net10.0.trx` (MembershipRoutes) | `454b229f54f6c79fca3b9c0e54074af63e65bbb359e429d14ab4a423e798cf77` |
| `nikit_SURFACE-LT_2026-10-04_11_47_47_net10.0[1].trx` (ProfileCarrier) | `3cde62a210c1614104762bc3f2348cf062e6afae5fdf9463416f6508036ee985` |
| `nikit_SURFACE-LT_2026-10-04_11_47_47_net10.0[2].trx` (Protocol) | `1aa15bcbccd8af4311c818221ce87da837b0c12e255e3c7eb63908744369db99` |

Final reviewed Shared publication/reopen/issued-head/renewal selection:
**12 passed / 0 failed / 0 skipped**, terminal0, duration1m58s. No Shared source
changes; this is targeted downstream regression, not a new full Shared gate.
TRX `deep-client-shared/artifacts/s00-one-time-commit/final-reviewed-consumer/publication-consumer.trx`;
SHA-256 `247d39073bfeedfee20c874fd9150cde7c6f2f8583cb86d0193c37bdf9e05e33`.

Node Release solution warnings-as-errors build: terminal0, zero warnings/errors.
Its external Protocol project references build Debug; this is source-cutover
evidence, not a uniformly Release package/installed artifact matrix.
Final-source real-Xray external smoke: terminal0, hard/soft failures0,
transport running/not mocked. Owned temporary smoke containers/volumes were
cleaned; the six pre-existing deep-dev containers were retained. This health/
transport result does not qualify current contact/mailbox composition or physical
delivery. Receipt `deep-devops/artifacts/s00-one-time-commit-final-smoke-20261004/runtime.gate.json`;
SHA-256 `3d53bd36b72723d4c8fbd1b6ed7a47983bbcac41a2c2093044501d13083eec07`.
No path/peer/runtime transport source changed, so the prior three-node rehearsal
is not repeated or presented as new evidence.

Strict generator/registry gate passes. DNP1 ownership exact314/package219/final95
has219 mapped/packageMissing0: mapping consistency, not package qualification.
Executable manifest integrity passes only; no new DNP1 executable evidence is
inferred. Root documentation174, CONTACT/crypto/ONION/governance ClassificationOnly
and selected source/doc/receipt secret scan pass. Four edited documents pass
strict UTF-8 and101 local file links. Consistency-only gates are not release evidence.

Final reviewed full Node: **1161 passed / 0 failed / 0 skipped**, terminal0.
Integration782, unit272, profile107; integration duration22m51s. The nineteen
new cases are added to the unchanged complete default graph, not a whitelist
or replacement for the earlier full suite. Tested code commits are Protocol
`b98698b8b12a5fafefd822d3ee33b4d0d176d9df` and XNode
`a7488b968223b1f23e280467938f5c8d8375a10b`; later checkpoint edits are docs only.

| Node TRX under `artifacts/s00-one-time-commit/final-reviewed-full` | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_11_48_12_net10.0.trx` (profile107) | `082841f1bc6d211658b4a7f321c441a2a9a8fb264f0bcdf2aed69afdb95c7b47` |
| `nikit_SURFACE-LT_2026-10-04_11_48_14_net10.0.trx` (unit272) | `10a111b048d64e1f421e43ee794016308b438ca9a9862600bd86c78fb82fa943` |
| `nikit_SURFACE-LT_2026-10-04_11_48_16_net10.0.trx` (integration782) | `717f17ec765931e18b5693597ec1f05aa8cf0f114bbf9c513fc2489a81cde65d` |

Account-owned one-time secret pending/winner/read-back/exact AEAD restoration,
retained genesis completion, local format closure and shipping export remain
open. Reusable journal9 stays reusable-only. Real distinct-key contact host
composition, package graph, installed artifacts and Windows/Android device E2E
are separate requirements. No production/device/account/secret state changed,
no old stash was restored, and no release or main merge was performed.
