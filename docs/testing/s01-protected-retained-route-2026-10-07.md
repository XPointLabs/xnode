# S01 protected retained-route native candidate

Date: 2026-10-07. Sole transition owner:
[CONTACT-RESOLVER §3.7.2](../../../docs/architecture/CONTACT-RESOLVER-V1.md#372-independent-retained-read-custody),
accepted native contract [DR-0103](../../../docs/survival-program/decisions/DR-0103-protected-retained-route-document.md).

`FileContactResolverStateCustody` authenticates the exact existing generation5
document with separately protected enrollment/checkpoint records, a lifetime
writer and one prepared transition. It adds no route table, payload/key copy,
protocol allocation, local opaque generation or registered identity change.
`ResolveProtectedRetainedMailboxRouteAsync` rejects an unprotected store and
rechecks both actual and captured document bytes around current authority
callbacks. Its result remains private facts, not signed issuance authority.

Focused integration run03 completed terminal0: **50 Passed /0 Failed /0 Skipped**.
It uses real signed DID2 publication/request fixtures, actual files, persisted
Data Protection keys and native ACL/durability. Cases include cold reopen,
data/root rollback, missing/tampered keys and records, wrong node/network/purpose,
bounded records, interrupted enrollment, six pending-replace crash boundaries,
candidate/read ABA substitution, callback mutation and exact orphan cleanup.
Missing authenticated metadata never adopts a temporary. Matching joint data
and root rollback is tested as explicitly outside the local guarantee.

Focused neutral resolver regression02 completed terminal0: **15/0/0**, including
the new lock-security failure test: construction releases the acquired writer
lease and creates no resolver document. Earlier runs01 (39/0/0),02 (47/0/0)
and neutral01 (14/0/0) remain separate receipts, not rewritten inputs.
TRX files are under `artifacts/s01-protected-retained-route`.

The actual DID2 resolver composition now requires the native custody owner;
there is no unprotected retained-read fallback. `ContactResolverCustody` captures
node/data/network/path bindings before deferred DI callbacks and uses an existing
persistent key ring. The explicit `contact-resolver-enroll` command verifies
actual current source/root/PMA2/time/signing custody before fresh enrollment
and actual history/authority plus document read-back after persistence. No
listeners, import/reset arguments, identity generation or startup enrollment.
Both real-DID2 contact replicas in the existing HTTP composition tests use
explicit enrollment and cold protected reopen; the assertions were not removed.

Final coupled03 completed terminal0: **196/0/0**, covering protected resolver,
DID2 contact/issuer HTTP composition and unchanged current mailbox composition.
Final neutral03 completed terminal0: **15/0/0**. Release solution build terminal0,
zero warnings/errors. Coupled02's **195/1/0** is preserved: the newly introduced
directory-obstructed lock test expected IOException, but Windows reports
UnauthorizedAccessException. The corrected exact expectation tests release of
the already opened resolver after runtime construction fails; no product guard
or existing assertion was weakened. Coupled01 (195/0/0) preceded that case.

Mandatory isolated external/no-mock Docker smoke completed terminal0 with a
fresh project `deep-s01-protected-retained-route-20261007` and fresh evidence in
`deep-devops/artifacts/s01-protected-retained-route-smoke-20261007-01`.
Only its seven smoke containers, temporary network and volumes were cleaned;
six pre-existing dev containers/data remain. This infrastructure profile does
not activate protected retained issuance; Registry uses the existing local
cutover package lane. It is not physical/device or shipping evidence.

| Smoke receipt | SHA256 |
| --- | --- |
| runtime.gate.json | `9A6E18B2A6412F33FB63ED3F557AE0F233B4D33FF6CDEF4BBED605AEAF23D081` |
| runtime.snapshot.json | `A5A9AC3DF785ED0650BB8ADB49F216F60BD7A4E8B2B4A3D070A8E1C42FF3A862` |

The original full Release Node run completed terminal0: **1294/0/0**
(Integration936, ProfileGenerator107, Unit251). Post-terminal qualification
completed0: all1242 prior executions and all211 final focused executions are
retained with their exact names/outcomes, and all2351 prelaunch inputs are
unchanged. The original capture and failed focused receipt were not replaced.
Prelaunch manifest SHA256:
`DFCF760C742AACFAB6C92FF3164689B721D2605D593D02243D736EB64FB4B73C`.

| Full receipt under artifacts/s01-protected-retained-route/full | SHA256 |
| --- | --- |
| nikit_SURFACE-LT_2026-10-07_15_22_06_net10.0.trx | `65CBDDA51470C1210553ADD72E2E1E8C55EB03E29C8A7B5355EF011DED471964` |
| nikit_SURFACE-LT_2026-10-07_16_01_04_net10.0.trx | `B57D7DE8BFA2CC3C90C87F47461EAF1BB9E24C34174D7437DE4774C2DCDEF865` |
| nikit_SURFACE-LT_2026-10-07_16_01_30_net10.0.trx | `0A40FA226B703905C85F3A616C9AE907D33699A1856D435D5CC9F973B21E3ECA` |

Both mandatory Node gates qualify only this native custody/composition slice.
This remains unfinished source within the same retained-read business batch.
Independent two-store retained evidence,
renewed issuer/owned holder, typed node Retrieve/ACK and accepted-object horizon
remain gated. No production deploy/reset, physical/device acceptance, GitHub
Release or main merge follows from these focused/smoke results.
