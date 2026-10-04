# S01 current host recovery/readiness — 2026-10-04

Owner: Mr. X. Execution order: [unified plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Contract/mapping: [operation custody](../mailbox-operation-custody.md),
[DR-0087](../../../docs/survival-program/decisions/DR-0087-current-mailbox-operation-custody.md).
This is source integration, not deployed or physical-client qualification.

Input matrix: XNode `16a2c4c474daa55f33a7dd55140f9769fd5f86bb`,
Protocol `6afceb2fc457b2df9ea207f542204de945cbb746`,
Shared `13c9b3da35bb94c8690b15d7c320c21885960da3`,
Registry `1f20f973a57378b78b536a84711a85a39a6341e6`,
DevOps `54fc3ab6911b8dc2f8cfa97dd7b767c2172cdc44`, plus this Node batch.
Unchanged dependencies' previous full results are not a new gate for this source.

## Connected behavior and evidence

The actual Program registers one recovery singleton as a hosted service and as
the fresh `/health/ready` consumer. It uses the actual current receiver's
host-only operation, descriptor signing custody, both protected role leases and
the same schema-6 operation owner. Recovery never creates client authority,
reserves replay or enrolls missing custody. Public health is observability only.

Real generic-host tests cover both replica owners after client grant expiry,
missing/split composition, missing operation data/protection/either role floor,
wrong descriptor key, fresh source/time rejection, precancellation, hostile
protected-read callback, busy/stopped checks and both sides of anchored exact
replacement. Original retry then completes over the existing actual TLS/H2 peer
path with no remint. Actual Program HTTP tests assert enabled unconfigured or
not-running recovery returns 503, and disabled mailbox skips authority owners.
Their isolated host omits unrelated hosted services; this negative composition
evidence is not a production-ready host or simulated positive authority.

Focused host tests: **15 pass / 0 fail / 0 skips**. Program HTTP: **3/0/0**.

| Local receipt | SHA-256 |
| --- | --- |
| `artifacts/s01-host-recovery/expanded/nikit_SURFACE-LT_2026-10-04_15_25_32_net10.0.trx` | `2b4a7c92995283cf56f189babe13874a4e81cb56714435ea45de1f686a8064dc` |
| `artifacts/s01-host-recovery/health/nikit_SURFACE-LT_2026-10-04_15_30_24_net10.0.trx` | `48f7a2254363e757aee7d11479546b0b7e9d974d3c404a372b53208b0123a187` |

Fresh source-cutover solution Release build: **0 warnings / 0 errors**, exit0.
Code gate: `77c946eefbd117ece248c7909aa8f6782b1aa4e3`.
Connected mailbox/readiness selection finishes **239/0/0**, exit0, 28m22s:
`artifacts/s01-host-recovery/connected/nikit_SURFACE-LT_2026-10-04_15_30_43_net10.0.trx`,
SHA-256 `39bc3f1cf1bb4ee57f507ec32eca79ea4b225a5ae318cb1bac1b353637e76995`.

## Full gate and unresolved setup failure

The required source-cutover Release full solution run finishes **1204 pass /
1 fail / 0 skips**, exit1. Unit272 and profile107 pass; integration825 pass /
1 fail / 0 skips (826 total), 30m17s. It is not a successful full gate.

| Local receipt under `artifacts/s01-host-recovery/full` | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_15_59_09_net10.0.trx` (profile) | `a7fbb1f5ab2c674a0146d56eca1e5bf0399c61a51e0ed70e9925e85748f7f355` |
| `nikit_SURFACE-LT_2026-10-04_15_59_09_net10.0[1].trx` (unit) | `5d50afff9986aad036875b8eaf791f367a4d017f1cf0be5f0e34fa129d8fdebf` |
| `nikit_SURFACE-LT_2026-10-04_15_59_10_net10.0.trx` (integration) | `5a826955fae33975ce35b201f5d6e6a9432f84c546adc08b53d713caf7dbd75b` |

`CurrentClientAckRevokedRoleCannotReleaseCachedAggregate` fails in its setup
`StoreItem`: expected Durable, observed PartialFailure, before the revocation
branch. That same test passes in the connected selection. The original failure
does not identify whether a transport deadline, storage failure or another
dependency prevented quorum; those explanations remain hypotheses.

Only the helper's failure message is expanded with existing enum/count/type
diagnostics. The assertion still requires Durable; no retry, skip, timeout,
quorum, crypto, authority or runtime behavior is changed. Original isolated
Debug ACK case passes1/1 in17s:
`artifacts/s01-host-recovery/ack-setup-diagnostic/nikit_SURFACE-LT_2026-10-04_16_16_59_net10.0.trx`,
SHA-256 `318c381eecd0570417b23a20a56daa948db6d1587d95bc65e3883f038e2c040b`.
The first full run's Release test assembly remains byte-identical during this
Debug diagnostic (SHA-256 `d21ddddb46647b05ed0f3d615d15bf9e344b333dda7eef0e5db3bac0ab093978`).

A bounded startup diagnostic runs the same ACK case with existing network and
publication tests while the existing unit/profile jobs run concurrently. All20
selected cases pass; unit272/profile107 also pass. The ACK takes37s there versus
49s in the failed full run, but timing correlation is not a cause diagnosis:
`artifacts/s01-host-recovery/startup-diagnostic/nikit_SURFACE-LT_2026-10-04_16_32_55_net10.0.trx`,
SHA-256 `5da78ac1dde8a44fbf104eebf737bb19b5d65f5875bc75a58936e56595806832`.
Release test-only diagnostic build finishes with0 warnings/errors. The full
reproduction finishes **1205 pass / 0 fail / 0 skips**: integration826,
unit272 and profile107. All three TRX result summaries are terminal Completed;
the observation watcher finishes exit0. The original test-process exit handle
was lost during output truncation, so its exit code is not inferred from that
watcher. The diagnostic test-assembly SHA-256 is
`d94235b4edcf395ebf0af4fda2e09230010afa6e56d068a249a8db00e8d1252a`.
The previously failed ACK case passes in18.86s. No runtime/deadline/assertion
change explains that result, and the cause of the original PartialFailure is
still unclassified; it is not declared a repaired production bug.

| Reproduction receipt under `artifacts/s01-host-recovery/reproduction-full` | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_16_49_55_net10.0.trx` (profile107) | `3bc401106ee8d9b7f15b04320d49e1e4bbdee967bcb3d91c16ed943056e38576` |
| `nikit_SURFACE-LT_2026-10-04_16_49_57_net10.0.trx` (unit272) | `4398becf421327ee089d91a5209e7b97dfffc6c0f4df3203ec80191c6dad2025` |
| `nikit_SURFACE-LT_2026-10-04_16_49_57_net10.0[1].trx` (integration826) | `c5e2a16d41d4872461d553d84365f30ade99035affe625f85052984e3d626822` |

This gate uses XNode `5d4c5d545b62ed0c98e99ddaf9b09dcd405b7d4f` and the
unchanged dependency binaries from the input matrix above. Later Protocol/Shared
Store-floor edits are not exercised by this run and require their own gates.

Fresh real-Xray transport smoke and three-node rehearsal both finish exit0:

| Local receipt under `deep-devops/artifacts` | SHA-256 |
| --- | --- |
| `s01-host-recovery-smoke-20261004/runtime.gate.json` | `89181d1bcb8ce2a1cb67882dab7278bb2077eb3480fd94a436d67fefd269f30b` |
| `rehearsals/multi-node/20261004T103408491Z-b427ddba3053/test-results/multi-node-topology.json` | `1ec9133d12f99775403f2d0d9240574d469d7f390e1c1b74951c0249d0f15e53` |

Those lanes have mailbox disabled and intentional missing-authority contact503;
they prove transport regression only, not activated current mailbox/contact.
Both private test stacks were cleaned up; all six existing deep-dev containers
remain. No production/device/account/secret state was changed.

## Remaining activation fences

Program still needs the complete current receiver/coordinator graph and removal
of retired PMA1/P04 services. This recovery hook does not qualify every historical
blob/mutation, retained-route Retrieve/ACK, signed retirement/compaction, object
horizon or application receipts. Five-second cancellation is cooperative, not a
hard guarantee for a provider ignoring cancellation. Coordinated matching
root/data rollback remains outside the local protection guarantee. Device E2E
and release remain open; no GitHub Release or main merge is authorized here.
