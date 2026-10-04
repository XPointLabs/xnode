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
Connected/full gate terminal results are pending; no former full result is
substituted for them.

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
