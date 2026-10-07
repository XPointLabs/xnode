# S01 retained-read private forwarding candidate

Date: 2026-10-07. Sole semantics:
[CONTACT-RESOLVER §3.7.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md#373-current-retained-retrieve-issuance),
[DR-0104](../../../docs/survival-program/decisions/DR-0104-current-retained-retrieve-issuance.md).
Matched issuer/source and its preserved full FAIL are in the
[Registry receipt](../../../deep-registry-api/docs/testing/s01-retained-private-issuer-2026-10-07.md).

The actual HTTPS client verifies the holder signature, requires explicit private
kind/horizon, signs the independent retained purpose and preserves the exact
request deadline. The success still requires independent current authority
verification by its caller; parsing a response is not holder or issuer custody.
Unknown/cross-fed kind, horizon, role, result, disposition, deadline and holder
proof reject before HTTP. Standard HTTPS validation is unchanged. Existing
public AcquireMailboxGrant dispatch explicitly uses CurrentRoute/zero horizon;
there is no automatic current-miss fallback to retained reads.

Release source-cutover solution build completed terminal0, zero warnings/errors.
Final focused157/0/0 terminal0 includes all147 prior cases plus10 new executions.
Receipt `artifacts/s01-retained-private-forwarding/focused/retained-private-forwarding.trx`,
SHA256 `1FBED31E351C2129EBF52F4147FCC24ACED4B0C175BDFFA7BB833FEA9F7B6950`.
This is not qualification of the pinned shipping package graph.

## Original full launch and input custody

Shared prelaunch input custody is the original3703-input Registry manifest,
SHA256 `093A66A54320EEF80D6EC72207873F4EA56DC8BFAFD2A70F16B04907DC9F649D`,
captured at18:33:21.6441375 local time. A premature Node full started at18:32:39;
its exact verified test-process tree was stopped, terminal-1. Its incomplete
`artifacts/s01-retained-private-forwarding/full` is not acceptance evidence.
No unrelated application, device, container or data was stopped/reset.

The qualified original full started at18:34:57.638753, after capture, with:

```powershell
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --no-build --no-restore -m:1 --logger trx `
  --results-directory artifacts/s01-retained-private-forwarding/full-after-capture --verbosity quiet
```

Original full completed **terminal1:1339 Passed /1 Failed /0 Skipped**
(Integration981/1, ProfileGenerator107/0, Unit251/0). Existing
`CurrentMailboxRevocationRefreshTests.ActualHttpConsumerAndNativeRefreshResumeBeyondBudgetWithoutEnrollmentOrExpiredAdmission(observed: True)`
failed at line44: its first refresh hit the unchanged30-second deadline during
actual observed-source revalidation, yielding OperationCanceledException instead
of the expected exact IOException for the64-step catch-up budget. No timer,
assertion or authority check was changed. Cause of the elapsed-time increase is
not established. An isolated frozen-binary repeat of both theory cases passed
2/0/0 terminal0 in8 seconds; it does not fix or supersede the original full FAIL.
The full was launched alongside Registry and temporary Docker lanes; subsequent
complete qualification should avoid concurrent CPU-heavy lanes, not relax guards.

Post-terminal matrix verification preserves the exact1330 prior+10 new union,
all157 focused cases Passed in the original full, complete unique execution
mappings and all3703 original inputs unchanged. It reports FullAccepted=false
and terminal1, not green full acceptance. The separate helper was finalized
after terminal to pin all three original Node receipt hashes as well as the
already pinned Registry receipts; the original prelaunch manifest stayed intact.

| Original receipt below artifacts/s01-retained-private-forwarding | SHA256 |
| --- | --- |
| full-after-capture/nikit_SURFACE-LT_2026-10-07_18_35_02_net10.0.trx | `11F35EBC8F28B3AFD8E0DC59DEEA98238DCEDA8CE66FF5743890070ED3E06D2D` |
| full-after-capture/nikit_SURFACE-LT_2026-10-07_19_17_26_net10.0.trx | `395E31E5BB7FDBC8DE5B102F7CF195494D73B1BB2E9BB1FDD6249CA2E45B735C` |
| full-after-capture/nikit_SURFACE-LT_2026-10-07_19_17_52_net10.0.trx | `E89E1F6BE3E642603485D259CB32F61A0824A597F0C147D0D32B1D1CC883F1DF` |
| refresh-budget-frozen-triage/refresh-budget-frozen-triage.trx | `6421F076914CEED9B9CF85487049561AEA5887D61E4899DDEC73850712DC9E5B` |

## Mandatory isolated infrastructure evidence

External/no-mock smoke and multi-node rehearsal both completed terminal0.
They used their own temporary Compose projects and preserved the six original
dev containers/data. The original dev authority remains expired; no new genesis,
issuer keys, state reset or production mutation was used to make it ready.

| Receipt in DevOps | SHA256 |
| --- | --- |
| artifacts/s01-retained-private-smoke-20261007-01/runtime.gate.json | `A4AFA42A7D0002A35B997EE7683143D2CEFC736D4A2AC5A8D5AB3445D4558BC3` |
| artifacts/s01-retained-private-smoke-20261007-01/runtime.snapshot.json | `D9D252065EE60B445F1D56BBBFC55C3C81032FE66E1966C5DDF71C40FEB6E79C` |
| artifacts/rehearsals/multi-node/20261007T133852343Z-ebc75c7444bd/test-results/multi-node-topology.json | `0F09980D7E7207219C895B4CFCF493C968030ABEA89E8380264413D04F86A0BE` |

The multi-node lane proves three running real Xray nodes and intentional privacy
503 without verified authority, not actual private retained issuance or device
delivery. No production deploy/reset, registered identity change, GitHub Release
or main merge was performed.
Final selected changed source/fresh evidence secret scan passed11 files;
root documentation174 checks, contact-machine consistency and governance30/0/0
passed. Neither full FAIL is superseded by these checks.

## Same S01 residual work

Join actual protected two-store RPC18/receipt7 to private Registry issuance,
actual held Shared original-publication/holder/result installation, genuinely
elapsed original-route under current protected lineage, typed original-selection
Retrieve/ACK and matching object/tombstone/replay horizon. Full failures remain
open; source prerequisites do not close S01 or open S02/S04/files/groups.
