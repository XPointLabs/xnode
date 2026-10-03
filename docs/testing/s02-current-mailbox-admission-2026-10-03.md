# S01/S02 — current native mailbox admission consumer

Date: 2026-10-03. Source inputs: XNode `529a103`, Protocol `de1c220`,
workspace `9ed8fc7`. Normative owners:
[DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
This is connected native source evidence, not activated ingress/peer/device or
release qualification. No wire, protocol public API or protected file format changed.

## Implemented consumer

The internal bounded owner captures canonical request bytes before callbacks,
verifies the actual closed network/root/PMA2 and grant-selected replica facts,
and checks local canonical node membership. Both native role owners must match
the exact node/network/policy scope and have fresh protected read-back. They
remain locked in fixed Deposit -> Retrieve order through the entire callback.
An installed floor successor cannot race a check and outcome mutation.

The role revocation result is derived from the actual scoped protected floor,
not absence/configuration or a parsed candidate. Its synchronous codec adapter
answers only the exact checked grant query while both leases remain active.
Canonical issuer, holder and body verification precede lazy acquisition of the
real native replay scope: invalid input cannot advance its accepted-time floor.
Reservation/recovery still uses the existing durable replay and canonical outcome
owners, with no fake replay disposition or in-memory completion substitute.

Current source and full protected monotonic interval are checked again before
scoped execution/outcome operations and after callback/result boundaries.
No UTC is read. Lease expiry, cancellation or missing authority after reservation
suppresses the result and keeps Pending. Cleanup releases native execution and
outcome capacity without deleting that exact claim. Escaped scoped requests reject.

## Tests and gates

`CurrentMailboxAdmissionTests`: **19 pass**, using actual signed DID2/PQ/network,
role issuer and holder signatures, persisted native MGR files/key ring and real
replay/outcome stores. Source proof/monotonic clock production is test-owned.
Cases cover all three operations, terminal exact replay after native reopen,
wrong holder/body/outer operation before time-floor/replay writes, either missing
role floor, callback expiry/cancellation/source loss, revoked completed grant,
scoped escape, a foreign signing key used as node ID, caller-buffer mutation,
and floor successor serialization across the complete callback.

The network fixture is generation-zero genesis: the author requires canonical
node ID to equal its initial identity key. It does **not** prove the required
rotated-descriptor distinct ID/key scenario; that remains an S02/S03 gate.
The new tests initially exposed invalid test envelope TTL and this genesis
assumption. The fixture was corrected; no existing assertions/failures removed.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --no-restore --filter "FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocationStoreTests|FullyQualifiedName~NativeMailboxIngressBindingTests" --logger "trx;LogFileName=current-admission-final.trx" --results-directory artifacts/s02-current-admission/connected
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore --logger trx --results-directory artifacts/s02-current-admission/full
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore -m:1 -warnaserror
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<fresh absolute child of deep-devops/artifacts>'
../deep-devops/scripts/multi-node-rehearsal.ps1
```

Connected **65/65** (19 new, 29 native floor, 17 ingress). Full solution:
**943 pass / 1 fail / 0 skips**, 944 total: integration 564/1, unit 272/0,
profile 107/0. Sole unchanged failure B8:
`ContactServiceOpaqueFacadeTests.PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`
needs the missing signed current one-time publication producer.
Build exit 0, zero warnings/errors. The solution invocation builds external
Protocol references in Debug while node projects use Release; this is source
cutover evidence, not a fully pinned shipping artifact matrix.

Docker smoke exit 0: real non-mocked Xray, zero failed hard/soft checks and zero
selected artifact secret findings. Three pre-existing external Node Dockerfile
ARG warnings remain outside .NET compilation. Three-node rehearsal exit 0:
actual Xray on all nodes, three registered local nodes, no reconciliation issue;
private contact remains 503 without current authority. These fixtures are not a
matched current mailbox issuer/runtime deployment or physical delivery claim.
Only temporary rehearsal containers/volumes were removed; six existing deep-dev
containers were preserved. Production, devices, registered keys and operator
secrets were not changed.

| Ignored evidence | SHA-256 |
| --- | --- |
| Connected TRX | `c4d6ac3cb934b882a96dad8f6ed44fe287c738e428b43624b0e1bd13186f1cc8` |
| Full integration TRX | `095dc8d2e9bfedd936233297ffe3341ebe47d8506b313627a67d13dbfefee957` |
| Full unit TRX | `49fe1867a21f20d94ab244f3ac15e4ee87df40d2b3379a4881ee7fdccef4317e` |
| Full profile TRX | `8942287f3482b27bc876bcf0f4167512ccf7a6d175162b293ca6a873ef16af4e` |
| Docker runtime gate | `7341be5cc4f69f08151d0984d93461935c6771831b1e1569605e54758822f7d3` |
| Three-node topology | `64982ec14a608fa983480dd4799fe537c72c652749654425a35e1242bac0167c` |

## Remaining activation boundary

Program/DI and mailbox adapter still do not consume this owner. Store/Retrieve/ACK
mutation, descriptor signing custody/rotation, current peer proof and two durable
replica quorum must be connected together before endpoint readiness changes.
The trusted clock/source must be composed from the same protected monotonic
owner; no caller-supplied time becomes authority. Existing retention, lifecycle,
application receipts, operational successor/package evidence and physical E2E
blockers remain in the sole [queue](../../../docs/NEXT-SPRINT.md).
