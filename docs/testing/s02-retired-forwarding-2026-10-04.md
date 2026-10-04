# S02 retired authority forwarding removal — 2026-10-04

This is a bounded removal under the auditor's
[S02/S03 execution plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Input Node is `0ed0ccb11f80aabcef0373dabc4b03086c58935f`; Protocol remains
`8989ad6a787cdc8194106a5130fcfa832608e252`. Final pins belong to the root commit.

## Actual change

Remove the unreachable PMA1 authority forwarding client, HTTP handler,
authentication/replay/limiter/options and routed dispatcher: four production
files and eleven exported types. Program already uses the current native
dispatcher and never registered these types. No current admission, transport,
TLS, signature, replay, quota, persistence or receipt check is relaxed.

The six positive tests for the removed forwarding implementation are removed
with it. Contact/onion tests now use their recording `INativeMailboxExitDispatcher`
directly, retaining the same zero-effect assertions on peer/contact/mailbox
boundaries. Eleven negative cases inspect the actual Node assembly for the
removed types. Retired configuration still rejects, including empty objects.
Existing actual-Program TLS/H2 tests still reject all three retired forwarding
URLs before authority reads and exercise current two-store Store/Retrieve/ACK,
cold reopen and exact replay.

PMA1 provider/closure and Protocol DNP1 membership closure consumers are not
removed by this slice. They require a coordinated replacement of their actual
consumers and frozen evidence ownership; this is not full package cleanup.

## Terminal local evidence

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --filter 'FullyQualifiedName~ContactServiceTerminalDispatchTests|FullyQualifiedName~PrivacyRoutingRuntimeTests|FullyQualifiedName~CurrentMailboxHostCompositionTests.Retired|FullyQualifiedName~ActualRegisteredOwnersCompleteNativeStoreRetrieveAckAndColdExactRetryOverPinnedHttp' --logger trx --results-directory artifacts/s02-retired-forwarding/focused
dotnet test XNode.slnx -c Release -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --logger trx --results-directory artifacts/s02-retired-forwarding/full
```

Focused run exits0: **74 passed /0 failed /0 skipped**,32s. No integration-source
compile whitelist is used. Receipt:
`artifacts/s02-retired-forwarding/focused/nikit_SURFACE-LT_2026-10-04_22_20_49_net10.0.trx`,
SHA-256 `4050ec3fac378c95e25cc625f0ea7aa7c3996fad4d9abd76dee669a2752a6f7e`.
The required unfiltered full solution gate completes exit0 on product source
`8298161fb0a1afadf7eefff38ecffbfadd14a178`: **1243 passed /0 failed /0 skipped**
(integration864, profile107, unit272), integration25m1s. Every recorded result is
Passed; no filters or compile whitelist are used. Six removed legacy forwarding
cases and eleven new actual-assembly absence cases explain the net five-case
increase from the prior1238. Previous1238 qualifies the prior source, not this removal.
The full solution maps external Protocol references to Debug and Node to Release;
this is not a uniformly Release shipping package qualification.

Real-Xray Docker smoke exits0 on a fresh retry: ten fixture-runner contract tests
pass and runtime failed-check count is zero. The first attempt fails before
runtime because the MCR runtime-image metadata HEAD request returns EOF; its
failed receipt is retained. Both runs clean their disposable resources.
Smoke uses disabled-mailbox development composition, not positive current
enrollment or physical delivery. Required three-node rehearsal runs separately
after smoke cleanup and exits0: three registered nodes, real non-mocked Xray,
zero reconciliation issues. Contact503 remains fail-closed, not positive contact
or mailbox delivery evidence. Its disposable resources are cleaned; all six
existing deep-dev containers remain healthy and running.

| DevOps retry receipt | SHA-256 |
| --- | --- |
| `artifacts/s02-retired-forwarding/transport-smoke-retry/runtime.gate.json` | `f7c110c9026cd89332151d0eb6c3d6d578d0f1a436046e5a05df6fbe27d3e4a1` |
| `artifacts/s02-retired-forwarding/transport-smoke-retry/runtime.snapshot.json` | `24e2d0e8fe7d01103a09dfd8f03dffb7f6f4645442bad8dc6e39cc8d39e385aa` |
| `artifacts/rehearsals/multi-node/20261004T172528392Z-56c78ce0471b/test-results/multi-node-topology.json` | `5e3ddf7305c2e20368f7e9e8063154a3e511a8fd9613c11bd72f914d3bc7c339` |

| Node full receipt under `artifacts/s02-retired-forwarding/full/` | SHA-256 |
| --- | --- |
| Integration864 `nikit_SURFACE-LT_2026-10-04_22_21_55_net10.0.trx` | `403ef8dc7178f3fa43e397a49f2d88b7abbcc4b8a8ec83ab5a011adf283cfe89` |
| Profile107 `nikit_SURFACE-LT_2026-10-04_22_47_02_net10.0.trx` | `1f1d961848c9c99856aea60dabccdebc6e187ee3f4896010c82bc3d06259aa2f` |
| Unit272 `nikit_SURFACE-LT_2026-10-04_22_47_28_net10.0.trx` | `6d4b3730993591eaa074b53e90876f0fc915747fe36ecf13b55539f7e7bf4988` |

No production host, device, account or operator secret is changed. Current issuer,
renewal, sustained lifecycle, shipping composition and physical qualification
remain open. Contacts/messages/attachments/groups physical matrix remains0/4.
