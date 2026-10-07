# S01 retained mailbox route custody — qualified source increment

Date: 2026-10-07. Sole contract:
[CONTACT-RESOLVER §3.7.2](../../../docs/architecture/CONTACT-RESOLVER-V1.md#372-independent-retained-read-custody),
[DR-0101](../../../docs/survival-program/decisions/DR-0101-retained-mailbox-route-custody.md).

Both real publication wrappers now create independent private custody through
the actual closed current XPA1 verifier, rather than from raw opaque inputs.
Publication and custody share the durable replace. Public DCR predecessor GC
does not delete this table. Typed lookup accepts DR-0100's current signed
request/time context, matches its exact scope, rechecks current time and rejects
an intervening durable mutation. Current-only resolve/Deposit are unchanged.
Private node state generation5 rejects generation4; no production data/reset,
registered key, certbot, release or main-merge change was made.

This is **not protected rollback/provenance or renewed issuance qualification**.
Existing file SHA/ACL/lease is not a cryptographic rollback floor. Lookup facts
cannot mint Current-route evidence, MCG3, holder custody, Retrieve/ACK dispatch
or retirement. Distinct matching exact routes fail closed; usable successor
disambiguation and the signed elapsed-history/horizon boundary remain activation
gates. No mailbox TTL constant was raised.

## Focused and build results

Release solution build completed terminal0 with zero warnings/errors:

```powershell
dotnet build XNode.slnx -c Release -m:1 -p:DeepProtocolSourceCutover=true `
  -p:ShouldUnsetParentConfigurationAndPlatform=false -warnaserror --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -m:1 `
  -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false `
  -warnaserror --filter 'FullyQualifiedName~RetainedMailboxRouteStoreTests|FullyQualifiedName~ContactAuthorizedPublicationReplicaTests' `
  --logger 'trx;LogFileName=retained-route-focused.trx' `
  --results-directory artifacts/s01-retained-route/final-focused-02 --verbosity quiet
```

Final focused **21/0/0**, terminal0:18 new cases and3 existing actual publication
wrapper cases. SHA-256 of the exact TRX:
`7C1CF5A0FD5AD6B1B859A9A16A497706711EEFE05F6F4A08A8EED90F170DE117`.
Coverage includes actual signed DID2/XPA/current host/holder requests, reopen,
defensive copies, wrong locator/capability, no authority from raw opaque storage,
quota/no eviction/exact replay, both sides of durable replace failure, old or
missing/malformed state quarantine, DCR GC independence, callback state mutation
and cancel/boot/rollback/expiry loss before release. The GC case isolates the
actual storage clock; it is not48h signed network-history or device evidence.

Initial compile attempts failed on the new alias/test clock interface and
produced no test acceptance. Two initial focused receipts retain20/1/0: the
quota fixture reused another publication's fixed capability/operation, so the
correct collision guard returned Conflict before quota. The fixture now authors
independent signed scope; all old default fixture inputs/assertions are unchanged.
No production guard or assertion was weakened.

## Mandatory solution run — observed and qualified

The separately built Release inputs were frozen **before launch**, at
2026-10-07T11:23:11+05:00. The original native solution process completed
terminal0: **1241/0/0**, comprising Integration884, ProfileGenerator107 and
Unit250. The post-terminal qualifier also completed terminal0. This accepts
this bounded source increment, not the whole S01 stage or shipping graph.

```powershell
./artifacts/s01-retained-route/qualify.ps1 -Capture
dotnet test XNode.slnx -c Release --no-build --no-restore -m:1 `
  -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false `
  -warnaserror --logger trx --results-directory artifacts/s01-retained-route/full --verbosity quiet
# Only after observing the original process terminal0:
./artifacts/s01-retained-route/qualify.ps1 -ObservedTerminalExitCode 0
```

Prelaunch manifest covers834 source/normative/actual Release binary inputs,
SHA-256 `E8A8105F58CEA43A7572677D9F9F5D5F4D3D1E2F51168FB40D51BC52409FA58D`.
Private qualifier SHA-256:
`2812B0648060170B46C6A3612566E92932EC7E7B7C3AAC1401AC82C4DF92D538`.
It verified the original successful native exit, exact three receipts,
1241 all-Passed result/entry/method mappings, all1223 prior and21 focused exact
case names, and every834 frozen input unchanged. No duplicate full run was
launched and no expectation was changed to obtain acceptance.

| Actual receipt under artifacts/s01-retained-route/full | SHA-256 |
| --- | --- |
| nikit_SURFACE-LT_2026-10-07_11_23_13_net10.0.trx | `4834C6F63A96CA198ADB2EF304759D59395939446D71FE8F6E27A156FA7E5ACF` |
| nikit_SURFACE-LT_2026-10-07_12_05_20_net10.0.trx | `8D2F81BFAF5EBD90586838EC3882E1F1855F30D2E39ADF2CB7CF598C39989FFD` |
| nikit_SURFACE-LT_2026-10-07_12_05_47_net10.0.trx | `3369B0ABF97F7342BEA8BD8747C93318FD89FC8F11CA5FD0030F9F7BBA7A4894` |

## Mandatory isolated Docker smoke

After the operator restarted Docker Desktop, engine28.3.3 was available. The
current-source smoke completed terminal0 with a fresh artifact directory and
Compose project `deep-s01-retained-route-20261007`:

```powershell
$env:COMPOSE_PROJECT_NAME = 'deep-s01-retained-route-20261007'
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external `
  -ManagedExternalProfile backend-external -RequireRouterNoMock `
  -RunArtifactDirectory '<fresh absolute child of deep-devops/artifacts>'
```

Fixture validation and10 harness/infrastructure tests passed. All seven services
were healthy, all four hard/five soft checks passed, transportRunning/mockfalse,
no runtime-gate warnings. Node used Protocol source-cutover; Registry used its
existing local-cutover package lane, not a uniform shipping graph. Three existing
Dockerfile ARG warnings remain. Push provider/device delivery was not tested.
Cleanup removed only this isolated project's containers/network/seven volumes;
all six original dev containers remain. Removed volumes held temporary smoke
data, not production or existing dev state; they were not retained for recovery.

| Receipt under deep-devops/artifacts/s01-retained-route-smoke-20261007-01 | SHA-256 |
| --- | --- |
| runtime.gate.json | `F98975738A42639A5AE8863838997FB39729B006436FE884F83F5AFEB52B8845` |
| runtime.snapshot.json | `AF6C1C0F532F9BFCF21EB94A47BA12631228B2B8B8117E26FB26784EE3498807` |
| compose.topology.redacted.json | `972A544A9DE03330D57FF3C99D25222D10E5DA1D70F2B53829499E98E85DE127` |

Registry strict source/hash gate0, root documentation174/0, governance22/0 and
selected-source scanner15 files/0 findings passed. Separate current Protocol
full remains2088/1/7 terminal1 and production graph remains MAU2 FAIL; static
evidence mapping219/219 is not executed package approval. S01, release and
physical E2E remain unaccepted; the next work stays within retained-read closure.

## Verified next producer/consumer boundary

The existing XMG1 binds PMT2 and PMS2, but not the exact six-record route hash:
tag11 is a random nonce. `DeepIdV2ContactRoutePredecessor` permits reuse of an
unchanged PMS2, while publication successors preserve the owner Retrieve
capability. Thus those lookup fields cannot uniquely name every legal retained
route. The fail-closed conflict above is intentional, not a usable renewal path.
The current139-byte `MailboxGrantRouteEvidenceAuthentication` tuple has an
explicit Current disposition and publication expiry; it must not be reinterpreted
as retained eligibility or `readUntil`. `DeepIdV2MailboxGrantIssuanceVerifier`
also requires the exact current PMT/view/head and live six-record intervals.

The next single coupled batch must settle exact route selection, independent
protected custody/read-back and both current selected stores' signed evidence
before renewed issuer and owned request/result consumers can use expired route
history. A new hash/domain/version is not allocated by this investigation.
Use the existing native protected-custody design rather than treating encrypted
files or the XPA saga as an anti-rollback floor. Its joint custody/key-ring
rollback limit must remain explicit. Runtime activation, object TTL and physical
claims remain fenced; no separate S02/S04 task is opened here.
