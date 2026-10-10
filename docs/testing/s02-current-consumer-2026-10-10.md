# S02 current consumer checkpoint — 2026-10-10

S02 is the sole active stage after the
[S01 contract/API review](../../../docs/S01-CONTRACT-REVIEW-2026-10-10.md).
S02 source/composition acceptance is recorded below and in the root review.
This checkpoint is not production activation, shipping qualification or
physical Windows/Android E2E.

## Explicit admission boundaries and retained client ACK corrective batch

Qualified source batch on top of `6cf28f6`; S02 source/composition is accepted.
This batch does not introduce wire values, a second journal, fallback readers,
new node keys or relaxed time/revocation/receipt checks.

The native client dispatcher now has explicit negative cases for retired MAU2
magic, altered body, a genuine wrong-role grant, holder-signed altered selector
without issuer authorization, a genuine issuer-signed grant selecting a pair
which excludes the local node, and PMA2 profile1. All refusals preserve the
complete native data-root file inventory/content of both actual owners, replay/outcomes,
intent/mutation state and peer request count. The original signed counter/body
then succeeds. The hostile profile is raw producer input: the real Protocol
verifier rejects the profile before root signature validation; no verified
authority object is forged or substituted. Separate native cases cover exact
grant expiry at the trusted upper bound, monotonic rollback and signed serial
revocation before replay/mutation.

Current runtime status is `StrictMau3Decoder`, with no MAU2 alias. The existing
unit case is renamed from `ValidMau2_UsesEd25519AndRecoversExactDurableOutcome`
to `ValidMau3_UsesEd25519AndRecoversExactDurableOutcome`; all assertions remain,
with an additional exact MAU3 prefix assertion. The decoder already used MAU3;
this is not a format change or replacement of neutral durable primitives.

A new native client scenario stores on two actual owners over pinned peer
HTTPS, advances genuine signed PMT/network/directory evidence, advances both
protected role floors on both nodes, reads with a current Retrieve grant bound
to the original epoch, loses the ACK response, cold-reopens and retries the
exact saved intent. It checks original commitment/epoch, two tombstones,
unchanged peer intent, cached exact page, a fresh empty page and no resurrection.
The expired original Store cannot release a cached response or modify custody.
This is native client ingress plus real peer HTTPS, not configured public H2
or physical Windows/Android evidence.

This scenario exposed a product defect: `ReserveCurrentAckAsync` received
`scope.Host.MembershipCommitment` from the new projection, while its authored
peer request correctly used `scope.Grant.MembershipCommitment` from the original
projection. The strict ledger rejected the inconsistent intent before HTTP.
The coordinator now passes the verified grant commitment; independently current
host, time, protected floors, selected replicas and revocation stay mandatory.

Matching `artifacts/s02-boundaries-20261010/focused-06` Release build finished
native0 at `2026-10-10T12:23:51.2379128Z`, zero warnings/errors. Focused10/0/0
finished native0 at `12:24:57.1453962Z`. Whole unit255/0/0 finished native0 at
`12:25:53.2494550Z`. Boundary TRX SHA256
`47D2C28889EA34B50D08769552958BCC65F0C65061B3B60A3669B182118415E8`;
unit TRX SHA256
`BA939C245A6C30D6621CCC87F8CC04EC2791592658AEFA2AC898FF4F50C292DC`.
The common `Read-TestGateReceipt` verifies all255 prior unit case names after
exactly the reviewed rename and every other stable case key: missing0/differences0.
No assertions or other cases were removed. The next full references old qualified
Integration1069/Profile107 plus these new whole-unit255 and boundary10 receipts,
not the retired unit method name, with no allowed FAIL/skips.

`artifacts/test-gate-20261010/node-current-boundaries-full-01` started at
`2026-10-10T12:27:36.5920660Z` and finished at `2026-10-10T13:06:07.5222342Z`,
Desktop5.1.26100.9457/SDK10.0.301. Build/preflight/test/qualification exits0,
zero build warnings/errors,1441/0/0, exact1441 cases,2136 unchanged inputs and
FullAccepted=true. Integration1079/Profile107/unit255 all pass. The common
receipt reader confirms all24 cases from the twelve named S02 review groups.
The input count differs from prior full03 solely because seven prior reference
TRX inputs were replaced with four matching references and two test source files
were added; no other executable/source inputs were removed.

Matching full TRX SHA256, in Integration/Profile/unit order:
`BC50105710B5A0EE19A9C0AF7FB40312D21B482B791BE4799F0BADB0BD74440A`,
`246EB8B01A95079A11DD8511FF3EADC1B98DF81B568C5AE416B1F4BA1E66CA98`,
`EAB0588C79F8C56E608C2EB9616C1A3C804F80C59869B132639DC581F824F6B6`.
Fresh external no-mock smoke in
`deep-devops/artifacts/s02-boundaries-20261010/smoke-01` finished native0;
`runtime.gate.json` at `2026-10-10T13:07:47.2004272Z` has hard/soft failures0,
runtime warnings0, RequireRouterNoMock=true and actual running, nonmocked Xray.
SHA256 `FDF4B60B4258587DF9AFDBDABECEBDDB7D5F369BB1D462D92FB5FC9571F6AE7D`.
Three existing BuildKit InvalidDefaultArgInFrom warnings belong to service
Dockerfile defaults, not the native source build or runtime gate.

Serial three-node rehearsal finished native0. Receipt
`deep-devops/artifacts/rehearsals/multi-node/20261010T130816429Z-00b4771325e1/test-results/multi-node-topology.json`
at `2026-10-10T13:09:06.699Z` has status=ok, three distinct real/nonmocked Xray
nodes, Registry count3 and reconciliation issues0. SHA256
`01C1598DDCB24849EB4A5B8A4F9EC7BE8CB31D3F10F9E3C7397A5EC2D8ECEB38`.
Expected privacy503 proves fail-closed without configured verified authority,
not message delivery. Both disposable stacks/volumes were cleaned by their
own scripts; all six existing deep-dev containers remain running.

The root requirement review and these matching full/transport receipts accept
S02 as the current-only native/configured node source/composition stage.
Peer-wide loss/rollback, shipping activation, actual issuer/owned-client join,
physical contacts/messages/files/groups and the remaining release DAG stay open.

Selected changed source/docs plus both passing TRX:11 files, findings0/native0
(`artifacts/s02-boundaries-20261010/selected-scan-02.json`). The first scan also
included the default root artifacts and rejected46 pre-existing raw/binary items;
the explicit selected scan is not a global security PASS or an exemption for
those files. Raw diagnostics remain local, excluded from approved uploads.
Matching full and fresh transport are accepted; S02 source/composition review is complete.

Preserved diagnostic failures: focused01 failed6 cases before dispatch because
the new digest helper tried opening an exclusive `.replay.lock`; the corrected
helper checks known empty lock inventory/length without bypassing ownership and
hashes all durable records. Focused02 had6 PASS/3 FAIL because post-refusal blob
inspection reused intentionally invalid authority; initial empty stores and
unchanged full native digests now prove preservation without that invalid read.
Focused03 passed9/0/0/native0. Focused04 build rejected three missing required
zero-valued NextEpoch window fields; no tests launched. Focused05 build0 and
9 PASS/1 FAIL exposed the retained ACK product defect above. None is reclassified
as a full PASS; raw diagnostics remain local and are not approved upload evidence.

## Public HTTPS/H2 entry and independent client replay floor batch

Candidate after qualified Node `31784a9`; matching full03 now qualifies the
current source batch, and its separate transport runs have also passed. Whole-S02
acceptance review is still pending. The previous full1423 and transport receipts below
qualify only that earlier source. S02 remains the sole active stage.

Matching full03 (`artifacts/test-gate-20261010/node-client-entry-full-03`) finished
native0 on `2026-10-10T11:30:58.3839995Z` (started `11:01:31.5693167Z`).
Desktop5.1.26100.9457/SDK10.0.301; build/preflight/test/qualification exits0,
zero build warnings/errors,1431/0/0, exact1431 required cases and2137 unchanged
captured inputs, FullAccepted=true. Integration1069/0/0,
ProfileGenerator107/0/0, unit255/0/0. The extra captured input versus full02 is
the new unit reference TRX, not an additional production component. SHA256:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_16_02_34_net10.0.trx` | `B0B8DCD331F28C1AD9D77785C258F5A1F5394D910D4CAE48D3306D60BF76A600` |
| `nikit_SURFACE-LT_2026-10-10_16_29_12_net10.0.trx` | `30F71171A8D632FD7600F35C9D8012D11CBB5A92FAAD1BFFBB6F6D2D603EE1CA` |
| `nikit_SURFACE-LT_2026-10-10_16_29_39_net10.0.trx` | `E104CA9E34D59AAA08C663DC6C438667833FFB5373A8E39861D012EC16C6152C` |

This successful run does not identify or erase full02's intermittent native5
denial. No retry/ACL repair or failure exemption was introduced. Neither this
source gate nor the configured test-only HTTPS proxy proves physical delivery.

Matching transport: external/no-mock smoke finished native0 at
`deep-devops/artifacts/s02-client-entry-20261010/smoke-01`. Actual Xray running,
routerTransportMocked=false, hard/soft failures0 and runtime warnings0;
runtime.gate.json SHA256
`2E3830AB8F4C8D8FAA294E8FE4B02A7C501444937553AF4FB5DD502DE893F1E5`.
Three pre-existing Dockerfile `InvalidDefaultArgInFrom` build notices remain
separate from .NET/runtime warnings.

Three-node rehearsal finished native0 at
`deep-devops/artifacts/rehearsals/multi-node/20261010T113549429Z-0b1e414bc3ae`:
status=ok, requireNoMock=true, three distinct real Xray routers, Registry count3,
reconciliation issues0. All three privacy endpoints return expected503 without
verified authority, not message success. `test-results/multi-node-topology.json`
SHA256 `2A3500972E09A0D5A0660BAC5D645F03A8666CC590C4A65E5CD4F70A0A695C89`.
Both disposable stacks were removed; six existing `deep-dev` containers remain.
Production and physical clients were not changed by these runs.

Matching full01 (`artifacts/test-gate-20261010/node-client-entry-full-01`) finished
native1 on `2026-10-10T09:58:58.1130029Z`: build0/zero warnings, preflight0,
test1/qualification1, FullAccepted=false. Integration1044/23/0,
ProfileGenerator107/0/0, unit255/0/0;1429 total cases,2134 captured inputs.
The public-entry cycle and new cold-loss/rollback tests passed, but this does not
override the23 failures. Input read-back qualification did not complete; do not
claim unchanged inputs or a full PASS. Full receipt SHA256:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_14_28_21_net10.0.trx` | `B4E5160A85C0DCCC9573BAA03BE5FEA81D06C0D68FFD9B8D8A4904B0A3FDDC2B` |
| `nikit_SURFACE-LT_2026-10-10_14_57_42_net10.0.trx` | `B573D2510960B86348EF956F96D490233A9EC02FBB416B5A768EDD2904CC097F` |
| `nikit_SURFACE-LT_2026-10-10_14_58_10_net10.0.trx` | `9EE7B850030C7688410E83B9CBB13CDE0D551901208BA3984F74709160E83DCC` |

The failing intent/settlement/checkpoint injectors counted every document write;
the added floor transition moved their intended crash points. Candidate fixture
fixes select business-document changes instead, without changing the existing
assertions or replacing native durability. Separate raw floor-write failures
cover before/after replacement. The Retrieve callback restore now captures the
exact document at the actual hostile callback, not a pre-floor snapshot that
the independent root correctly rejects as stale. Focused16 finished native0,
warnings-as-errors build0,27/0/0: all23 failing cases, two previously passing
mutation variants and two new raw floor-write cases. Receipt:
`artifacts/s02-client-entry-20261010/focused-16/nikit_SURFACE-LT_2026-10-10_15_03_36_net10.0.trx`,
SHA256 `2854501AE7B5ECDC7C7EDF95BE426045A985A8C468618BF3EC3A07C51D2A2F08`.
The raw floor cases preserve Pending and issue no effects/outcome; recovery of
the exact anchored floor is not authority to remint a missing peer intent. That
request still denies safely. This preserves the original pre-intent failure
contract, not a claim that every disk failure can settle automatically.
Corrective full02 finished native1 on `2026-10-10T10:47:18.5304977Z`:
build0/zero warnings, preflight0, test1/qualification1, FullAccepted=false.
Integration1069/0/0 and ProfileGenerator107/0/0 passed; unit254/1/0 failed.
The exact union contained1431 cases and2136 captured inputs; final unchanged-input
qualification did not complete. No allowed FAIL/skips were supplied. All23
previously failing integration cases now pass, but the batch is not accepted.
The sole failure is
`DurableMailboxCapabilityReplayJournalTests.ConcurrentAcceptedTimes_NeverMoveDurableFloorBackwardOrLoseClaims`:
native `MoveFileEx` replacement throws `Win32Exception`5 (`Access is denied`)
through `MailboxDurabilityBarrier.ReplaceFile`. The denying process/condition is
not established; a later passing repeat cannot erase this failure. Investigate
the current Release binaries before another matching full. Receipt SHA256:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_15_09_10_net10.0.trx` | `5DE81A99DFE0A1320C5359389FD3315A5CDD1AC6056FAD73FA008614352BB2B2` |
| `nikit_SURFACE-LT_2026-10-10_15_45_58_net10.0.trx` | `FDD2B1E558B4FF3473827B10B33DD7BE49306D342FE8BE1AD0F19D54DC3CFC07` |
| `nikit_SURFACE-LT_2026-10-10_15_46_25_net10.0.trx` | `DEB58BDC6965ED01B1B23012B4DE78A4E08AB00CF4DEB315C5ED991317AF688E` |

At full02, transport had not yet run against that candidate. The subsequent
full03/transport receipts are above; original full01/full02 FAIL remain unchanged.

Native-denial diagnosis: all129 selected current unit Release binary/source inputs
matched full02 hashes before repetition. Six isolated current Release repeats and
two whole-unit repeats255/0/0 finished native0 (`unit-repro-04`). Debug repeats
were also run accidentally; they are not current-source qualification. The
native denying process/condition remains unknown, so no product retry budget,
ACL, error classification or assertion has been relaxed. The affected test now
adds failure-only numeric error/file-attribute observation around the unchanged
native barrier and independently reopens all51 claims and the durable time floor.
New Release warnings-as-errors build0/zero warnings; focused replay/barrier19/0/0
and whole unit255/0/0 both native0 (`unit-repro-05`). SHA256:

| Receipt | SHA256 |
| --- | --- |
| `unit-repro-04/run-7.trx` | `75B6D66D8044BFD87991BEEE8156C2955DC0852435CE8029D0FECC909E080A0E` |
| `unit-repro-04/run-8.trx` | `DF0308D4C58EAFA6D41C9AC0863C2AACE983D62665FB5E41F3044A8944D60C20` |
| `unit-repro-05/run-1.trx` | `585423E4AA5B917E138D511FD17459AA21AC6A9E02C2C2A16AC182B59BD647C7` |
| `unit-repro-05/run-2.trx` | `84616D95B48987B00E8D0112DBEC41B6873CC4620FB76FCE522DD9CD25241C9A` |

These receipts are below `artifacts/s02-client-entry-20261010`. They do not erase
full02's FAIL or identify the external cause. Matching full03 includes the
strengthened unit receipt in the existing exact reference union and has now
passed as recorded above. Transport follows that actual full acceptance.
The unresolved intermittent native
denial remains explicitly tracked for further observation rather than called fixed.

Privacy check: scanning the complete two diagnostic directories rejects11 raw
`.log` files by artifact policy. They remain ignored local diagnostics and are
not eligible for upload; no renaming, deletion or policy exemption hides them.
An explicit eligible selection of changed source, TRX receipts and full02 passes
52 files/native0 (`deep-devops/artifacts/s02-client-entry-20261010/unit-eligible-selected-scan.json`).
This is not a global artifacts PASS or authorization to export the raw logs.

The configured three-Program cycle now enters the signed public origin over
actual HTTPS/H2 with the typed selected-entry transport and descriptor SPKI pin.
Both onward onion hops and replication remain actual Program HTTP/native owners.
A test-only transparent Node.js built-in HTTP/2/TLS proxy joins each signed public
origin to its private Program listeners. It applies the existing HAProxy header
hygiene, validates the private certificate name/chain/SPKI, and neither parses
native frames nor makes authority/outcome decisions. The client checks the
unfiltered received MHT response. This proves the source HTTP boundary, not the
deployed HAProxy/Xray carrier or installed Windows/Android clients. The fixture
requires Node.js22+; CI selects24, with an executable preflight and captured copied
`.cjs` input. It adds no npm packages or production Node.js dependency.

The same real public-entry cycle rejects eight malformed MHT inputs, a genuine
but wrong entry and a genuine selected second replica used as the Store exit.
Every refusal preserves all native mailbox digests and the Store/ACK peer count.
The wrong exit returns the exact MHT504 `UpstreamOutcomeUnknown` contract:
forwarding already occurred, so the client cannot infer absence of effects or
replace its exact intent. Positive Store/read from both replicas/ACK/cold exact
retry still requires strict MHT transit completion and a decrypted success.

A cold-loss repro previously recovered successfully after both client replay and
canonical outcomes were removed, despite independently protected operation
custody remaining. The current fix implements DR-0084 through that same existing
operation document, as amended in [DR-0087](../../../docs/survival-program/decisions/DR-0087-current-mailbox-operation-custody.md):
counter/claim/completed-outcome floors are recorded before effects/response,
joined on actual host, client and peer admission, and never evicted. Private
operation generation7 rejects old6 without migration/reset. Public wire and node
keys are unchanged. Coordinated peer replay/mutation/blob loss is not proved
independently anchored by these client floors; it remains a separate S03 concern.

Focused12 finished native0/build0 with warnings-as-errors:34/0/0, including joint
loss, authentic older counters, distinct Store intents, exact recovery and the
new public-entry cycle. Its SHA256 is
`3629BA9E5765DC133419A40ED5DBDBA4DBDDFFA35287F7182BFEA16E7C7E7036`.
Focused13 contains30/0/0, including restored Pending after completion and
Retrieve-only native loss; its native handle was lost, so it is not terminal0
evidence. Focused15 finished native0/build0:5/0/0, covering those two new cases,
helper preflight, the extended public-entry cycle and retained original-epoch
read/ACK after signed projection advance and native peer cold reopen. That
retained case is direct native-peer evidence, not configured public HTTP evidence.
Receipt `artifacts/s02-client-entry-20261010/focused-15/nikit_SURFACE-LT_2026-10-10_14_25_28_net10.0.trx`,
SHA256 `FFFEDDE6102EF6D0ECE7995D31F9C3BC11CE366C557ABEC82344AAC48FDBB368`.
Root executable-input gate contracts pass35 checks, native0.

Original FAILs remain in the focused run directories:05/06 exposed extra response
headers in the attempted Kestrel front end;08 test-key export;09 early rejection
upload flow-control deadlock;10 the real coordinated client cold-loss defect;
14 incorrectly expected a sealed successful transit for the wrong exit instead
of its exact MHT unknown contract. None is relabelled PASS. The successful
response contract/assertions are unchanged. No production deployment, release,
main merge or physical device delivery is claimed by this candidate.

## Configured Program / descriptor-bound HTTP forwarding batch

This source batch extends the registered-native business cycle to three
actual configured Program hosts. The fixture provisions the actual graph with
the existing enrollment command boundary, then closes that provider before
starting Program on the same persistent directories. No endpoint/current-source
replacement or hosted-service removal is used. Directory responses are raw
nonce/request/floor-bound signed packages over real HTTPS, independently checked
by `DeepIdV2DirectoryProofRuntime`; network authority/closure and protected floors
are the configured file/native owners. Only the monotonic clock and trust of a
test-owned loopback TLS certificate are test dependencies. The client enters the
actual entry runtime; both onward onion hops and mailbox replication use the real
Program HTTP endpoints/descriptor-pinned clients. Xray is disabled in this source
fixture: it is not carrier, deployed or physical-device qualification.

This exposed a product defect hidden by earlier ID-equals-key fixtures:
`PrivacyPeerAuthenticator` treated RouterId as an Ed25519 public key at signing
and verification. Forwarding now carries the receive binding's verified network
context; local signing custody and inbound signatures resolve the exact identity
key from the current XND1. The HTTP transcript/headers are unchanged; no extra
key configuration, compatibility overload or ID-as-key fallback was added.
Missing verified authority rejects before peer replay acceptance. The existing
UTC peer timestamp remains a bounded transport replay check, not grant authority.

Focused09 completed native0 under explicit Desktop5.1/SDK10.0.301 with a matching
warnings-as-errors solution build0/zero warnings. Result49/0/0, exact49 names,
case keys and executions. Includes configured enrollment/readiness,
Store/Retrieve/ACK through three signed hosts/two native stores, cold restart and
exact retry without resurrection, corrupt authority readiness503, distinct-ID/key
authentication and hostile body/identity/recipient/signature/nonce/time/expired
network refusals. The verified fixture-source shortcut is never read in the
configured cycle. Standalone expiry matrix8/0/0 on the same binaries is diagnostic.
The negative expiry case uses a genuine late signed proof, unchanged1500 view end,
and its actual one-second lease; existing signed epochs/expiry assertions are not
extended. Receipt:
`artifacts/s02-configured-program-20261010/focused-09/nikit_SURFACE-LT_2026-10-10_12_23_16_net10.0.trx`.
SHA256 `AF838EC446A7973819A3A296D6BF8DD58EF72BE14FD0964411100E0C3CDE2CCB`.

Original focused FAILs remain in01/03/04/05/06/07: the new raw proof server initially
ignored the restored directory floor; released port reservations could be reused
before host startup;04 exposed the actual identity/key defect. The new expiry
test initially confused fixture sample/DTT issuance duration with the minted
elapsed-time lease, then attempted issuance past the original signed view end.
The server now builds proof material against an exact known signed caller floor;
ports remain held during the ceremony, and late test issuance ends at1500.
No historical failing receipt is relabelled PASS. Selected source/current-run
secret scan passes21 files/0 findings; the existing global artifact scan still
fails46 unrelated raw/diagnostic artifact checks, and no upload was performed.

Matching canonical `artifacts/test-gate-20261010/node-configured-program-full-01`
finished Completed/native0 through explicit Desktop5.1.26100.9457/SDK10.0.301.
Started `2026-10-10T07:27:42.1242586Z`, finished `2026-10-10T07:57:21.1713236Z`.
The predeclared references are the three previous `node-new-host-full-02/full`
TRX plus focused09, with no allowed FAIL/skips. Build/preflight/test/qualification0,
zero build warnings/errors,1423/0/0, exact1423 required cases and2129 unchanged
inputs; FullAccepted=true. Integration1061, ProfileGenerator107, unit255.
Full receipts (in `full/`):

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_12_28_35_net10.0.trx` | `0AD955011AECA95D4FFF496453FFDF4BA7065EB44AD414059F202F93CD862383` |
| `nikit_SURFACE-LT_2026-10-10_12_55_18_net10.0.trx` | `0FC8CF5612F78BB4E000BE9F09B1A2514D7861C2E36E14880167CD9253E4340A` |
| `nikit_SURFACE-LT_2026-10-10_12_55_42_net10.0.trx` | `C15C4CCD39E8D4478D71C7291A97F799975F2975BE7CE335EF67282C8FBE015D` |

Separate current transport checks finished native0 through explicit portable
PowerShell7.5.4. External/no-mock smoke in
`deep-devops/artifacts/s02-configured-program-20261010/smoke-01` reports no
hard/soft runtime failures or warnings, running/nonmocked Xray and requiredNoMock.
Its three existing BuildKit InvalidDefaultArgInFrom notices are build notices,
not runtime-gate warnings. `runtime.gate.json` SHA256:
`07DE80E7CA69CA4B2CBE1408DA8DA554F6442B7CE0A5617DE9533DF96A69BD8E`.
Three-node rehearsal `20261010T075933893Z-e58c3ba4cc5c` has three distinct,
real/nondegraded Xray routers, Registry count3/reconciliation issues0 and three
expected privacy-contact503 refusals without configured authority. Its
`test-results/multi-node-topology.json` SHA256:
`A796172783372593B963D7F2B2218E36DD5C56385491C640937FF432FF68FED8`.
Post-terminal label inspection found no containers/volumes from either
test-owned disposable project; the separate `deep-dev` stack remains running6.
Only those disposable stacks/data were removed, not production or developer data.

This qualifies the source batch and Development transport, not whole S02 or
shipping/device delivery. Current retained-route/selected-exit and independent
native cold-loss/rollback closure still need the exact stage review. In particular,
the configured positive enters the actual entry runtime in-process, not the public
client HTTPS/carrier endpoint; cached-index readback is not an independent cold
anti-rollback anchor. Neither gap is closed by a full test count. No production
state, release, main branch or physical Windows/Android claim is changed.

## Current source build and focused result

Inputs: Node `c000dc1`, Protocol `9700e76`, Shared `c79c0a8` (documentation-only
successor of qualified Shared source `5057069`). No Node implementation or
fixture source was changed for this run.

Run from Windows PowerShell5.1:

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj --configuration Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxHostRecoveryReadinessTests|FullyQualifiedName~ActualRegisteredOwnersCompleteNative' --logger trx --results-directory artifacts/s02-current-consumer-20261010/focused-01 --verbosity minimal
```

Native exit0; build completed with warnings treated as errors. VSTest result:
**91 Passed /0 Failed /0 Skipped**, reported test duration37s. This duration is
not the build/wall-clock duration. The canonical root `Read-TestGateReceipt`
finds91 exact names,91 case identities and91 unique execution mappings:
85 composition cases,4 readiness cases and2 actual registered-native cases.

Receipt:
`artifacts/s02-current-consumer-20261010/focused-01/nikit_SURFACE-LT_2026-10-10_08_06_25_net10.0.trx`.
SHA256: `69001B184A3DF8C523F4538A6DC7D8EB4699F171E59BDF5849680AEC1167F7A1`.

This is not a canonical unfiltered full: there is no full gate terminal or
captured-input qualification for this focused run. The old Node full02 receipt
must not be relabelled a full on these newly compiled Protocol consumer inputs.

## Remaining S02 implementation boundary

At the initial 91-case checkpoint, readiness invoked the actual current receiver under both restored role owners,
checks current descriptor signing custody and the anchored operation document.
That version of `CurrentMailboxReplicaReceiver.InitializeHostAsync` did not itself
join all stored native blob/mutation/replay/outcome recovery dependencies.
Constructors and individual request guards are not proof of whole-host recovery.
The next coherent S02 unit is that native-state recovery/readiness boundary,
including retained work and fail-closed missing/corrupt custody. Do not replace
it with an extra Boolean, an empty store, host UTC, a synthetic client grant,
automatic enrollment or a new operation journal.

Enabled configured Program observer/provisioning, selected-exit/ONION boundaries
and the matching whole-host tests remain required. The existing positive Program
peer fixtures use explicitly enrolled native owners and test TLS endpoints;
they do not prove the production configuration or installed client composition.
No production machine/data/key, package, release or main branch was changed.

The native recovery implementation below precedes another broad test cycle.
Run matching focused fault/reopen checks, canonical Node full, and the separate required external
no-mock smoke/multi-node rehearsal. S04 renewal/cleanup and S07 scheduler/receipt
orchestration remain later stages; S02 is not accepted by91 focused passes.

## Native recovery implementation batch

`InitializeHostAsync` now joins existing mutation/blob, peer replay and client
replay/canonical-outcome owners before reporting fresh readiness, while the two
current protected role owners remain held. No extra journal, grant, caller time,
GC, auto-enrollment or permissive reader is introduced. The operation ledger's
already anchored pending replacement recovery is unchanged.

The native read phase validates bounded file framing and names, mutation index
membership/cursor uniqueness, exact MEO1/blob linkage, absence of orphan or
tombstoned-resurrected blobs, peer replay inventory/partition counts, exact live
client replay readback and completed replay-to-outcome digests. Existing expired
blobs must still be structurally valid; absence of an expired blob is not treated
as loss of a live completed Store. Pending/tombstone-pending prefixes may have no
blob and are not completed by readiness. Native links reject before content read.

Fault/reopen fixtures use the existing signed distinct-ID/key peers and real
TLS/H2/native stores. They also exercise actual Store -> Retrieve -> ACK and
cold reopen after the original client grant expires, without new admission or
HTTP from readiness.

Independent protected cold anti-rollback/absence coverage for the client/peer
replay and mutation documents is still incomplete. Live cached-index/readback
comparison and cross-store consistency do not prove that coordinated cold loss
or rollback is impossible. Whole-host provisioning, retained-route/selected-exit
closure and sustained-capacity health remain explicit acceptance requirements.
This batch alone does not accept S02 or qualify shipping/device E2E.

## Native batch focused receipts

Windows PowerShell5.1, SDK10.0.301, warnings-as-errors, current Protocol source
cutover. Initial integration run `artifacts/s02-native-recovery-20261010/focused-01`
passed37/0/0/native0 (37 exact names/cases/executions). SHA256 of its TRX:
`EC22C7C2190DA6771A90FF5837697A65DE9EF8188F364864696783A178C5D2C2`.

The broader `focused-02` solution command exited1: integration38/1/0 plus
unit13/0/0. Its failure is retained, not relabelled PASS. The new tombstone fixture
used a fixed peer timestamp older than the server-authored Store; native mutation
validation correctly rejected it. The test now uses the actual Retrieve/ACK APIs
and keeps the same expiry and mutation bounds. Review also corrected the initial
native replay file bound to preserve the neutral primitive's maximum supported
cached outcome; a one-scope maximum-size cold-open regression passes.

Final matching command:

```powershell
dotnet test XNode.slnx --configuration Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentHostNativeRecovery|FullyQualifiedName~CurrentHostRecovery|FullyQualifiedName~DurableMailboxCapabilityReplayJournalTests' --logger trx --results-directory artifacts/s02-native-recovery-20261010/focused-03 --verbosity minimal
```

Terminal native0; **52/0/0**, with exact52 name/case/execution mappings. Integration
39/0/0 (reported3m7s) and unit13/0/0 (358ms); these are test durations, not total
build/wall-clock time. ProfileGenerator has an exact empty0/0/0 filtered receipt,
not a suite PASS. Node outputs are Release; the solution invocation builds its
Protocol project references as Debug. This is source evidence, not a shipping
package/configuration qualification.

All receipts under `artifacts/s02-native-recovery-20261010/focused-03`:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_08_43_14_net10.0.trx` | `8FBF26EAE66D6B446DB553ACA093B924D42AC749AE76346C28637D98539DF296` |
| `nikit_SURFACE-LT_2026-10-10_08_46_16_net10.0.trx` | `6FB82692575704948E89573EBCEFCA8072D87E494A3D1E8803D36448097A8C11` |
| `nikit_SURFACE-LT_2026-10-10_08_46_17_net10.0.trx` | `BED2946729BE13F9AE4B4E238D268A27A15E9649B2248C108A3C53A508F280E7` |

## Matching canonical Node full

`artifacts/test-gate-20261010/node-native-recovery-full-01` is terminal
Completed/native0, not a running observation. Windows PowerShell5.1.26100.9457,
SDK10.0.301; build/preflight/test/qualification all exit0. Started
`2026-10-10T03:50:16.2237011Z`, finished `2026-10-10T04:21:58.2511358Z`.

**1390/0/0**, exact1390 cases/executions and2130 unchanged captured inputs;
`FullAccepted=true`. Integration1028, ProfileGenerator107 and unit255 all pass.
The predeclared union contains the three previous Node full02 receipts, the
earlier91-case current-consumer receipt and all three final focused03 receipts.
The original focused02 fixture FAIL is preserved separately, not treated as a
passing reference or waived assertion.

Receipts under the run's `full` directory:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_08_51_07_net10.0.trx` | `49C864FFD0425DD6321121A4DAEF367EEB36975DAFDF4FB1E4A821918A7B4CF2` |
| `nikit_SURFACE-LT_2026-10-10_09_20_07_net10.0.trx` | `08A0EC8F191AC838BD0DAE696418AD15DB57231BD44A7417F8A07E60C9E6A145` |
| `nikit_SURFACE-LT_2026-10-10_09_20_33_net10.0.trx` | `B6448A37E7842A96CF9CD89659C762A5FBFA712E6497F64B38AB80754383BF2F` |

The separate external/no-mock smoke and multi-node rehearsal are both terminal
native0. The existing
Shared/Protocol full receipts are not rerun or relabelled by this Node batch.
This full qualifies the current implementation package, not the outstanding
independent cold-protection/provisioning boundaries or whole-stage acceptance.

## External/no-mock smoke

PowerShell7.5.4, `deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode
external -ManagedExternalProfile backend-external -RequireRouterNoMock`;
run `deep-devops/artifacts/s02-native-recovery-20261010/smoke-01`.
Terminal native0. Fixture validation and ten compatibility-runner tests pass;
these are not ten physical device scenarios. The runtime gate records no hard
or soft failures, no warnings, actual router transport `running` and
`routerTransportMocked=false`. The two selected runtime/topology files pass the
run's secret scan; this does not qualify other artifacts for upload.

This isolated Development transport lane uses external storage/file/push
services and real Xray. It does not provision current production mailbox
authority or prove contacts/messages/attachments/groups on installed devices.
Only its own `deep-integration` containers/volumes were removed by the script;
the existing `deep-dev` stack was preserved.
Runtime gate SHA256:
`1CCDE50A06ED3DB5CBC2498C28B7EC9CE18A759D600EBD57C3A2A9139AFD09C9`.

## Three-node no-mock rehearsal

PowerShell7.5.4, `deep-devops/scripts/multi-node-rehearsal.ps1` without
`-AllowMockRouter`. Terminal native0; run
`deep-devops/artifacts/rehearsals/multi-node/20261010T043622503Z-e8ad5309923d`.
The source-cutover image was rebuilt. All three distinct routers run real Xray,
register with the isolated Registry and have no reconciliation issues.
Each rejects privacy contact with503 without verified authority; this tests
honest unavailability, not successful current mailbox/onion delivery.
The script removed only its own `deep-multi-node-rehearsal` containers/volumes.
The pre-existing `deep-dev` stack was not restarted or reset.
Topology receipt SHA256:
`BB4BB981C3B946A2B510399C785793FCF0D056299C0E76AECC2D709E9C6506E4`.

This completes the required external transport/topology checks for Node source
commit `1c38f45`. It does not accept S02, qualify production authority or count
as any of the four required physical device flows.

## New-host native-state provisioning batch

On top of qualified source `1c38f45` / checkpoint `4fdf0b3`, enrollment now
refuses any existing native blob/mutation/peer replay/client replay/outcome
custody, including files ignored by their normal indexes. The existing operation
owner rejects all non-lock entries in its replaceable directory as well as its
independent root. Only the actual empty owner locks are permitted; file/directory
and ancestor links reject. Checks are read-only, cancellable and bounded by
immediate refusal on a non-lock entry. No bytes, wire or second journal change.

`EnrollConfiguredAsync` checks these actual owners before the explicit
`RestoreHeadAsync` / `AcquireObservationAsync` acquisition; construction of the
configured owner graph may resolve the proof/network providers, but does not
perform that acquisition. Direct enrollment checks before source callbacks and repeats
after signed preflight, before either role enrollment. Native readers no longer
purge observed `.tmp`/`.deleted` files on construction. They preserve interrupted
custody for explicit owner-approved lifecycle/recovery; none is silently adopted.

The actual factory matrix adds24 pre-open cases: six native owner directories,
each with `.tmp`, `.deleted`, unknown file or child directory. It asserts refusal,
unchanged leftover/key bytes, no role/operation enrollment and command rejection
before missing proof providers can be resolved. The original fresh/late-current
positive and cold reopen cases remain unchanged. Matching focused passes
185/0/0/native0; matching full01 failed as recorded below and external-gate results
for this batch are still pending; the prior1390 full does
not qualify these new inputs. This closes neither independent cold rollback/loss
coverage of the other stores nor whole S02/device/release acceptance.

Windows PowerShell5.1.26100.9457 / SDK10.0.301, warnings-as-errors:

```powershell
dotnet test XNode.slnx --configuration Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxEnrollmentCommandTests|FullyQualifiedName~CurrentHostNativeRecovery|FullyQualifiedName~CurrentHostRecovery|FullyQualifiedName~DurableMailboxCapabilityReplayJournalTests|FullyQualifiedName~MailboxClientCanonicalOutcomeStoreTests|FullyQualifiedName~DurableMailboxPeerReplayJournalTests|FullyQualifiedName~MailboxPeerMutationStoreTests' --logger trx --results-directory artifacts/s02-new-host-20261010/focused-01 --verbosity minimal
```

Integration154/0/0 (reported3m13s), unit31/0/0 (445ms); canonical receipt parsing
finds185 exact names/cases/executions. ProfileGenerator's filtered receipt has
exact zero counters and is not a suite PASS. Node outputs Release and its
solution-built Protocol references Debug, as in the prior focused command.

Receipts under `artifacts/s02-new-host-20261010/focused-01`:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_09_55_25_net10.0.trx` | `883A2EAEC2953C36ADE6EE35A568B367E8B9EE84A10ED88C27AD1B7F93DA0E5E` |
| `nikit_SURFACE-LT_2026-10-10_09_58_42_net10.0.trx` | `97F693DEBF7BE48F2EB8DE3029049EFB93F5FBA47633316A75B7774F56569147` |
| `nikit_SURFACE-LT_2026-10-10_09_58_46_net10.0.trx` | `FCAE928E4A39297C779FD10BA29DDACF1D2BEC94703D81AC41C22F110071A16B` |

Canonical full `artifacts/test-gate-20261010/node-new-host-full-01` finished
at `2026-10-10T05:33:50.5983061Z` in Windows PowerShell5.1 using all three previous
native-recovery full TRX and all three focused185 TRX as the predeclared reference
union. No allowed failures/skips. Build/preflight0, test/qualification1,
FullAccepted=false. Integration1051/1/0, ProfileGenerator107/0/0, unit255/0/0:
1413 passed and1 failed across1414 executions. The failure is
`CurrentRetrieveCannotSkipLivePendingCustodyBelowCrossReplicaContinuation(reopen: True)`:
the initial explicit-producer Store returned PartialFailure instead of Durable
at Retrieve.cs:100, before the later reopen branch. Cause is not yet established;
the original FAIL is retained. A separate post-terminal input check using all six
reference TRX confirmed2129 captured/current inputs and zero differences; it
does not turn this failed gate into PASS. The two-case no-build diagnostic repeat
under `artifacts/s02-new-host-20261010/retrieve-diagnostic-01` finished2/0/0/native0
on the same executable binaries. This does not establish a cause or fix.
The same initial/resumed Store assertions now include existing safe HTTP status,
counts, elapsed/cancellation and handler-phase diagnostics; they still require
Durable and do not retry or extend any deadline. A matching focused repeat of
the185-case batch plus both Retrieve cases finished187/0/0/native0 under
`artifacts/s02-new-host-20261010/focused-02` (integration156, unit31, exact empty
ProfileGenerator receipt). A subsequent shell observation found the command
tool had ignored its requested shell and executed PowerShell7.6.5. Therefore
diagnostic01/focused02 are diagnostics, not the required PowerShell5.1 lane.
The attempted full02 was rejected by the canonical interpreter guard before
build/run-directory creation; it is not a launched full or a product failure.
Focused03 used an explicit nested `powershell.exe -NoProfile -NonInteractive`
invocation, which emitted Desktop/5.1.26100.9457/SDK10.0.301 before the same
187-case command. That verified-shell repeat finished187/0/0/native0:
integration156 (reported3m49s), unit31 (394ms), exact empty ProfileGenerator
receipt. Canonical parsing finds187 names/case keys/executions. No product source,
test expectations, deadlines or reference case names were changed for it.

Focused03 receipts:

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_10_40_40_net10.0.trx` | `4A1A99FC806F967B201CE8D0D02AD1F3020EFA7DD3E0D484A00B2E80C43AB923` |
| `nikit_SURFACE-LT_2026-10-10_10_44_31_net10.0.trx` | `0E25471B2C4258CD4E210F0DB4BF0EE8A07C0DB65F7BDE25212A0743CF52F0DC` |
| `nikit_SURFACE-LT_2026-10-10_10_44_34_net10.0.trx` | `A9FCA025050D16AAA62B0E44669E39752B0C4686D8BC14C10C91594130EDFEA4` |

Canonical `artifacts/test-gate-20261010/node-new-host-full-02` finished Completed
through the explicit Desktop5.1 invocation. Started `2026-10-10T05:44:48.7517702Z`,
finished `2026-10-10T06:16:06.7594145Z`. Its predeclared reference union is the three
previous native-recovery full TRX plus all three focused03 TRX, with no allowed
failures/skips. Build/preflight/test/qualification0, zero build warnings/errors,
1414/0/0, exact1414 required cases and2129 unchanged inputs; FullAccepted=true.
Integration1052 (reported28m35s), ProfileGenerator107 (21s), unit255 (49s).
This qualifies the current source batch, not whole S02, shipping or devices.
The original full01 failure remains preserved and unexplained; a passing repeat
does not establish its cause. Required current external smoke/rehearsal are
terminal0 as recorded below; the remaining S02 whole-host boundaries are still
outstanding.

Full02 receipts (in `full/`):

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_10_45_42_net10.0.trx` | `2E0B9DF1CEAEEC2465657D6E8167DF0EDAFA8EC6A3842FC04A3BA314784B6517` |
| `nikit_SURFACE-LT_2026-10-10_11_14_21_net10.0.trx` | `A93AB05FAFA78BDBB5A5E80C7C23096076A782F1AA6C86C642F2EA88193524FA` |
| `nikit_SURFACE-LT_2026-10-10_11_14_44_net10.0.trx` | `784DB46BA6EAC02D07CF3F21A0CADAC42B4CF54FEE7656DC88C2A0430D3B28FD` |

Current external/no-mock smoke finished native0 through explicit portable
PowerShell7.5.4, under `deep-devops/artifacts/s02-new-host-20261010/smoke-01`.
Fresh scope checks found no pre-existing `deep-integration` containers/volumes
and only the separate six-container `deep-dev` stack. Managed external URLs
and Compose project are scoped to the disposable integration stack, not
production. Fixture validation and ten compatibility-runner tests passed;
these are harness tests, not physical flows. Runtime gate: hard/soft failures0,
warnings0, transport running, mocked=false and requireNoMock=true. BuildKit's
three existing InvalidDefaultArgInFrom notices are separate build notices,
not runtime-gate warnings. The script's two selected evidence files passed its
secret scan; this is not a global artifact/upload qualification.
`runtime.gate.json` SHA256:
`0C50DDDA8B32E8616929875B2AA401E3A1C99E8992485011CE654A20F004162E`.

Current three-node no-mock rehearsal finished native0 through the same verified
PowerShell7.5.4, without AllowMockRouter. Run:
`deep-devops/artifacts/rehearsals/multi-node/20261010T061929955Z-d7498eec9b31`.
Its rebuilt source image ran three distinct, real/nondegraded Xray routers,
Registry count3 and reconciliation issues0. All three privacy-contact responses
are the expected503 without verified authority. This remains Development
transport/topology evidence, not successful current mailbox or device delivery.
Topology receipt SHA256:
`E53FE3B12D604BFDE7F9A979D3F5E1522A622FD170B0AF8DE2B0939C0F20D3BF`.
Post-terminal label inspection found no remaining containers/volumes from either
disposable project and the unchanged separate `deep-dev` project running6.
Only test-owned stacks/data were removed; no production state was reset.

Full01 receipts (in `full/`):

| TRX filename | SHA256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-10_10_02_58_net10.0.trx` | `D1FEA980DD5B690239087BA76DB3C4981808C2061A73F42ECD37C7EF9869ECF2` |
| `nikit_SURFACE-LT_2026-10-10_10_32_40_net10.0.trx` | `AA881C96BB778F46184BCF2997151A5D9A568AEF840D63440DA5C4C34342EC71` |
| `nikit_SURFACE-LT_2026-10-10_10_33_03_net10.0.trx` | `F2F38EEE1E201A57A43997C4000C29E6FE94E4ADDE08A61C271C6A37DB48FFFF` |
