# S01 — native protected mailbox revocation custody

Date: 2026-10-03. Inputs: XNode
`27397999edf0b34bd66cb5a6528ecd48a43d0e70`, Protocol
`149d689c86a73c2bbc47f028948c96f553680d32`, workspace
`d115f56409c4ccafefc86cc8d6cb30ad5a426f6f`.
Contract owner: [DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
Native source evidence, not node ingress, peer quorum, shipping packages,
operational signer renewal or physical delivery.

## Implemented boundary

`FileMailboxGrantRevocationStore` protects exact signed MGR1 using existing
ASP.NET Data Protection, mailbox file security and native durability barriers.
Custody is scoped to node/network/exact policy/role outside replaceable node
data. Enrollment, anchor and floor have separate protection purposes; an
authenticated issuer conflict adds a protected fault latch. No additional wire,
plaintext journal grammar, primitive, signer role, client version or legacy
adapter is introduced.

Explicit genuinely new-scope enrollment and successor planning use the real
Protocol verifier. Authority requires protected exact read-back; restored bytes
alone are facts. Anchor-before-floor replacement, actual flush/replace, exclusive
process writer and retained partial files reject split/uncertain commits. A
complete exact write can restore after restart even if its call returned
uncertainty. Signed fork/removal latches; unsigned hostile inputs and normal
stale/gap rejection do not poison valid custody.

The same scoped concurrency owner encloses floor replacement and the entire
bounded operation callback. The raw Protocol capability is not exposed. Native
leases check closure before and after asynchronous verification; result release
also rechecks current authority. This is the S02/S03 integration seam, not an
implementation of reservation, peer mutation or receipts.

## Actual regression evidence

`MailboxGrantRevocationStoreTests` uses current signed DID2/network/PMA2,
actual role signatures, persistent on-disk Data Protection keys, service-only
file security and native replacement/flush. Clock/proof production is test-owned.
No fabricated verified capability, AcceptAll verifier or no-op storage barrier.

| Cases | Observed boundary |
| --- | --- |
| Both roles | Missing floor rejects before callback; genesis/read-back; new provider/restart; successor/exact replay; revoked vs valid actual MCG3 serial |
| Ten restore faults | Missing/corrupt records, wrong purpose, partial file and lost key ring reject without automatic genesis or callback |
| Rollback and loss | Authentic stale floor rejected against retained anchor; initialized owner cannot re-enroll after all records disappear |
| Signed fork/removal | Authenticated failure, persistent latch, prior floor preserved, restart unready |
| Unsigned fork/gap/rollback | No latch or floor loss; valid current operation still works |
| Three native interruption points | Failure after actual enrollment/anchor/floor replacement; no authority returned; partial restore rejects, complete exact write restores |
| Concurrency/escaped work | Successor/dispose wait; second writer rejects; escaped lease and verification crossing closure reject |
| Time/cancel | Callback expiry suppresses result, retains floor; fresh successor advances expired prior; pre-enrollment cancellation writes nothing |
| Three root layouts | Same/nested/enclosing replaceable data rejected |

Focused **29 pass / 0 fail / 0 skips**. Full final source solution:
**897 pass / 1 fail / 0 skips** (898): ProfileGenerator 107/107, Unit 266/266,
Integration 524 pass / 1 fail. Unchanged B8:
`ContactServiceOpaqueFacadeTests.PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`
requires a signed current one-time publication producer, not reusable genesis.
No failure/assertion removed. Earlier Windows storage nondeterminism remains
open despite not reproducing in this run.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --filter FullyQualifiedName~MailboxGrantRevocationStoreTests --logger 'trx;LogFileName=mgr1-native-floor.trx' --results-directory artifacts/s01/mgr1-native-floor --verbosity quiet
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror --verbosity minimal
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror --logger trx --results-directory artifacts/s01/mgr1-node-final-full --verbosity quiet
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
```

Release source build: exit 0, **0 warnings / 0 errors**, both external Protocol
refs preserved in Release. Shipping NuGet graph/retained MAU2 gate not closed.

Managed-external smoke: isolated project `deep-s01-mgr1-native-20261003`, explicit
local URLs, generated local test identities and fresh artifacts. Exit 0:
fixture validation, ten runner/contract tests, real non-mocked Xray, runtime
hard/soft checks and secret scan pass. Only this temporary project's containers
and volumes removed; all six existing deep-dev containers remain healthy.
Three existing external Node Dockerfile `InvalidDefaultArgInFrom` warnings
are outside .NET compilation. No multi-node rerun: no active path/peer/transport
sources changed. This does not prove successful contact/message/device delivery.

| Raw ignored evidence | SHA-256 |
| --- | --- |
| Final focused TRX | `a31ee3fed774daa611573fd8860b3374d235448f6c9029ccb86d1ee911efb740` |
| Full ProfileGenerator TRX | `eca081cd3592233497165bca55163b84f5f3f2e68deadad740bcc4bc8d596c6b` |
| Full Unit TRX | `33cc97cc17d6a3aa9fd6e6c11553d3171e8a24fe2eb0c19a91dca07b048f9470` |
| Full Integration TRX | `1d83a0acfd40350199769fb94df9fb5bbdbc8ce0fe37b01ff0ec99a2f6ea553a` |
| External runtime gate | `086e57215ecddde16e2f7280b3e6c687467ccc3a8c47a3eabeebebcf057638af` |

## Remaining integration and recovery limits

Program does not register this owner; no flag activates it. S02 must supply a
persistent existing protection provider outside replaceable volumes, restore
before refresh/admission and use the same owner at every reservation/callback/
mutation/receipt boundary. This class does not introspect the injected
provider's key-ring location. S03 must connect current grant-bound peer mutation
and separate ID/key receipt verification. Both current role snapshots and
complete host authority are required, never inferred empty sources.

Joint rollback/loss of all independent custody and keys across restart is
outside this local guarantee; it is not a hardware monotonic counter. Explicit
new-scope provisioning cannot reset a lost old scope. A totally unwritable
medium cannot guarantee persistence of a newly observed latch; the running owner
faults and preserves available partial state. Operator recovery, not automatic
cleanup/re-enrollment, is required.

S01 settlement, retirement/compaction and application receipt contracts and S05
cumulative issuer ledger/renewal/distribution/catch-up remain open. No production,
device, registered node identity or operator secret changed. Neither S01/S02
nor release readiness is declared done.
