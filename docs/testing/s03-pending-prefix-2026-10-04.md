# S02/S03 — pending custody below a cross-replica continuation

Date: 2026-10-04. Source baseline: XNode `5fdb9b9`, Protocol `a253260`,
root `aba388f`. Execution owner: [S02/S03](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
This is a native connected regression, not Program activation or physical E2E.
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md) remains the only unfinished queue.

## Reproduced defect and correction

Retrieve previously skipped index entries at or below `AfterCursor` before
reading their native mutation state. A valid continuation from the other
replica could therefore pass a live local Pending Store without rejecting.
That Store can subsequently complete below the already-issued cursor.

The reader now checks native record/index binding, protected expiry and mutation
state before skipping consumed cursors. Live unresolved Store custody rejects
the new read without a canonical successful outcome. Completed consumed records
do not reread blobs; expired and tombstoned records retain their existing handling.
Checks use the existing bounded index, mutation files and current operation lease.
No new journal, wire, authority DTO, route selection or activation flag is added.

The two regression cases use actual signed current grants, two independent
native stores and pinned TLS/HTTP2. An injected interruption after the real
local reservation leaves cursor 1 Pending. A separate signed grant then stores
cursors 2 and 3. The remote replica, which has not received cursor 1, issues a
real signed first page and continuation. Switching that continuation to the
local replica must reject its unresolved prefix, both before and after reopening.
No mutation JSON, cursor, signature or verified authority is fabricated.

After exact retry completes the original Store, the unchanged admitted read
recovers successfully. A fresh snapshot returns all three messages. Importantly,
the old continuation still starts after cursor 2: this fix does not rewind it or
recover cursor 1 into that old snapshot. A replica with no local mutation yet
cannot detect the remote Pending intent. Consequently this is a necessary
fail-closed guard, **not** a complete global-order/no-loss solution. Shared cursor
ownership, intent-before-mutation visibility and late completion below a captured
high-water boundary remain activation blockers under S01/S02/S03.

## Verification

Before the production correction the two genuine regression cases both failed
at the expected assertion: the unresolved-prefix read returned success. After
the correction both pass, including original Store and Retrieve recovery.
Release source-cutover solution build: zero warnings and zero errors.

```powershell
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --filter 'FullyQualifiedName~CurrentRetrieveCannotSkipLivePendingCustodyBelowCrossReplicaContinuation' --logger trx
```

Final focused current admission/Store/Retrieve/ACK/peer/revocation:
**132/132 pass**. Full XNode solution: **1027 pass / 1 fail / 0 skip**, total 1028;
Integration 648/1, Unit 272/0, ProfileGenerator 107/0. The sole unchanged failure
is `PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays` (B8): the signed
current DID2 one-time invitation producer is still missing. It is not skipped
or replaced by reusable genesis.

```powershell
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --logger trx --results-directory artifacts/s03-pending-prefix/full
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --filter 'FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocation' --logger trx --results-directory artifacts/s03-pending-prefix/connected
```

Final ignored TRX SHA-256:

- Connected: `2b77bb9ecfce2b148d45a9476602bec87a10f43b38c93b4f8a09f62de2b279ea`;
- Integration: `0183ef62969af1a37751a2b698bbc05850c80b9961ddbeee8aa1f05921d73d7c`;
- Unit: `3a2dd2adf578a2886bb6cccde0849e2a1e68f84f718325673934cbd78c492c7f`;
- ProfileGenerator: `ca268231db49c0b24bd5cfa60e6a7314f64e49566b5475d40b87e6b73f09ac6b`.

Managed-external Docker smoke passed with real Xray, zero hard/soft failed checks
and no mock. Three-node rehearsal passed: three running Xray instances, zero
mocked transports and zero reconciliation issues. These lanes exercise the
existing compiled composition, not activated current mailbox Program/DI.
Both temporary projects finished cleanup with zero containers, volumes and
networks; all six existing dev-contour containers were preserved running.
Documentation gate: **174 checks pass**. The eight selected regression/full/
connected/Docker artifacts have zero secret-scan findings; raw artifacts remain
ignored and no payload, private identifier or secret is copied here.

## Remaining boundaries

Current Program/DI is not activated. Retained routes, object horizon, sustained
renewal/settlement/retirement, distinct node ID/descriptor-key qualification,
one-time DID2 invitation producer, shipping clients and full physical E2E remain
open. Transport tombstone ACK is not application Delivered/Read. Production,
devices, existing accounts and operator custody were not modified by this run.
