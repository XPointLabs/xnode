# S02/S03 — current client ACK and exact recovery

Date: 2026-10-04. Source baseline: XNode `4a3d0ff`, Protocol `a253260`,
root `ebc6091`. Execution owner: [S02/S03](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Contracts remain [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md)
and [DR-0085](../../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).
This is internal connected local evidence, not Program activation, complete
stage acceptance or physical E2E. [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md)
remains the only current queue.

## Implementation

Captured canonical MAU3/MBA2 enters the actual current admission owner: signed
host/selector, holder/body, both protected MGR1 floors, current source/time and
native capability replay/outcome. Native completed Store mutation records on
either replica provide the exact ordered cursor/digest/expiry targets. The
recipient replica needs no coordinator client Store ledger. Missing, ambiguous,
pending, expired or already tombstoned targets reject a new batch before deletion.

The receiver authors grant-bound PRQ2 tombstones using actual selected descriptor
signing custody. Each item gets an independent random nonce; the entire exact
batch is saved in the existing `operations.json` before peer reservation,
local deletion or HTTP. Capacity is checked first, without host-UTC collection.
Existing intent binds the exact request digest, membership, replicas and ordered
targets. A known native replay without its intent cannot remint another batch.

The existing current peer coordinator performs native tombstones on two separate
stores through pinned TLS/HTTP2. Each independently authenticated MQR3 is saved
in the same operation ledger. Only after all ordered items have quorum does the
neutral MAR1 framing enter the existing canonical client outcome owner. Partial
commit/lost response retains Pending; saved item quorum recovery avoids redundant
peer HTTP. Store authoring shares its existing signing implementation with ACK;
Store wire, key/authority checks and exact intent custody remain unchanged.

The local operation ledger becomes schema 5, rejecting schemas 3/4, missing ACK
authority and null/incomplete intent without a migration or automatic reset.
There is no new journal, protocol magic, public authority DTO or activation flag.
Inactive neutral persistence helpers do not provide retired mailbox admission.
Current ACK record structure is not cryptographic authority: actual admission
and peer owners independently authenticate each original request and quorum.

## Recovery and acceptance

New non-final ACK requires the existing signed page token and exact page digest.
It is checked only when creating the native exact batch. Reopening that already
admitted batch may resume after pagination expiry, but cannot replace its bytes.
Retrieve similarly returns an actual request-bound saved outcome before checking
whether its original continuation still permits a new page. Both paths still
require independently current grant, time, projection, selected local exit and
revocation; ACK rechecks original peer proofs/quorums. This does not extend grant
validity or authorize an expired token for a new operation/snapshot.

Twenty-two added cases cover either-replica ACK without recipient Store ledger,
cold exact replay/no resurrection, cross-replica non-final pagination, hostile
token/signature/page digest/trailing bytes, before/after intent persistence failure,
lost intent, changed persisted signature, capacity, authority expiry across peer
deletion, crash after actual blob deletion, concurrent retry, new operation on
tombstoned target, revoked role, wrong holder, actual item-quorum flush failure,
and pending/completed ACK plus saved Retrieve after page-token expiry.
An additional incompatible-schema case preserves Store rejection at schema 4.

The first expiry-test drafts used a token already expired at initial admission
and did not exercise recovery. The corrected fixture derives token expiry from
the actual signed trusted upper bound plus one, then advances the actual fixture
monotonic sample by two. With that fixture all three cases fail at the recovery
branch before the fix and pass afterward; fresh expired-token operations still
reject. No trusted-time/replay assertion was relaxed. An earlier compilation
attempt failed because other test hosts held the DLL; it ran no regression test
and is not product evidence. Tests were allowed to finish before rebuilding.

## Commands and evidence

From `xnode`, after formatting and the final source build:

```powershell
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --logger trx --results-directory artifacts/s03-ack/verified-full
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --filter 'FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocation' --logger 'trx;LogFileName=current-ack-verified.trx' --results-directory artifacts/s03-ack/verified-connected
```

Final Release source-cutover build: **0 warnings / 0 errors**. Corrected expiry
regressions: **3/3 pass** after **0 pass / 3 fail** before the production fix.
Final focused current admission/Store/Retrieve/ACK/peer/revocation:
**130/130 pass**. Full solution: **1025 pass / 1 fail / 0 skip**, total 1026:
Integration 646/1, Unit 272/0, ProfileGenerator 107/0. The unchanged B8 failure
is `PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`; it is retained
as a release blocker, not hidden behind a skip or reduced full-suite filter.

TRX SHA-256 (ignored artifacts, selected secret scan passed):

- Focused: `72dcc88087fd05bb3eb97343e272f3fd116acb988992f20a578219de7c7e82c5`;
- Integration: `945bbcbffa7ad79ce0b119f795e802079fa9993b1ad6b6b0b8538faab5bede21`;
- Unit: `79a95b3af0297ed36b8a207176d2a4488a1ecc8585e2445f378c94562324a7cd`;
- ProfileGenerator: `a93364b0cb99f5075304ff01389aa5a512fce01b43b3196833cddf3b290ab2ef`.

Managed-external Docker smoke and three-node rehearsal passed on the final
production source with real Xray, no mock: smoke required-check failures 0,
rehearsal three Xray processes running and reconciliation issues 0. Temporary
containers/volumes/networks were removed; all six existing dev-contour containers
remain running. These lanes check the existing
compiled runtime/transport; they do not activate current mailbox Program/DI.
No production deployment, secret access, account reset or dev-contour change
occurred. Raw run artifacts remain ignored; no payload or private identifier
is copied into this checkpoint. Documentation gate: **174 checks pass**;
selected strict UTF-8/local links and `git diff --check` pass; changed files
and nine final test/Docker artifacts have zero secret-scan findings.

## Open boundaries

- Shared cursor ordering across coordinators and late completion below a captured
  high-water boundary remain unresolved; duplicate rejection is not global order.
- Guarded startup, retained-route/old-epoch Retrieve/ACK, normative object horizon
  and sustained grant/send retirement remain activation requirements.
- Native rotated distinct ID/key qualification, issuer/package/installed matrix
  and current-only public Program/DI remain open. No retired provider bridge.
- Mailbox ACK is transport deletion, not authenticated application Delivered/Read.
  No ONION client text, remote files/groups or Windows/Android physical delivery
  is qualified by these connected fixture tests.
- The missing signed DID2 one-time invitation producer (B8) remains a separate
  prerequisite; its failing scenario is not skipped or replaced by reusable genesis.
