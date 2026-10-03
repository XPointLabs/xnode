# S02/S03 — current client Retrieve from actual replica custody

Date: 2026-10-04. Source baseline: XNode `26102c7`, Protocol `a253260`,
root `5100f79`. Execution owner: [S02/S03](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Contracts remain [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md)
and [DR-0085](../../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).
This is connected local evidence, not Program activation, stage completion or
physical E2E. The single current queue is [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).

## Connected implementation

The internal Retrieve entry accepts captured canonical MAU3. Actual current
host/selector, holder/body, both restored MGR1 floors, protected time and the
native capability replay owner admit the request before reading. The receiver's
installed signing custody must match the selected descriptor KEY, not node ID.
No caller-supplied authority, host UTC or retired proof verifier is introduced.

The read uses completed records and ciphertext from the existing native peer
mutation/blob owners on either independent replica, including the replica with
no coordinator client ledger. It cross-checks the exact native scope, cursor,
filename, blob hash, envelope operation/dedup/placement and expiry. A bounded
derivable index covers the same retained mutation files; it is not another
journal, admission authority or evidence of two-replica quorum. Writes refresh
that index/count from actual files even when replace/flush reports an error
after persistence. Capacity therefore still produces backpressure without an
owner reopen. Native blob JSON is bounded before deserialization.

Missing/corrupt blob, unresolved live Store and ambiguous cursor custody reject
the page, rather than silently advancing past a message. Tombstoned/expired
records are not resurrected. Protected time/source is rechecked across actual
file/blob callbacks and before persisting/releasing the result. The existing
canonical outcome store is the sole owner of MRP1; exact replay after cold
reopen returns those saved bytes only under valid current admission.

Continuation encoding factors the existing neutral XCT1 grammar without changing
its bytes, public API, local journal generation or Protocol dependency. It does
not revive an old grant/authority reader. The current caller uses actual selected
descriptor signing keys and protected upper time, binds the retained snapshot,
scope/cursor/item ceiling and caps validity by the grant. Pages can switch
replicas and exclude records inserted above the captured high-water boundary.
The page is reduced by item count until its existing canonical byte bound fits;
remaining items stay reachable by continuation. No payload/identifier is logged.

## Acceptance and fixture correction

Sixteen additional cases exercise both-replica cold replay, cross-replica
pagination, hostile continuation/signature/cursor/limit/trailing bytes, wrong
holder, lost/tampered/oversized blob, ambiguous native cursor, source expiry
after the actual blob read, role revocation before cached replay, and page byte
bounds with sixteen maximal envelopes through real peer TLS/HTTP2 Stores.

The native-capacity case performs a real durable mutation flush followed by an
injected error, then attempts an independent valid Store without reopening the
native owner. The initial test reused the same grant with a higher counter; its
prior Pending claim correctly stopped it at admission, before the quota branch.
The corrected test uses a separately signed grant scope, retains the exact
capacity assertion and reaches native storage. No replay rule/assertion is
weakened and no incomplete claim is erased to make the test pass.

## Commands and evidence

From `xnode`, after formatting and the final source build:

```powershell
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --logger trx --results-directory artifacts/s03-retrieve/verified-final
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --filter 'FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocation' --logger 'trx;LogFileName=current-retrieve-verified.trx' --results-directory artifacts/s03-retrieve/verified-connected
```

Release source-cutover build: **0 warnings / 0 errors**. Final focused current
admission/Store/Retrieve/peer/revocation: **107/107 pass**. Full solution:
**1002 pass / 1 fail / 0 skip**, total 1003: Integration 623/1,
Unit 272/0, ProfileGenerator 107/0. The single unchanged failure is B8,
`PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`: a signed current
DID2 one-time invitation producer is still missing. It is not skipped or replaced
with reusable genesis, and this full-suite failure remains a release blocker.

Sanitized TRX SHA-256 (raw artifacts remain ignored):

- Focused: `dbed44af2d4759356214dcf110dad8881b639c633311234cc910cb8e276ef2ff`;
- Integration: `3bcdd3b2849ab2f71ec29d8a5f82485994125ba2c2cb8e93fffe064b938be68b`;
- Unit: `ab9f515325c2c2ca061f97718c57570a618071522baa1569cf6db1e7aa2d9a73`;
- ProfileGenerator: `87deb6b56b62a479055c089137e88087fb9137f22cb2e67cc3048d8edd18c6ce`.

Managed-external Docker smoke passed with real Xray, no mock and no failed
required runtime check. Three-node rehearsal passed with three real Xray
processes and no reconciliation issue. These lanes built the final production
source; the subsequent correction changed only the test fixture. They do not
activate current mailbox composition; contact without matching authority stays
fail-closed. Temporary smoke/rehearsal resources are removed; all six existing
dev-contour containers remain running and were not altered.
Public documentation gate: **174 checks pass**. Selected validation:
**13 strict UTF-8 files, 71 existing local links, zero secret-scan findings**;
`git diff --check` clean. No frozen normative bytes or Protocol package
generation changed in this batch.

## Remaining boundaries — not qualified by these tests

- A single coordinator still allocates cursors. Two selected exits can allocate
  the same value. Rejecting duplicate cursor custody is safe denial, not a global
  ordering implementation; concurrent coordinators and late Store completion
  below an already captured high-water mark remain activation blockers.
- Current client ACK authoring, durable quorum/replay and guarded startup/recovery
  need integration. Existing peer tombstone tests are not client ACK completion.
- Retained-route/old-epoch read/ACK, normative object horizon and sustained grant/
  journal renewal/retirement remain open; current reads are current-scope only.
- Program/DI still does not register these owners. Native rotated distinct ID/key
  evidence, issuer/package/installed matrix and shipping composition remain open.
- No ONION message delivery, authenticated Delivered/Read, remote files/groups
  or physical Windows/Android transfer was qualified. No production deployment,
  secret access, account reset or existing dev-contour mutation occurred.
