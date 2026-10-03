# S02/S03 — native current Store producer and exact intent custody

Date: 2026-10-04. Source baseline: XNode `df1a3d1`, Protocol `a253260`,
root `84bdbf2`. Execution owner: [S02/S03](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Contracts remain [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md)
and [DR-0085](../../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).
This is connected local evidence, not stage completion, activation or physical E2E.

## Actual connected change

The internal client Store path now needs only captured canonical MAU3 and the
native operation-ledger owner, rather than a test-supplied second peer frame.
Actual holder/body/current-source/time/selected-exit admission precedes intent
creation. Under that same native protected scope, the existing operation ledger
allocates a per-mailbox cursor, and the actual receiver signs the complete PRQ2
using its installed key matched to the selected descriptor's signing key.
The request contains a cryptographically random nonce and the exact current
grant/projection proofs. Its complete canonical bytes and cursor are durably
saved BEFORE peer replay reservation, blob mutation or HTTP dispatch.

This adds a field to the existing `operations.json`, not another journal or
public client wire field. The local ledger generation is now schema 4; schema 3,
missing fields and malformed records reject without migration or automatic
reset. No production data or registered node key was changed. Provisioning and
the local-format/API activation fence remain unfinished S01 work.
The older two-frame method is an internal current-only test seam, not a legacy
reader, client input extension or production authority adapter.

Current reservations do not invoke host UTC or collect entries using a short
grant. Capacity produces backpressure. Current source, protected time and actual
MGR custody are checked across native write/replace/flush boundaries. Writes
now use the existing native durability barrier and enforce the same document
size bound as reads. Reopen/retry reuses the saved cursor, random nonce and full
signed frame, even after time advances; it never authors a replacement request.
The existing canonical outcome store remains the sole owner of the final MQR3.

Known replay without its saved intent fails closed. A new valid holder counter
also cannot recreate an intent when the actual mutation owner retains Store
custody. That lookup is denial-only: it does not grant dispatch, receipt or
placement authority. Corrupt mutation custody is not treated as absence.
A failure before intent replacement retains client Pending without any peer
effect; retry remains unresolved rather than guessing new bytes. This proves
safe uncertainty, NOT successful recovery from every pre-intent storage failure.
After a durable intent flush followed by an exception, reopening can continue
that exact intent. A changed saved signature rejects before another peer effect.

## Connected cases

Thirteen additional cases use actual signed test-owned authority, native stores
and independent TLS/H2 peer endpoints:

- server-authored intent survives a lost response, time advance and owner reopen;
- replay after tombstone does not resurrect the blob;
- eight concurrent requests create one intent and one remote write;
- separate operations retain distinct random nonces and durable cursors across reopen;
- native replacement failure and failure after actual durable flush have different outcomes;
- lost intent, incompatible local generation and forged holder input reject;
- capacity does not collect custody or dispatch the second operation;
- source loss after actual intent flush prevents peer work until valid exact recovery;
- changed saved peer signature rejects without rewriting custody;
- a higher valid holder counter cannot remint an intent lost after a mutation.

Fixture corrections preserve runtime checks: hostile signatures are made by
mutating a valid signed frame, rather than calling a protected signer with the
wrong key or asking its encoder to accept an all-zero signature. Replay counters
are asserted per grant/highest counter, not incorrectly per operation. Tombstone
creation is not earlier than the actual server-authored Store creation time.

## Commands and evidence

From `xnode`:

```powershell
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --logger trx --results-directory artifacts/s03-server-intent/full-final
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -m:1 -warnaserror
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --filter 'FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocation' --logger 'trx;LogFileName=server-intent-final-connected.trx' --results-directory artifacts/s03-server-intent/final-connected
```

Full solution: **986 pass / 1 fail / 0 skip**, total 987: Integration 607/1,
Unit 272/0, ProfileGenerator 107/0. The remaining unchanged B8 failure requires
the signed current DID2 one-time publication producer; reusable genesis is not
that producer. Release source-cutover build: **0 warnings / 0 errors**.
Final focused current Store/admission/peer/revocation: **91/91 pass**.

Managed-external Docker smoke passed with actual Xray and the final source.
Three-node no-mock rehearsal passed with three real Xray processes and no
reconciliation issue. Its first attempt failed on a host-port collision with
the concurrently running smoke; after cleanup, a fresh rehearsal used distinct
loopback ports and passed. Neither lane activates current mailbox composition;
private contact remains correctly fail-closed 503 without matching authority.
Temporary smoke/rehearsal containers and volumes were removed; all six existing
dev-contour containers remain running and were not altered. Public documentation
gate: **174 checks pass**. Selected validation: **8 strict UTF-8 files, 68 existing
local links, zero secret-scan findings**; `git diff --check` clean. No frozen
normative bytes or Protocol dependency generation changed in this batch.

Sanitized TRX SHA-256 (raw artifacts remain ignored):

- Focused: `c07c4254c9ff204fde315241539e54aadcaa542da08ea0df629f7bce7724e41e`;
- Integration: `92fd95ac43f7b61f7040e62d1525ebb2f9c086aae1cfc7004cefe1c1a69f26e3`;
- Unit: `d458c26e31662423ee19070ea1c7073db49e47be0def439f3e4103c8b77cf727`;
- ProfileGenerator: `5d9818def90c11845f8ea471bd778aa673874a3384aa24f8b0b4e687251bf09f`.

## Remaining connected boundaries

The cursor above is owned by ONE coordinator's durable ledger. Two selected
exits can independently allocate the same cursor; this is not a globally ordered
mailbox. Cross-coordinator cursor ownership/order must be closed before activation,
without changing the client's sealed route selection or treating a nonce/hash as
an ordered cursor. Retrieve/ACK must use actual mutation/blob custody on either
replica, not just the coordinator's local client ledger. Guarded startup/recovery,
retention/renewal, native rotated distinct ID/key evidence and the atomic
current-only Program/DI cutover remain open.

No installed package/client matrix, ONION message delivery, Delivered/Read,
remote files/groups or physical Windows/Android transfer was qualified. No
production deployment, secret access or existing dev-contour mutation occurred.
The single remaining queue is [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
