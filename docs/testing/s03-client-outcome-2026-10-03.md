# S02/S03 — current client Store and durable quorum outcome

Date: 2026-10-03. Baseline: XNode `43daf6a`, Protocol `a253260`, root
`b8641dd`. Execution owner: [S02/S03](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Contracts remain [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md)
and [DR-0085](../../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).
This is local connected evidence, not activation, stage completion or device E2E.

## Actual connected change

Internal `StoreClientAsync` captures canonical MAU3 and the internal producer's
exact peer request before callbacks. Operation, payload, local sender and exact
grant/proof equality are checked before either durable replay owner is touched.
The actual current client admission verifies holder, selected pair, current
source/time and both native role floors. Peer verification then uses that SAME
bounded owner/scope, avoiding re-entry into its non-reentrant native floor locks.
A scope from another admission object rejects even with identical node/floor facts.
The independent peer ingress retains cheap operation/local-role/proof rejection
before contacting its authority source.

Execution and outcome capacity are reserved before the native Store/real peer
HTTP operation. Two descriptor-key receipts are required. Final canonical MQR3
is persisted in the existing client outcome store, then the existing capability
replay journal is completed. No new journal, wire, public API or legacy bridge
was added. On exact replay the persisted quorum is independently verified under
the current peer scope; the Store mutation/HTTP write is not repeated.

The tests use the previous real Kestrel TLS/H2 hosts and two independent native
stores/keyrings, with actual signed test-owned network, grants and time source.
They reopen client outcome/capability journals as well as peer/blob owners.
No test-owned source is production authority; no host UTC is used by this path.

New connected cases cover:

- byte-identical final outcome after time advances and both owners reopen;
- Store replay after completed tombstone without blob resurrection;
- lost response after actual remote persistence: both sender replays remain
  Pending, exact retry reconciles with one mutation per replica;
- wrong body/grant/holder, borrowed admission scope, callback expiry/source loss;
- eight concurrent client retries: one final outcome and one remote write;
- actual completion-write failure AFTER the outcome is durable, followed by
  native reopen and exact recovery without another HTTP call.

The crash fixture rejects every native capability-journal atomic-replace attempt.
Windows has four bounded attempts, other hosts one; the assertion matches this
existing storage behavior. All fail, leaving one real durable outcome and Pending
capability replay. Recovery repairs completion from that outcome's exact digest.
No persistence assertion, authority check or failure gate was removed.

## Commands and evidence

From `xnode`:

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --no-restore --filter 'FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocation' --logger 'trx;LogFileName=client-current-peer-final.trx' --results-directory artifacts/s03-client-current-peer/final
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --logger trx --results-directory artifacts/s03-client-current-peer/full
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -m:1 -warnaserror
```

Full solution: **973 pass / 1 fail / 0 skip**, total 974: Integration 594/1,
Unit 272/0, ProfileGenerator 107/0. The unchanged B8 failure requires the missing
signed current DID2 one-time publication producer. Release source-cutover build:
**0 warnings / 0 errors**. Public documentation gate: **174 checks pass**.
Final focused Store/admission/peer/revocation run passed **78/78**, including all
ten newly connected client cases and the restored early peer-ingress check.
Docker managed-external smoke passed with actual Xray, as did the three-node
rehearsal (three real Xray processes, no reconciliation issue). These are
separate transport/readiness lanes, not activation of the current mailbox graph;
private contact correctly remains fail-closed 503 without matching authority.
Temporary smoke/rehearsal containers and volumes were removed; all six existing
dev-contour containers remain running and were not altered.
Selected source/docs validation: 10 strict UTF-8 files, 66 existing local links,
zero secret-scan findings; `git diff --check` clean. No frozen normative bytes or
Protocol dependency generation changed in this batch.

Sanitized full TRX SHA-256 (raw artifacts remain ignored):

- Focused: `f733e4d1a414aa1b8954e7bfce0abcb89f81d7b9f43b9bc5c16a3e96b944bf01`;
- Integration: `591c476ace992fc393f815809e8bf6a0a6fdff498dbc9e64ad6f36fba7076402`;
- Unit: `070a3228189364bd392b2b6998f561dab69b9b321c859fb8b1d3ae2247442e0e`;
- ProfileGenerator: `3268f24f827e9ce00c2b19dc2af9de98096198f4256112f872f3c3e240662fe3`.

## Remaining connected boundaries

The actual internal peer-request producer/cursor and exact nonce custody are
not yet composed. The two-frame Store method is internal, not a new client wire
or permission to accept caller-authored replication facts. Current native
Retrieve/ACK and guarded startup/recovery/GC still need integration. Program
remains on its unactivated retired graph; do not turn it on as a fallback.
Default readiness must fail closed without matching independent MGR custody.
Native rotated distinct node ID/key evidence is still open.

No installed package/client matrix, ONION client transport, Delivered/Read,
remote files/groups or physical Windows/Android transfer was qualified. No
production deployment, operator-secret access or existing dev-contour mutation
was performed. The single remaining queue is [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
