# S02/S03 — current peer native persistence consumer

Date: 2026-10-03. Inputs: XNode `e54cd0b`, Protocol `de1c220`, workspace
`35ea953`. Sole contracts:
[DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md)
and [DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
This is connected source/native persistence evidence, not HTTP/DI activation,
two-store quorum, installed client or release qualification. No public Protocol
API, wire or protected record format changed.

## Actual consumer

The current peer receiver captures the bounded canonical request before external
callbacks. Both proofs bind the same actual grant and current projection. The
closed host independently verifies selected canonical nodes and descriptor
signing keys. Source signature and body-derived placement are checked before
native peer reservation; tombstone lookup occurs only after source authentication.
Local signing custody must match the verified descriptor key.

Both restored native role floors stay locked in the admission owner's fixed
order through mutation and receipt. Source, exact protected network history,
full monotonic interval and actual role revocation are rechecked after callbacks
and before persistence/result boundaries. A descriptor or roster successor with
unchanged projection/policy cannot silently replace the captured authority.
The peer codec's proof adapter answers only facts already checked inside that
live scope; it does not accept a caller time, trust boolean or retired proof.

Actual native replay, mutation and blob owners are used. Their current operations
check the same scoped authority before/after awaited I/O and durability seams.
Journal restore no longer garbage-collects using host UTC. Authority/floor I/O
failure after blob read propagates; it is not swallowed as an absent blob.
Operation expiry releases no receipt and preserves pending exact custody.
Object expiry is checked separately from the short grant horizon; this is not
closure of the normative long-retention activation fence.

## Scenarios

Ten current peer cases use actual signed DID2/PQ/network/grants, native protected
role floors, replay/mutation files and durable blobs. A throwing UTC clock proves
that this entire path uses the protected monotonic source instead.

- Store, exact blob read-back, reopen/exact Store response, tombstone,
  reopen/exact tombstone response. Historical completed Store returns its exact
  cached receipt without resurrecting data; a newly signed nonce cannot rewrite
  the retained tombstone.
- Invalid signature, different grant in second proof, substituted descriptor
  key, retired proof, outer operation mismatch and wrong placement reject before
  peer replay/mutation records or blob writes.
- Expiry at actual StoreReserved and TombstoneBlobDeleted fault seams leaves
  native peer Pending and releases no receipt. Returning the test clock to the
  still-valid original interval and reopening recovers the exact operation. This
  is deterministic boundary testing, not production renewal across expiry.
- An issuer-signed native revocation successor prevents a completed receipt from
  being released again under the revoked grant.

One new test initially expected a completed historical Store to fail after
tombstone. It was corrected to assert exact cached receipt **and no resurrection**;
fresh-nonce rejection is checked separately. No pre-existing assertion or B8
failure was removed. Genesis node IDs still equal initial signing keys; the
required genuinely rotated distinct ID/key positive case remains open.

## Gates

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --filter "FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocationStoreTests" --logger "trx;LogFileName=current-peer-final.trx" --results-directory artifacts/s03-current-peer/final
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --logger trx --results-directory artifacts/s03-current-peer/full
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -m:1 -warnaserror
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<fresh absolute child of deep-devops/artifacts>'
../deep-devops/scripts/multi-node-rehearsal.ps1
```

Focused connected **58 pass / 0 fail / 0 skips**: peer 10, admission 19, native
floor 29. Full solution **953 pass / 1 fail / 0 skips**, 954 total: integration
574/1, unit 272/0, profile 107/0. Sole unchanged B8 failure:
`ContactServiceOpaqueFacadeTests.PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`.
The signed one-time publication producer is missing; reusable genesis is not
substituted. Release build has zero warnings/errors; the explicit parent-build
property also builds the external source Protocol references in Release.

Docker smoke exit 0: actual Xray, zero failed hard/soft checks, selected artifact
secret scan zero findings. Three-node rehearsal exit 0: actual Xray on all three
nodes, three registered local nodes, zero reconciliation issues, private contact
503 without current authority. Neither run qualifies current mailbox activation.
Only temporary test containers/volumes were removed; the six existing deep-dev
containers remain. Production, devices and operator custody were not changed.

| Ignored evidence | SHA-256 |
| --- | --- |
| Connected final TRX | `5b6dcbd138a86a85742f56d82903f5f8c93ab768e60e1c64ab11e411fef2a3ff` |
| Full integration TRX | `1fbbf2d7e32df5927b8a251f35f9877475e5214f0ba3835d0fc716a36ccad702` |
| Full unit TRX | `a1eda2b1cd8cc10de5a333d7ee1634e97638bc3b6ad8ad3927d58dd6981e213f` |
| Full profile TRX | `bb0f92885d5c4398d97dc0ce5b221d0f42f1a2868e2f1f046948fc3c17559091` |
| Docker runtime gate | `ec76cb711697405afd0c4be2677eb90495fb97f19d8ac6f2c6769a6c0ee44916` |

## Integration boundary

Program still resolves the retired peer receiver and client adapter. This new
consumer must replace that graph, not become an optional fallback. Actual HTTP
peer dispatch, two separate stores/quorum, partial remote commit, lost response,
rotated descriptor custody, current client mutation/read/ACK and native protected
startup/renewal remain unclosed. No readiness or deployment flag was enabled.
All unfinished stage status remains in the sole [queue](../../../docs/NEXT-SPRINT.md).
