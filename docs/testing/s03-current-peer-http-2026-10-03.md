# S03 — current peer HTTP and two-store coordinator

Date: 2026-10-03. Source baseline XNode `4cf9056`, Protocol `de1c220`, root
`a284117`. Owners: [S02/S03](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md),
[DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md),
[DR-0085](../../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).
This is integration evidence, not stage completion or release activation.

## Connected path

The recipient receiver and sender coordinator use the same bounded current
native admission owner. Exact grant/projection, selected replicas, descriptor
keys, operation/body and sender signature precede replay reservation. Real blob
mutation and replay completion recheck protected time, current source and both
native MGR1 floors. The remote callback cannot manufacture quorum after expiry
or source loss. Quorum verification requires the selected pair's signatures;
a local duplicate or forged response leaves real local custody and Pending.

The peer client consumes only the transport minted from the actual admitted
NETCODEC node, with exact TLS IP/port/SPKI and HTTP2. There is no P04 decode,
configured URL, proxy, redirect, plaintext, alternate-pin or authority fallback.
Ingress bounds/media, HTTPS listener, operation and resource budget checks
precede allocation/mutation; public errors have empty bodies.

Tests start real Kestrel TLS/HTTP2 listeners, author the signed test network
with those exact origins and use two independent native roots/keyrings. Real
receiver receipts cross HTTP; injected loss happens after target persistence.
The test-owned signed source/clock remain fixtures, not operator authority.
The Windows certificate fixture imports its disposable key for Schannel rather
than mistaking ephemeral-key handshake failure for a product transport failure.

The connected test exposed and fixed a sender bug: a memory/null conditional
implicitly converted null to empty `ReadOnlyMemory`, skipping peer dispatch.
Pending now explicitly has no response; no assertion or TLS check was weakened.

## Verification

From `xnode`:

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --filter 'FullyQualifiedName~CurrentMailboxPeerHttpTests|FullyQualifiedName~CurrentMailboxReplicaReceiverTests|FullyQualifiedName~CurrentMailboxAdmissionTests|FullyQualifiedName~MailboxGrantRevocation' --logger 'trx;LogFileName=current-peer-final-connected.trx' --results-directory artifacts/s03-current-peer-http/final-connected
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --logger trx --results-directory artifacts/s03-current-peer-http/full
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -m:1 -warnaserror
```

Focused result: **68 pass / 0 fail / 0 skip**, including ten HTTP cases:
direct client, two-store Store/read/ACK/reopen, eight simultaneous exact retries,
lost-response/reopen reconciliation, four hostile/callback cases, wrong signed
TLS pin, and wrong operation/media before mutation. Completed native peer replay
avoids another HTTP write; one mutation record remains per store.

| Gate | Fresh result |
| --- | --- |
| Full node solution | 963 pass / 1 fail / 0 skip, total 964; Integration 584/1, Unit 272/0, ProfileGenerator 107/0 |
| Release build, source cutover | 0 warnings / 0 errors; actual external Protocol references also use Release |
| Full Protocol solution | 2067 pass / 1 fail / 12 skips; existing actual package gate rejects retired MCG2 |
| Protocol production source graph | FAIL on retained MAU2 in the old authority codec; not waived |
| Strict registry / evidence ownership | PASS; current source binding, exact314/package219/final95 mapping; integrity-only manifest check, not executable qualification |
| Docker managed-external smoke | PASS with actual Xray, not mock; separate authority-readiness lane |
| Docker three-node rehearsal | PASS, three actual Xray processes / three Registry nodes / no reconciliation issue; private contact stays fail-closed 503 without matching authority |

The remaining node failure is B8's missing current signed one-time publication
producer, unchanged by this batch. Neither failure nor the native/operator skips
was removed to make the suites green. Temporary smoke/rehearsal containers and
volumes were cleaned up; all six pre-existing dev-contour containers were kept.

Sanitized local artifact SHA-256 (raw artifacts remain ignored):

- focused: `956bd3c0cc92669045d9205ed8f6b383137ffaa9aab1d094837272db83d098a0`;
- full Integration: `d3c655682b013b1a372179f7ffb0f82910e6fea37e1f85aa6787126da752ff60`;
- full Unit: `2025a31f1c622da1d0324377de1077ff2a757e96880faabe3c269ec2f613051c`;
- full ProfileGenerator: `6ab3d845046420ba16a7abf2376e682eb542d5b9e4cdd3868d8f861e6bb40c7e`;
- smoke runtime gate: `be2547ff5fcce3f39907e76c85cff2716e41712bb31c48ccfeb3ebe3b31d9c0d`.

## Remaining integration and evidence boundaries

`Program` has not switched from the retired composition; no activation flag or
dual-path bridge was introduced. The actual MAU3 client Store/Retrieve/ACK
adapter, peer request producer, outer durable canonical client outcome and
startup/protected-floor renewal composition still need connection. Cached remote
MRR2 survives reopening; final MQR3 is reconstructed, not a newly added durable
quorum journal. Exact MQR3 equality tests use a frozen test clock and do not prove
byte-identical final outcomes across advancing time or completed Store after ACK.

The XNode network fixture is genesis and does not prove rotated distinct node
ID/descriptor key behavior. Protocol's selected-fact test uses distinct ID/key;
the native positive rotation gate stays open. Loopback HTTP read-back is not
ONION routing, real-client Retrieve, application Delivered/Read, installed
packages, remote files/groups or physical Windows/Android E2E. No production,
operator secrets or existing dev contour was changed. S00/S01 and B1–B8 stay
tracked in [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
