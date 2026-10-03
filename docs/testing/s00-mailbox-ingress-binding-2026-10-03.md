# S00 — native mailbox ingress operation binding

Date: 2026-10-03. Baseline XNode `8db6ddd55dcef55476eca8bcabae35c4512ce638`;
Protocol source `de1c2205cec0521bc3052c84dbada22d0a0f12e0` is unchanged.

The real native dispatcher compared the outer ONION operation to the decoded
MAU3 operation only after `MailboxAuthenticatedCapabilityRuntime.Verify`.
That call can resolve authority and reserve durable replay. Finally-aborting a
new reservation does not undo the durable accepted-time floor. A dependency
callback could also change the caller-owned request buffer before verification.

The dispatcher now captures the bounded request once before dependency callbacks,
then strictly decodes it within the existing ingress rate/concurrency budget and
requires the matching operation before issuer resolution or replay reserve.
Runtime verification uses those captured bytes. The existing
post-verification operation check remains defense in depth. Canonical errors use
the existing empty-body 400 contract; no wire/API/time/crypto/quorum changes,
compatibility parser, bypass or production activation are introduced.

## Regression and scope

The initial ten-case regression was 6 pass / 4 fail: three cross-operation
requests reached issuer resolution (403 instead of early 400); a caller-buffer
mutation changed the parsed request (400 instead of the pinned issuer rejection).
Some other cross-operation pairs already reject on endpoint length bounds.

Final ingress selection is 17/17: all six cross-operation pairs, three matching
operation issuer-rejection controls, one dependency-buffer mutation, and six
explicitly pinned signed controls. In the latter cases, rejection leaves both
native replay scope count and accepted-time floor zero. The exact same request
and counter then pass real Ed25519 verification and obtain `NewReserved` in the
native replay owner for their correct inner operation. A separate rate test proves
malformed requests still exhaust the existing budget and then receive 429.
No new counter or grant
is minted. Fixture readiness and revocation policy are deliberately isolated
ordering inputs, not current PMA2/MGR1 or production-readiness evidence.

Connected selection (ingress, activated adapter restart/crash/cancel, activation
guards and authority forwarding): 39 pass / 0 fail / 0 skips. Those old adapter
fixtures do not qualify current node/peer admission or physical delivery.
Release source build: 0 warnings / 0 errors. Final full solution: 924 pass /
1 fail / 0 skips (925 total), exit 1: Integration 545/1, ProfileGenerator 107/0,
Unit 272/0. The sole failure remains the signed one-time publication prerequisite
B8; no assertions or failing scenario were removed.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --no-restore --filter 'FullyQualifiedName~NativeMailboxIngressBindingTests|FullyQualifiedName~MailboxClientActivatedEndToEndTests|FullyQualifiedName~MailboxClientActivationGuardTests|FullyQualifiedName~MailboxAuthorityForwardingTests' --logger trx --results-directory artifacts/s00-native-ingress-binding/connected
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore -m:1 -warnaserror
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-build --no-restore -m:1 --logger trx --results-directory artifacts/s00-native-ingress-binding/final
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
../deep-devops/scripts/multi-node-rehearsal.ps1
```

Final external smoke exits 0, real Xray, hard/soft failures 0/0 and selected artifact
secret scan 0 findings. Multi-node rehearsal exits 0: three non-mocked Xray
processes, no Registry reconciliation issues; all private contact checks remain
503 without verified authority. XNode uses current source, but Registry uses its
existing local-cutover package; neither Docker lane qualifies a matching current
mailbox matrix. Three existing external Node Dockerfile ARG warnings remain.
The temporary rehearsal containers/volumes were removed; all six existing
deep-dev containers remain. Production, devices and operator secrets were not
touched. B1–B8 and S01–S13 remain open in [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
One final multi-node attempt failed before startup on an MCR metadata HEAD EOF;
its failed evidence is retained locally. A single unchanged-script retry passes,
without weakening validation or substituting mock transport.

## Ignored local evidence

| Evidence | SHA-256 |
| --- | --- |
| Before regression TRX | `889e62e34b021e6c29c3fe953975fa6403003ef4e6985a13b5b248095ea180cc` |
| Final connected TRX | `abc66abf61d00897deed1f58b98dcb99e7b956e53fd71cc0a229f3ab12008cf3` |
| Final full Integration TRX | `3ed6bcb4c84670815fe2ac37d5f749864f449193c6264284c6112cd5f7296042` |
| Final full ProfileGenerator TRX | `ca3989d217f2dee2437ce5b236085d9e143bbebd6eda5a02cd6312cb93c52e2a` |
| Final full Unit TRX | `492c924ddd3c123fac89fdd6db8c27547d3e530dac2767966c505c4b081e321a` |
| Final external runtime gate | `cdfb215e29719c862fe49138dbeb76ff2a9e85ef805cde23f79f9968ce8feffd` |
| Final multi-node topology | `c26fbd77a7b85a3c7df3b74ab97236a49f3dbc0a2ea0c0eb3c7225565a086675` |

Final ignored evidence roots: `xnode/artifacts/s00-native-ingress-binding/verified`,
`xnode/artifacts/s00-native-ingress-binding/connected-final`,
`deep-devops/artifacts/s00-ingress-final-20261003-2110`, and
`deep-devops/artifacts/rehearsals/multi-node/20261003T161341086Z-3a84809038bb`.
