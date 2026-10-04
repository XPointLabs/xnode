# S02 current Program/native composition — 2026-10-04

Integration of the existing current owners under the auditor's
[S02/S03 execution plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md),
not new wire, authority, production activation or installed/device evidence.
Input Node `d07f930720e049233698548a634b05c46a04b942`, Protocol
`8989ad6a787cdc8194106a5130fcfa832608e252`, Shared
`f60e03406790564b037fdeab3e89faca41dfb46b`. Final pins belong to the root commit.

## Actual registration and call path

Program replaces the retired PMA1 provider/forwarding/adapter graph with one
current receiver, coordinator, operation ledger and admission owner. Both MGR1
roles are separate keyed singletons, using the existing independent protected
custody; ONION terminal and peer ingress use the same receiver. Neutral durable
stores retain their bounds. Their current path throws on host-UTC access rather
than accidentally enabling retired expiry/GC. Old class declarations and their
unconnected unit corpora still exist; this is not complete package/source removal.

The sole local configuration is
[CurrentMailboxCustody](../operator.md#current-mailbox-host-composition-candidate).
Disabled bindings must be empty; enabled public scope is canonical/nonzero and
data/custody/keys are absolute disjoint non-root paths. Reader key generation and
enrollment are forbidden. Duplicate native graph registrations reject before
resolution. Empty retired JSON objects also reject, not only enabled settings.
Explicit signed test-owned provisioning is not a reader or production bypass.
The existing Development/UAT network-source restriction remains unchanged.

Readiness checks actual current host/role/operation custody. It does not recover
every historical blob, replay or retained route. Object horizon, retirement,
renewal, global recovery and supported operator provisioning remain activation
requirements; the new DI does not close them.

## Focused terminal evidence

Final source-cutover integration build uses warnings as errors and compiles every
integration test, no compile whitelist. It writes to a separate output directory
to avoid replacing binaries of the already running initial full suite.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release --no-restore -p:DeepProtocolSourceCutover=true -p:OutputPath=C:/Work/DeepSession/XPointLabs/xnode/artifacts/s02-current-program/focused-bin/ -warnaserror --filter 'FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxHostRecoveryReadinessTests|FullyQualifiedName~ActualRegisteredOwnersCompleteNative' --logger trx --results-directory artifacts/s02-current-program/final-focused
```

Terminal exit0: **23 passed /0 failed /0 skipped**,17s, zero warnings/errors.
Coverage includes real factory ownership, signed role/operation enrollment and
cold recovery, missing ring without key generation, scope/path/TLS/config guards,
split graph before callbacks and actual Program negative HTTP health/routes.
The new positive case uses two separately registered native stores and actual
descriptor-pinned TLS/H2 peer HTTP: native Store -> both Retrieve -> quorum ACK
-> cold reopen -> exact Store/ACK replay -> fresh empty Retrieve on both replicas.
Neither replay adds HTTP writes or resurrects the object. IDs differ from keys.
The HTTP server is the existing test endpoint harness, not full deployed Program
middleware or ONION/carrier/device qualification.

Initial actual-Program HTTP selection failed3/3 because deleting the retired DI
block also removed an independent membership-artifact publisher. Restoring its
registration fixes endpoint construction; final actual HTTP tests check its
missing-artifact503 and current sanitized health, not a source-string assertion.
Two obsolete Program/default assertions for PMA1 wiring are replaced by these
actual current HTTP/configuration cases; crypto/quorum/deadlines are unchanged.

Final receipt:
`artifacts/s02-current-program/final-focused/nikit_SURFACE-LT_2026-10-04_19_04_40_net10.0.trx`;
SHA-256 `2fff44bc8ff6572b79d2ac2eef7574e99c77320001c235091622b34f9f55e963`.

## Broader gates remain in progress

The initial full source-cutover solution run completes exit1: **1220 passed /
3 failed /0 skipped** (integration841/3, unit272/0, profile107/0),25m53s for
integration. Two failures are obsolete PMA1 Program/default assertions; the third
is the recurring ACK-test setup Store timeout before its revocation assertions.
That timeout is not classified or fixed. This run predates the final empty-object
guard, HTTP assertions and positive registered-owner case; it cannot qualify the
final source matrix. A green isolated case never erases the full-run failure.
The fresh unfiltered final-source full run is now running with `-m:1` to avoid
parallel project suites sharing the same host resources. No product deadline,
assertion or in-test concurrency case is changed. Resource contention is a
hypothesis, not a confirmed diagnosis; terminal results remain required.

```powershell
dotnet test XNode.slnx -c Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --logger trx --results-directory artifacts/s02-current-program/final-full
```

The solution maps external Protocol references to Debug; Node projects are
Release. These source-cutover results are not a uniformly Release package matrix.

| Initial full receipt under `artifacts/s02-current-program/full/` | SHA-256 |
| --- | --- |
| Profile107 `nikit_SURFACE-LT_2026-10-04_18_51_59_net10.0.trx` | `6b3c7e5ddf1661e7df222a593bd8e12a4579b67792ef74636ee372383036ab8e` |
| Unit272 `nikit_SURFACE-LT_2026-10-04_18_52_14_net10.0.trx` | `6392847bb990f4eb0aad942242b4d4e7b47917d288bbeb10d204da8ccc1b96c9` |
| Integration841/3 `nikit_SURFACE-LT_2026-10-04_18_52_20_net10.0.trx` | `941044a9842f20ae09f7866679b7b264554fa17e278628035483c23db49e9722` |
Real-Xray smoke and the required three-node rehearsal finish exit0 with no mocked
router. They exercise the disabled-mailbox development transport boundary, not
current mailbox/contact delivery: contact remains503 without verified authority.
Smoke XNode is source-cutover; Registry retains its existing local-cutover
package graph. Both scripts clean their disposable resources; the six existing
deep-dev containers remain running. Release packages/installed matrix are separate.

The pre-existing unconfigured Reality private-value placeholder is now empty;
actual protected secret-file inputs are unchanged. The initial scoped scan rejected
that default as a sensitive assignment. Actual Program HTTP tests rerun after
this default cleanup:4/4, terminal0, no skips. Docker runs started before this
placeholder-only cleanup; they are not exact final shipping-image evidence.

| Additional local receipt | SHA-256 |
| --- | --- |
| Default HTTP4 `artifacts/s02-current-program/final-default-http/nikit_SURFACE-LT_2026-10-04_19_11_27_net10.0.trx` | `3f879fc232bb2e2342f981a43c1edac732678200f5a4c50758156c1a3a1e7de4` |
| DevOps `artifacts/s02-current-program/transport-smoke/runtime.gate.json` | `4e3f4227eb7ed476eb99aec94f044017cdca2929ea5e337ec8d266c43fa2fec6` |
| DevOps `artifacts/s02-current-program/transport-smoke/runtime.snapshot.json` | `620e87a1a3abfb16b0696058c395f9dc0936c0fdea684fc5d75359c75b637417` |
| DevOps `artifacts/rehearsals/multi-node/20261004T140848604Z-6b4590ef9e6b/test-results/multi-node-topology.json` | `8b7a2901ed9e984748fcd5ec2d8f130d1e5937667e6ebfb380f03aad9fb95c3f` |

No production host, device, account or operator secrets are changed. Public
documentation gate passes174 checks. The scoped precommit source/docs/receipt
scan passes after default cleanup, including the final full Shared receipt;
no scanner rule is weakened. Broader terminal evidence remains required.
Physical contacts/messages/attachments/groups qualification remains0/4.
