# S00 connected private contact authority hops — 2026-10-04

Local source candidate under DR-0082; not installed/device/release qualification.
The root RC commit pins the exact Node source. Base Node is
`66f3f426e51ba86bd7881fd42b39fcc3ffa1e54e`; Protocol remains
`de091f1c87088636f5548fc21e219d28ef0732e6`, Shared remains
`59eba8b7ddfd9090a99df51021c72e02b5da394c`, Registry remains
`1f20f973a57378b78b536a84711a85a39a6341e6`. DevOps also has the narrowly reviewed
scanner correction described below; other child source is unchanged.

## Connected correction

Remove the remaining private HTTP clients' node-ID/signing-key equality guards.
The mailbox grant request now carries a required closed verified ResolveInvite
placement internally, never on the wire. Require its exact XMG locator/network
and selected local ID before signing. Resolve the actual descriptor signing key
and compare it with the configured seed's public key; reject wrong custody,
public-key-as-ID and ID-as-signing-seed before HTTP. Keep the JSON node ID and
private admission transcript unchanged. Own the parsed XMG request before awaits
and validate the result against that original request, not caller-mutated bytes.
Validate the HTTPS origin at the client's own boundary, not only in options.

The route/publication backend requires the selected gateway's independently
verified network. Check the local descriptor key before signing and recheck that
network around the response. DR-0048 headers still identify the public key and
Registry still uses its mandatory public-key allow-list; no new header, wire,
domain, public Protocol API, journal generation, reset or key replacement.

The connected test now runs publication/lost peer response/reopen/permanent
resolve/deposit and retrieve grant with distinct descriptor IDs/keys through the
actual private HTTP client. One lane also uses actual pinned TLS/H2 peer stores.
The private issuer/journal is an in-process fixture, not deployed Registry or
PostgreSQL evidence. Separate route and publication gateway tests include both
genesis/successor and distinct IDs. Canonical handler-only body fixtures remain
transport fixtures, never publisher/witness authority.

## Commands and terminal evidence

```powershell
# Isolated outputs avoid modifying assemblies used by existing full runs.
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -p:DeepProtocolSourceCutover=true --artifacts-path C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-build --filter "FullyQualifiedName~Did2ContactServiceCompositionTests|FullyQualifiedName~ContactCoordinationBackendClientTests|FullyQualifiedName~ContactCoordinationOnionDispatcherTests" --logger trx --results-directory artifacts/s00-private-grant/final-focused
# Final reviewed source was built by the default full command below.
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj --no-build --no-restore -p:DeepProtocolSourceCutover=true --filter "FullyQualifiedName~Did2ContactServiceCompositionTests|FullyQualifiedName~ContactCoordinationBackendClientTests|FullyQualifiedName~ContactCoordinationOnionDispatcherTests" --logger trx --results-directory artifacts/s00-private-grant/final-current
dotnet build src/XNode/XNode.csproj -c Release -p:DeepProtocolSourceCutover=true --artifacts-path C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-release --no-restore -warnaserror
dotnet test XNode.slnx -p:DeepProtocolSourceCutover=true --no-restore --logger trx --results-directory artifacts/s00-private-grant/full-current
dotnet restore XNode.slnx -p:DeepProtocolSourceCutover=true --artifacts-path C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified --packages C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified/packages
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:RestorePackagesPath=C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified/packages --artifacts-path C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified --no-restore -m:1 -warnaserror
dotnet restore tests/XNode.ProfileGenerator.Tests/XNode.ProfileGenerator.Tests.csproj --locked-mode --artifacts-path C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified --packages C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified/packages
dotnet test tests/XNode.ProfileGenerator.Tests/XNode.ProfileGenerator.Tests.csproj -c Release --no-build --no-restore -p:RestorePackagesPath=C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified/packages --artifacts-path C:/Work/DeepSession/XPointLabs/xnode/artifacts/s00-private-grant-verified --logger trx --results-directory artifacts/s00-private-grant/approved-profile
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory C:/Work/DeepSession/XPointLabs/deep-devops/artifacts/s00-private-grant-smoke-20261004
```

Final focused **61/61**, terminal0, no skips. Actual host Release build,
warnings-as-errors, terminal0 with zero warnings/errors. Full Node **1187/1187**
completed terminal0 without failures/skips: profile107, unit272, integration808.
Integration took26m13s. The previous
[contact matrix](s00-contact-descriptor-2026-10-04.md) completed Node1173 and
Shared547; its full result is not transferred to this new Node source.

Fresh isolated full-solution restore/build stopped with NU1403 for the existing
ProfileGenerator and its tests: Deep.Protocol `0.5.0-survival.9a7eaed` actual
global-cache package content hash disagrees with the checked-in lock. Read-only
SHA-512 comparison confirmed that the tracked vendor archive matches the lock
and the global cached archive does not. Source-cutover does not replace that
ProfileGenerator package edge. No locks/vendor packages/global cache were
rewritten or cleared, and hash validation was not disabled. A fresh full restore
into a task-owned isolated package cache completed terminal0 against the same
approved vendor/lock inputs. Full warnings-as-errors build on those assets is
terminal0 with zero warnings/errors. Explicit ProfileGenerator locked restore
also completed terminal0 and the approved-package Release tests pass107/107,
terminal0/no skips; SHA-512 matches all three tracked Protocol package locks.
The full test command above explicitly uses previously restored assets;
its ProfileGenerator results are not approved-package qualification. The
separate isolated ProfileGenerator result is the approved-package evidence.
B6 remains
open for current shipping package/API/resource closure, alongside the Protocol
MCG2 package witness and MAU2 source gate.

Real-Xray smoke terminal0: non-mocked running transport, no hard/soft failures or
warnings. Its temporary resources were cleaned; existing deep-dev was retained.
Three-node rehearsal initially hit a port conflict with the concurrent smoke;
owned resources were cleaned. A new rehearsal with four checked free host ports
completed terminal0: three healthy real-Xray routers and zero reconciliation
issues. Current contact503 remains missing verified authority, not successful
contact delivery. Both scripts cleaned only their owned temporary resources;
the six existing deep-dev containers remain. Neither Docker lane enables that
missing authority or closes physical E2E.

Sanitized ignored receipt hashes:

- Final focused61 `artifacts/s00-private-grant/final-current/nikit_SURFACE-LT_2026-10-04_13_17_44_net10.0.trx`:
  `3785bd4ac31d0b1abf0d8a84eb87886e862d6450852863cc9f0a9317444edff6`.
- Smoke `deep-devops/artifacts/s00-private-grant-smoke-20261004/runtime.gate.json`:
  `b006f2f689ad60637e12da59d97ea2c7d221c849b254a667e6a7ba4d073bd4c0`.
- Three-node `deep-devops/artifacts/rehearsals/multi-node/20261004T081857088Z-de598f68016e/test-results/multi-node-topology.json`:
  `d4e982d420f671031fc413cdb2567d0d0947af9661837b3798e18995b3310f44`.
- Approved-package profile107 `artifacts/s00-private-grant/approved-profile/nikit_SURFACE-LT_2026-10-04_13_24_25_net10.0.trx`:
  `e5559fb03799a29d618557bf66df79708aa83ee207e70499ae975becd926ed77`.
- Default full profile107 `artifacts/s00-private-grant/full-current/nikit_SURFACE-LT_2026-10-04_13_15_42_net10.0.trx`:
  `7413b1ef5e28842566553dcef13dd1af700929e1e29f372fc8e8285fa459abdd`.
- Default full unit272 `artifacts/s00-private-grant/full-current/nikit_SURFACE-LT_2026-10-04_13_15_46_net10.0.trx`:
  `a1277357cd282eed7d1077425c76134c8f5aba71f1eb9c46adc32747b9c5972b`.
- Default full integration808 `artifacts/s00-private-grant/full-current/nikit_SURFACE-LT_2026-10-04_13_15_52_net10.0.trx`:
  `560be28b4289d1015cca5f8d6cba608e2746c3eb7bca4e1a974f051a90b226b2`.

Root documentation174 and CONTACT/crypto/ONION/governance ClassificationOnly
pass; these consistency/classification gates are not release/package evidence.

The initial scoped source scan classified the existing unquoted private-key
member reference as a literal. DevOps now preserves quote information: unquoted
compiler member references are non-literals only in source; quoted strings and
JSON/environment/evidence values still reject. Matching source/quoted/member-
shaped credential regressions and the existing archive/redaction/manifest tests
pass24/24. No path or secret rule was excluded to obtain a pass. Initial scoped
source/docs/TRX/metadata scan passed18 selected files; final scan including the
three full TRX receipts and corrected dev harness passes22. Five edited docs pass
strict UTF-8 and100 local links. Private operator inputs and global diagnostics
are not part of these checks.

DevOps full release-gate contract validation completed51/51, terminal0. Its
generated positive/negative fixtures qualify the harness only, not this release.
Full tracked/generated contract-artifact secret scan passed447 selected files.
The dev-compose harness passes16/16 after correcting three test-only issues:
quoted synthetic private-field canary is assembled through a local variable;
package-source mapping compares the exact duplicate-sensitive member set, not
XML child order; expected HTTPS production domains match the unchanged public
template. No legacy consumer, package, credential, topology or scanner exemption
was added. Actual production-readiness status exits1 with10 missing evidence
blockers; that is expected incomplete-release evidence, not a harness failure.
Contract summary SHA256: `9ad921870fd905162917747060d0b8e7a93d4ca7fc039e9c8b4114b2403cc74e`.
Actual blocked status SHA256: `9f6274ee3b9901ee25d6c355f10859798f0b5080ea0339b0b971fc482548299f`.

## Next work, not a parallel plan

Follow only root NEXT-SPRINT / IMPLEMENTATION-PLAN. B8 protected one-time
pending/winner/retained-genesis/exact AEAD restore/export remains unimplemented;
reusable journal9 grants no one-time rights. Deployed authority/provisioning,
whole-host current mailbox composition/lifecycle, shipping package matrix and
physical Windows/Android contacts/messages/files/groups remain open. No
production, device, account, secret, release or main-branch state was changed.
