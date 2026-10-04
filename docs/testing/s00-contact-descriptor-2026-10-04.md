# S00: connected Contact descriptor-key composition

Date: 2026-10-04. Local source-cutover evidence, not release/device qualification.
Owner: Mr. X. The governing implementation order remains
[DR-0082](../../../docs/survival-program/decisions/DR-0082-integration-first-delivery-baseline.md)
and [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Current status belongs only in [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).

## Connected correction

The previous [commit checkpoint](s00-one-time-commit-2026-10-04.md)
qualified distinct descriptor keys using synthesized receipts, while the actual
contact producer still equated the replica ID with its Ed25519 public key.
This batch fixes the connected path, rather than adding another protocol slice:

- Local receipt custody has an explicit node ID and an independent private seed.
  The derived public key must match the current signed descriptor before local
  dispatch/replica mutation. The path-only test constructor also checks custody.
- The facade and mailbox-route evidence resolve receipt keys exclusively from
  the complete NETCODEC network context. Stable selected IDs and exact transcripts
  are retained, with current-network checks around async receipt callbacks.
- Contact HTTP request/response authentication uses descriptor keys, retaining
  the exact CRA1/CRA2 transcripts, IDs, replay bounds, correlation and HTTP/2/TLS.
  The endpoint mints its own current placement, compares the received projection,
  checks the selected sender and local key, and remints/comparisons after receiver
  completion before signing a bound response. A received projection cannot grant
  key authority. Composition registers the required placement source.
- The connected positive exposed the same ID-as-key error in the client's
  permanent-contact read verifier. It now resolves both keys from the verified
  placement, preserving canonical two-selected-node membership checks.

No public API, wire grammar, crypto suite, signature domain, persistence format,
production configuration or operator key was changed. Equal ID/key descriptors
are not rejected as a special legacy mode; both equal and distinct inputs obey
the same signed-descriptor verification path, without an ID-derived-key fallback.

## Business scenario and bounds

The current permanent-contact scenario runs the production dispatchers, two
independent stores, signed DID2/PQ/network/XPA inputs, actual local/remote receipt
producers and the client commit/read verifiers. It loses a response after durable
remote execution, reopens both service owners and exact-replays the publication,
resolves/decrypts the contact, and verifies deposit/retrieve route evidence against
the independent descriptor keys. The private grant issuer in this scenario is
still an in-process authenticated fixture, not a deployed Registry/database claim.
Its separate private HTTP lane retains equal IDs/keys: the private authority-hop
ID/key alias is explicitly outside this batch and remains open.

One permanent-contact lane uses two real ephemeral Kestrel TLS/H2 sockets,
Schannel, actual product SPKI/name verification and the actual product binary
HTTP client/endpoint. Only test connection selection is explicitly bound to the
owned loopback listeners because the production configured-peer address guard
correctly excludes loopback. No product address guard or TLS validation is
relaxed. This does not qualify signed descriptor endpoint provisioning, shared
production ingress, onion routing or physical devices. The wrong-SPKI lane
reaches neither peer endpoint nor returns quorum receipts.

One-time publication/claim is separately tested through the actual two-store
facade with distinct IDs/keys: typed commit verification, first claim, exact replay
and competing AlreadyClaimed. It is not yet account-owned invite custody/export.
Hostile coverage includes wrong descriptor seed, ID-as-seed receipts, foreign
selected-node signatures, public-key substitution into an ID field, modified
body/correlation/time/headers and request/response domain confusion. Receipt rows
remain canonical in negative key-selection tests so the cryptographic rejection
is actually reached.

## Fresh gates

Commands run from the named repository:

```powershell
# xnode
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -p:DeepProtocolSourceCutover=true --filter "FullyQualifiedName~TwoSelectedStoresPublishResolveAndResumeExactAfterLostPeerResponse|FullyQualifiedName~InvalidSignatureSizeFailsClosedWithoutReceiptEmission" --logger "trx;LogFileName=final-review.trx" --results-directory artifacts/s00-contact-descriptor/final-reviewed
dotnet test XNode.slnx -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00-contact-descriptor/full
# deep-protocol
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build --logger trx --results-directory artifacts/s00-contact-descriptor/full
# deep-client-shared (the production gate, not the retired solution)
dotnet test Deep.Client.Shared.Production.slnx --configuration Release -m:1 --logger trx --results-directory artifacts/s00-contact-descriptor/full-production
# deep-devops
./scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory C:/Work/DeepSession/XPointLabs/deep-devops/artifacts/s00-contact-descriptor-smoke-20261004
./scripts/multi-node-rehearsal.ps1
```

Final reviewed connected/key-selection assertions: **7/7**, no skips, terminal0.
The earlier broader connected run was **116/116**, terminal0, before the last
test-only permanent-read negative assertions; it is not labelled final-source
qualification. The full Node and Shared production gates are still running at
this checkpoint; no terminal result is inferred from partial pass output.

Fresh Protocol full: **2079 pass / 1 fail / 12 skips**, terminal1, split into
Protocol1843/1/12, MembershipRoutes131 and ProfileCarrier105. The sole actual
package witness still finds retired MCG2 in the assembly. The separate production
source gate still rejects MAU2. Neither gate/assertion was weakened. The fresh
default Protocol build has zero warnings/errors.

Diagnostic attempts are not qualification: initial fixtures supplied untrusted
placement projections where descriptor authority is now required; positive
lost-response/read cases were rebuilt from actual signed placements. An initial
loopback attempt was correctly rejected by the configured-peer address guard.
A negative receipt-ID substitution first broke canonical row ordering; sorting
the hostile rows restored the intended key/membership branch. A briefly overlapping
test build produced file-copy retries, not a source compile defect; the final
reviewed build/test is terminal0. A mistakenly selected retired Shared solution
does not compile and was not repaired or counted: only the production solution
can qualify the current client. An incorrect ownership-fragment selector was
replaced with the tracked approved mapping fragments; mapping is not executable
package evidence.

Final-source real-Xray smoke and three-node rehearsal both ended terminal0.
Smoke hard/soft failures0, running/non-mocked transport; rehearsal has three
healthy non-mocked routers and no reconciliation issues. Its contact503 remains
the explicit missing-authority boundary, not successful current-contact delivery.
Owned temporary resources were cleaned; the six pre-existing deep-dev containers
were retained. No production/device/account/secret state was changed.

Receipt hashes (ignored local artifacts):

- Final reviewed7 `artifacts/s00-contact-descriptor/final-reviewed/final-review.trx`:
  `e2bd31ee56b5b8cae1f4f37667cfd802c41c57d075cc909d94a2e6f141a1c306`.
- Protocol MembershipRoutes131 `deep-protocol/artifacts/s00-contact-descriptor/full/nikit_SURFACE-LT_2026-10-04_12_42_51_net10.0.trx`:
  `c177ec458ff864f7a28e9f0a5b403421660318a774ba34ea66f4ebc4f68d3e53`.
- Protocol ProfileCarrier105 `deep-protocol/artifacts/s00-contact-descriptor/full/nikit_SURFACE-LT_2026-10-04_12_42_51_net10.0[1].trx`:
  `e8bc455458ddc81e4b0ae8e2a7034a42c396067d2d6f802ef87874c931e87f6e`.
- Protocol1843/1/12 `deep-protocol/artifacts/s00-contact-descriptor/full/nikit_SURFACE-LT_2026-10-04_12_42_52_net10.0.trx`:
  `2a008c47aec337e23a89495bbc79ad05043f2287beef2eeeba3b49944d90f118`.
- Smoke `deep-devops/artifacts/s00-contact-descriptor-smoke-20261004/runtime.gate.json`:
  `8e909486fef3885a3e1f034c2ecb7b6712632cc163edd5e392d51ec1ee1bf9c5`.
- Rehearsal `deep-devops/artifacts/rehearsals/multi-node/20261004T074557481Z-ba2c67603737/test-results/multi-node-topology.json`:
  `7de4f9156fdb917b675218fa27defa1d646114cde416b93b1aac945b72ec1c28`.

Strict registry/generator, ownership mapping219/packageMissing0 and executable
manifest integrity-only pass; none is package/executable release qualification.
Root documentation174 and CONTACT/crypto/ONION/governance ClassificationOnly
pass. Two edited docs pass strict UTF-8/59 local links; selected source/docs/TRX
secret scan passes21 files (not private/operator evidence).

## Still open

Whole-host startup/readiness/current mailbox DI, protected time/lifecycle/retirement,
retained routes, private authority-hop ID/key binding, shipping package matrix,
one-time account pending/winner/retained-genesis/AEAD restore/export and physical
Windows/Android contacts/messages/files/groups remain release requirements.
Reusable journal9 is not repurposed for one-time invitations. No release or main
merge is authorized by this checkpoint.
