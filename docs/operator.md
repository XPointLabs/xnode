# Operator Guide

## Current DID2 mailbox issuer input

The independent node network boundary now retains and validates the public
PMA2 chain required by [DR-0052](../../docs/survival-program/decisions/DR-0052-did2-mailbox-authority-distribution.md).
File-based inputs require `DeepIdV2NetworkPlacement:ExactMailboxAuthorityPaths`
alongside the existing projection paths; the atomic NCP2 bundle retains its
eighth chain. Missing configuration rejects, with no issuer synthesis or older
reader. Re-export/re-prepare the complete public configuration and match the
runtime/installer before rollout. Do not reset registered keys or network floors.

The runtime selects exactly the PMA2 referenced by verified current PMT2,
verifies its root threshold and full independently authenticated time interval
before floor advancement, then rechecks inputs/time before releasing a snapshot.
The internal snapshot carries only that verified public issuer policy. This
does not activate the dormant mailbox authority/replication graph, issue grants,
or prove device message delivery. No issuer signing key is installed on XNode.

## Private DID2 mailbox grant candidate

[DR-0054](../../docs/survival-program/decisions/DR-0054-did2-private-mailbox-grant-issuance.md)
connects acquisition to the same current DID2 ONION/contact replica graph.
It is disabled by default. Explicit `DeepIdV2ContactResolver:MailboxGrantEnabled`
requires the enabled DID2 resolver and one
`DeepIdV2ContactResolver:MailboxGrantAuthorityOrigin` HTTPS origin without a
path, user information, query or fragment. The client uses platform TLS without
redirects/cookies/decompression and signs admission with the existing registered
node key. No mailbox issuer key is installed on XNode. Both selected stores
independently attest their current durable publication/role lookup; exact retry
preserves the original result deadline. Existing observer, proof/network floor,
V2 staging and candidate environment guards still apply.
This opt-in composition is not production activation or device delivery evidence.

The acquisition consumer now follows
[DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md)
and accepts only the current bounded XMC2 result paired to the exact XMG1.
Old result magic/length, malformed records, foreign operation bindings,
compressed/truncated/trailing HTTP bodies and foreign media types reject.
Protocol independently verifies the enclosed route/selector/issuer authority;
HTTP parsing alone does not authorize a grant. Rebuild Registry/node/client
and provision the matching signed successors together. Node mailbox admission,
peer mutation and physical delivery remain separate activation gates.

## Private DID2 coordination backend candidate

Coordination consumers must rebuild/repin with Registry and clients under
[DR77](../../docs/survival-program/decisions/DR-0077-did2-route-successor-coordination.md).
The route response retains its actual signed issuance head; the enclosed current
request now carries bounded exact predecessor records for renewal. The outer
ONION wrapper and calling-node signature scheme stay unchanged, and the full
request remains authenticated. Before activating matched artifacts,
the Registry operator performs its explicit journal provisioning described in
[the Registry runbook](../../deep-registry-api/docs/DID2_ROUTE_THRESHOLD_COORDINATION.md).
No registered Ed25519/BLS key or node state reset is implied. An older backend
response fails closed; there is no mixed-generation fallback.
Publication envelopes also require the matched V3-only rebuild under
[DR79](../../docs/survival-program/decisions/DR-0079-did2-publication-issuer-successor.md)
and [publication journal provision](../../deep-registry-api/docs/DID2_PUBLICATION_COORDINATION.md).
The full node signature covers the enclosed publisher-bound prior receipts.
This does not grant issuer/client evidence or export any resolver capability;
old publication media/envelopes reject without forwarding. Node keys and floors
are retained; matched artifacts and actual transport/device tests remain gates.

[DR-0048](../../docs/survival-program/decisions/DR-0048-private-contact-coordination-peer-authentication.md)
defines the independent calling-node proof. The bounded backend client signs
using the node's existing `Node:Ed25519PrivateKeyPath`/registered identity and
one operator-configured HTTPS origin. It never changes registration keys,
follows redirects, accepts an arbitrary target URL or bypasses platform TLS.
Registry separately requires the intended public keys in its transport access
list; do not copy node private keys into Registry or client configuration.

The host candidate registers the verified carrier defined by
[DR-0049](../../docs/survival-program/decisions/DR-0049-did2-three-hop-coordination-carrier.md)
only with explicit `ContactCoordination:Enabled=true` and one
`ContactCoordination:BackendOrigin` HTTPS origin. Partial disabled settings,
unknown configuration fields, an unavailable privacy carrier or missing
independent DID2 observer configuration fail startup. Existing DID2 proof/network
options still restrict activation to Development/UAT; this does not relax them
or certify a production deployment. The default is disabled.

Provision the intended registered public node keys separately at Registry;
no key reset or private-key transfer is needed. Explicit
`DeepIdV2ContactResolver:Enabled=true` connects DID2 publication/resolve to the
V2 contact terminal under
[DR-0050](../../docs/survival-program/decisions/DR-0050-did2-contact-service-composition.md).
It requires the independent DID2 observer/network boundary, privacy carrier and
`DeepIdV2ReplicaStage:Enabled=true`. `ContactService` runtime/endpoint flags may
be enabled only together and with this complete DID2 resolver composition.
The existing candidate environment guards are unchanged. The same
one authenticated replica route multiplexes current contact/prekey operations;
no second route or public direct fallback is introduced. Store expiry/retention
uses fresh signed DID2 time plus boot-scoped monotonic elapsed time, while peer
HTTP signatures use the separate host clock. Missing/expired/rolled-back proof
fails closed. Full production clock/floor/root/package activation remains gated.
The `ContactCoordinationFocused=true` local lane exercises real public DID2/NET
ceremony, node signatures and HTTP-handler boundaries; it does not replace the
full default suite, socket TLS, multi-node rehearsal or physical device E2E.

## DID2 opaque contact-publication candidate

The sole XPU/XPA reader and node publication authorization now follow
[DR-0039](../../docs/survival-program/decisions/DR-0039-did2-opaque-publication-consumer.md).
Placement and authorization both use the independently configured DID2
observer proof, protected network floor and signed network artifacts; the old
Contact snapshot is not a publication fallback. Missing DID2 composition
rejects rather than reusing old proof material.

Existing publication-authorization saga files are incompatible and fail closed.
An explicit isolated QA saga reset is required; there is no automatic reset
or migration. Preserve registered node keys and unrelated stores. The local
business slice verifies real DID2 signatures, opaque storage, two durable
replica receipts, restart and exact retry after a discarded response. It is
not socket/TLS, authenticated remote-peer, shipping client or physical-device
evidence. Private coordination ingress and mailbox membership/grants remain
activation gates. The default full test suite is unchanged; only an explicit
`PublicationConsumerFocused=true` local run selects this small slice.

## DID2 recovery candidate

Private contact coordination logs one closed warning on rejected completion:
`phase`, `check`, dispatch `certainty` and a fixed exception category. These
values identify whether independent authority, a currentness predicate, backend
exchange or reply pairing failed. Repeated warnings are throttled per fixed
phase/check bucket using local monotonic diagnostic scheduling, not trusted time.
No exception text/object, payload, credential,
capability, node identifier or authority bytes are logged. Diagnostics do not
change the DR48/DR49 checks, authorize replay or prove physical delivery. A
pre-backend rejection remains `RejectedBeforeForward`; every failure after the
backend boundary remains `OutcomeUnknownAfterForward`.

The hosted ContactResolve terminal now reports only closed dependency-failure
categories (`proof-rate-limit`, `proof-unavailable`, cryptographic/authorization
rejection, custody/I/O or configuration/state). Logging is bounded to one
warning per ten seconds per process, across categories. It never emits exception
objects/messages, account identifiers, capabilities, payloads or origins.
These diagnostics retain outcome-unknown behavior; they do not permit a retry,
receipt, fallback or successful publication. The native DID2 focused runtime
batch passes 37/37; production/device evidence is a separate requirement.

The DID2 prekey claim runtime classifies native Windows replacement errors as
I/O uncertainty. A claim whose reservation/completion cannot be confirmed returns
`OutcomeUnknown`, without releasing a prekey. The authenticated peer endpoint
returns a bodyless, unsigned HTTP 503 for these errors. After storage readiness
is restored, reconcile the exact original operation; do not substitute a new
operation or assume that the failed response means no write occurred. This is
error containment, not a diagnosis of intermittent Windows access-denied errors,
an automatic retry, or permission to weaken storage ACLs.

Malformed external authority responses and frames keep ONION readiness closed,
but do not terminate its bounded idle acquisition loop, including at startup.
No rejected response or retained stale binding is served; recovery requires a
new independently verified current binding. Known malformed responses use the
same local retry delay, without resetting floors, changing keys or bypassing
Registry throttling. Health reads perform no proof issuance. Wrong local key
configuration still rejects startup rather than being treated as a network retry.
The explicit `PrivacyRecoveryFocused=true` local test slice checks this lifecycle;
it does not replace production recovery or physical messaging evidence.

The DID2 proof reader consumes independently verified historical pages and
durably advances its protected head before requesting a fresh current proof.
Network closure configuration can use one atomically replaced `PublicBundlePath`;
it cannot mix that mutable bundle with individually listed file generations.
The configured public observation credential is not a requester-selected proof.

`PrivacyRouting:NextX25519PrivateKeyPath` may stage one distinct next key in the
protected vault. A sealed, current signed network view selects the installed
current or staged slot. Identity keys are never converted to traffic keys;
unknown/uninstalled signed keys cannot advance the local network floor.
This is not unlimited unattended key generation or TLS rotation.

The background receive capability reports only closed diagnostic categories,
not exception messages, recipients, key paths or proof bytes. The general
development health exemption applies only when privacy is explicitly disabled.
When privacy is enabled, missing current verified capability returns readiness
503 even in Development; `deep-dev` requires the
actual `privacyRouting=ready` result. See
[Deep DEV](../../deep-devops/docs/DEEP_DEV.md),
[DR-0014](../../docs/survival-program/decisions/DR-0014-directory-historical-catchup.md)
and [DR-0015](../../docs/survival-program/decisions/DR-0015-delegated-operational-renewal.md)
for the normative contracts and retained-custody operations.

Existing cleartext management/legacy peer listeners explicitly use HTTP/1.1,
matching Kestrel's actual previous behavior without a misleading HTTP/2 warning.
TLS listeners keep ALPN HTTP/1.1 + HTTP/2; dedicated privacy/managed-ingress
HTTP/2 listeners and their authentication/proxy trust checks are unchanged.

## Verification tooling

Profile-generator restore/closure tests use native `git` and PowerShell on
each CI operating system. Windows retains Windows PowerShell by default;
Linux uses `pwsh`. A local PowerShell 7 regression may set `DEEP_PWSH` to an
explicit executable for these test subprocesses. This affects the harness,
not node authority, protocol pins or production configuration. Temporary
Git isolation overrides are removed when originally absent; an empty override
does not satisfy the independent snapshot-authority check.

## Architecture

XNode runs the Deep-native privacy relay and mailbox exit runtime in .NET and supervises Xray only for VLESS ingress. Xray forwards accepted public traffic to the bounded managed-ingress HTTP/2 surface.

The DID2 ONION receive capability refreshes through its existing verified
source on a ten-second background timer, including while the node has no traffic.
Traffic may reuse the exact verified local binding within that interval only
after `EnsureCurrent`; expired signed authority is never extended. The worker
forces a fresh proof independently of traffic. This leaves budget for client
proofs instead of consuming the complete six-per-ten-second Registry issuance
budget with three idle nodes; transport traffic does not force redundant
observation proofs for every hop. A proof failure still clears the binding.
Health reads remain side-effect-free. A failed refresh clears readiness; a
later refresh can recover only with fully verified fresh authority. Stop cancels
the worker and prevents an in-flight result from reactivating readiness. This
does not renew offline-root checkpoints or extend signed artifact lifetimes.
Startup without a fresh binding because of a Registry/network outage, a bounded
HTTP timeout or expired authority keeps the host alive but unready; the same
worker retries without traffic or an account/key reset. Configuration and
opaque-key-handle mismatches still reject startup. Persisted corrupt/forked
state never becomes usable through retry. Transport failure, timeout and
dependency-owned cancellation schedule a monotonic pause of at least the
refresh interval. A typed 429/503 may lengthen it with positive `Retry-After`
deltas up to the transport's five-minute bound. Caller/host cancellation remains
prompt. Traffic shares this gate and cannot bypass or extend the same pause;
retry creates a new proof nonce. This is a local runtime contract,
not evidence that automated trusted-time/view/key renewal or the Docker soak
gate has passed.

Current product status (2026-08-30): this server path is implemented, but the
MAUI authenticated-mailbox transport does not yet dial it through its Reality
runtime. It sends the opaque frame directly to the HTTPS entry origin. Do not
claim censorship-resistant messenger delivery until a client-bound
VLESS/Reality physical gate passes with direct HTTPS blocked.

## DID2 directory-proof UAT boundary

### Offline accepted-network checkpoint audit

`did2-network-floor-audit` runs before web-host construction. It authenticates
an **offline copy** of the exact floor and independent anchor with the copied
existing Data Protection key ring, unchanged application discriminator and
directory-genesis/node purpose. Key generation is disabled. It acquires no runtime lease,
creates no keys or custody directories and offers no import, repair or reset.
Snapshot acquisition remains an operator custody task: keep it private, copy
both records and the matching key ring, and compare capture hashes if a writer
can advance during capture. A mixed capture rejects; do not erase a floor to
make the audit pass. Coordinated rollback of both records is not detected.

The snapshot contains exactly `floor.bin`, `anchor.bin`, and `keys/` with the
original bounded `key-*.xml` / `revocation-*.xml` records. Mount it read-only when
auditing in a container. Scope values are independently configured canonical
uppercase nonzero 32-byte hashes. Use the reader's `GenesisHeadCoreHashHex`
(ADH1 directory genesis), **not** `GenesisAuthorityCoreHashHex` (XNA1 network
genesis). The purpose is unchanged from the live reader. The output is a new
file outside the snapshot:

```text
dotnet XNode.dll did2-network-floor-audit --snapshot-root <offline-snapshot> --directory-genesis-core-hash <pinned-directory-genesis-hash> --node-id <registered-node-id> --output <new-history.dnh2>
```

The output is the unchanged non-secret local DNH2 capsule defined by
[DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md).
The console reports only revision, length and digest. This proves matching local
custody, not signature freshness, an independent global checkpoint or readiness.
Treat it as historical predecessor input for the supported operational ceremony;
the current signed closure still requires full Protocol verification. No protocol
API, traffic lifetime or registered identity changes. Runtime and audit both reject
an authenticated anchor whose history length differs from its floor.

`DeepIdV2DirectoryProof` is an opt-in, fail-closed diagnostic proof reader.
The authorized seed fleet is production infrastructure; `UAT` names its
pre-release software profile, not a separate remote environment. Mr. X permits
testing there until he explicitly reports users exist. This permission does not
turn partial host readiness into release approval.
It independently verifies the exact signed XNA1/DTS1 authority lineage from
`NetworkIdHex` and `GenesisAuthorityCoreHashHex`, restores an exact signed DID2
genesis head from `GenesisHeadPath` and `GenesisHeadCoreHashHex`, then protects
successor heads beneath `Node:DataDirectory`. It refuses to start in Production
and rejects the removed `ContactAuthority`/`GroupControlAuthority` sections,
including disabled settings. It does **not** by itself activate
DID2 contact publication, pre-key claims, messages, or groups. Do not advertise
it as an E2E-capable XNode release.
The internal candidate gate combines a durably complete XPP1 V2 journal,
recipient-specific current directory proof and public DCA1/XPS1/inventory
verification. The UAT authenticated peer endpoint can request a final XIC1
receipt only after rechecking that authority and locally minted NETCODEC
placement. This is not client publication or claim activation: two selected
replicas' durable receipts and client-side final verification remain mandatory.
The independent `DeepIdV2NetworkPlacement` UAT section may be enabled only
alongside this proof boundary. It takes complete ordered absolute paths for
`ExactPolicyPaths` (XVP1), `ExactViewPaths` (XNV1), matching `ExactHeadPaths`
(XNH1), `ExactActiveNodePaths` (XND1), and
`ExactMailboxProjectionPaths` (PMT2). All files must be distinct and mounted
read-only. Startup checks path presence and closed byte bounds; each placement
request then re-verifies the entire signed network closure against a fresh
recipient-specific DID2 directory proof before minting a NETCODEC capability.
`DeepIdV2ReplicaStage:Enabled=true` adds authenticated peer staging on the
existing HTTP/2 replica port and a DID2-only ONION ContactResolve terminal on
a selected local replica. It requires this independent DID2 placement source,
rejects retired authority configuration, and is accepted only in
UAT/Development. Peer requests re-mint current placement and check the
authenticated selected peer; ONION terminal requests use only a newly minted
verified placement and reject an unselected local exit. Both durably stage
exact XPP1 V2 fragments beneath `Node:DataDirectory/did2-prekey-stage`.
Manifest/Chunk terminal responses are one-byte staging acknowledgements,
never XIC1 or permission to claim pre-keys. The terminal Commit can return one
XIC1 after a complete durable candidate; the separate authenticated peer
final-commit operation requires exact replay of the staged Commit fragment.
Both paths then recheck current DID2/device authority and placement before
advancing the service-capability-keyed inventory state beneath
`Node:DataDirectory/did2-prekey-commits` and returning one signed XIC1.
Its local snapshot version 2 atomically retains the exact public XPP1 (all
one-time and last-resort DPK2 bytes), the exact XIC1 and at most one predecessor
inventory. A domain-separated snapshot digest is signed by the same registered
node identity and verified before reading the inventory; no new custody key is
introduced. Receipt operation/placement/manifest bindings, inventory hash,
closed allocation bounds and sequential lineage are rechecked after restart.
The previous metadata-only snapshot format is rejected, not migrated or rebuilt
from staging. The retained inventory is not claim authority: fresh DID2/device
verification and both selected replicas' receipts are still required. A signed
local snapshot alone does not detect restoration of an older valid backup.
Corrupt/lost active state or conflicting operation/epoch latches the service
fail-closed. Back up that state with node keys; restoring keys alone is not
enough. The supported installer selects the explicit `UAT` candidate profile;
the `Production` activation guard remains closed. Only the bounded authenticated
replica route is allowlisted through signed-origin HTTPS to its dedicated H2
listener. It is not an unauthenticated direct publication API. This source is
not yet a production LKG/renewal owner.
Two-replica dispatch/final verification and client claim/receive remain release
gates.
The internal DID2 claim journal now shares the inventory custody lock and stores
`claims.state` plus `claims-activated.marker` in that same capability directory.
It reserves only exact locally retained members and retains pending reservations
across expiry, lost responses and restart. It can record a completed local
result only from Protocol's verified two-replica signature capability matching
the durable proposal. The local registered node signs the bounded snapshot;
restart checks canonical V2 inputs, sequential reservation generations, unique
one-time IDs and persistent last-resort counters. A write with uncertain outcome
requires reopen and reconciliation; missing/corrupt activated custody latches
the entire service closed. Back up these files together with inventory state.
There is deliberately no timeout release, GC, migration or automatic repair.
This candidate has bounded local admission capacity and does not detect rollback
to an older valid complete backup. `DeepIdV2PreKeyClaim:Enabled=true` now
exposes the candidate V2 claim on the selected ONION terminal. It defaults to
false and requires DID2 staging, a configured public observation credential,
the independent placement/proof source, absent retired authority sections and
Development/UAT. The first ranked selected replica coordinates; the other
forwards without holding its local claim lock. Internal authenticated replica
operations 14–17 coordinate, prepare, complete and read the retained inventory
receipt, respectively. Legacy ClaimPreKey RPC is not a DID2 fallback.
Both replicas independently verify current recipient/device/publication
authority and the two selected XIC1 receipts before reservation/completion.
The coordinator releases success only after both durable completion read-backs;
the forwarding replica additionally verifies both result signatures. Pending
uncertainty blocks later selection until the exact operation reconciles.
The coordinator now distinguishes a proven pre-reservation exhaustion of the
signed last-resort reuse limit from uncertain custody: it returns the existing
`PreKeysUnavailable` / `None` result with no offering or receipt payload only
after rechecking current authority. This creates no reservation. A pending
operation, lost prepare/complete response or uncertain write still returns
`OutcomeUnknown` and requires retry of the original exact operation; timeout
does not free its key or reuse counter. Existing completed results replay
byte-identically even after the signed counter is exhausted, subject to the
same current authority checks. No wire/version, configuration, durable-state
generation or registered key changes; rebuild the matched candidate runtime.
Completion divergence persistently fork-latches custody without deleting its
journals. Unknown capability lookup creates no inventory directories.
Global admission quotas, complete valid-backup rollback detection, expired
pending-operation recovery and signed placement handover remain gates under the
[claim specification](../../docs/architecture/CONTACT-RESOLVER-V1.md#34-atomic-pre-key-claim-xpk1--xpc1).
This opt-in claim candidate is not messaging activation or physical delivery
evidence. Keep the flag disabled until the applicable deployment rehearsal
and device gates are complete; Production startup still rejects activation.
The separate candidate authority gate reads signed DCA1/XPS1 from the exact
bounded manifest; it never receives plaintext DCR1. It verifies this support
against its own fresh DID2 checkpoint; a caller cannot supply a
pre-verified DCA1. The staging response does not invoke that gate; only the
final commit does.

Set `DeepIdV2DirectoryProof:Enabled=true` only with an exact HTTPS
`RegistryOrigin`, paired ordered absolute `ExactAuthorityPaths` and
`ExactTimePolicyPaths`, the two genesis pins, a nonzero `DeploymentProfileId`,
and a bounded `RequestTimeoutSeconds` (1–30). Choose distinct relative
`StateRelativeDirectory` and `DataProtectionKeysRelativeDirectory` paths under
`Node:DataDirectory`; neither may overlap the reserved `did2-head-anchor`.
Mount signed public artifacts read-only. Keep the Data Protection key ring and
the node data directory recoverable as one custody unit; do not place private
signer material in XNode configuration. A partially populated disabled section
is rejected. Startup verifies the signed authority and restores the protected
head before serving requests. The native ML-DSA verifier used here is still a
hash-pinned candidate, not production release approval.

## Current mailbox revocation custody candidate

`FileMailboxGrantRevocationStore` is an internal native-state owner for the
[DR-0083 contract](../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
It is not registered in Program and adds no usable configuration flag, HTTP
endpoint, admission fallback or release activation. Current client/peer mailbox
integration and issuer renewal remain prerequisites.

The caller must provision a separate persistent custody root outside, and not
enclosing, replaceable `Node:DataDirectory`, plus a recoverable persistent Data
Protection key ring outside those replaceable volumes. The injected provider's
key-ring location is a host-composition obligation; this store does not infer
or validate it. Do not use an ephemeral provider or regenerate lost protection.
Each node/network/policy/role scope has an exclusive writer lease and
purpose-separated protected enrollment, anchor, floor and fault records. These
protect exact signed source bytes; they are not another mailbox wire format.

First enrollment is an explicit genuinely new-scope provisioning operation,
not restore behavior. Reads/admission/advance never create a missing floor.
Missing, corrupt, split or partial state rejects without deleting evidence;
an authenticated issuer conflict persists a fault latch and preserves the
previous floor. An uncertain write faults the running owner. Interrupted
replacement must be recovered from authenticated retained custody; operators
must not clear the latch, remove partial records, re-enroll an old scope or
reset node identity just to obtain readiness. A complete exact write can be
restored after restart even when the original call returned uncertainty.

Floor replacement and the entire bounded operation callback share one owner.
Consumers must await their work, check authority at the required mutation and
receipt boundaries, and not retain the operation lease. A check continuing
after lease closure also rejects after its awaited verification. The callback
does not by itself implement replay reservation, peer quorum or safe receipts.

Preserve the complete custody root and its existing protection keys for recovery,
alongside the registered node keys. This is local protected custody, not a
hardware monotonic counter: joint rollback/loss of all independent custody and
keys across restart cannot be detected by these files alone. No automated
enrollment is provided for that recovery condition. Native source/restart
evidence and remaining integration limits are recorded in the
[S01 checkpoint](testing/s01-mailbox-revocation-native-2026-10-03.md).

The registry payload advertises the transport parameters clients need:

- mask domain
- transport mode
- public host and port
- Reality or TLS metadata
- capabilities
- config version

Clients should consume `/api/bootstrap/client` or the registry record instead of asking operators to type VLESS settings manually.

## Quorum-signed membership artifact

`GET /api/network/membership-route-catalog` publishes a prebuilt artifact as opaque bytes. Set
`MembershipArtifact__ArtifactPath` only to an artifact produced by the external membership signer
pipeline. XNode does not sign, parse, edit, or synthesize it. If the setting is empty, the file is
missing, or its bounded read fails, the endpoint returns `503`.

For local Docker development only, mount a deterministic fixture read-only and point
`MembershipArtifact__ArtifactPath` at that mount. Never put an online/offline signer private key,
seed, or mnemonic in XNode configuration.

## Install

1. Publish the service for Linux:

   ```bash
   dotnet publish src/XNode/XNode.csproj \
     --configuration Release \
     --runtime linux-x64 \
     --self-contained true \
     -p:PublishSingleFile=true \
     --output artifacts/xnode-linux-x64
   ```

2. Create directories and user:

   ```bash
   sudo useradd --system --home /var/lib/xnode --shell /usr/sbin/nologin deep
   sudo mkdir -p /opt/xnode /var/lib/xnode /etc/xnode
   sudo chown -R deep:deep /var/lib/xnode /etc/xnode
   ```

3. Copy the published files to `/opt/xnode`.

4. Install Xray at `/usr/local/bin/xray` and generate Reality keys with Xray's key generator.

5. Copy `deploy/xnode.service` to `/etc/systemd/system/`.

6. Put production settings in `/opt/xnode/appsettings.Production.json`.

7. Start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now xnode
   ```

## Production Go / No-Go Checklist

Use this checklist to separate three different questions:

1. Can we build the router as a production binary?
2. Can we deploy it on a real Linux host for controlled operator validation?
3. Can we call the router fully production-ready for public rollout?

### Current Status Snapshot

As of 2026-09-10:

- `GO`: Release tests pass locally (`dotnet test XNode.slnx --configuration Release`).
- `GO`: self-contained `linux-x64` publish path works (`dotnet publish ... --configuration Release --runtime linux-x64 --self-contained true`).
- `GO`: production profiles reject mocked VLESS/Xray settings at startup.
- `GO`: devops release rehearsal can run a real Xray-backed router locally via `deep-devops/scripts/test-env.ps1 -RequireRouterNoMock`; latest managed external smoke/full runs reported `routerTransportMode=running` and `routerTransportMocked=false`.
- `GO`: devops CI wiring now runs backend-external smoke/full with `-RequireRouterNoMock`.
- `GO`: the current native-privacy C3 baseline runs fail-closed
  soak/malformed-frame chaos/concurrent load plus a real supervisor restart-storm
  probe, and publishes `artifacts/test-results/c3/latest.json` plus `latest.md`.
  Its report explicitly excludes authority-bound multi-hop acceptance.
- `GO`: devops real-Xray image supports `XNODE_XRAY_SHA256` archive verification for release rehearsals.
- `GO`: messenger-node release rehearsal requirements are now captured in `deep-devops/docs/MESSENGER_NODE_PRODUCTION_RUNBOOK.md`.
- `CONDITIONAL GO`: operator deployment is possible if the target host has a real Xray binary, valid Reality/TLS material, and a real `appsettings.Production.json`.
- `NO-GO`: authority-bound multi-hop staging evidence is still outstanding; the
  C3 CI baseline is deliberately not a substitute for that release gate.
- `NO-GO`: current MAUI message transport is not bound to the Xray/Reality
  ingress; real-Xray server readiness is not proof that user messages use it.
- `NO-GO`: program-level platform matrix, full security/compliance, and release-discipline sign-off gates are not yet closed.

### Router Build Gate

Mark this section `GO` only when all items are true:

- [x] `dotnet build --configuration Release` succeeds.
- [x] `dotnet test XNode.slnx --configuration Release` succeeds.
- [x] `dotnet publish src/XNode/XNode.csproj --configuration Release --runtime linux-x64 --self-contained true -p:PublishSingleFile=true` succeeds.
- [x] Published artifact includes non-mock default config (`Vless:MockProcess=false`, real `Vless:XrayExecutablePath` in base config).

If all four are true, the answer to “can we build the production binary?” is `YES`.

### Operator Deployment Gate

Mark this section `GO` only when all items are true on the target host:

- [ ] Xray is installed at the configured production path.
- [ ] Reality or TLS keys/certificates are provisioned.
- [ ] `appsettings.Production.json` is present and reviewed.
- [ ] `DOTNET_ENVIRONMENT=Production` is enforced by the service manager.
- [ ] `GET /health/live` returns healthy after startup.
- [ ] `GET /health/ready` returns healthy or intentionally degraded under the documented semantics.
- [ ] `GET /status` shows the expected transport metadata and registry payload.
- [ ] One controlled client bootstrap flow succeeds against the real node.

If all items are true, the answer to “can we deploy it for controlled production-like validation?” is `YES`.

### Public Production Sign-Off Gate

This section is still `NO-GO` today.

The remaining blockers are:

- [ ] Attach the first green CI/release artifacts for the real-Xray no-mock
  rehearsal and current native-privacy C3 report.
- [x] Close the CI-safe router baseline: native-privacy fail-closed
  soak/chaos/load and supervisor restart-storm evidence is green.
- [ ] Close authority-bound multi-hop staging acceptance with production-shaped
  authority material and real node-to-node forwarding.
- [ ] Close the program-level Android+Windows release matrix gate; iOS remains
  unverified/non-blocking and not release-supported.
- [ ] Close mandatory security/compliance gates: security-gate CI artifact, policy-as-code, and external audit closure.
- [ ] Close release-discipline gates: credentialed provider canary, rollback rehearsal, post-release verification.

Until those items are closed, the correct answer to “is the router fully production-ready for public rollout?” remains `NO`.

### Practical Decision Rule

- If you only need a production build artifact for staging, controlled node bring-up, or infra rehearsal: `GO`.
- If you need a formal public production / GA sign-off: `NO-GO` until the blockers above are closed.

## Health

- `GET /health/live`: process liveness.
- `GET /health/ready`: returns `200` only when privacy routing is enabled, Xray is running or deliberately degraded, enabled mailbox/authority dependencies are ready, and every terminal selected under `RequiredTerminals` has an active verified-authority runtime composition.
- `GET /status`: sanitized transport, privacy-routing, mailbox and authority state. It never emits private X25519 material, MAU2 bytes, blinded mailbox identifiers, peer authentication headers, or replay IDs.

A node with `PrivacyRouting:Enabled=false` is live but not ready. There is no direct MAU2 compatibility readiness lane.
`RequiredTerminals:Contact=true` or `RequiredTerminals:GroupControl=true` reports
`required-unavailable` and returns `503` until the corresponding ContactService
or GroupControlService production composition is active. Development mode does
not bypass an explicitly required terminal.

## Deep-native privacy ingress

The public client surface is HTTP/2 only:

- `POST /api/ingress/v1/frame` — one bounded opaque `XRF1` request frame;
- `GET /api/ingress/v1/capabilities` — managed-ingress capability document;
- `POST /api/peer/privacy/v1/frame` — authenticated peer-only relay ingress on the peer listener.

Direct `/api/client/mailbox/v2/store`, `/retrieve`, and `/acknowledge` HTTP routes are not mapped. The exit node opens the final privacy layer. An authoritative exit invokes the MAU2 verifier, durable outcome journal and two-replica PRQ2/MQR3 runtime in process. A forwarding-only exit sends the unchanged canonical MAU2 body to the explicitly pinned authoritative router over the authenticated privacy-peer transport; it never owns a client adapter, operation ledger, cursor authority, or MQR3 signing authority.

The public request contract requires exact HTTP/2, HTTPS scheme, canonical
length/media headers and the closed ingress request contract. TLS termination
must preserve that scheme through the scoped proxy boundary below. ONION bytes
and response/error semantics belong to the
[frozen privacy-routing specification](../../deep-protocol/docs/deep-extension-privacy-routing-v1.md);
retired privacy frame/response magics are not accepted as compatibility paths.

Kestrel keeps the existing API and peer listeners when the dedicated managed-ingress listener is
disabled (the default). An internal HTTP/2-only listener can be enabled for an h2c reverse-proxy
backend without changing those listeners:

```json
{
  "Node": {
    "apiListenUrl": "http://127.0.0.1:8080",
    "peerRpcListenUrl": "http://0.0.0.0:8081",
    "managedIngressH2ListenUrl": "http://0.0.0.0:8082/",
    "privacyPeerH2ListenUrl": "http://0.0.0.0:8083/",
    "managedIngressTrustedProxyAddresses": [ "172.30.82.7", "172.30.82.8" ],
    "privacyPeerTrustedProxyAddresses": [ "172.30.82.7", "172.30.82.8" ]
  }
}
```

`ManagedIngressH2ListenUrl` must be an absolute root-only HTTP(S) URL without user info, query,
fragment or surrounding whitespace. `PrivacyPeerH2ListenUrl` uses the same canonical URL rules.
Their ports must differ from each other and from both API and peer RPC ports.
`ManagedIngressTrustedProxyAddresses` is mandatory when that listener is enabled and must contain
unique exact IPv4/IPv6 literals; DNS names, CIDRs, unspecified/scoped addresses, whitespace and
duplicates fail startup. The UAT TLS ingress and chaos proxy use the fixed `172.30.82.7` and
`172.30.82.8` addresses shown above.
Literal IPs bind exactly, `localhost` retains localhost binding, and other host names retain
`UseUrls` wildcard-bind semantics. When enabled, only the managed-ingress frame and capability
paths are served on that port, and those paths no longer accept traffic on the API listener. HTTPS
uses the configured Kestrel default certificate; internal h2c uses `http://`. Every dedicated-port
request must originate from the exact proxy allowlist and carry exactly one
`X-Forwarded-Proto: https`. XNode then consumes that header and sets the request scheme to HTTPS
before managed-ingress contract validation. Unknown proxies receive 404; missing, duplicate or
non-exact forwarded-proto values receive 400. The API and mixed peer-RPC listeners never trust or consume
this header.

The optional privacy-peer listener is exact HTTP/2 and serves the privacy frame,
enabled authenticated replica and authoritative-mailbox routes. These paths are
not exposed on the mixed peer-RPC listener. An h2c privacy-peer listener requires
its own `PrivacyPeerTrustedProxyAddresses`, with the same literal/duplicate
validation. It does not inherit managed-ingress trust. Before dispatch, only
that exact local port/proxy pair may promote one exact HTTPS header; unknown
proxies return 404 and invalid headers return 400. Direct HTTPS privacy-peer
listeners use real Kestrel TLS and do not trust forwarded scheme headers.
The production compose forwards the HTTPS frontend to h2c `8082`/`8083` using
HAProxy `proto h2`, without publishing those backend ports.

Each relay decrypts only its own layer. A relay layer contains a replay ID, a next router ID and an opaque inner frame. The endpoint never comes from the frame: the router ID must resolve in `PrivacyRouting:Peers`, and the configured origin, DNS result, HTTP version and TLS SPKI pins are revalidated for every outbound peer request. Peer requests additionally carry an Ed25519 signature bound to sender, recipient, timestamp, nonce and SHA-256 of the opaque frame. Both transport nonces and hop replay IDs use bounded TTL windows.

## Privacy routing configuration

```json
{
  "PrivacyRouting": {
    "enabled": true,
    "x25519PrivateKeyPath": "/run/secrets/xnode-x25519-private",
    "publicPeerBaseUrl": "https://node.example:443/",
    "stateProtectionKeyPath": "/run/secrets/xnode-onion-state-key",
    "replayStateRelativePath": "privacy-routing-v1/replay.state",
    "entropyStateRelativePath": "privacy-routing-v1/entropy.state",
    "keyVaultDirectoryRelativePath": "privacy-routing-v1/key-vault",
    "maximumConcurrentRequests": 64,
    "requestsPerMinute": 600,
    "requestTimeoutSeconds": 30,
    "replyPaddingBlockBytes": 4096,
    "replayCapacity": 65536,
    "replayTtlSeconds": 300,
    "allowInsecureHttpPeerTransport": false,
    "peers": [
      {
        "routerId": "<64 lowercase hex>",
        "baseUrl": "https://peer.example:443/",
        "currentSpkiSha256": "<64 lowercase hex>",
        "nextSpkiSha256": "<different 64 lowercase hex>"
      }
    ]
  }
}
```

Activation is atomic and fail closed. `StateProtectionKeyPath` is a separate raw
32-byte secret (not hexadecimal text) and must not reuse the node Ed25519 or
ONION X25519 secret. The three state paths must be distinct clean relative paths
inside `Node:DataDirectory`. A fixed receive-position configuration is retired:
the host derives all permitted positions from its current signed XND1 role mask.
Startup requires the independent DID2 proof/network source, not the retired
V1 Contact authority snapshot. `DeepIdV2NetworkPlacement:PublicObservationDid2Path`
names an operator-configured public DID2 credential used for fresh proof acquisition;
an incoming request cannot choose it. The exact policy/view/head/node/PMT chains
are configured with the other `DeepIdV2NetworkPlacement` paths. Current composition
is UAT-only and does not authorize a Production environment activation.
Missing, stale, cross-network, duplicate-owner, wrong-key
or wrong-role authority leaves the capability unavailable and fails enabled-node
startup before ingress can accept traffic. The X25519 scalar is imported into an
authenticated opaque-handle slot; a pre-existing slot with different key material
is rejected rather than overwritten.

The network rollback floor and its independent anchor live in `did2-network-state`
and `did2-network-anchor` beneath the node data directory. Back up these directories
and the DID2 Data Protection key ring together with the existing proof floor/anchor.
Never delete one half to repair an error. A missing, corrupt, split or rolled-back
half fails closed; restoring both halves to an older matching snapshot is not
detectable by this local store. Protocol semantics and the explicit authority-rollover
restriction belong to [DR-0012](../../docs/survival-program/decisions/DR-0012-protected-network-history.md).
The local replay generation is also incompatible with the retired adapter:
an old replay file fails closed, without migration or overwrite. Before initial
UAT activation, replace only explicitly disposable replay state through the
operator deployment/reset procedure; preserve identity keys and all rollback floors.

The X25519 private key is independently generated and stored as exactly 32 bytes of lowercase hex in an absolute secret file. It must never be derived from or converted from the router Ed25519 key. Startup fails closed for a missing, zero, uppercase/non-canonical or invalid key; duplicate/self peers; non-origin URLs; repeated TLS pins; invalid bounds; or an empty peer inventory.

HTTPS and two distinct CA-valid SPKI pins are mandatory outside the local Development lane. `AllowInsecureHttpPeerTransport=true` is accepted only when ASP.NET Core is running in `Development`; in that lane peer origins may use HTTP and SPKI fields must be empty. This exception exists for the isolated six-node survival compose network and is rejected in UAT and Production.

`PublicPeerBaseUrl` is the origin advertised in the signed native privacy contact. The runtime appends the exact peer path itself. Registry heartbeat publishes `privacy-routing-v1`, the independent X25519 public key and the privacy peer endpoint.

### Single authoritative mailbox coordinator

PMA1 defines one logical coordinator. Multiple terminal privacy paths therefore must converge on
the same coordinator rather than activate independent client adapters. Configure a forwarding-only
exit with the authoritative router already present in its pinned `PrivacyRouting:Peers` inventory:

```json
{
  "MailboxAuthorityForwarding": {
    "enabled": true,
    "authorityRouterId": "<authoritative router id>",
    "allowedExitRouterIds": []
  },
  "MailboxClient": { "enabled": false },
  "MailboxClientAdapter": { "enabled": false }
}
```

On the authoritative router, keep forwarding disabled and allow only the exact terminal exits that
may bridge canonical MAU2 requests:

```json
{
  "MailboxAuthorityForwarding": {
    "enabled": false,
    "authorityRouterId": "",
    "allowedExitRouterIds": [ "<forwarding exit router id>" ]
  }
}
```

The bridge uses exact HTTP/2 and the private `MAF1` Ed25519 transcript. `MAF1` binds sender and
recipient router identities, Store/Retrieve/Acknowledge operation, exact constant route, timestamp,
nonce, and SHA-256 of the unchanged MAU2. It has a dedicated bounded replay window and a separate
admission limiter acquired before body allocation. The three peer-only paths are store, retrieve,
and acknowledge under `/api/peer/mailbox-authority/v1/`. In Development the authority origin and
pins come from the exact `PrivacyRouting:Peers` row. In Production they come only from the live,
verified PMA1 `NodeIngress` current/next SPKI binding; stale or unavailable authority is rejected
before forwarding. Only an exact bounded canonical response is accepted. Transport failure,
timeout, malformed response, any `5xx`, or loss after dispatch is surfaced as outcome-unknown; it
is never converted into an empty Retrieve or a second coordinator attempt. The authority allowlist
is invalid unless the local client adapter is active, and forwarding is invalid when a local client
adapter is active. A forwarding-only node does not register the MAU2 capability replay journal,
canonical outcome store, operation ledger, or outcome GC service.

Operational checks:

1. Verify secret ownership/permissions without printing the key.
2. Confirm every peer row has the expected router identity, origin and current/next SPKI pins.
3. Confirm `GET /api/ingress/v1/capabilities` over HTTP/2 reports ready.
4. Confirm `GET /health/ready` returns `200` on all relays and mailbox exits.
5. Negative-test an unknown next router, replayed frame, oversized frame, wrong media type, redirect, DNS rebind and each TLS pin independently.
6. Confirm direct MAU2 URLs return `404`.

The privacy route restores single-node unlinkability under the documented non-collusion/no-global-observer assumptions. It does not hide timing, direction or padded ciphertext length from a global observer.


## Xray

The service writes the generated Xray config to `Vless:GeneratedConfigPath` and starts Xray with:

```bash
xray run -config /etc/xnode/xray.generated.json
```

For development or CI, set:

```bash
Vless__MockProcess=true
Vless__XrayExecutablePath=mock
```

Production guardrail:

- Non-development profiles reject VLESS mock settings at startup.
- Keep `Vless:MockProcess=false` and a real `Vless:XrayExecutablePath` in production profiles.

Supervisor failover policy:

- `Vless:MaxRestartAttempts`: max failures allowed inside `Vless:FailureWindow` before degraded mode.
- `Vless:FailureWindow`: rolling failure window for restart threshold counting.
- `Vless:DegradedCooldown`: cooldown duration before supervisor retries after entering degraded mode.

Default profile values are defined in `appsettings.json` and can be overridden per environment.

### Failover Validation Scenario

1. Configure a failing transport command (for test only):

  ```bash
  export Vless__Enabled=true
  export Vless__XrayExecutablePath=dotnet
  export Vless__MockProcess=false
  export Vless__MaxRestartAttempts=1
  export Vless__FailureWindow=00:00:10
  export Vless__DegradedCooldown=00:00:30
  ```

2. Start the router and watch `GET /status`.

3. Verify supervisor transitions:

  - `xray.mode` goes to `restarting`, then `degraded`.
  - `xray.degraded=true` and `xray.degradedUntil` is populated.
  - `xray.restartCount` increments.

4. Verify readiness/registry behavior during degraded state:

  - In non-Production, `GET /health/ready` stays `200` with `degraded=true` and `transportMode="degraded"`.
  - In Production, `DenyAll` public-peer authorization overrides transport health and keeps readiness at `503`.
  - `registry.transport` in `GET /status` mirrors supervisor metadata (`mode`, `degraded`, `restartCount`, `lastExitReason`).

## Registry Heartbeat

Enable heartbeat by setting:

```json
{
  "registryHeartbeat": {
    "enabled": true,
    "endpoint": "https://registry.example.org/nodes",
    "interval": "00:00:30"
  }
}
```

The payload model is implemented in `XNode.Registry.RegistryPayload`.

`registry.transport` includes live transport metadata used by registry consumers:

- endpoint and transport mode (`publicHost`, `publicPort`, `transportMode`)
- health and lifecycle (`healthy`, `degraded`, `mode`)
- restart/failure counters (`restartCount`, `consecutiveFailures`)
- last lifecycle details (`lastExitReason`, `lastStartedAt`, `degradedUntil`)

## Verification

Run `dotnet test XNode.slnx` after configuration or runtime changes. Privacy-routing tests cover relay allowlisting, unknown-next-hop rejection, sealed exit results, key/configuration guards, and peer-authentication binding.

## Canonical P10C peer mailbox runtime

The XNode peer listener implements the P10I binary wire only. It is disabled by default and
must not be confused with public client-mailbox activation.

```json
{
  "mailbox": {
    "enabled": false,
    "directoryName": "mailbox-v1",
    "maxBlobBytes": 81920,
    "maxStoredBlobs": 100000,
    "maxRecoveryScanFiles": 200000,
    "minimumTtl": "00:01:00",
    "maximumTtl": "7.00:00:00",
    "replicationFactor": 2,
    "writeQuorum": 2,
    "peerTimeout": "00:00:05",
    "peerReplayDirectoryName": "mailbox-peer-replay-v2",
    "peerMutationDirectoryName": "mailbox-peer-mutations-v2",
    "maxPeerReplayRecords": 100000,
    "maxPeerReplayRecordsPerRouterPairEpoch": 20000,
    "maxPeerReplayGcBatch": 1024,
    "maxPeerMutationRecords": 100000,
    "maxPeerMutationGcBatch": 1024,
    "allowInsecureHttpPeerTransport": false
  },
  "MailboxPeerAuthority": {
    "currentEpoch": 0,
    "currentMembershipCommitment": "",
    "currentEpochExpiresAtUnixSeconds": 0,
    "nextEpoch": 0,
    "nextMembershipCommitment": "",
    "nextEpochExpiresAtUnixSeconds": 0,
    "placementSelections": [
      {
        "epoch": 0,
        "placementCommitment": "64-lowercase-hex",
        "firstRouterId": "64-lowercase-hex",
        "secondRouterId": "64-lowercase-hex"
      }
    ]
  }
}
```

Enabling `Mailbox` also requires an authoritative current epoch/commitment/retirement time,
optionally a cryptographically distinct E+1 entry, and at least one exact placement-commitment to
two-distinct-router selection. Replace the illustrative zero/placeholder values above; they are
not an enableable configuration. The only mailbox peer routes are:

- `POST /api/peer/mailbox/v2/store`;
- `POST /api/peer/mailbox/v2/tombstone`.

Both accept exact raw `PRQ2` with `application/vnd.deep.mailbox.prq2` and return exact signed
`MRR2` with `application/vnd.deep.mailbox.mrr2`. The removed
`/api/peer/mailbox/replica` JSON route returns 404. The canonical routes return 404 on the public
API listener. Any non-POST method on either canonical path also returns 404.

Plain HTTP is rejected by default because it exposes otherwise opaque mailbox metadata.
`allowInsecureHttpPeerTransport=true` is a development-only escape hatch for an isolated
Docker network or a deployment where an authenticated outer transport terminates immediately
in front of XNode.

Operational invariants:

- PRQ1, MQR2, JSON and cross-operation frames are rejected; no translation exists;
- both RIP1/MIP1 proofs must verify Storage role/capability, exact router signing keys, epoch and
  the configured membership commitment; sender/recipient RouterIds are distinct identities,
  distinct from their independently bound and mutually distinct signing keys;
- Store binds the exact canonical MEO1 placement preimage; Tombstone must resolve the identical
  durable Store context; the exact router pair must be present in the authoritative placement
  selection allowlist;
- created-at has zero future skew and at most the protocol's fixed past-age window;
- replay is reserved before mutation in an exclusive crash-safe journal; an exact completed retry
  returns the cached verified MRR2 and a pending crash claim resumes idempotently. Persisted exact
  scopes remain retryable after the initial freshness window and retain their original effective
  reservation timestamp; an unknown stale request allocates no replay record;
- replay GC uses the authoritative epoch retirement time plus the protocol-fixed seven-day
  retention interval;
- replay startup and every sender/receiver reserve path run priority-ordered bounded collection
  before reporting capacity, so a full journal containing retired completed state remains live;
- every replay record is semantically validated at startup even when its retention boundary is in
  the future: the P10I state machine must accept its status/timestamp/epoch/retention ordering,
  Pending carries no response, and Completed carries an exact canonical MRR2-domain response;
- each Store mutation has one durable record with expiry/retention metadata. Pending Store is
  exclusive to its exact replay nonce. Tombstone advances that same record through
  `tombstone-pending` to `tombstoned`, so no two-file gap can admit a duplicate Store; startup
  validates exact epoch-plus-seven-day retention and state-specific nonce/timestamp fields,
  reconciles deletion, and bounded GC removes only state past its live/replay boundary;
- the sender coordinator accepts only the exact local and recipient MIP1-keyed MRR2 pair and
  the recipient endpoint must exactly match its verified RIP1 RPC endpoint plus the operation
  route, and emits native PRQ2-only MQR3. One receipt, timeout or invalid evidence is never quorum;
- host-global and per-operation fixed-window/concurrency admission happens before body parsing or
  cryptography. Request body, content type/encoding, at-most-15-second deadline, per-operation
  concurrency/rate and 120/minute verified-sender limits come from `MailboxWireHttpContract`;
- replay and mutation leases plus full corruption validation are resolved during hosted startup
  and are included in `/health/ready`; the first peer request is never the readiness probe;
- Windows ACLs are replaced and verified as service-account-only; Unix modes are verified as
  `0700` for directories and `0600` for files;
- on Windows, journal replacement uses `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`. Durable
  deletion first write-through-renames to an anonymous `.deleted` tombstone, which startup
  removes after a crash. Unix replacement/deletion fsyncs the file and parent directory;
- metrics and status contain counts only: no router id, membership capability, mailbox, placement
  route, operation id, ciphertext or receipt bytes are logged or labeled.

Privacy peer nonces and decrypted hop replay IDs are process-memory-only, capacity bounded and
TTL-pruned. `/status` reports `privacyReplay=bounded-ttl`. MAU2 operation replay and canonical
outcomes remain durable in their existing journals.

### Native MAU2 client adapter

The in-process privacy exit accepts only MAU2 carrying an authenticated canonical `MEO1`, `MBR2`,
or `MBA2` body and produces `MQR3`, `MRP1`, or `MAR1`. Direct client mailbox HTTP routes are not
mapped in any environment. There is no MCP1 envelope, V1 request decoder, translation, or fallback
route.

The adapter ledger stores native MRR2 evidence and native MQR3 completion. Development ACK emits
the exact MBA2-ordered MQR3 list in MAR1; no MQR2 transcode is permitted.

The adapter reports `StoreReady`, `RetrieveReady`, and `AcknowledgeReady` independently;
aggregate `Ready` is true only when all three are ready. Status also exposes durable-replay and
tombstone-fanout configuration instead of overclaiming readiness. When used in a test
composition it reserves
`(epoch, blindedMailboxId, operationId)`, request digest and a per-mailbox monotonic cursor before
fanout, persists the full opaque `MEO1`, and accepts only the deterministic replica ids selected
for the exact membership/placement context. Two native context-bound `MRR2` receipts and the
ledger-allocated next global monotonic coordinator sequence are durably bound in one mutation
before `MQR3` signing. Request hashes and fanout responses have no sequence authority.
Replica receipt clocks are independent: each accepted time must be no earlier than the persisted
request acceptance, and each durable time must be no earlier than its own accepted time and
strictly before the common expiry. Equality between local and remote timestamps is not required.

The host reserves canonical-outcome capacity for the endpoint maximum before the first
ledger/blob/peer access. It persists exact MQR3/MRP1/MAR1 (or coarse MTO1 terminal state) before
completing replay with the outcome digest. A host-global per-operation pre-auth limiter keeps no
IP partitions; the post-verify limiter keys only a domain-separated hash of operation plus holder.

Exact concurrent retries are single-flight. Restart recovery either resumes the exact persisted
completion statement or fails closed; one coordinator sequence cannot sign two statements.
Only the exact durable PendingSame claim may acquire a recovery execution. PendingPrior and a
concurrent in-process InFlight request perform no worker or outcome mutation.
Cached `MQR3` bytes are not trusted as a cache hit: signatures, coordinator identity/sequence,
replica set and all request/membership bindings are reverified on every retry. Ledger loading
rejects non-canonical keys/hex, duplicate or rewound cursors/sequences, and inconsistent
state/receipt combinations.

E and E+1 use distinct membership commitments. Blob, size and remaining-TTL preflight occurs
before reserving a cursor, and expired operation records are cleaned without reusing cursor or
coordinator authorities. Conflicting operation-id reuse within an epoch/mailbox is rejected.
The two commitments must differ. `maxCursorAuthorities` bounds live per-mailbox authorities;
unused authorities compact into a durable retired cursor floor rather than remaining as
unbounded dictionary keys. `maxConcurrentSingleFlights` bounds unique active operations while
exact-operation waiters share one reference-counted entry.

The ledger owns `.adapter.lock` with exclusive file sharing for its complete lifetime. A second
ledger for the same directory, or a second adapter claim on one ledger, fails startup. Dispose
the adapter first and ledger second during orderly shutdown; only then can a replacement runtime
acquire the directory.

The native MAU2 runtime is the authorization boundary. It verifies the exact operation, operation
id, epoch, mailbox/placement/membership authority, canonical request digest, holder signature,
replay counter and claim digest before a worker can run. Readiness requires the strict decoder,
Ed25519 verifier, durable replay journal and durable canonical outcome store.

`MBR2` pagination is a stable high-water snapshot. The signed `XCT1` token binds the mailbox and
authority context, last cursor, snapshot high-water, page-size ceiling, expiry and exact page ACK
digest. It verifies against any currently authorized replica key to permit failover. If a replica
does not possess the durable snapshot data it fails closed; clients restart at cursor zero and
deduplicate locally.

`MBA2` reserves all targets and logical tombstones atomically before signing or fanout. Quorum
failure therefore hides the ciphertext from later retrieval but leaves retryable durable journal
state. Every item completes as a native Tombstone `MRR2` quorum and a native `MQR3`; exact retries
resume or return persisted, reverified bytes through the latest item expiry, including
multi-item ACKs with staggered TTLs. A new operation id for an already tombstoned cursor is
rejected and cannot create another journal or fanout. Retrieval emits MRP1, and Development ACK
returns exact MBA2-ordered MQR3 receipts in MAR1. The node never infers or persists client-side
`Delivered`.

Physical ciphertext cleanup is bounded after a durable ACK and repeated on initialization.
Deletion failure does not roll back a logical tombstone or ACK receipt; the ledger marks the blob
clean only after the exact delete and parent-directory durability barrier succeed. Ledger schema
v3 is intentionally incompatible with v2, whose records lack the canonical blob/placement/
membership evidence needed for safe retrieval and tombstones. Operation capacity counts stores,
ACK operation records and each ACK item.

Do not add direct client mailbox endpoints. XNode can now consume the public PMA1
issuer/epoch/NodeIngress-SPKI substrate, but it deliberately remains unready until a separate
hash-bound revocation artifact can answer serial-level decisions. A survival-only Development
composition exists for honest two-XNode interoperability testing. The activation decision is frozen in
`docs/adr/0006-mailbox-client-activation-blocker.md`.

`MailboxClient` remains fail-closed by default:

```json
{
  "MailboxClient": {
    "enabled": false
  }
}
```

Setting it to `true` from JSON, environment variables or command-line configuration prevents host
construction in production while the revocation artifact gate is open. In Development it also requires `MailboxClientAdapter:Enabled=true`,
`Mailbox:Enabled=true`, and an explicit `developmentFixture` containing a pinned 16-byte network
id, issuer public key and generation/validity window, coordinator base URL, current/next
placement ids and their SHA-256 commitments, two distinct replica ids and matching Ed25519 public
keys, current/next local and remote canonical base64 MIP1 proofs, and revoked serials. E/E+1
membership commitments and validity windows live in `MailboxClientAdapter`. The node key must
match the local proof; there is no remote or client private-key field. Proof descriptors provide
the remote peer RPC endpoint. `coordinatorUrl` must be an origin-only URL whose host and port
exactly match `Node.PublicHost` and `Node.PublicPort`; it is intentionally independent from the
container bind address in `Node.ApiListenUrl`. LAN HTTP is accepted only inside this explicit
Development composition. `/status` and `/health/ready` expose
`starting`, `ready`, or fail-closed startup state and never report enabled before the durable
ledgers and adapter initialize.

### Production PMA1 authority substrate

The production-only public authority loader is configured independently from route activation:

```json
{
  "MailboxClientProductionAuthority": {
    "enabled": true,
    "artifactPath": "/run/secrets/deep/mailbox-authority.pma1",
    "revocationArtifactPath": "/run/secrets/deep/mailbox-revocation.pmr1",
    "topologyArtifactPath": "/run/secrets/deep/mailbox-topology.pmt1",
    "selectionArtifactDirectory": "/run/secrets/deep/selections",
    "readinessBlindedPlacementId": "<64 lowercase hex>",
    "readinessSelectionInputCommitment": "<64 lowercase hex>",
    "artifactTrustRoot": "/run/secrets/deep",
    "lastKnownGoodPath": "/var/lib/xnode/mailbox-authority/authority.pml1",
    "closureDirectory": "/var/lib/xnode/production-mailbox-closures",
    "closureStateHmacKeyPath": "/var/lib/xnode/secrets/closure-state-hmac.key",
    "closurePublisherEd25519PublicKey": "<64 lowercase hex>",
    "pinnedMrXPublicKeySha256": "<64 lowercase hex>",
    "expectedNetworkId": "<32 lowercase hex>",
    "clockSkewSeconds": 60,
    "maximumArtifactBytes": 65536,
    "maximumRevocationArtifactBytes": 131072,
    "maximumTopologyArtifactBytes": 4997504,
    "maximumSelectionArtifactBytes": 8840,
    "maximumStoredClosures": 100000,
    "maximumClosureStoreBytes": 536870912,
    "maximumClosureVersionsPerSelection": 4,
    "maximumClosureLineagesPerSelection": 4,
    "maximumClosureReservations": 128,
    "maximumClosureReservationLifetimeSeconds": 86400,
    "minimumClosureReservationLifetimeSeconds": 60,
    "closureScheduleAccountingOverheadBytes": 1024
  }
}
```

This section is rejected outside `Production`. All paths must be absolute; PMA1, PMR1, global PMT1
and the per-selection PMS1 directory must stay inside the explicit immutable trust root, while the LKG must stay inside
`Node:DataDirectory`. Every
ancestor from each file to that trust root is checked before each open and may be writable only by
the service identity. On Linux all public artifacts are owner-only `0400` regular files and the
pre-provisioned PML3 LKG is `0600`; no traversed path may be a symlink. On Windows files and
ancestors must have the exact service owner and protected non-inherited service-only ACLs, with the
public artifacts read-only. PML3 contains
only generations and SHA-256 chain state, never a private/signing key, holder, capability,
mailbox id, or endpoint.

Startup performs canonical PMA1 decode, pinned Mr. X key-hash and Ed25519 verification, then
canonical PMR1 verification with the same clock observation and skew. PMR1 must match the exact
network, authority binding, issuer, revocation generation/head/previous-head/times and snapshot
hash declared by PMA1; its issuer signature is verified before an unknown MCG2 serial may return
`false`. PMA1, PMR1, PMT1, PMS1, LKG and lock opens reject final-path links and compare native file identity
before/during/after validation. The lock is either exclusively created or opened only after exact
validation; an unchecked `OpenOrCreate` path is never used. XNode then verifies issuer-signed PMT1
against that exact authority and a caller-bound readiness PMS1 against the same time observation.
Only after all four artifacts verify does XNode atomically replace and durably flush one combined
LKG. The accepted immutable authority, revocation, topology and readiness-selection bundle is
published with one reference swap only after persistence. Separate authority and topology anchors
permit independent exact successors and idempotent restart; rollback, forks, mismatches and
partial successor publication fail closed without advancing the durable bundle.
Diagnostics expose only coarse state and generations, not paths, endpoints, pins, hashes or
exception text.

Registry-independent refresh uses only constant-path binary POST endpoints. The public
`/api/production-mailbox/closure` request is exactly 272 bytes (PMQ2) and binds a timestamp, nonce,
selection commitment, exact durable old-PMS hash, lineage commitment, target replica and owner key
to an Ed25519 proof by the mailbox owner. Neither path nor query contains a
mailbox-derived identifier; ASP.NET request-body logging is not enabled and responses carry
`Cache-Control: no-store`. The peer-only preposition endpoint accepts a bounded PMP2 command,
not a bare closure: a dedicated pinned publisher signs its timestamp, nonce, exact envelope hash
and target replica id. PMP2 retains a legacy-count byte and two fixed legacy-replica slots solely
for its fixed header layout; clean-break v2 requires the count and all 64 slot bytes to be zero.
XNode accepts the target only when it is present in the verified PSS2 old or new selections. The
host also enforces the inverse listener rule: the PMP2 route returns 404
on the public API listener and is reachable only on the configured peer RPC port. The envelope
always contains exact PMA1/PMR1/PMT1/current+next PMS1/PSS2/PRC1/RTC1 and tagged
Owner(PRA2) or Delegated(active RCH1 + RCA1) authorization. Protocol's cache-only verifier checks
the closure; no client activation capability or RCD1/RDA1/RCR1/RHB1/RHC1 material is accepted.

Before a proactive rotation sweep, Registry reserves conservative capacity through peer-only
`POST /api/peer/production-mailbox/closure-capacity`. The request is an exact 208-byte PMB1
publisher-signed reserve/renew/release command bound to a random opaque cohort id, target replica,
monotonic revision, expiry, count and bytes. XNode returns an exact 248-byte PMB2 receipt signed by
the target node. PMP2 is a clean-break 280-byte header and binds the same cohort id, verified
transition mode and lineage commitment; a zero cohort
is allowed only for ordinary unreserved publication, while a non-zero cohort atomically transfers
the positive cardinality-one closure count/byte delta from unused reservation headroom to actual store usage.
The byte charge includes the configured conservative per-closure filesystem overhead.
Exact command and closure replay never double-charge. Renewal cannot reduce already consumed
capacity; release or expiry frees only unused balance, and actual closures remain charged until
their ordinary safe expiry GC. The HMAC ledger is only a rebuildable cache. Each cohort has a
content-addressed PBF1 floor containing the complete authoritative reservation state, monotonic
state generation and predecessor marker hash; startup rejects marker forks and rebuilds any stale
or replayed ledger from the highest exact chain. PBT2 binds selection, durable old-PMS hash,
lineage commitment, old/new closure hashes and before/after
floor hashes/generations and recovers in journal→closure→floor→ledger order. A bounded terminal
floor is retained after release/expiry before deletion, so recently replayed pre-release ledgers
cannot restore headroom. Full rollback of the complete protected closure directory beyond that
tombstone retention remains an operator/storage-integrity boundary and is not a hardware monotonic
counter guarantee. Registry must keep fresh PMB2 receipts from every required replica with its configured
renewal margin; expiry or renewal failure freezes further cohort publication rather than admitting
part of a rotation.

PMB1 freshness is required for every mutation. After publisher signature and exact target
verification, an exact command hash that is already the authoritative cohort floor may recover its
byte-identical PMB2 after PMB1 expiry or restart. This is a read-only lost-response path: it does
not extend expiry, change counters, renew or resurrect released capacity. Unknown, changed,
same-revision-fork and superseded expired commands are rejected coarsely.

If an unreleased reservation has already auto-expired into a terminal floor, the node accepts only
its authenticated exact revision-successor Release. The returned PMB2 binds that Release command,
reports reserved equal to consumed, preserves every actual closure charge, and cannot renew or
resurrect capacity. This lets Registry finish durable post-cutover cleanup after a long outage.

If Registry remains unavailable until the bounded terminal floor is garbage-collected, it uses the
peer-only constant-path `POST /api/peer/production-mailbox/closure-capacity-reconciliation`. The
exact 504-byte publisher-signed PMB3 embeds the last exact node-signed PMB2 and binds cohort,
target, revision and command/receipt hashes. XNode returns an exact 272-byte node-signed PMB4
`AbsentTerminal` only after a read-only authoritative floor/ledger/`.pmcs2` accounting check under
the process lock. A live floor, pending transfer, invalid prior receipt, fork, corrupt ledger or
stale accounting returns a coarse 400. The endpoint never reserves, releases, renews or extends
capacity, is peer-listener-only and returns `Cache-Control: no-store`.

Each route lineage occupies one bounded cardinality-one `closure.pmcs2` under sharded
HMAC(selection commitment)/HMAC(selection commitment + durable old-PMS hash + lineage commitment)
directories, so
neither stable value is present in filesystem names. Different devices at different durable old-PMS
anchors can coexist and PMQ2 selects one exact lineage. Exact byte replay is idempotent. A distinct
commitment for the same retained old-PMS lineage represents another device/ROL lineage and is
allowed only within the configured per-selection cap. Every candidate preserves the exact
network, owner, blinded route, selection commitment and durable old-PMS/authority/topology anchor.
Forks, renamed cross-route files and commands for another replica fail
closed under an in-process gate plus a native cross-process store lock. Fetch acquires that same
lock and completes any pending PBT2 recovery before stable-read/response, so another process cannot
serve a closure between journal, file, floor, ledger or parent-flush durability phases. Lock wait is
cancellable and bounded to five seconds. The lock is released after the stable owned snapshot;
Protocol verification then runs under only the lineage stripe, avoiding cross-lineage head-of-line
blocking, and time windows are rechecked before response. Two XNode processes must
not normally share a closure directory, but if they do, the lock serializes reconciliation and
cardinality-one insertion rather than allowing the last writer to win.
Startup and every mutation reconcile count and bytes through stable no-follow handles, reject
unsafe/reparse/identity-swapped files, and refuse stores above both configured
caps. Fetch returns only the exact commitment within Protocol's hard cache window (the minimum of
all authenticated artifact expiries), never serves a future entry early, and converts expected
Protocol parse/verification failures to a coarse miss. Startup globally removes expired `.pmcs2`
files using count-derived bounded snapshots.
Mutation performs selection-local expiry compaction first and runs the global expired scan only on
count/byte pressure; an ambiguous file or directory delete/parent flush fails the attempt and the
next locked reconciliation resumes from exact disk state. Empty lineage/selection/shard directories
are removed durably, and startup bounds then sweeps the empty tree deepest-first; an over-bound tree
fails closed for operator inspection. A live closure is never evicted. Clients
still perform full PSS/LKG verification and do not trust the cache.
An orphan `*.tmp` atomic-write file makes startup fail closed instead of disappearing from byte
accounting. Inspect the interrupted write and remove the orphan only after confirming the adjacent
canonical route file is intact; restart then performs a fresh authoritative scan.

`maximumClosureLineagesPerSelection` separately bounds simultaneous device/LKG anchors for the
same stable selection commitment; exceeding it fails before any new closure is written.

After the complete bundle verifies, diagnostics report `authorityRevocationReady=true`,
`topologyArtifactVerified=true`, and `productionMailboxRoutesReady=true`. Each mailbox operation
still fails closed unless its own commitment-named PMS1 verifies for the requested blinded
placement. The runtime recomputes rendezvous ranking, requires exactly two distinct replicas and
canonical MIP1/RIP1 proofs, binds the proof route to the PMT HTTPS origin, and enforces the current
or next SPKI pin during TLS. Raw mailbox identifiers, selection inputs and replica IDs are not
logged or exposed. Official-managed PMA1 still requires public HTTPS; explicit user-managed
private-HTTPS policy remains supported.

Client HTTP is binary-only:

| Operation | POST route | MAU2 inner body | Request bytes | Success response | Success |
|---|---|---|---:|---|---:|
| Store | `/api/client/mailbox/v2/store` | MEO1 | 608..82344 | `application/vnd.deep.mailbox.mqr3` | 200 |
| Retrieve | `/api/client/mailbox/v2/retrieve` | MBR2 | 536..792 | `application/vnd.deep.mailbox.mrp1` | 200 |
| Acknowledge | `/api/client/mailbox/v2/acknowledge` | MBA2 | 576..4792 | `application/vnd.deep.mailbox.mar1` | 200 |

All three request media types are `application/vnd.deep.mailbox.mau2`.

Failures have empty bodies: malformed 400, authentication 401, authorization 403, replay/
idempotency conflict 409, missing length 411, too large 413, media type/encoding 415, admission
429, dependency/quorum unavailable 503, and deadline 504. Exact byte limits, deadlines and
admission ceilings come from `MailboxWireHttpContract`.

The active privacy-routing and native mailbox protocol closure is locked under
`vendor/production-privacy-e75bfed/packages`:

- `Deep.Protocol.0.5.0-production.e75bfed.nupkg` —
  `69578c00c503383b149c4e9bccb3f14f87d3608c9781fe684710233059060098`
- `Deep.Protocol.MembershipRoutes.0.5.0-production.e75bfed.nupkg` —
  `5dacdef966835452ffa2c0a404dac72524b508ebeffa3f44b79d5d290c2de75e`

Core/runtime/test projects restore the exact version from the local feed in locked mode.
`XNode.ProfileGenerator` and its tests use a separate frozen DNP1 closure under
`vendor/dnp1-survival-9a7eaed`. Its exact protocol inventory is
`Deep.Protocol`, `Deep.Protocol.MembershipRoutes`, and
`Deep.Protocol.ProfileCarrier`, all pinned to `0.5.0-survival.9a7eaed` from
protocol commit `9a7eaed337286758ab43bd3706457264c3be7c55`.
Every nuspec dependency uses an exact bracket range. The resulting runtime
dependency set contains only `Sodium.Core` and `libsodium`; the former
`Deep.Protocol.Abstractions`, `Deep.Protocol.Protobuf`, and `Google.Protobuf`
dependencies are not part of the active graph. `Deep.Protocol*` can restore
only from the repository-local feed selected by `eng/dnp1-survival.NuGet.Config`;
the production runtime remains isolated on `eng/survival-beta.NuGet.Config`.
Run `eng/Verify-Dnp1ProtocolClosure.ps1` before building the generator; it
fails closed on package inventory, bytes, provenance, dependency edges,
project pins, lock files, or source mapping drift.

The native MAU2 client adapter is active when the validated mailbox-client activation plan maps
the development routes documented above. Startup remains fail-closed until the peer runtime,
authenticated capability runtime, operation ledger, and native adapter all report ready.

The active replay journal is stored below
`<Node.DataDirectory>/mailbox-capability-replay-v3/replay.json`, which resolves to the existing
`/state` volume in survival containers. It uses an exclusive process lease, same-directory
write-through replacement and file/parent durability barriers. A crash after reservation leaves
an explicit `Pending` record; it is never silently retried as new, and only recovery with the
exact claim can complete it. Diagnostics expose counts only, never issuer, serial, operation,
request or capability bytes.

### Contact route closure and recipient evidence

The canonical route closure is part of the threshold-authorized XPU1
publication and is durably replicated with the opaque DCR ciphertext. Resolve
returns those exact published bytes; XNode never sends a contact locator to
Registry and production startup has no `ContactRouteClosure` Registry adapter.
The permanent resolve response includes two authenticated `resolve-read`
receipts, while a one-time resolve includes the existing durable claim receipts.

The DID2 host no longer reads the former V1 recipient-evidence cache.
`ContactService` configuration is closed: the removed recipient-evidence limits
and all unknown fields reject startup. Rebuild and repin the complete DID2
consumer graph before activation; there is no old-cache reader or migration.
See [DR-0069](../../docs/survival-program/decisions/DR-0069-did2-retired-identity-surface-removal.md).

Side-effect-free post-verification cancellation may instead persist `Released`. This is not a
deletion: the counter floor and exact claim digest survive restart, exact retry can reserve it
again, lower and same-counter conflicting claims remain rejected, and only a higher counter can
advance. Records are collected only after grant/authoritative epoch validity plus the fixed
seven-day replay-retention interval. A host background worker processes at most 1024 entries per
minute. It durably marks a bounded replay batch expired first, removes only the exact matching
canonical outcomes, and then finalizes those replay markers. Interrupted batches resume safely
after restart, and the equality boundary remains retained. Diagnostics include Pending,
Completed, Released and remaining-capacity counts. Long-lived issuer-key validity does not pin
expired individual grants, and issuer authorities must never reuse a capability serial.

Replay schema v3 also stores the accepted wall-clock high-watermark. Capability validity and
collection use `max(observedTime, durableFloor)`, and the floor never decreases. Rollback up to
60 seconds is absorbed by the floor; larger rollback rejects capability verification until the
clock recovers. Because the messenger is pre-production, older replay schemas are rejected
unchanged rather than migrated.

For MBR2 and MBA2, cryptographic capability verification occurs before delivery admission,
replica-authority selection, continuation processing, or mailbox-specific ledger/blob access.
Therefore a forged but canonically framed request cannot probe mailbox presence or spend storage
I/O. Cancellation before the first durable effect releases only a new reservation. Cancellation
after ACK reservation, local storage, or peer mutation preserves Pending; exact restart retry
resumes the ledger and completes replay without duplicating remote work.
