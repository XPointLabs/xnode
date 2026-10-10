# Operator Guide

## Current native mailbox admission candidate

The S01 retained-route storage candidate now commits private read-route custody
with each exact verified XPA1 publication. Public DCR predecessor cleanup does
not erase it. Its bounded typed lookup is not wired as renewed grant issuance;
current Resolve/Deposit and their deadlines remain unchanged. The sole contract
is [CONTACT-RESOLVER §3.7.2](../../docs/architecture/CONTACT-RESOLVER-V1.md#372-independent-retained-read-custody).
Opaque resolver state is generation5: an older or incomplete state fails closed
with quarantine, not migration or empty recovery. Do not reset production data
or registered node identities to activate this source candidate. File integrity
is not a protected rollback floor, and quota exhaustion is backpressure rather
than permission to evict outstanding read paths. See the
[source qualification](testing/s01-retained-route-custody-2026-10-07.md).

The subsequent DR-0103 native checkpoint candidate protects that same resolver
document with a separate node/network-bound enrollment and checkpoint. It uses
an explicitly provisioned persistent Data Protection key ring and purpose
separation; preserve the document, independent custody and original key ring
together for recovery. A missing checkpoint/key, data-only rollback or foreign
scope fails closed. No startup import, reenrollment or temporary-file adoption
is permitted. Joint rollback of matching data and root remains outside its
guarantee. The enabled DID2 resolver now requires protected custody in its native
composition, without unprotected fallback. This is still an unqualified source
candidate: do not activate or reset existing production data to try it.
Its focused tests do not qualify retained issuance or physical
Retrieve/ACK. See the [candidate receipt](testing/s01-protected-retained-route-2026-10-07.md).

The DR-0104 peer producer candidate adds private retained read/signing using the
same real protected document. The enabled DID2 peer composition requires its
actual current-source owner: missing admission, native root/data loss, a changed
snapshot, wrong signing key or expired request cannot return a retained signature.
This is not an operator import/reenrollment path and adds no public operation.
Public grant acquisition and physical Retrieve/ACK remain gated; do not reset
registered identities or existing state to enable the candidate. See its
[exact verification scope](testing/s01-retained-native-peer-2026-10-07.md).

The matched private HTTPS boundary now requires explicit evidence kind and
retained horizon, using the independent DR-0104 forwarding purpose. Deploying
only one side of the Node/Registry private JSON cutover is unsupported. At the
`8607c60` checkpoint public grant dispatch was current-only; that checkpoint is not automatic retained fallback or
permission to reset identities, floors or journals. Current source qualification
and its remaining activation boundaries are recorded in the
[matched private-boundary receipt](testing/s01-retained-private-forwarding-2026-10-07.md).

The next coupled source batch now selects protected retained custody for public
Retrieve from the outset; Deposit stays current-only. It checks both native
stores over the authenticated peer, issues independent receipts and rechecks
local custody/current source around private issuance and response release.
Current Shared/Node full source matrices and required isolated infrastructure
checks pass; matching Protocol source qualification preserves its shipping FAIL.
Registry connected qualification and complete shipping/installed boundaries are
still required. These results do not authorize automatic runtime activation.
[Current source follow-up](testing/s01-retained-private-forwarding-2026-10-07.md#coupled-public-retrieve-follow-up).

`ContactResolverCustody` contains only local bindings: canonical public
`networkIdHex`, absolute `independentCustodyDirectory` and existing persistent
`dataProtectionKeysDirectory`. The data, checkpoint and key-ring directories
must be disjoint and non-root; these settings are mandatory when the DID2
resolver is enabled, including on a contact-only node. Configuration is never
membership/time authority. Key generation is disabled on every reader; the
application purpose is separate from mailbox-operation custody even if an
operator uses the same explicitly provisioned persistent key ring.

For a genuinely new resolver scope only, under the node's normal configuration:

```sh
dotnet XNode.dll contact-resolver-enroll
```

This bounded non-listening command restores the actual configured DID2 proof,
acquires independent network observation, verifies current network/root/PMA2
and local descriptor signing custody, then creates the canonical empty resolver
document and its independent enrollment/checkpoint. It rechecks actual source
history, current authority/time and exact read-back before reporting success.
Existing documents, interrupted roots, missing keys, foreign scope or authority
loss reject; partial custody is preserved. There are no import/reset arguments,
node-identity generation or automatic startup enrollment. Back up the complete
coherent custody; never delete its root to make an existing document enrollable.
The command cannot issue/renew a grant or authorize an object ACK/deletion.

`CurrentMailboxAdmission` connects the closed current network/PMA2 host verifier
to both restored native MGR1 owners and the existing durable replay/outcome
stores. The bounded operation owns captured MAU3 bytes and selected canonical
node facts; it rechecks current source, protected time and actual role revocation
before reservation and across the callback/result boundary. Holder/body rejection
does not advance the replay time floor. Expiry, cancellation or unavailable
authority after reservation retains exact Pending custody.

Windows MGR1 and operation-custody reads now inspect entry attributes instead
of resolving every ordinary ancestor's link target. Every read still checks the
full ancestor chain without a cache, rejects reparse points (including dangling
links), and propagates access failures. This changes no custody format, ACL,
enrollment, grant/replay check or Store deadline. Source qualification is tracked
in [the S01 path checkpoint](testing/s01-native-store-path-safety-2026-10-08.md).

The same protected operation now also guards `CurrentMailboxReplicaReceiver`:
current grant-bound peer verification, native replay, blob mutation/read-back,
tombstone and descriptor-key receipt. Restoring its peer replay journal no
longer collects custody using host UTC. Both selected proofs must bind the
actual current host; no retired proof verifier is used on this path.

The current peer HTTP endpoint/client and sender coordinator now share this
protected owner. The client connects only to the selected descriptor's exact
TLS origin/current SPKI; quorum requires two independently verified receipts.
A lost remote response retains sender Pending and can reconcile on exact retry
after reopening both stores. Unsupported transport or authority loss is not a
fallback. Endpoint errors are bounded empty-body responses without private logs.

`NativeMailboxExitDispatcher` now calls the same current receiver/coordinator
and its required protected operation ledger for Store/Retrieve/ACK. It does not
resolve the retired adapter, raw authority source or old readiness flag. A missing
current pair is rejected before dispatch; a split pair cannot mutate either owner.
Ingress and authenticated-holder budgets use monotonic resource time only.
Partial quorum, callback/expiry or custody failures suppress success and retain
exact unknown work; an exception is not proof of absence of a remote effect.
Program now registers one current owner graph for explicitly configured local
mailbox custody. Do not enable the retired provider as a bridge. Program runs current
host-only native recovery at startup and afresh in `/health/ready`; an enabled
mailbox without the actual current receiver/coordinator stays unready. This hook
now rereads the mutation/blob inventory, peer replay and client replay/outcome
dependencies under the same held current host/role owners. Missing live completed
blobs, orphan/resurrected blobs, corrupt records, missing indexed custody and a
completed replay without its exact canonical outcome keep readiness closed.
These checks do not collect, repair, re-enroll or dispatch work. Pending prefixes
remain available for the original exact retry. See the custody configuration
below; retained-route, signed retirement and object-horizon gates remain required.
The dedicated peer listener no longer permits retired authority-forwarding paths.
The retired forwarding client, HTTP handler, authentication/replay/configuration
types and routed dispatcher have also been removed from the node assembly.
Do not configure an authority-forwarding node or relay raw client requests to a
second admission server: the selected exit admits through the current native
owner. The retired configuration section still rejects, even when empty.
Current binary replication remains HTTPS-only on its exact configured listener;
API/public client mailbox URLs are not an alternate admission path. The
[Program pipeline checkpoint](testing/s02-current-program-2026-10-04.md#actual-program-peer-pipeline-follow-up)
records actual local Kestrel/TLS evidence and its fixture/provisioning limits.
See the [native terminal checkpoint](testing/s02-native-terminal-2026-10-04.md)
for the precise local three-hop/current two-store evidence, not device qualification.
The matching
[descriptor-key checkpoint](testing/s03-descriptor-keys-2026-10-04.md) now
exercises genuinely separate node IDs and immutable descriptor identity keys
through the current producer and native consumer, not fabricated rotation.
Signing custody must match that actual descriptor key; a node ID is never
a key or signing seed. This also applies to HTTP onion peer authentication:
the forwarding runtime supplies its verified network context; signing custody
and inbound signatures resolve the identity key from the current signed XND1.
Missing current authority rejects before peer replay acceptance. Configured
peer IDs/pins do not authorize an identity key, and there is no ID-as-key fallback.
Two-store loopback HTTP evidence is not deployed, onion or physical
client delivery evidence. Internal client Store now binds captured MAU3 to the
exact peer request under the same native admission owner and persists final
canonical MQR3 in the existing outcome store. Retry after advancing time/reopen
returns those bytes; replay after tombstone does not rewrite the deleted blob.
Loss of a peer response retains both client and peer Pending. There is no new
quorum journal, public wire field, authority adapter or activation switch.
The current internal Store producer now owns a durable random nonce and complete
signed peer frame in the existing operation ledger before any peer effect.
Reopening retains those exact bytes; known replay or existing mutation custody
without its intent rejects instead of reminting. The local ledger is schema 7;
older schemas 3/4/5/6 or malformed state reject without migration or automatic reset.
The same independently anchored document now retains current client replay
scope/counter/claim floors and completed outcome digests for Store/Retrieve/ACK.
Reservation floors precede operation effects; completion digests precede a
successful response. Startup and current admission reject missing/older native
replay against these floors, including joint replay/outcome loss after cold open.
An unanchored higher native Pending can be retried only through ordinary current
authentication; recovery does not promote it or initialize lost state. These
floors are not collected by current native reads or working-set compaction.
Bounded floor capacity remains backpressure; retirement/lifecycle activation
belongs to its subsequent stage. This clean break is not deployed automatically:
an old document remains unready, without resetting operator keys or enrollment.
This is not another journal or a production data/key reset. Current reservations
do not use host UTC for garbage collection; capacity remains backpressure until
protected retention is composed. A pre-intent write failure can remain Pending;
there is no claim of automatic reconciliation for that uncertainty.
The current operation document now has
[independent protected custody](mailbox-operation-custody.md). Native startup
uses current host/both role leases without a client grant. Missing data is not
fresh provisioning; the native receiver now requires this owner for
Store/Retrieve/ACK and peer Store/tombstone, including completed replay.
Holder/peer authentication and actual local descriptor signing custody precede
recovery/replay; callback/result checks cannot release a page or receipt after
operation custody loss. Missing/malformed local operation data at the current
peer HTTP endpoint returns bodyless 503, preserving state. Only an
authenticated pending replacement can recover exact bytes. Unknown pre-plan
writes still cannot remint a known request. The actual startup/readiness hook now
uses this same non-enrolling recovery; it does not qualify global recovery,
retirement or deployed provisioning. The linked owner
defines the consistent backup and local anti-rollback limits.
The current Store producer also retains the exact authenticated MQR3 in that
same operation ledger. A new Store in the same epoch/mailbox/placement/membership
cannot pass an unsettled earlier intent, even under a different signed grant or
before a mutation file exists. Original retry can restore settlement from the
native client outcome without another peer write. Saved quorum bytes are checked
against the complete signed intent, independently current projection/issuer and
descriptor identity keys before a later cursor is allocated. Expired former
grants do not become current admission authority through this verification.
Unsigned state, hostile receipts and unavailable history remain backpressure.
The internal candidate now enforces the authenticated PMS2 writer under
[DR-0086](../../docs/survival-program/decisions/DR-0086-current-mailbox-store-order.md):
only the ranked first node admits client Store or authors Store intent, and both
peer roles reject a different Store sender before native replay/mutation. The
matching Shared client keeps Store's writer exit across primary/fallback attempts.
Retrieve/ACK remain available on either replica; a node never reroutes a sealed
client request. Complete Program activation/global recovery, retained projection history
and signed expiry retirement remain gated. Current Store intents are not collected
by host-UTC startup GC. This is not physical delivery or release qualification.
Ledger initialization now avoids host UTC entirely for current-only Store/ACK
custody; the neutral collector cannot delete current ACK intents either. Before
client Store replay for a new operation, the ledger checks every retained native
mutation in the exact authenticated mailbox scope against its saved intent,
cursor, nonce and body. An existing exact retry checks its own native cursor
without allocating another one; unrelated damage cannot replace its intent or
prevent that bounded reconciliation. Missing/rolled-back intent blocks new work
even for a new grant/operation. Pending, completed, expired and tombstoned native
records are not filtered out.
Native mutation metadata is only a rejection fence, never quorum evidence or
permission to reconstruct a missing intent. Restore exact coherent custody;
do not delete independent records or initialize a new counter to clear unready.
This scoped recovery check does not detect loss of an intent before any native
mutation, nor qualify global startup/rollback protection or retained-route
ordering. Those remain activation blockers. See the
[recovery checkpoint](testing/s03-store-recovery-2026-10-04.md).
Internal client Retrieve now reads the actual completed mutation/blob custody
on either replica under that same current admission, without requiring the
coordinator's client ledger. It persists the canonical MRP1 in the existing
outcome owner before releasing it. The existing neutral continuation grammar
is signed/verified with selected descriptor keys and protected time; pagination
can continue on the other replica. Missing/corrupt blobs, unresolved Store and
ambiguous cursors fail closed rather than silently omitting retained messages.
An actual continuation from the other replica also rejects live Pending Store
custody below its consumed cursor. Exact Store completion permits read retry,
but only a fresh snapshot can include a late lower-cursor message; this local
guard is not shared cursor ownership or a no-loss snapshot guarantee.
Native mutation counts include a file that persisted before its flush reported
failure, even without reopening the owner. This is local candidate evidence,
not an activated public endpoint or global cursor-order guarantee.
Internal client ACK now captures the entire signed tombstone batch in that same
operation ledger before any peer effect. Native completed mutation records on
either replica supply the targets; a coordinator client Store ledger is not
required on the receiving replica. Every item needs two actual authenticated
replica receipts, saved before the canonical MAR1 aggregate is persisted in the
existing client outcome store. Lost responses or interruptions retain the exact
intent; retry never remints a peer nonce or resurrects a deleted blob.
Pagination expiry still rejects new work. Exact saved ACK intent and Retrieve
outcome recovery do not depend on a still-live page token, but always require
independently current grant/time, both restored revocation floors and native
request binding; ACK also revalidates each original peer request/quorum.
Missing intent, changed request or unavailable current authority fails closed.
The cursor is still per-coordinator, not globally ordered across the two exits.
Cross-coordinator cursor ownership, late completion below a snapshot boundary,
and guarded startup/recovery need connection before the atomic
Program cutover. Retained-route/old-epoch Retrieve remains unfinished.
The trusted monotonic clock must be the same protected owner used by the actual
network source when composing this candidate. No host-UTC fallback is accepted.
The sole contracts remain
[DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md)
and [DR-0083](../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
See the [native connected checkpoint](testing/s02-current-mailbox-admission-2026-10-03.md).
The [current peer checkpoint](testing/s03-current-peer-native-2026-10-03.md)
records durable Store/read/tombstone/reopen and callback-expiry tests.
The [HTTP checkpoint](testing/s03-current-peer-http-2026-10-03.md) records actual
pinned TLS/HTTP2, two-store quorum, lost-response and concurrent-retry evidence.
The [client outcome checkpoint](testing/s03-client-outcome-2026-10-03.md) records
same-owner composition, durable final Store outcome and completion-write recovery.
The [server intent checkpoint](testing/s03-server-intent-2026-10-04.md) records
actual producer custody, crash/capacity/hostile-input boundaries and final gates.
The [current Retrieve checkpoint](testing/s03-current-retrieve-2026-10-04.md)
records both-replica reads, bounded cross-replica pagination, native custody
failure checks and the remaining ordering/activation boundaries.
The [current ACK checkpoint](testing/s03-current-ack-2026-10-04.md) records
either-replica ACK, exact batch/quorum recovery, capacity and crash boundaries.
The [pending-prefix regression](testing/s03-pending-prefix-2026-10-04.md) records
the live/reopened cross-replica continuation defect, fix and its ordering limits.
The descriptor transport API owner is
[DR-0085](../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).

## Mailbox ingress operation binding

The native Store/Retrieve/ACK dispatcher captures the bounded exact MAU3 bytes
and, within the existing ingress rate/concurrency budget, checks the canonical
inner operation against the outer ONION operation before resolving issuer
authority or reserving durable replay. Malformed or
cross-operation input returns the existing empty-body 400 response. Dependency
callbacks cannot replace the captured request with different caller-buffer bytes.
This structural check grants no issuer, holder, selected-exit or mutation authority;
the remaining checks and fail-closed readiness are unchanged. It is not activation
of the current mailbox composition required by
[DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md).
See the [ingress regression checkpoint](testing/s00-mailbox-ingress-binding-2026-10-03.md).

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
The forwarding node ID is an opaque descriptor identity, not its Ed25519 public
key. The grant client requires the locally verified ResolveInvite placement for
the exact locator and checks its signing seed against that descriptor before
HTTP; the JSON admission still carries the actual node ID. The private route/
publication backend likewise checks its seed against the independently verified
network supplied by the selected gateway. DR-0048's `Deep-Coordination-Node`
header remains the public signing key (and its operator allow-list remains
mandatory); it is not replaced by an ID. Neither transcript or endpoint changes.
Both clients recheck the verified network around the HTTP response. These local
checks do not provision Registry ingress, signer custody or deployed endpoints.
This opt-in composition is not production activation or device delivery evidence.

The acquisition consumer now follows
[DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md)
and accepts only the current bounded XMC2 result paired to the exact XMG2.
Old result magic/length, malformed records, foreign operation bindings,
compressed/truncated/trailing HTTP bodies and foreign media types reject.
Protocol independently verifies the enclosed route/selector/issuer authority;
HTTP parsing alone does not authorize a grant. Rebuild Registry/node/client
and provision the matching signed successors together. Node mailbox admission,
peer mutation and physical delivery remain separate activation gates.

The request clean break is governed by
[DR-0102](../../docs/survival-program/decisions/DR-0102-exact-mailbox-request-route-binding.md).
Both private coordination JSON and ONION operation4 use only the new request;
the retired request/JSON field is rejected, not converted. Retained lookup now
uses the holder-signed exact route hash, never a newest-route guess. Rebuild and
repin Registry, Protocol and Shared/client consumers together before activation.
No node-state generation, registered key, certbot configuration or object TTL
changes in this increment. Exact lookup still does not establish protected
retained authority, renewed issuance or physical Retrieve/ACK. See the
[source checkpoint](testing/s01-exact-request-binding-2026-10-07.md).

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
Publication envelopes also require the matched V4-only rebuild under
[DR89](../../docs/survival-program/decisions/DR-0089-did2-one-time-publication-coordination.md)
and [publication journal provision](../../deep-registry-api/docs/DID2_PUBLICATION_COORDINATION.md).
The full node signature covers the enclosed publisher-bound prior receipts and
public locator. XPA admission accepts exact kind2/usage1 genesis as well as
reusable genesis; it does not grant a one-time successor or bypass placement,
witness, protected time or claim replay checks.
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
error containment, not identification of the process responsible for intermittent
Windows access-denied errors or permission to weaken storage ACLs.

The native Windows replacement barrier now makes at most four attempts to move
the **same already flushed temporary file** with unchanged replace/write-through
flags. Only native access/sharing/lock errors (5/32/33) with the source still
present permit the three bounded waits (10/20/40 ms). It never recreates a missing
source, clears protection, changes ACLs or infers success from a destination file.
Persistent denial and every other error still throw; the caller's read-back,
uncertainty and exact-operation recovery obligations remain unchanged. Unix
replacement and logical deletion behavior are unchanged. This is local storage
retry, not grant renewal or another remotely issued/signed operation.

Native prekey custody also distinguishes an unavailable read from a proven
corrupt snapshot. I/O or access failure before capture of the bounded snapshot
rejects the operation without creating a corruption latch or moving authenticated
state to quarantine. Once access is restored, every signature/scope check still
runs; the original reservation and completed result can exact-replay, including
after restart. Invalid captured records and missing activated custody still
reject with persistent fault/quarantine. Do not reset inventory or keys to
recover from a file lock. This distinction does not diagnose or eliminate the
earlier intermittent native replacement access-denied failure.

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
Program binds one keyed native owner for each role through CurrentMailboxCustody.
There is no raw revocation HTTP authority or admission fallback. Explicit signed
provisioning and issuer renewal remain activation prerequisites.

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

Direct `/api/client/mailbox/v2/store`, `/retrieve`, and `/acknowledge` HTTP routes are not mapped. The selected exit opens the final privacy layer and invokes the current MAU3 admission, durable outcome/operation owners and two-replica PRQ2/MQR3 runtime in process. There is no retired forwarding-only authority bridge.

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

### Current selected mailbox exits

The selected pair and ranked writer come from verified PMA2/PMT2 and the signed
MCG3 selector. Privacy terminal dispatch calls the local current receiver and
coordinator; there is no PMA1 single-coordinator forwarding bridge. See
[the current network owner](../../docs/architecture/XPOINT-NETWORK-V1.md) and the
current custody configuration below. Retired forwarding sections are rejected.

The old PMA1/PMR1 authority provider, PMC2 closure cache/preposition surface and
single-coordinator replica fanout are also removed from the compiled node.
`MailboxClientProductionAuthority` remains rejected, including an empty section;
it cannot reactivate a dormant legacy provider. Provision and recover only the
current DID2 authority/custody graph. This source removal does not authorize
deleting installed keys, independent floors, journals or retained volumes.


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

## Current mailbox host composition candidate

The actual Program registers one current native graph when Mailbox is enabled.
The same receiver, operation ledger and coordinator serve ONION client
Store/Retrieve/ACK and descriptor-bound TLS/H2 peer Store/tombstone. The default
remains disabled. Development/UAT network-source restrictions remain intact:
this composition does not provide production authority or qualify activation.

```json
{
  "Mailbox": { "enabled": false },
  "CurrentMailboxCustody": {
    "networkIdHex": "",
    "mailboxAuthorityCoreHashHex": "",
    "independentCustodyDirectory": "",
    "dataProtectionKeysDirectory": ""
  }
}
```

While disabled all four bindings must be empty. For a reviewed local enabled
composition, networkIdHex is a nonzero canonical lowercase 16-byte public network
binding; mailboxAuthorityCoreHashHex is the exact nonzero 32-byte PMA2 core hash.
These are local protection contexts, not issuance or currentness authority.
Data, independent custody and the existing key ring must be absolute non-root,
mutually disjoint directories. Ancestor/descendant aliases are rejected.

The protected application is `XPoint.XNode.Mailbox.Custody.v1`. The reader
requires an existing unlinked key ring with restricted regular key files and
disables automatic generation. Explicit trusted provisioning of both signed
MGR1 roles and the operation document is separate from startup. Missing,
incompatible or rolled-back custody stays unavailable; startup neither enrolls
nor repairs it. Node signing seed must match the current descriptor's key, not
the node ID. Retain consistent backups of data, independent roots and key ring;
local files cannot detect joint rollback of all three.

For a genuinely new reviewed Development/UAT node scope, the explicit command
uses the same configuration, current network/proof source and native owners as
Program, without starting HTTP listeners or hosted services:

```sh
dotnet XNode.dll current-mailbox-enroll --deposit-mgr1-file /run/node-control/deposit.mgr1 --retrieve-mgr1-file /run/node-control/retrieve.mgr1
```

Inputs must be absolute, regular, unlinked files containing exact signed MGR1
fresh current snapshots for the two configured roles, including a later issuer
generation when the shared genesis has expired. Initial pinning and existing-floor
transitions follow [DR-0083](../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
This does not permit skipping history or resetting an existing floor. Existing node identity, matching
descriptor signing custody, an independently observed current network closure
and the separately provisioned restricted mailbox key ring are mandatory. The
command does not create role signatures, keys, identity or fabricated trust.
After owning both bounded inputs, it explicitly restores the DID2 head and
acquires a nonce-bound proof for the configured public observer through the
actual Registry HTTPS source, verifies the signed closure and commits the
protected network floor. This acquisition is part of the operator command;
ordinary readiness/admission remains observational and cannot bootstrap a cold
source. Invalid grammar or pre-cancellation rejects before acquisition.
Existing production source restrictions are unchanged; this is not production
activation. Configuration comes from the normal appsettings/environment inputs;
additional command-line switches and reset options reject.

Before writing either protected role, the command validates both signed inputs,
actual signing custody and that the operation document and its independent root
are genuinely new. It also requires empty native blob, mutation, peer/client
replay and canonical-outcome custody, apart from the actual empty owner locks.
The native-state refusal runs before proof acquisition and is repeated after
authority callbacks, before role enrollment. Even a valid empty replay document,
an unknown file or an empty child directory is existing state, not new custody.
Opening the replay/mutation/outcome readers no longer deletes `.tmp`/`.deleted`
files: interrupted files are preserved, never adopted by enrollment.
Unknown or interrupted protection rejects. Writers repeat
their checks, then enroll both roles and the existing operation document and
perform normal host recovery. There is a 30-second cooperative command budget.
The operation is not a multi-file transaction: any failure can leave partial
state that stays unready. Preserve it; do not rerun as recovery, erase records,
or re-enroll an existing node. Public output contains only a closed success/error
message, not exceptions, identifiers or private paths. Normal startup still never
calls enrollment.

A successful command is only an initial local enrollment. Issuer-authored signed
successors and their distributor must maintain current role freshness; enrollment
does not lengthen the MGR1 interval or close the S05 renewal gate. Registry's
candidate now authors and distributes retained signed successors; configured
production provisioning and connected issuer-to-node-to-client qualification
remain unfinished. See
[operation custody](mailbox-operation-custody.md) for the retained-data contract.

### Bounded current revocation refresh

The existing configured DID2 proof-source graph also registers a background
consumer of the signed control transport in
[CONTACT-RESOLVER §3.8](../../docs/architecture/CONTACT-RESOLVER-V1.md#38-current-mailbox-grant-revocation).
It uses the existing strict Registry HTTPS client: no redirect, decompression,
TLS bypass or direct shipping-client fallback. Fixture-owned source graphs do
not enable this worker. Existing production source restrictions are unchanged.

Both protected role floors must restore before a remote read. Refresh verifies
a fresh signed target under the actual complete current host, then installs one
verified successor at a time through the same native owner and read-back. A
30-second flight commits at most 64 steps per role; unfinished history resumes
from its durable floor next time. Expired intermediates provide no admission.
Missing protection, gaps, source changes and invalid signatures cannot trigger
enrollment, floor reset, pruning or key generation. A network failure leaves the
worker running with bounded backoff; successful attempts delay 15–17 seconds,
failures 10–62 seconds. Stop cancels the attempt and delay.

This is locally tested actual Registry HTTPS-producer/configured-node/native
integration on synthetic owned inputs, not a deployed Registry-to-node or
physical client result. The node's authority/admission reads
now observe a previously acquired observer proof: they reverify the actual
signed closure, PMA2, directory custody, independent network floor and monotonic
interval without fetching a nonce or committing a successor. The existing ONION
receive refresh and the explicit non-listening enrollment command acquire that
observation; cold or failed acquisition does not
let readiness bootstrap it. Missing directory index/anchor is unavailable on
this read path, not permission to repair. Source/floor changes, clock rollback,
expiry and host stop clear the observation; no TTL extension or enrollment is
performed. A rejected unrelated publisher or cancelled observation request does
not invalidate the independent healthy observer. Every later use still repeats
the same source/floor/time checks. Configured live acquisition budgets and HTTPS producer-to-consumer
qualification still need closure in the same delivery vertical. See the
[exact scope and receipts](testing/s05-mgr1-lifecycle-2026-10-04.md).

Retired ContactAuthority, GroupControlAuthority, MailboxPeerAuthority,
MailboxClient, MailboxClientAdapter, MailboxClientProductionAuthority and
MailboxAuthorityForwarding sections reject, including empty sections. There are
no retired client, closure or forwarding HTTP handlers in Program. Do not use
the old survival-mailbox authority generators for this graph.

Readiness checks actual current host/role/operation and native mailbox custody
afresh and returns sanitized state, never a cached success flag. Native file
scans are bounded and cancellable within the existing health budget; expiry is
checked with the held host lease, not host UTC or a synthetic client grant.
This is not proof against coordinated cold rollback/loss of otherwise consistent
replay and mutation files: their independent protected checkpoint coverage still
requires closure. It also does not qualify retained-route recovery. Unified retention, signed
retirement, issuer renewal, complete provisioning and shipping composition
remain activation requirements under the
[implementation plan](../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Neutral storage limits remain bounded; no entry is retired by this change and
no TTL, grant validity or timeout is lengthened to make a test pass.

See [composition evidence](testing/s02-current-program-2026-10-04.md) for the
exact local tests and remaining gates. Physical contact/text and release
qualification are not implied.

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

### Retained-object source cutover (not yet activated)

The matching DR-0104 increment derives native peer Store/ACK retention from the
exact signed object expiry rather than the current network-authority end. Product
retention is owned by [RETENTION-AND-RECOVERY](../../docs/architecture/RETENTION-AND-RECOVERY-V1.md);
current authority, revocation and short grants still gate every admitted operation.
Rebuild/repin the whole consumer graph before activation. Existing private mutation
records with authority-derived retention are incompatible with this invariant and
fail closed; no migration, automatic reset or silent deletion is provided. This
source change does not alter registered node keys, protected authority floors,
production volumes, certbot or other colocated services. An explicit scoped data
reset, if needed for activation, is a separate operator step.
