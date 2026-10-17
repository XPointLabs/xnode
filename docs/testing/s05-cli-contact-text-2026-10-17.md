# S05 CLI contact/text: diagnostic checkpoint

Scope: local `deep-dev-current`, real Shared/Protocol clients and three XNode
processes. No production deployment, account/key/volume reset, release or device
acceptance. Windows/Android remain deferred until CLI contact/text passes.

## Actual observations

- CLI account creation, cold reopen and authenticated network/contact publication
  work. Commands use the same account-owned business APIs, not private node state.
- One retained pair reached real recipient `IncomingRequest`, then explicit local
  acceptance. Its acceptance expired during diagnosis; no deadline was extended.
- Fresh claim failure localized to a private replica timeout **after** reservation.
  Original unknown claims remain retained; no noncommit/key reuse is inferred.
- A later exact request passed claim processing and reached mailbox Store, but
  Store exhausted its15s contract. Closed work:81 lease checks,14,328ms lease work,
  12,505ms authority work. These nested timings are not additive.
- Metadata-only inspection found98 directory-floor records per node. The
  retained reader reauthenticates the complete chain on every observation.
- Matching CLI run20 recovered the original Alice publication and published a
  new Bob. Contact request passed claim but Store still exhausted15s:75 checks,
  14,277ms lease work,12,305ms authority work. Signature-only memoization did
  not by itself solve connected Store. Alice retains `OutgoingRequest`; Bob
  has no materialized contact yet. No delivery or consent PASS is inferred.

## Candidate corrections and limits

- Tiny procfs clock reads complete inline, remain bounded, and reread both actual
  sources on every sample. No clock cache or larger authority interval.
- The small public authority keyring avoids synchronous ThreadPool fork/join.
- One exact claim may retain its previously verified public publication candidate.
  Each phase rereads native inventory/receipt/support, checks the actual protected
  directory floor before/after inventory verification and rechecks original time.
  A failed observation clears the memo and rethrows; no weaker fallback, new key,
  response or authority is manufactured. Leaf RPC budgets are unchanged.
- Forwarded claim coordination performs three leaf RPCs. Its authenticated
  outer request now has one total resource budget of four configured leaf
  budgets (default25s with10s leaves, cap25s), measured from the original start. Admission
  still uses the leaf budget; no crypto/nonce/proof/reservation lease is renewed.
  The regression uses three400ms leaves with a1s leaf budget; the composite
  succeeds without increasing any individual leaf's allowance.
- Directory-floor signature memoization retains only already verified **public**
  heads, bound to exact record bytes and verified authority/witness/time-policy
  references. Every read still checks actual files, paths, Data Protection,
  revision/linkage, independent anchor and index. Currentness and revocation are
  separate live checks. Histories above the4MiB memo resource bound use full
  verification; the accepted history bound and disk grammar do not change.
- Closed numeric/code-location diagnostics never log payloads, identities,
  capabilities, private paths, raw exceptions or credentials.
- Exact-source context reuse has a10s resource window instead of1s. This reuses
  the same immutable capability only while its ORIGINAL lease remains live;
  actual files, both floors, proof, clock, issuer and revocation checks remain.
  Source changes, rollback, stop or expiry still reject. Nested authority-work
  timings distinguish lineage, source files, native floor, proof observation
  and full network verification; they are not additive or admission evidence.

## Receipts

Node `artifacts/cli-prekey-claim-20261017`: `focused-02`44PASS, `focused-03`41PASS,
`focused-04`75PASS, `focused-05`35PASS/native0/0skip. These qualify their successive
source scopes, not one final full gate. `focused-06` retained1FAIL/107PASS: the new
memo test assumed genesis initialization had already warmed chain validation;
the test now explicitly performs a retained read before measuring reuse.
`focused-07`18PASS/native0/0skip includes the repaired warm-read test, authority
binding/tamper/link/index cases and actual pinned TLS Store/Retrieve/ACK/reopen.
It is not the connected CLI acceptance or a final full gate.
`focused-08`35PASS/native0/0skip includes the composite-budget regression and
the native claim recovery/refusal cases.
`focused-09`10PASS/native0/0skip checks closed timing metadata and coordination.
The oversized `focused-10` was explicitly cancelled after eight minutes. Its
console reported139 passing cases but its captured native exit is1; the run
is interrupted/unqualified, never PASS. Narrower matching `focused-11` passed
10/native0/0skip: resource reuse, live source/floor/expiry refusals, pinned TLS
Store/Retrieve/ACK/cold retry and closed timing scope. This is not a full gate.

## Composite resource budgets and retained old intent

Run21 reduced Store authority work to7,807ms (68 checks,9,366ms lease work),
but the old15s composite still timed out. Nested measured buckets:1,859ms
lineage,1,256ms source files,4ms network floor,2,316ms proof observation;
no full network re-verification during that invocation. These are partial,
nested observations, not an additive CPU account.

Store/aggregate ACK now use Protocol's25s total coordinator budget; native peer
services and the peer client's default use15s. Retrieve remains10s and public
ONION30s. Contact RPC leaves default10s; the authenticated claim composite is
capped25s. Explicit smaller operator budgets still reject/cancel normally.
Original signed validity, replay records, grants and authority do not change.

The controlled native/TLS regression uses two8s disk stalls. Focused12 retained
the old15/5 failure. Focused13 exposed the still-short5s peer client. Focused14
completed Store but failed a new assertion that incorrectly checked a recipient
MAU3 client counter rather than its PRQ2 peer journal. The corrected peer-journal
and blob check passed focused15/native0. Matching focused16 passed5/native0,
including the deliberately explicit5s deadline and authority refusals.
Focused17 passed3/native0 for contact leaf/composite budgets and timeout certainty.

Run22's preserved old Store returned incomplete quorum rather than a native
deadline: its recipient rejects stale PRQ2 without an existing reservation.
This is not evidence of noncommit or permission to re-sign/remint it. Original
profiles, intent and keys remain retained. A fresh QA pair after the resource
fixes is a separate connected test, not recovery evidence for that old operation.

Supported local activation `deep-devops/artifacts/cli-prekey-claim-20261017`:
deploy01–04 Build/Up/Verify native0; deploy05 Build/Up native0 is diagnostic only.
Deploy06 failed preflight before activation; its exact retry deploy07 passed
Build/Up/native0 (no Verify). The original failure remains unqualified.
All completed activations retained9 services/54 mounts; no reset or production change.
Later own-publication retries hit Registry route `Threshold/authority` refusal;
this is not a TLS failure or permission to replace the pending operation.
Matching CLI business receipts remain **FAIL/unqualified**, not message delivery.
Full source/package, smoke/rehearsal and physical qualification remain open.

## Retained cycle retries and admission diagnostics

Runs23–25 used the same newer QA pair. Both own publications passed in run23;
the contact requests first returned503 BeforeForward, subsequently the exact
retry rejected an expired auxiliary XMG2 in Protocol's `RequireWindow`. These
are failed receipts, not end-to-end delivery. The pending acquisition remains
retained; Shared's focused regression and fix are recorded in
`deep-client-shared/docs/testing/s05-cli-pending-grant-2026-10-17.md`.

Resolver pre-forward admission failures now use the existing bounded closed
ONION diagnostic sink instead of silently losing the original code location.
Node focused18 passed3/native0/0skip for closed phases, hostile exception text,
sink interruption and rate bound. Diagnostic activation deploy12 Build/Up0
preserved all9 services/54 mounts, with no reset or production changes. It is
not Verify/smoke/full acceptance.

Run26's exact cold retry obtained durable Initial Store. Bob subsequently
materialized the request, but its ACK remained unknown after cancellation;
this is not completed CLI contact/text acceptance. Isolated retained Bob sync
after deploy13 identified the effective peer budget as5000ms (5009ms elapsed),
not the constructor's15s. Read-only inspection of the actual container's base
`appsettings.json` confirmed its lower-case `Mailbox.peerTimeout`5s override;
Development and environment had no override. The checked-in base setting is
now15s. Focused19 passed1/native0 for actual pinned-TLS5s cancellation/cold
recovery and closed timing metadata; focused20 passed1/native0 for the actual
shipping JSON's retention and15s resource values. No replay/validity guard was
relaxed, original failed ACK remains exact and retained.

Run27 completed contact request, incoming materialization/ACK, ContactAccept
Store and peer acceptance after exact cold retries. The first text remained
pending: its retry rebuilt changed public evidence after ordinary view renewal.
This is a Shared original-evidence defect, not successful text delivery; the
original operation/ciphertext is preserved. Repeated local preparation also
consumed the client's unchanged30s dispatch scope before its final hop.

The node's paired XNA1/DTS1 source now reuses immutable signature verification
only after rereading every exact file. Source focused21 passed7/native0/0skip:
warm identity, altered authority/policy/size, wrong pin and actual source/floor/
clock/currentness refusal cases. Local diagnostic deploy15 Build/Up0 retained
all9 services/54 mounts without reset. No live authority interval is extended.

## Native client replay before the first Store intent

Run28 passed the repaired Shared evidence boundary, then failed with
`ReserveStoreCoreAsync` IL1104. Read-only matching PDB inspection maps this to
the guard “Known current Store replay has lost its exact peer intent.” The
client MAU counter/floor had persisted, but cancellation preceded first-intent
allocation. That is distinct from actual loss of a committed intent.

Focused22 reproduced the genuine cold gap (1FAIL/native1). Focused23 retained
a compile failure from an incorrect enum name during the edit, not PASS.
Focused24 passed4/native0/0skip: explicit gap, both replay-floor write faults
and refusal after mutation/intent loss. Focused25 passed8/native0/0skip:
missing/rollback before mutation, new-grant prefix blocking and quorum-write
fault recovery. Root DR-0139 declares the two exact source-case replacements;
full qualification must preserve and bind the original TRX, not waive them.

The coordinator still verifies actual current grant/replay/custody. The
complete anchored snapshot permits only first allocation for NewReserved or
InFlight without a recovered outcome or native Store effect. A persisted PRQ2
always returns unchanged; existing cursor/prefix/receipt rules are unchanged.
Real retained CLI text/full qualification remains unaccepted at this checkpoint.

Deploy16 failed closed in preflight's authenticated policy observation before
image build/activation (native1, no Up). The exact supported retry deploy17
passed Build/Up0 and preserved9 services/54 mounts. Neither attempt reset data,
weakened time verification or touched production. Run29 continues the same
pending CLI text on that activation; its business result is not inferred here.
