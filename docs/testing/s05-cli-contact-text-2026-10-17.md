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
