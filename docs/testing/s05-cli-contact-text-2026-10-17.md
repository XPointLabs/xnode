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
  budgets (default20s, cap25s), measured from the original start. Admission
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

Supported local activation `deep-devops/artifacts/cli-prekey-claim-20261017`:
deploy01–04 Build/Up/Verify native0; deploy05 Build/Up native0 is diagnostic only.
Deploy06 failed preflight before activation; its exact retry deploy07 passed
Build/Up/native0 (no Verify). The original failure remains unqualified.
All completed activations retained9 services/54 mounts; no reset or production change.
Later own-publication retries hit Registry route `Threshold/authority` refusal;
this is not a TLS failure or permission to replace the pending operation.
Matching CLI business receipts remain **FAIL/unqualified**, not message delivery.
Full source/package, smoke/rehearsal and physical qualification remain open.
