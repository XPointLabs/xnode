# Current mailbox operation custody

Native local-state owner for
[DR-0087](../../docs/survival-program/decisions/DR-0087-current-mailbox-operation-custody.md).
Network semantics remain solely in
[XPOINT-NETWORK §9.1](../../docs/architecture/XPOINT-NETWORK-V1.md#91-current-two-replica-store-ordering).
This is a current candidate with a real Program startup/readiness recovery hook,
not a fully enabled current service graph or physical E2E.

## Local contract

The existing schema-6 `operations.json` remains the only complete Store/ACK
intent, quorum and allocator document. Its existing size/capacity validation is
unchanged. No peer bytes, mailbox identifiers or cursor table are duplicated.

`FileMailboxOperationCustody` uses the existing ASP.NET Core Data Protection
provider. Its independent directory must not overlap node data or traverse
symlinks/reparse points. The key ring is also independently recoverable; it must
not live in replaceable node data. The deployment owner must enforce that
provider placement; the provider interface does not expose its key-ring path.

Local protection/naming scope is SHA-256(node ID 32 || network ID 16), plus the
fixed relative operation path in distinct enrollment/checkpoint protection
purposes. PMA/PMT rollover does not create a fresh allocator. This hash is not a
wire ID, authority or hardware monotonic counter.

Two protected records, each bounded to 4096 encrypted bytes:

- `enrollment.bin`: local format version 1, random enrollment ID, initial exact
  document SHA-256 and length;
- `checkpoint.bin`: local format version 1, matching enrollment ID, unsigned
  64-bit local commit generation, committed exact document SHA-256/length and
  at most one pending SHA-256/length/exact temporary basename.

Only canonical `operations.json.<32 lowercase hexadecimal chars>.tmp` basenames
in the same operation directory can be pending. Unknown JSON members/versions,
invalid bounds/scope/protection, missing/split records and generation exhaustion
reject. A process-independent writer lock pairs with the existing ledger lock.

## Producer and recovery mapping

`CurrentMailboxAdmission.WithHostAsync` verifies real local membership, closed
current host/source/time and both protected role leases. It does not reserve
client replay or manufacture a grant. Explicit `EnrollNewOperationsAsync`
rejects existing/interrupted protection before persisting the empty operation
document and enrollment. `InitializeOperationsAsync` is the non-enrolling
reader/recovery entry point.

`current-mailbox-enroll` now connects explicit new-scope enrollment to the same
configured source and native graph, without running listeners/hosted services.
The command preflights both signed role genesis records, the actual descriptor
key and genuinely new operation custody before the first protected write. The
operation owner rejects every non-lock entry in a new protected scope, including
unknown/partial records. Its replaceable operation directory likewise rejects
every non-lock entry, not just `operations.json` and `.tmp`. The same command
checks actual empty blob/mutation/replay/outcome owners before network acquisition
and repeats the refusal before role writes. Reader construction preserves
interrupted native files rather than erasing evidence of prior custody.
These denial-only checks do not independently anchor the other native stores
against coordinated cold loss/rollback. Actual writers recheck; there is no multi-file atomic
commit, restart enrollment or repair fallback. See the single operator procedure
in [operator.md](operator.md#current-mailbox-host-composition-candidate).

`CurrentMailboxHostRecovery` is registered by Program as the same singleton
hosted service used by `/health/ready`. Startup and each readiness request call
the actual receiver's host-only recovery: matching receiver/coordinator owner,
actual descriptor signing custody, both native role leases and the exact
protected operation document. No client grant or replay is created. A previous
successful status is not admission authority and is not reused on another check.
Checks are single-flight with a five-second cooperative cancellation budget;
busy, stopped, missing or unavailable owners cannot report successful recovery.
Missing current composition with mailbox enabled now makes readiness 503.
Mailbox disabled skips these owners; that state qualifies no mailbox operation.
Only the recovery boolean and a closed state label are added to public health,
not exceptions, private files, identifiers, keys or contents.

Every current native receiver requires one operation ledger at construction;
Store/Retrieve/ACK and peer Store/tombstone cannot omit this owner or substitute
a neutral ledger. A supplied producer ledger must be that same instance.
Client holder and actual descriptor signing custody are checked before recovery
and client replay. The peer verifies the complete signed candidate before
recovery and before rate/replay/mutation. Both use the same live native role
leases, without reacquiring them or inventing a client grant. Current request
and peer result checks revalidate custody after callbacks, before releasing a
page/receipt or completing an outcome. Already completed replay also requires
the current independent root; it is not an alternate readiness path.
Every current ledger load checks
the protected root under the real operation lease, including the exact opened
snapshot actually parsed after callbacks. A prior path check or decoded state
label is not snapshot authentication. Every current save uses:

1. validate/flush the existing exact temporary document;
2. flush the independent protected pending transition;
3. replace/flush/read-back the operation document;
4. commit/read-back the protected root.

If the pending next document is already installed, verified startup finalizes
the protected commit. If the predecessor is still installed, only the named,
hash-matching, structurally valid temporary can finish replacement. Missing or
hostile data remains unchanged/unready. Unanchored operation temporaries are
collected only after the current protected document is verified; a known client
replay still cannot author another missing intent. Uncertain protected-write
temporaries are retained as local diagnostic evidence, never adopted.

Public neutral initialization/collection/writes cannot operate on a protected
current ledger. There is no schema migration or automatic re-enrollment.

## Deployment/recovery boundary

Back up the exact operation document together with its independent enrollment,
checkpoint and key ring using a consistent quiesced snapshot. Restoring only
one side fails closed. Do not erase protection, re-enroll, regenerate a node ID
or reconstruct operation data from blobs to clear an error. Preserve uncertain
files for owner-approved recovery; diagnostics must not expose their contents.

This covers the connected native request/peer handlers, Program recovery hook
and explicit new-scope command, not deployed provisioning/issuer renewal. Recovery here
checks the protected operation owner; it does not independently qualify every
historical blob/mutation, retained route or object horizon. Missing/malformed
local operation data at the peer HTTP boundary yields a bodyless dependency
unavailable response; it is not a new protocol failure record. Retained-route,
retirement, sustained quotas and horizon qualification remain separate blockers.
No anti-rollback guarantee survives a coordinated rollback of independent root
and matching data, even when the key ring remains intact. No production state
was reset for this change.
