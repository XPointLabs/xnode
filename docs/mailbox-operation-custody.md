# Current mailbox operation custody

Native local-state owner for
[DR-0087](../../docs/survival-program/decisions/DR-0087-current-mailbox-operation-custody.md).
Network semantics remain solely in
[XPOINT-NETWORK §9.1](../../docs/architecture/XPOINT-NETWORK-V1.md#91-current-two-replica-store-ordering).
This is an internal current candidate, not enabled Program/DI or physical E2E.

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

The current Store/ACK admission invokes the same owner before client replay;
holder verification precedes any recovery. Every current ledger load checks
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

Program/DI, whole-host readiness on Retrieve/peer operations and deployed
provisioning are not activated by this internal mapping. Retained-route,
retirement, sustained quotas and horizon qualification remain separate blockers.
No anti-rollback guarantee survives a coordinated rollback of independent root
and matching data, even when the key ring remains intact. No production state
was reset for this change.
