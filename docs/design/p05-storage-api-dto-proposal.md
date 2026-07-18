# P05 storage API/DTO proposal

Status: **PROPOSED / NOT-APPROVED**. Decision owner: **Mr. X**. Deadline: **2026-07-21**.
Approved ADR SHA: **NOT-APPROVED**.

This proposal is not a production wire contract and registers no endpoint. P08/P09 must turn the
selected shapes into versioned protocol code and canonical vectors after ADR approval.

## Contract dependencies

| Purpose | Pinned contract |
| --- | --- |
| Capability presentation and replay | P03B `MCP1`, package `0.3.0-p03b.6e2c709`, source `6e2c709a378ffac40c441e97e2e4da40aac9a104` |
| Replica/durable/error receipts | P03B `MRR1` / `MQR1` / `MBE1`, same pin |
| Signed membership | P04 `MSM1`, package `0.3.0-p04.b887fa0`, source `b887fa088f486390be182cac4cbcb59b60ce8931` |
| Inclusion proof | P04 `MIP1`, same pin |
| Membership verifier | `Deep.Protocol/P04-canonical-v1` |

The existing Session-compatible `/storage/store` and `/storage/retrieve` payloads are legacy input,
not signed P03B/P04 DTOs. They must not be reinterpreted as trusted v2 records.

## Type separation

```csharp
// Proposal only; intentionally not compiled into production.
readonly record struct RouteHopId(string RouterId);
readonly record struct StorageReplicaId(ReadOnlyMemory<byte> ReceiptId16);
readonly record struct MembershipEpoch(ulong Sequence);
readonly record struct OpaquePlacementKey(ReadOnlyMemory<byte> Bytes32);
readonly record struct RequestNonce(ReadOnlyMemory<byte> Bytes);
```

No implicit conversion exists between route hops and replicas. A physical node may hold both
identifiers, but equality is not assumed by either API.

## Verified roster input

P04 commits to a membership Merkle root but does not define a full roster transport. P08/P04D must
provide a verified, immutable `StorageRosterSnapshotV1`:

```json
{
  "schema": "deep-storage-roster.v1-proposed",
  "networkId": "<16-byte base64>",
  "membershipEpoch": 301,
  "signedMembershipMsm1": "<canonical bytes base64>",
  "members": [
    {
      "replicaId": "<16-byte base64>",
      "internalEndpoint": "https://storage-node.example/internal/storage/v1/replica",
      "receiptKeyId": "<16-byte base64>",
      "memberCommitment": "<32-byte base64>",
      "inclusionProofMip1": "<canonical bytes base64>"
    }
  ]
}
```

Rules:

- exact P04 member count, root, network, sequence, validity and protocol must match;
- members sort by raw `replicaId`, are distinct, and every inclusion proof verifies;
- endpoint and receipt-key binding are inside `memberCommitment`;
- temporary health never edits the snapshot;
- a storage roster is an internal membership view and is not exposed through public bridge
  discovery;
- P08 must define canonical member-leaf bytes and golden vectors before implementation.

## Placement API (P08)

```csharp
interface IStoragePlacementProvider
{
    StoragePlacementResultV1 Place(
        OpaquePlacementKey placementKey,
        MembershipEpoch membershipEpoch,
        StorageRosterSnapshotV1 roster);
}

sealed record StoragePlacementResultV1(
    MembershipEpoch MembershipEpoch,
    ReadOnlyMemory<byte> MembershipStatementHash32,
    IReadOnlyList<StorageReplicaTargetV1> Replicas); // exactly 3
```

The method has no nonce or route argument. Transport code may carry a nonce alongside the result,
but it cannot affect placement.

## Cryptographic composition gap

P03B `MRR1` has no explicit P04 membership epoch. Proposed JSON fields are not signed evidence.
P08 must define and vector the following derivation before P09:

```text
placementCommitment32 =
  SHA-256("deep-storage-placement-commit-v1" || placementKey32)

epochOperationId16 =
  first16(SHA-256(
    "deep-storage-epoch-operation-v1" ||
    networkId16 || u64be(epoch) || membershipStatementHash32 ||
    placementCommitment32 || logicalOperationId16 || operationDomainByte
  ))
```

`epochOperationId16` occupies P03B `MailboxReplicaReceipt.OperationId`. The client recomputes it,
verifies the `MQR1` expectation, and checks both signed replica IDs against its computed P08 owner
set. E and E+1 receive different epoch operation IDs derived from the same logical operation ID.
The coordinator deduplicates/charges the logical ID once; each replica deduplicates its epoch ID.

If the 16-byte binding is not accepted, a canonical replica-signed placement wrapper/new receipt
version is required in `deep-protocol`. No implementation may substitute an unsigned epoch field.

## Client-to-coordinator envelope (P09B)

Proposed method: `storage_coordinate_v1` inside the existing onion RPC body.

```json
{
  "schema": "deep-storage-coordinate.v1-proposed",
  "operation": "append|read|tombstone",
  "networkId": "<16-byte base64>",
  "membershipEpoch": 301,
  "membershipStatementHash": "<32-byte base64>",
  "capabilityMcp1": "<deposit or retrieve presentation>",
  "placementMcp1": "<placement-domain presentation>",
  "logicalOperationId": "<16-byte base64>",
  "idempotencyKey": "<16-byte base64>",
  "expectedGeneration": 42,
  "afterCursor": 100,
  "ttlSeconds": 86400,
  "isTombstone": false,
  "payloadDigest": "<32-byte base64>",
  "ciphertext": "<bounded base64>",
  "requestNonce": "<transport replay nonce>"
}
```

Validation:

- operation selects the exact expected P03B capability domain;
- `placementMcp1` is decoded only as placement; no conversion from deposit/retrieve exists;
- placement key and capability bytes never enter logs/metric labels;
- the derived `epochOperationId`, generation, tombstone and digest must match P03B receipt
  expectations;
- read has no ciphertext and carries a retrieve presentation;
- tombstone has no payload bytes and a fixed domain-separated tombstone digest;
- maximum envelope size is a reviewed constant no larger than the small-envelope product limit;
- request nonce is replay input only.

Response:

```json
{
  "schema": "deep-storage-coordinate-result.v1-proposed",
  "membershipEpoch": 301,
  "placementCommitment": "<32-byte base64>",
  "status": "durable|no-quorum|epoch-mismatch|conflict",
  "durableQuorumMqr1": "<canonical bytes base64 or null>",
  "errorMbe1": "<canonical bytes base64 or null>",
  "read": {
    "cursor": 101,
    "isTombstone": false,
    "payloadDigest": "<32-byte base64>",
    "ciphertexts": ["<available union, deduplicated>"]
  }
}
```

The client verifies P03B receipts against its exact expected operation/generation/digest/tombstone
context and verifies the placement/membership binding added by P08/P09. A JSON success field alone
has no authority.

## Coordinator-to-replica API (P09A/P09B)

Internal mutually authenticated endpoints:

- `POST /internal/storage/v1/replica/append`
- `POST /internal/storage/v1/replica/read`
- `POST /internal/storage/v1/replica/repair`

Every request binds network, epoch, roster hash, destination replica ID, operation, derived epoch
operation ID, generation, idempotency key, cursor expectation, tombstone state and payload digest.
A replica verifies that it is one of the three owners before persisting. A durable response is
canonical `MRR1`; a failure is `MBE1`. HTTP status is transport information and never substitutes
for a receipt.

Repair accepts only a verified state that is strictly newer under generation/cursor/tombstone
ordering. It cannot create a logical quota event.

## Overlap DTO

```json
{
  "schema": "deep-storage-epoch-overlap.v1-proposed",
  "previousEpoch": 300,
  "activeEpoch": 301,
  "overlapUntilUnixSeconds": 1785000000,
  "mode": "dual-read-strict-dual-write",
  "previousEpochRollbackContinuous": true
}
```

Only E/E+1 are accepted. Quorum receipts are epoch-bound and cannot be mixed. At most two sets and
six distinct targets may be active.

## Version negotiation and legacy

Proposed feature token: `deep-storage-replication-v1`.

- absence selects `LegacySingleExit`;
- shadow mode returns no authoritative v2 success;
- legacy mirror requires P03B `LegacyMirrorOverlap` plus finite overlap;
- an operator flag cannot bypass capability, membership, receipt or durable-state verification;
- downgrade preserves v2 objects, receipts, cursors and tombstones.
