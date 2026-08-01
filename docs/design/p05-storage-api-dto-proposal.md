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

## P05A predecessor contract

P03B `MRR1` has no P04 epoch, log-chain, ballot or high-water field. Proposed JSON fields are not
signed evidence. A separate pre-P08 `deep-protocol` package **P05A** must canonically define and
vector:

```text
epochOperationId16 =
  first16(SHA-256(
    "deep-storage-epoch-operation-v1" ||
    networkId16 || u64be(epoch) || membershipStatementHash32 ||
    placementCommitment32 || u64be(generation) || u64be(cursor) ||
    previousCommitHash32 || logicalObjectId16 || operationDigest32
  ))
```

P05A also owns the exact storage-member leaf, ballot/proposal, commit-chain, replica-signed
high-water, per-record commit envelope, exact tombstone target and legacy mirror envelope/receipt.
`epochOperationId16` occupies P03B `MailboxReplicaReceipt.OperationId`; every other added field is
cryptographically connected by the P05A framing. If the 16-byte binding is rejected, P05A adds a
replica-signed wrapper/new receipt version. P08 only consumes the accepted package/hash.

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
  "expectedGeneration": 42,
  "afterCursor": 100,
  "ttlSeconds": 86400,
  "payloadDigest": "<32-byte base64>",
  "ciphertext": "<bounded base64>",
  "tombstoneTarget": {
    "logicalObjectId": "<16-byte base64>",
    "generation": 42,
    "epochOperationId": "<16-byte base64>",
    "payloadDigest": "<32-byte base64>"
  },
  "readChallenge": "<fresh unpredictable 16..64-byte base64>",
  "requestNonce": "<transport replay nonce>"
}
```

Validation:

- operation selects the exact expected P03B capability domain;
- `placementMcp1` is decoded only as placement; no conversion from deposit/retrieve exists;
- the two decoded presentations have matching generation/lifecycle/mixed-version/idempotency
  metadata; the P03B 16-byte idempotency value is the authoritative logical operation ID, so there
  is no substitutable duplicate JSON field;
- a separate atomic operation-idempotency store binds that logical ID to the complete canonical
  request digest because the P03B replay callback alone does not receive application payload bytes;
- placement key and capability bytes never enter logs/metric labels;
- the derived `epochOperationId`, generation, tombstone and digest must match P03B receipt
  expectations;
- read has no ciphertext and carries a retrieve presentation;
- tombstone has no ciphertext, names the exact immutable target tuple, and its payload digest is
  the P05A canonical tombstone-body digest;
- maximum envelope size is a reviewed constant no larger than the small-envelope product limit;
- request nonce is replay input only.
- read challenge is client freshness input, distinct from the transport nonce, and is signed into
  both replica high-water responses.

Response:

```json
{
  "schema": "deep-storage-coordinate-result.v1-proposed",
  "status": "durable|no-quorum|epoch-mismatch|conflict",
  "epochWrites": [
    {
      "membershipEpoch": 301,
      "placementCommitment": "<32-byte base64>",
      "cursor": 101,
      "previousCommitHash": "<32-byte base64>",
      "commitHash": "<32-byte base64>",
      "durableQuorumMqr1": "<canonical bytes base64>",
      "finalizedReplicaIds": ["<16-byte base64>", "<16-byte base64>"]
    }
  ],
  "errorMbe1": "<canonical bytes base64 or null>",
  "read": {
    "membershipEpoch": 301,
    "pageStartCursor": 101,
    "pageEndCursor": 125,
    "highWaterCursor": 140,
    "readChallenge": "<same challenge as request>",
    "highWaterEvidence": [
      "<P05A replica-signed high-water>",
      "<P05A replica-signed high-water>"
    ],
    "records": [
      {
        "cursor": 101,
        "previousCommitHash": "<32-byte base64>",
        "commitHash": "<32-byte base64>",
        "logicalObjectId": "<16-byte base64>",
        "ciphertextOrTombstone": "<bounded canonical bytes>",
        "durableQuorumMqr1": "<canonical bytes base64>"
      }
    ],
    "continuationHash": "<commit hash at pageEndCursor>",
    "nextCursor": 125
  }
}
```

Each `epochWrites` entry needs an independent W2 final certificate; E and E+1 never share receipts.
For reads the client verifies two fresh challenge-bound high-water statements for the exact
`StorageLogIdV1`, every P03B/P05A record envelope, contiguous cursor/commit-hash edges across
bounded pages, and eventual arrival at `highWaterCursor`. It persists a monotonic per-log LKG.
One `MQR1` never authenticates an array. A JSON success field alone has no authority.

## Coordinator-to-replica API (P09A/P09B)

Internal mutually authenticated endpoints:

- `POST /internal/storage/v1/replica/promise`
- `POST /internal/storage/v1/replica/accept`
- `POST /internal/storage/v1/replica/finalize`
- `POST /internal/storage/v1/replica/read`
- `POST /internal/storage/v1/replica/repair`

Promise/accept/finalize implement a per-slot quorum ballot. Every request binds one canonical log
ID (which itself binds network, roster hash, placement, epoch, generation and algorithm policy),
exact owner ID, ballot, common cursor, previous commit hash, derived operation ID, canonical request
digest, tombstone target and payload digest. A replica persists and signs `MRR1` at accept; the
coordinator acknowledges the client only after the resulting `MQR1` commit envelope is finalized
on W2. High-water additionally signs the client challenge and freshness bucket. HTTP status never
substitutes for evidence.

Repair accepts only a contiguous P05A per-record certificate chain from the local high-water to a
strictly newer signed high-water. It cannot skip a cursor, replace a chosen slot, alter a tombstone
target or create a logical quota event.

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
six distinct targets may be active. This DTO is only ReplicatedV2 membership rotation; it says
nothing about the legacy backend.

## Separate legacy migration/mirror contract

P05A proposes `LegacyMirrorEnvelopeV1` containing one complete v2 record/commit certificate under
an opaque idempotent mirror object ID. `ILegacyRollbackMirror` must:

- durably store that opaque envelope through `LegacySingleExit`;
- read it back before the corresponding rollback-safe client acknowledgement;
- retrieve all mirror objects after restart using an opaque cursor;
- return a coordinator-signed P05A mirror receipt bound to the read-back digest;
- persist a continuity journal and reject a deadline extension/gap.

The embedded v2 evidence remains client-verifiable even though the legacy server is unaware of the
format. If the current backend cannot meet durable store/read/restart semantics, strict mirror mode
is unavailable and no legacy rollback guarantee is made.

## Version negotiation

Proposed feature token: `deep-storage-replication-v1`.

- absence selects `LegacySingleExit`;
- shadow mode returns no authoritative v2 success;
- strict legacy mirror requires the P05A envelope/receipt, verified read-back, P03B
  `LegacyMirrorOverlap` and a finite deadline;
- an operator flag cannot bypass capability, membership, receipt or durable-state verification;
- downgrade preserves v2 objects, receipts, cursors and tombstones.
