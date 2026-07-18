# P05A proposed work package: storage replication binding contract

Status: **PROPOSED / NOT-APPROVED**. This package does not exist yet and is a mandatory predecessor
to P08. Decision owner: **Mr. X**. Target repository: `deep-protocol`.

## Role and ownership

The assigned agent acts as protocol maintainer. `deep-protocol` owns canonical bytes, strict
decoders/verifiers, vectors and packages. It does not implement XNode placement, disk storage,
network endpoints, billing or client UI.

## Required pins

- approved P05 ADR SHA;
- accepted P03B source/package/manifest;
- accepted P04 source/package/manifest;
- P04D storage-roster producer contract, if available;
- decision owner and deadline.

Stop if any pin is mutable, missing or not independently accepted.

## Canonical contracts

Define one versioned `Deep.Protocol.DeepExtension.StorageReplication` surface with fixed domain
tags and exact bounds for:

1. `StorageMemberLeafV1`
   - P04 network ID and membership sequence;
   - exact 16-byte P03B replica receipt ID;
   - internal endpoint commitment, receipt-key ID and role/capability bits;
   - canonical leaf hash consumed by P04 `MembershipInclusionProof`.
2. `StoragePlacementCommitmentV1`
   - 32-byte opaque placement-key commitment, membership statement hash, N/W/R and algorithm ID;
   - no raw Session ID, sender/recipient pair, wallet or sender master secret.
3. `StorageLogIdV1`
   - SHA-256 over network ID, P04 membership statement hash, placement commitment, epoch,
     generation, placement algorithm/policy version and exact N/W/R;
   - the same 32-byte ID scopes every promise/accept/finalize/commit/high-water record.
4. `StorageBallotProposalV1`
   - canonical `StorageLogIdV1`, 64-bit cursor/slot, `(counter, coordinatorId16)` ballot;
   - previous commit hash, logical object ID, request digest and exact tombstone target.
5. `StorageEpochOperationBindingV1`
   - canonical derivation of the 16-byte P03B `OperationId`;
   - binding to network, epoch, membership/placement, generation, cursor, previous commit and
     operation digest.
6. `StorageCommitEnvelopeV1`
   - exact log ID, canonical record/tombstone body, previous/current commit hashes and embedded
     P03B `MQR1`;
   - verifier checks two exact HRW owner IDs and caller expectations.
7. `StorageReplicaHighWaterV1`
   - exact log ID, replica ID, committed cursor/hash, unpredictable client read challenge,
     issued/expiry bucket and replica signature;
   - client verifier requires its exact challenge, freshness window and monotonic per-log LKG.
8. `LegacyMirrorEnvelopeV1` and `LegacyMirrorReceiptV1`
   - opaque mirror object ID, complete v2 commit envelope, deadline/read-back digest and coordinator
     signature;
   - no claim that a signature alone proves the legacy backend is durable.

If a 16-byte P03B operation binding is rejected, introduce a replica-signed wrapper or new receipt
version. Unsigned JSON fields are forbidden as authority.

## Required state-machine rules

- quorum ballots use canonical total ordering and reject lower/conflicting promises;
- promise, accept, finalize, commit and high-water signing bytes carry the same canonical log ID;
- one cursor has one chosen value; same-slot payload/tombstone disagreement is fork evidence;
- high-water advances only after a P03B commit envelope is finalized on W2;
- chain hashes are contiguous and cannot skip a cursor;
- a tombstone names an exact immutable target and has a strictly higher cursor;
- E/E+1 statements never combine receipts;
- legacy mirror framing is separate from membership rotation.

## Test/vectors

- golden encode/decode/signing bytes for every record;
- exact 4/20/100/1000 placement-owner vectors using raw 16-byte replica IDs;
- malformed length/version/domain/reserved/trailing-byte rejection;
- P03B receipt substitution across epoch, owner, generation, cursor, previous hash, operation and
  tombstone target;
- alternating AB/BC/AC quorums, concurrent ballots and unknown-result adoption;
- high-water omission/gap and stale-prefix repair;
- same-bucket old-head replay, challenge substitution, client-LKG downgrade and empty-head
  cross-network/cross-placement substitution;
- bounded multi-page continuation with omission/reorder/substitution at page boundaries;
- E/E+1 cross-quorum rejection;
- legacy mirror envelope/read-back substitution;
- fixed-seed malformed smoke and cross-language vector fixtures.

## File locks

- `deep-protocol/src/Deep.Protocol/DeepExtension/StorageReplication/**`
- `deep-protocol/tests/Deep.Protocol.Tests/DeepExtension/StorageReplication/**`
- `deep-protocol/artifacts/survival/P05A/**`
- P05A package version/manifest and compatibility/security/migration documents

No XNode, client, DevOps, Docker, network, key or production configuration file is in scope.

## Verification and evidence

- full `deep-protocol` Release suite;
- focused P05A suite and malformed smoke;
- locally packed versioned packages with exact SHA-256 manifest;
- compatibility/migration/security boundary;
- independent protocol/security review with P0/P1/P2 disposition;
- no publish/push/runtime activation.

## Acceptance

P05A is accepted only when Mr. X pins an independently reviewed source commit and local
package/manifest hashes. P08 then consumes that exact package and must not reimplement canonical
bytes in XNode.
