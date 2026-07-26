# Session Porting Spec - Node Router

Last updated: 2026-07-26.

## Scope

This document defines how Session router/service-node behavior is ported into the XNode. The target is Session-compatible messaging and bootstrap behavior over a Deep transport stack.

## Reference Sources

Use local upstream checkouts when available:

- `../source/session-android` for client path/bootstrap expectations.
- `../source/session-desktop` and `../source/session-ios` for client compatibility checks.
- Session service-node/router references when present under `../source`.

If upstream router source is unavailable, use e2e bootstrap/path fixtures and existing tests as the current baseline.

## Porting Rules

- Preserve Session-visible routing semantics above the transport layer.
- Keep transport implementation details (VLESS/Xray) isolated in `Transport.Vless`.
- Do not leak Xray-specific assumptions into core path selection or Session RPC models.
- Mock Xray only in tests/dev; release evidence must use no-mock Xray.

## Behavior Mapping

- Service node identity -> `RouterId`, registry payloads, heartbeat service.
- Relay contacts -> `RelayContact`, `NodeDb`, bootstrap document.
- Path selection -> `PathSelector`, `SelectedPath`, `PathSelectionOptions`.
- Session RPC ingress -> `SessionRpcRequest`, `SessionRpcResponse`, ASP.NET endpoints.
- Transport profile -> `VlessTransportOptions`, `VlessProfileGuard`, `XrayConfigGenerator`.
- Runtime status -> `RouterRuntime`, health/readiness endpoints.

## Required Evidence

For each ported behavior:

- unit test in `XNode.Tests`,
- integration test when runtime/transport/process behavior is involved,
- e2e coverage when clients or registry consume the output,
- DevOps no-mock rehearsal for release transport paths.

## Accepted Deviations

- VLESS/Xray replaces upstream ingress transport while preserving client bootstrap metadata and routing behavior.
- Local tests may use fake storage/runtime dependencies.
- Multi-node rehearsal uses deterministic local nodes, not production network discovery.

## Route Trust V1

- `storage_route` returns exactly three unique, reachable relay contacts. The responding local router must be registered and is always hop 0.
- Dynamic relay membership authorization comes from the exact registered catalog currently loaded into `NodeDb`. Locally stored or gossiped contacts outside that catalog are not eligible, and an unavailable or undersized catalog fails with `path-not-found`.
- Relay contact self-signatures prove contact integrity, key possession, and freshness only. They are never registry or membership authorization.
- Session RPC responses add `xpoint-rpc-response-v1` metadata signed by the responder Ed25519 identity. The signature binds the pinned responder, request id/method/nonce/payload digest, issuance time, success state, and result/error digest.
- Public direct storage RPCs do not traverse their advertised relay route. Their downstream HTTP outcomes and public path reports are therefore never used as relay-health evidence; churn blocking remains disabled until direct, authenticated peer-health measurements exist.
- A future quorum-backed catalog checkpoint may replace the current registered-catalog authorization source. Route trust v1 does not implement a Merkle or on-chain catalog checkpoint.

## Membership Route Publication V1

- The public artifact endpoint serves only opaque bytes from a configured file. It receives no
  mailbox/placement target and XNode does not inspect member topology.
- Missing or invalid publication configuration fails closed with `503`; no unsigned catalog is
  synthesized from `NodeDb`.
- Clients must quorum-verify the P04 membership envelope, every canonical MRL1 inclusion proof,
  validity and monotonic LKG state before local route selection.
- Production publication remains disabled until an external signer/indexer generates the artifact.
  Deterministic signers are permitted only for an explicitly mounted Docker development fixture.

## Replicated Encrypted Mailbox Primitive V1

- XNode owns an internal authenticated peer replication protocol for opaque encrypted blobs.
  It does not define the client-facing mailbox discovery/retrieval contract.
- A write is successful only after the configured number of distinct storage-router receipts
  verifies against the exact mailbox id, blob digest and expiry. Missing, timed-out or invalid
  receipts never count toward quorum.
- The blob id is the SHA-256 digest of the canonical base64-decoded ciphertext. Replays are
  transactionally idempotent: exact signed-request retries return the cached receipt only after
  durable storage, while a conflicting request with the same sender nonce fails closed.
- Sender and storage-node identities are self-certifying Ed25519 router identities. The receiver
  additionally requires the sender to be present and fresh in the locally verified registered
  relay catalog.
- Mailbox ids are opaque, rotating client-derived values. They are not account identifiers.
  No mailbox id, blob id or ciphertext is written to application metrics or logs.
- The primitive is disabled by default. Enabling peer storage before a reviewed client AEAD,
  blinded mailbox-id derivation, placement and authenticated retrieval contract exists is not a
  production activation.

## Client Mailbox Adapter V1 (Dormant)

- The first client-facing adapter slice consumes only the pinned corrected
  `Deep.Protocol 0.3.0-p09c2.f1a93c9` closure. The superseded
  `0.3.0-p09c.451f3dc` package is forbidden.
- The adapter has no HTTP route and remains unreachable in the runtime composition. Its default
  capability verifier and replica fanout dependencies fail closed.
- The store boundary accepts only a canonical `MST1` frame and persists the complete canonical
  `MEO1` bytes as the opaque payload in the existing crash-safe replica store.
- A capability verifier must atomically and durably enforce replay and attest the exact
  operation type, outer operation id, epoch, blinded mailbox id, SHA-256 placement commitment,
  membership commitment, canonical request and capability digests, replay counter, idempotency
  key and replay disposition. The adapter compares every field in constant time where
  applicable. The parser replay guard is deliberately non-authoritative. A verifier that cannot
  advertise durable atomic replay keeps the adapter not-ready.
- The durable operation key is `(epoch, blindedMailboxId, operationId)`. Each epoch/mailbox has
  its own monotonic cursor authority; a separate global coordinator-sequence authority is never
  reused. Request context is durably reserved before local storage or fanout.
- Concurrent exact retries are single-flight. Before a coordinator signature is made, the exact
  two native replica receipts and the next global coordinator sequence are atomically persisted.
  Crash recovery can therefore sign only that previously reserved statement.
- Completed retries return a persisted `MQR2` only after fully reverifying its replica signatures,
  current epoch membership commitment, placement, operation, cursor, expiry, expected replica
  set and current local coordinator identity. Membership or node-key rotation fails closed.
- Replica responses count only after native `MRR2` signature, complete context verification and
  membership/placement authorization. An injected authorizer selects the deterministic expected
  replica ids for the exact epoch, membership commitment and placement commitment; an arbitrary
  self-signed receipt from any other node never counts.
  The coordinator emits native `MQR2` binding operation, epoch, cursor, blinded mailbox,
  placement, membership, envelope digest and expiry.
- No node seed, retrieve capability, master secret, account identifier or plaintext is persisted
  in the adapter ledger or returned by its contracts.
- E and E+1 have distinct configured membership commitments. TTL/size/blob validation is
  side-effect-free and precedes cursor reservation. Expired terminal/retryable/durable records
  are boundedly removed without rewinding either cursor or coordinator authorities.
- E and E+1 commitments must also be cryptographically distinct; equal values are a
  configuration error. Cursor authorities have an explicit bound. Authorities with no live
  operation are compacted into a persisted retired high-water floor, so unique-mailbox churn
  cannot grow the ledger forever and a returning mailbox can never reuse a cursor.
- A process holds an exclusive file lease on the adapter directory for the ledger lifetime and
  one adapter claim per ledger. A second runtime fails closed. In-memory single-flight entries
  are separately admission-bounded, reference-counted across waiters and removed only after the
  final waiter releases them.
- `MRT1` retrieval uses a persisted cursor index and a fixed high-water snapshot. New stores
  cannot extend an in-progress traversal. The signed `XCT1` continuation binds epoch, mailbox,
  placement, membership, snapshot high-water, last cursor, maximum page size, expiry and the
  exact page acknowledgement digest. Its canonical purpose mask authorizes only the next
  retrieve and the matching non-final `MAK1`; signatures from any currently authorized replica
  support failover. A replica without the corresponding durable journal/blob state fails closed;
  the client may restart from cursor zero and deduplicate by envelope digest.
- `MAK1` validates every cursor/digest target before a single mutation, then atomically journals
  the complete ACK and logical tombstones before local signing or peer fanout. Tombstoned
  envelopes disappear from retrieval immediately, including when quorum is unavailable.
  Per-item native Tombstone `MRR2` bytes and a unique coordinator sequence are persisted before
  native `MQR2` creation. Partial progress resumes exactly after restart; a durable retry returns
  the identical reverified receipt without fanout. For a multi-item ACK, its cached replay
  authority and referenced ledger targets remain until the latest item expiry, preserving exact
  idempotency when item TTLs differ; expired items are never returned by retrieval. A different
  operation id cannot ACK an already tombstoned cursor or mint another receipt.
- Retrieval has no receipt. ACK currently returns an internal list of per-item `MQR2` receipts;
  no aggregate public frame or V1 transcode is invented. XNode never records client-side
  `Delivered`.
- Ciphertext reclamation is bounded and best-effort immediately after durable ACK. A logical
  tombstone remains authoritative if deletion or parent-directory durability fails, and startup
  retries every pending `BlobCleaned=false` item before marking cleanup complete.
- Ledger schema v3 adds canonical blob, placement and membership bindings plus ACK journals.
  Schema v2 is rejected fail-closed rather than migrated because it cannot prove those bindings.
  `maxOperationEntries` charges stores, ACK operations and every ACK item.
- Real capability-verifier composition, native store/tombstone peer transport, and a reviewed
  public ACK response contract remain mandatory before exposing any client mailbox route.

## Stop-The-Line Conditions

- A release build or rehearsal can pass with mocked transport.
- Bootstrap data is not enough for a client to select/connect to a route.
- Runtime status hides degraded transport or registry heartbeat failures.
- Ported path behavior is asserted only by manual testing.
