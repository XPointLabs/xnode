# Session Porting Spec - Node Router

Last updated: 2026-07-30.

## Scope

This document defines the active Session-compatible behavior of XNode. Session semantics stay
above the Deep transport stack; VLESS/Xray and native mailbox wire formats are implementation
choices below that boundary.

## Sources and general rules

- Use `../source/session-android`, `../source/session-desktop`, and `../source/session-ios` when
  present.
- Preserve client bootstrap, path selection, onion routing, and service-node identity semantics.
- Keep Xray details inside `XNode.Transport.Vless`.
- Release evidence must use a real Xray process. Mock transport is development/test only.
- Every ported behavior requires unit coverage, integration coverage for durable/process behavior,
  and client E2E coverage when a client consumes it.

## Route trust

- `storage_route` returns exactly three unique reachable contacts; the responding registered
  router is hop zero.
- Only the currently registered `NodeDb` catalog authorizes relays. Contact self-signatures prove
  integrity, possession, and freshness, not membership.
- A chain-free non-production private UAT may explicitly use an exact three-router allowlist as
  membership authority, but only after each contact is received, freshly self-signed, and matched
  to its exact router-ID, literal RFC1918 address, port, and `/api/peer/onion` path. Configuration
  alone never creates membership; the catalog snapshot remains atomic for each route decision.
- Route validation and the actual socket connection share one immutable endpoint policy. Private
  DNS/rebinding, loopback, special-use addresses, redirects, and proxies fail closed. Production
  public forwarding additionally requires HTTPS, an allowed port, and endpoint-ownership proof
  bound to the router identity; the executable remains unready while only `DenyAll` is available.
- RPC responses bind the pinned responder, request metadata, payload/result digests, issuance
  time, and success state under the responder Ed25519 identity.
- Direct storage RPC outcomes are not relay-health evidence.

## Membership route publication

- The public endpoint serves only an externally generated opaque quorum-signed artifact.
- Missing or invalid configuration is `503`; XNode never synthesizes an unsigned catalog.
- Clients verify the P04 envelope, every MRL1 proof, validity, monotonic LKG state, and the exact
  route selection before use.

## Native peer mailbox runtime

- Peer routes accept only canonical P10I PRQ2 Store/Tombstone and return signed durable MRR2.
- The configured epoch commitment, RIP1/MIP1 proofs, exact two-router placement, Storage
  role/capability, endpoint, and signing keys are the authority.
- Replay is durably Pending before mutation. Completed retries return the exact cached MRR2;
  conflicts fail closed; exact pending claims recover idempotently.
- Store and Tombstone share one durable mutation record. Startup validates every record and
  retries recoverable tombstone/blob cleanup.
- Journal/blob replacement is write-through and atomic, with parent-directory durability on Unix
  and recoverable deletion tombstones on Windows.
- Sender quorum is exactly 2-of-2 and emits only native MQR3.
- Host-global/per-operation pre-auth admission precedes parsing and crypto. Verified sender
  admission follows verification. No sensitive identifier or payload enters logs or metric labels.

## Native MAU2 client ingress

- Client routes are exactly:
  - `POST /api/client/mailbox/v2/store`
  - `POST /api/client/mailbox/v2/retrieve`
  - `POST /api/client/mailbox/v2/acknowledge`
- Every request media type is `application/vnd.deep.mailbox.mau2`. The authenticated inner bodies
  are respectively MEO1, MBR2, and MBA2. Responses are respectively MQR3, MRP1, and MAR1.
- Route authority comes from `MailboxWireHttpContract.AuthenticatedOperation`; a caller cannot
  select or override the operation.
- Strict MAU2 decoding and Ed25519 MCG2/MCP2 verification precede all mailbox-specific reads,
  writes, fanout, or outcome allocation. Issuer, generation, lifecycle, revocation, membership,
  and placement authority are injected and fail closed.
- The replay journal stores only a SHA-256 digest of a completed outcome. The separate canonical
  outcome store persists the exact MQR3/MRP1/MAR1 or a coarse MTO1 terminal result.
- Outcome capacity for the endpoint maximum is reserved before the first ledger/blob/peer access.
  A successful or terminal outcome is atomically persisted before the replay digest is completed.
  Capacity failure therefore performs no mailbox mutation.
- An authenticated execution is owned by one opaque outcome key per process. A concurrent exact
  InFlight request receives a dependency failure and performs no work. After the owner exits or
  the process restarts, only the exact durable PendingSame claim (same replay scope, counter, and
  claim digest) may enter the recovery worker. PendingPrior is never executable.
- Recovery workers decode typed bodies only from
  `reservation.Verified.Binding.CanonicalRequest`. Durable operation journals make Store and ACK
  recovery idempotent and prevent duplicate local or peer mutation. Retrieve uses its fixed
  high-water snapshot.
- Before side effects, cancellation or validation failure releases only a NewReserved claim.
  After any ledger/blob/peer access, cancellation leaves the exact claim Pending and releases only
  the in-process execution/outcome-capacity lease so a bounded exact retry can recover.
- Completed and repaired InFlight retries load the exact canonical outcome, verify its digest in
  constant time against replay state, and return it without worker execution.
- Pre-auth admission is host-global and independent per authenticated operation; it stores no IP
  or other attacker-controlled partition key. Post-verify holder admission uses only a
  domain-separated hash of operation plus holder public key and permits 120 requests per minute.
- Store validates TTL/size/blob data before mutation, authorizes the exact two replicas, journals
  cursor/receipts/coordinator sequence, and returns native MQR3.
- Retrieve reads a fixed high-water snapshot and emits MRP1 up to the one-megabyte protocol bound.
  XCT1 binds epoch, mailbox, placement, membership, snapshot, cursor, page size, expiry, and exact
  page acknowledgement digest.
- ACK validates all targets before mutation, atomically journals logical tombstones, resumes
  partial fanout after restart, emits MAK-order native MQR3 values inside MAR1, and performs
  physical blob cleanup as bounded best effort after logical durability.
- The client adapter consumes only the exact locked P10J protocol closure. There is no public
  MST1/MRT1/MAK1 path, MCP1 compatibility envelope, V1 translation, or fallback call graph.
- Production consumes a protected read-only canonical PMA1 artifact only through a pinned Mr. X
  key hash and protected atomic LKG chain. It exposes signed NodeIngress current/next SPKI and
  issuer/E/E+1 authority, but readiness and routes remain fail-closed until a hash-bound public
  revocation artifact can answer serial-level revocation. Development remains a separate explicit
  pinned two-XNode fixture and cannot consume the production provider.

## Readiness and diagnostics

- Readiness includes router/Xray state, peer endpoint authorization/private membership, peer
  journals, native MAU2 authority/revocation policy,
  durable replay, durable canonical outcomes, operation ledger, placement authority, and fanout.
- Active client status is `native-mau2-meo1-mbr2-mba2`.
- Logs and metrics expose only coarse failure categories and bounded operational counts.
- Authority diagnostics never expose PMA1 paths, endpoints, pins, hashes, or exception text.

## Stop-the-line conditions

- Release readiness can pass with mocked transport.
- Bootstrap metadata is insufficient for client route selection/connection.
- Peer/client journals or canonical outcomes are corrupt or missing without readiness failure.
- Outcome capacity is allocated after a mailbox side effect.
- PendingPrior or a concurrent InFlight request can enter a worker.
- A completed replay can return without exact outcome bytes and constant-time digest verification.
- Any public V1 mailbox route, compatibility decoder, conversion, or fallback remains reachable.
- Production readiness can pass without proof-capable public-peer authorization, or private UAT
  readiness can pass with an incomplete/non-unique exact signed membership catalog.
- Ported behavior is asserted only manually.
