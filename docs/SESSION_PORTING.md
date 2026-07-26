# Session Porting Spec - Node Router

Last updated: 2026-06-10.

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

## Stop-The-Line Conditions

- A release build or rehearsal can pass with mocked transport.
- Bootstrap data is not enough for a client to select/connect to a route.
- Runtime status hides degraded transport or registry heartbeat failures.
- Ported path behavior is asserted only by manual testing.
