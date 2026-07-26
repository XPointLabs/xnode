# Operator Guide

## Architecture

XNode keeps Session Router behavior in the .NET runtime and runs Xray as a supervised child process. Xray owns only VLESS ingress. It forwards accepted client traffic to the local session RPC/API ingress at `127.0.0.1:8080`.

The registry payload advertises the transport parameters clients need:

- mask domain
- transport mode
- public host and port
- Reality or TLS metadata
- capabilities
- config version

Clients should consume `/api/bootstrap/client` or the registry record instead of asking operators to type VLESS settings manually.

## Quorum-signed membership artifact

`GET /api/network/membership-route-catalog` publishes a prebuilt artifact as opaque bytes. Set
`MembershipArtifact__ArtifactPath` only to an artifact produced by the external membership signer
pipeline. XNode does not sign, parse, edit, or synthesize it. If the setting is empty, the file is
missing, or its bounded read fails, the endpoint returns `503`.

For local Docker development only, mount a deterministic fixture read-only and point
`MembershipArtifact__ArtifactPath` at that mount. Never put an online/offline signer private key,
seed, or mnemonic in XNode configuration.

## Install

1. Publish the service for Linux:

   ```bash
   dotnet publish src/XNode/XNode.csproj \
     --configuration Release \
     --runtime linux-x64 \
     --self-contained true \
     -p:PublishSingleFile=true \
     --output artifacts/xnode-linux-x64
   ```

2. Create directories and user:

   ```bash
   sudo useradd --system --home /var/lib/xnode --shell /usr/sbin/nologin deep
   sudo mkdir -p /opt/xnode /var/lib/xnode /etc/xnode
   sudo chown -R deep:deep /var/lib/xnode /etc/xnode
   ```

3. Copy the published files to `/opt/xnode`.

4. Install Xray at `/usr/local/bin/xray` and generate Reality keys with Xray's key generator.

5. Copy `deploy/xnode.service` to `/etc/systemd/system/`.

6. Put production settings in `/opt/xnode/appsettings.Production.json`.

7. Start the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now xnode
   ```

## Production Go / No-Go Checklist

Use this checklist to separate three different questions:

1. Can we build the router as a production binary?
2. Can we deploy it on a real Linux host for controlled operator validation?
3. Can we call the router fully production-ready for public rollout?

### Current Status Snapshot

As of 2026-06-01:

- `GO`: Release tests pass locally (`dotnet test XNode.slnx --configuration Release`).
- `GO`: self-contained `linux-x64` publish path works (`dotnet publish ... --configuration Release --runtime linux-x64 --self-contained true`).
- `GO`: production profiles reject mocked VLESS/Xray settings at startup.
- `GO`: devops release rehearsal can run a real Xray-backed router locally via `deep-devops/scripts/test-env.ps1 -RequireRouterNoMock`; latest managed external smoke/full runs reported `routerTransportMode=running` and `routerTransportMocked=false`.
- `GO`: devops CI wiring now runs backend-external smoke/full with `-RequireRouterNoMock`.
- `GO`: router C3 chaos/soak/load/restart-storm validation is green locally and publishes `artifacts/test-results/c3/latest.json` plus `latest.md`.
- `GO`: devops real-Xray image supports `XNODE_XRAY_SHA256` archive verification for release rehearsals.
- `GO`: messenger-node release rehearsal requirements are now captured in `deep-devops/docs/MESSENGER_NODE_PRODUCTION_RUNBOOK.md`.
- `CONDITIONAL GO`: operator deployment is possible if the target host has a real Xray binary, valid Reality/TLS material, and a real `appsettings.Production.json`.
- `NO-GO`: attached green CI/release artifacts for the real-Xray no-mock rehearsal and C3 report are still outstanding.
- `NO-GO`: program-level platform matrix, full security/compliance, and release-discipline sign-off gates are not yet closed.

### Router Build Gate

Mark this section `GO` only when all items are true:

- [x] `dotnet build --configuration Release` succeeds.
- [x] `dotnet test XNode.slnx --configuration Release` succeeds.
- [x] `dotnet publish src/XNode/XNode.csproj --configuration Release --runtime linux-x64 --self-contained true -p:PublishSingleFile=true` succeeds.
- [x] Published artifact includes non-mock default config (`Vless:MockProcess=false`, real `Vless:XrayExecutablePath` in base config).

If all four are true, the answer to “can we build the production binary?” is `YES`.

### Operator Deployment Gate

Mark this section `GO` only when all items are true on the target host:

- [ ] Xray is installed at the configured production path.
- [ ] Reality or TLS keys/certificates are provisioned.
- [ ] `appsettings.Production.json` is present and reviewed.
- [ ] `DOTNET_ENVIRONMENT=Production` is enforced by the service manager.
- [ ] `GET /health/live` returns healthy after startup.
- [ ] `GET /health/ready` returns healthy or intentionally degraded under the documented semantics.
- [ ] `GET /status` shows the expected transport metadata and registry payload.
- [ ] One controlled client bootstrap flow succeeds against the real node.

If all items are true, the answer to “can we deploy it for controlled production-like validation?” is `YES`.

### Public Production Sign-Off Gate

This section is still `NO-GO` today.

The remaining blockers are:

- [ ] Attach the first green CI/release artifacts for the real-Xray no-mock rehearsal and C3 report.
- [x] Close router-specific operational evidence expected by the program baseline: local C3 chaos/soak/load validation plus operational artifacts are green.
- [ ] Close the program-level Android+iOS+Windows release matrix gate.
- [ ] Close mandatory security/compliance gates: security-gate CI artifact, policy-as-code, and external audit closure.
- [ ] Close release-discipline gates: credentialed provider canary, rollback rehearsal, post-release verification.

Until those items are closed, the correct answer to “is the router fully production-ready for public rollout?” remains `NO`.

### Practical Decision Rule

- If you only need a production build artifact for staging, controlled node bring-up, or infra rehearsal: `GO`.
- If you need a formal public production / GA sign-off: `NO-GO` until the blockers above are closed.

## Health

- `GET /health/live`: process liveness.
- `GET /health/ready`: runtime plus Xray readiness.
- `GET /status`: runtime status, Xray supervisor status, and current registry payload.

Readiness semantics for transport failover:

- `ready=true` when runtime is `running` and transport is either `running` or `degraded`.
- `degraded` means Xray hit restart limit inside `failureWindow` and entered cooldown before next retry.
- `transportMode` in readiness payload exposes current supervisor mode (`running`, `restarting`, `degraded`, and related states).

## Session RPC Ingress

`POST /api/session/rpc` accepts Session-style RPC envelopes:

```json
{
  "id": "request-1",
  "method": "fetch_rids",
  "payload": {}
}
```

Supported first-pass methods are `status`, `path_ping`, `fetch_rids`, `fetch_rcs`, `select_path`, and `store_rc`.

Runtime rejects public `report_path_result` requests. Public storage RPC results, including downstream HTTP failures, are not path-health evidence and cannot influence relay selection. The compatibility `churn-blocked router count` remains zero until XNode has an authenticated, direct peer-health plane.

Private peer routing is disabled by default. A controlled container or private-LAN deployment may opt in to
RFC1918 peer endpoints with `Runtime__AllowPrivatePeerEndpoints=true`. This does not permit loopback,
link-local, multicast, unspecified, CGNAT, documentation, or IPv6 unique-local addresses. Loopback remains
separately gated by `Runtime__AllowLoopbackPeerEndpoints=true`.

## Runtime Metrics

`GET /status` now includes `router.metrics` counters for key runtime flows:

- RPC ingress totals and failures
- relay/contact sync cycles and failures
- relay contact merge/reject counts
- heartbeat submission count
- path selection attempts/failures
- path repair attempts/successes
- compatibility churn-blocked router count (currently always zero; no unauthenticated failure scoring)

These counters are also persisted in heartbeat snapshots via `NodeDbStorageBackend`.

## Xray

The service writes the generated Xray config to `Vless:GeneratedConfigPath` and starts Xray with:

```bash
xray run -config /etc/xnode/xray.generated.json
```

For development or CI, set:

```bash
Vless__MockProcess=true
Vless__XrayExecutablePath=mock
```

Production guardrail:

- Non-development profiles reject VLESS mock settings at startup.
- Keep `Vless:MockProcess=false` and a real `Vless:XrayExecutablePath` in production profiles.

Supervisor failover policy:

- `Vless:MaxRestartAttempts`: max failures allowed inside `Vless:FailureWindow` before degraded mode.
- `Vless:FailureWindow`: rolling failure window for restart threshold counting.
- `Vless:DegradedCooldown`: cooldown duration before supervisor retries after entering degraded mode.

Default profile values are defined in `appsettings.json` and can be overridden per environment.

### Failover Validation Scenario

1. Configure a failing transport command (for test only):

  ```bash
  export Vless__Enabled=true
  export Vless__XrayExecutablePath=dotnet
  export Vless__MockProcess=false
  export Vless__MaxRestartAttempts=1
  export Vless__FailureWindow=00:00:10
  export Vless__DegradedCooldown=00:00:30
  ```

2. Start the router and watch `GET /status`.

3. Verify supervisor transitions:

  - `xray.mode` goes to `restarting`, then `degraded`.
  - `xray.degraded=true` and `xray.degradedUntil` is populated.
  - `xray.restartCount` increments.

4. Verify readiness/registry behavior during degraded state:

  - `GET /health/ready` stays `200` with `degraded=true` and `transportMode="degraded"`.
  - `registry.transport` in `GET /status` mirrors supervisor metadata (`mode`, `degraded`, `restartCount`, `lastExitReason`).

## Registry Heartbeat

Enable heartbeat by setting:

```json
{
  "registryHeartbeat": {
    "enabled": true,
    "endpoint": "https://registry.example.org/nodes",
    "interval": "00:00:30"
  }
}
```

The payload model is implemented in `XNode.Registry.RegistryPayload`.

`registry.transport` includes live transport metadata used by registry consumers:

- endpoint and transport mode (`publicHost`, `publicPort`, `transportMode`)
- health and lifecycle (`healthy`, `degraded`, `mode`)
- restart/failure counters (`restartCount`, `consecutiveFailures`)
- last lifecycle details (`lastExitReason`, `lastStartedAt`, `degradedUntil`)

## C3 Resilience and Load Baseline

Run the C3 scenario:

```bash
dotnet test xnode/tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj --configuration Release --filter "FullyQualifiedName~C3FailureAndLoadIntegrationTests" --logger trx
```

C3 test artifacts are written to:

- `xnode/artifacts/test-results/c3/latest.json`
- `xnode/artifacts/test-results/c3/latest.md`

Scenario coverage:

- soak: sustained runtime/session-rpc stability run
- chaos: packet loss + peer churn + restart storm fault injection
- load: path selection latency and session-rpc throughput

SLO baseline gate (current thresholds):

- soak success-rate >= 99%
- chaos success-rate >= 55% under packet loss profile 35%
- load throughput >= 400 req/s
- path-select p95 <= 15 ms
- restart storm must enter degraded mode

Observed baseline (latest run):

- soak success-rate: 100%
- chaos success-rate: 57.5% (packet loss profile 35%)
- load throughput: ~36.2k req/s
- path-select p95: ~0.62 ms
- restart storm: degraded mode entered

Known bottlenecks and remediation plan are emitted in C3 artifacts:

- bottleneck example: churn blocklist pressure under sustained loss/churn (requires a future authenticated peer-health plane)
- remediation actions:
  - scale path candidate pool for churn windows
  - add authenticated direct-peer health measurements before enabling any adaptive failure scoring
  - add supervisor restart jitter to reduce synchronized storms
  - enforce ingress concurrency budget/backpressure at saturation

## Replicated Encrypted Mailbox (Dormant)

The internal XNode-to-XNode replication endpoint is disabled by default. Do not enable it in
production until client AEAD, rotating/blinded mailbox identifiers, membership-based placement
and authenticated retrieval have a reviewed cross-repository contract.

```json
{
  "mailbox": {
    "enabled": false,
    "directoryName": "mailbox-v1",
    "maxBlobBytes": 81920,
    "maxStoredBlobs": 100000,
    "maxRecoveryScanFiles": 200000,
    "minimumTtl": "00:01:00",
    "maximumTtl": "7.00:00:00",
    "replicationFactor": 3,
    "writeQuorum": 2,
    "peerTimeout": "00:00:05",
    "maxReplayEntriesPerPeer": 2048,
    "maxReplicaRequestsPerPeerPerMinute": 240,
    "maxReplayPeerStates": 4096,
    "replayRetention": "00:05:00",
    "replayReservationTimeout": "00:02:00",
    "allowInsecureHttpPeerTransport": false
  }
}
```

When enabled, `POST /api/peer/mailbox/replica` is available only on the peer RPC listener.
Requests must be signed by a fresh registered XNode and are replay guarded. The `/status`
mailbox section reports only aggregate receiver counters; it never reports mailbox/blob
identifiers or ciphertext.

Plain HTTP is rejected by default because it exposes otherwise opaque mailbox metadata.
`allowInsecureHttpPeerTransport=true` is a development-only escape hatch for an isolated
Docker network or a deployment where an authenticated outer transport terminates immediately
in front of XNode.

Operational bounds:

- ciphertext is canonical base64 and its SHA-256 digest must equal `blobId`;
- TTL and ciphertext size are rejected outside configured bounds;
- writes are atomic and duplicate writes are idempotent;
- exact signed-request retries return the cached receipt after the first durable write;
- admission quotas are isolated per registered sender and stale reservations are recoverable;
- expired, corrupt and stale temporary entries are purged during bounded startup recovery;
- Windows ACLs are replaced and verified as service-account-only; Unix modes are verified as
  `0700` for directories and `0600` for files;
- file data and metadata are flushed before a receipt; parent directories are fsynced where the
  host filesystem supports it;
- peer timeouts and invalid node receipts fail closed and do not count toward write quorum.

### Dormant canonical client adapter

The source tree contains a deliberately uncomposed store-only adapter for the canonical
`MST1`/`MEO1` contract. It is not mapped to HTTP and therefore cannot be enabled by configuration
alone. This is intentional: production composition requires both a reviewed
`IMailboxClientCapabilityVerifier` and a native `MRR2` peer fanout implementation.

The adapter reports separate states for disabled, missing verifier, missing replica authorizer
and missing fanout. When used in a test composition it reserves
`(epoch, blindedMailboxId, operationId)`, request digest and a per-mailbox monotonic cursor before
fanout, persists the full opaque `MEO1`, and accepts only the deterministic replica ids selected
for the exact membership/placement context. Two native context-bound `MRR2` receipts and a
separate global coordinator sequence are durably bound before `MQR2` signing.

Exact concurrent retries are single-flight. Restart recovery either resumes the exact persisted
completion statement or fails closed; one coordinator sequence cannot sign two statements.
Cached `MQR2` bytes are not trusted as a cache hit: signatures, coordinator identity/sequence,
replica set and all request/membership bindings are reverified on every retry. Ledger loading
rejects non-canonical keys/hex, duplicate or rewound cursors/sequences, and inconsistent
state/receipt combinations.

E and E+1 use distinct membership commitments. Blob, size and remaining-TTL preflight occurs
before reserving a cursor, and expired operation records are cleaned without reusing cursor or
coordinator authorities. Conflicting operation-id reuse within an epoch/mailbox is rejected.

Do not expose a store endpoint until the remaining retrieve/ack slice is complete. In particular,
servers must return cursor-bound `MRP1`, persist `MAK1` tombstones, and must never infer or record
the client-side `Delivered` state.

Pinned offline package closure under `vendor/mailbox-client-package-corrected`:

- `Deep.Protocol.0.3.0-p09c2.f1a93c9.nupkg` —
  `6fb5c0f5e05ed5ef78e962c7ed515dec2656dd50f5f201fd68ff1cf29821ca23`
- `Deep.Protocol.Abstractions.0.3.0-p09c2.f1a93c9.nupkg` —
  `b48cfe11bc1481b1f210c25a02aa6f96c50937d79165fe76889b6564d2a91804`
- `Deep.Protocol.Protobuf.0.3.0-p09c2.f1a93c9.nupkg` —
  `8f27c94281ad70edd70f9e6c1876a9b9ec37abdc180a92eb7ea9009098cb3668`

The older `0.3.0-p09c.451f3dc` package must never be introduced into this repository.
`eng/mailbox-client.NuGet.Config` maps `Deep.Protocol` and `Deep.Protocol.*` exclusively to this
offline feed. Relevant projects restore in locked mode and commit `packages.lock.json` content
hashes; nuget.org has no wildcard mapping capable of resolving a Deep protocol package.
