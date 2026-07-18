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
- `GET /health/ready`: runtime, Xray, and production public-peer authorization readiness.
- `GET /status`: runtime status, Xray supervisor status, and current registry payload.

Readiness semantics for transport failover:

- `ready=true` when runtime is `running`, transport is either `running` or `degraded`, and Production public-peer authorization is in verified-ticket mode.
- `degraded` means Xray hit restart limit inside `failureWindow` and entered cooldown before next retry.
- `transportMode` in readiness payload exposes current supervisor mode (`running`, `restarting`, `degraded`, and related states).
- `publicPeerAuthorizationMode` exposes `DenyAll`, `UnverifiedNonProduction`, or the future `VerifiedTickets` mode. Production `DenyAll` deliberately returns `503`.

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

Runtime now also accepts `report_path_result` to feed churn/failure outcomes back into path repair.

## Private Peer Endpoints for UAT

Public/mainnet nodes must advertise a publicly routable peer RPC URL with the exact
`/api/peer/onion` path. A local Docker UAT may instead enable the exact private-peer
policy documented in `docs/ROUTER_SECURITY_TUNABLES.md`.

The exception is deliberately narrow:

- it binds the recipient router ID to one literal RFC1918 IPv4 `/32`, port, and exact path;
- the same immutable policy filters route contacts and the socket address used for the connection;
- it is disabled by default and fails startup in `Production`, on `mainnet`, or when the explicit test network identities differ;
- loopback, private DNS names, DNS rebinding, link-local/cloud metadata, multicast, unspecified addresses, redirects, and proxies remain blocked.

For UAT, set `DOTNET_ENVIRONMENT=UAT`, then set `Node:Network` and
`Runtime:PrivatePeerNetworkIdentity` to the same explicit test identity (normally `uat`)
and supply the complete per-recipient allowlist. Mr. X
owns approval of that UAT inventory. Remove the entire allowlist and disable the feature
before promoting a configuration to production.

For a three-router UAT, "complete" means the following 3 x 3 matrix. Each
router configuration must contain all three exact recipient tuples, including
its own tuple:

| Configuration loaded by | Recipient A | Recipient B | Recipient C |
| --- | --- | --- | --- |
| Router A | `A_ID @ 10.20.30.40:8080/api/peer/onion` | `B_ID @ 10.20.30.41:8081/api/peer/onion` | `C_ID @ 10.20.30.42:8082/api/peer/onion` |
| Router B | `A_ID @ 10.20.30.40:8080/api/peer/onion` | `B_ID @ 10.20.30.41:8081/api/peer/onion` | `C_ID @ 10.20.30.42:8082/api/peer/onion` |
| Router C | `A_ID @ 10.20.30.40:8080/api/peer/onion` | `B_ID @ 10.20.30.41:8081/api/peer/onion` | `C_ID @ 10.20.30.42:8082/api/peer/onion` |

Replace the symbolic IDs with full router IDs and derive all three rows from
the same Mr. X-approved inventory. Do not abbreviate IDs in configuration and
do not replace exact tuples with ranges. Private membership mode rejects any
allowlist whose exact unique cardinality is not three. Missing or mismatched
local and remote tuples have the same result: a three-hop storage route fails
with `path-not-found`. In private-only mode, a public contact cannot fill that
gap.

Validate the mode before accepting the UAT:

1. Set `Runtime:AllowPublicPeerEndpoints=false` and
   `Runtime:EnablePrivateAllowlistMembership=true` on all three routers, and
   deny public egress at the network layer.
2. Fetch each router's fresh signed contact from `/api/network/contact`.
   Mr. X must verify its signature, derived router identity, freshness, and
   exact advertised tuple before distributing it.
3. Submit all three contacts to every router through `/api/session/rpc` with
   method `store_rc`. The payload is the complete signed contact returned by
   `/api/network/contact`; no unsigned contact may be synthesized from config.
4. Confirm `/status` reports
   `publicPeerAuthorizationMode="DenyAll"` and
   `productionPublicRoutingReady=true`, plus:

   ```json
   {
     "router": {
       "privateMembership": {
         "enabled": true,
         "expectedRelays": 3,
         "registeredRelays": 3,
         "ready": true
       }
     }
   }
   ```

   `ready` remains `false` when any two of the three fresh signed contacts
   advertise the same X25519 public key, even if all three router identities
   are registered.

5. With runtime and transport healthy, confirm `/health/ready` returns `200`.
   Before all three signed contacts are registered it must return `503`.
6. Request a storage route and confirm it contains exactly the three expected,
   unique router IDs, with the contacted local router as entry hop.
7. In a disposable negative test, remove or alter each of the A, B, and C
   tuples in turn and confirm `path-not-found`; restore the approved inventory
   after every check.

The private allowlist is a trust anchor, not membership data. A contact becomes
registered only after `store_rc` validates its fresh Ed25519 self-signature and
its exact allowlisted router-ID/RPC-endpoint tuple. A seed whose derived public
ID differs from `Node:RouterId` fails startup in this mode.

`DenyAll` has different readiness meaning across environments: in
non-production private-only UAT it denies public peers while exact private
tuples remain operational. With private membership mode enabled, healthy
readiness is `200` only after all expected signed contacts are registered; in Production it
means no proof-capable public routing is available, so readiness is
intentionally `503` and `productionPublicRoutingReady=false`.

## Runtime Metrics

`GET /status` now includes `router.metrics` counters for key runtime flows:

- RPC ingress totals and failures
- relay/contact sync cycles and failures
- relay contact merge/reject counts
- heartbeat submission count
- path selection attempts/failures
- path repair attempts/successes
- churn-blocked router count

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

  - In non-Production, `GET /health/ready` stays `200` with `degraded=true` and `transportMode="degraded"`.
  - In Production, `DenyAll` public-peer authorization overrides transport health and keeps readiness at `503`.
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

- bottleneck example: churn blocklist pressure under sustained loss/churn
- remediation actions:
  - scale path candidate pool for churn windows
  - tune adaptive failure-score decay/threshold
  - add supervisor restart jitter to reduce synchronized storms
  - enforce ingress concurrency budget/backpressure at saturation
