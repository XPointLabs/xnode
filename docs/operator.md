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

Runtime rejects public `report_path_result` requests. Public storage RPC results, including downstream HTTP failures, are not path-health evidence and cannot influence relay selection. The compatibility `churn-blocked router count` remains zero until XNode has an authenticated, direct peer-health plane.

Private peer routing is disabled by default. The only private-LAN exception is the exact
router-ID/RFC1918-address/port/path inventory described below. Loopback and broad private-network switches
are not supported.

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

- bottleneck example: churn blocklist pressure under sustained loss/churn (requires a future authenticated peer-health plane)
- remediation actions:
  - scale path candidate pool for churn windows
  - add authenticated direct-peer health measurements before enabling any adaptive failure scoring
  - add supervisor restart jitter to reduce synchronized storms
  - enforce ingress concurrency budget/backpressure at saturation

## Canonical P10C peer mailbox runtime

The XNode peer listener implements the P10I binary wire only. It is disabled by default and
must not be confused with public client-mailbox activation.

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
    "replicationFactor": 2,
    "writeQuorum": 2,
    "peerTimeout": "00:00:05",
    "peerReplayDirectoryName": "mailbox-peer-replay-v2",
    "peerMutationDirectoryName": "mailbox-peer-mutations-v2",
    "maxPeerReplayRecords": 100000,
    "maxPeerReplayRecordsPerRouterPairEpoch": 20000,
    "maxPeerReplayGcBatch": 1024,
    "maxPeerMutationRecords": 100000,
    "maxPeerMutationGcBatch": 1024,
    "allowInsecureHttpPeerTransport": false
  },
  "MailboxPeerAuthority": {
    "currentEpoch": 0,
    "currentMembershipCommitment": "",
    "currentEpochExpiresAtUnixSeconds": 0,
    "nextEpoch": 0,
    "nextMembershipCommitment": "",
    "nextEpochExpiresAtUnixSeconds": 0,
    "placementSelections": [
      {
        "epoch": 0,
        "placementCommitment": "64-lowercase-hex",
        "firstRouterId": "64-lowercase-hex",
        "secondRouterId": "64-lowercase-hex"
      }
    ]
  }
}
```

Enabling `Mailbox` also requires an authoritative current epoch/commitment/retirement time,
optionally a cryptographically distinct E+1 entry, and at least one exact placement-commitment to
two-distinct-router selection. Replace the illustrative zero/placeholder values above; they are
not an enableable configuration. The only mailbox peer routes are:

- `POST /api/peer/mailbox/v2/store`;
- `POST /api/peer/mailbox/v2/tombstone`.

Both accept exact raw `PRQ2` with `application/vnd.deep.mailbox.prq2` and return exact signed
`MRR2` with `application/vnd.deep.mailbox.mrr2`. The removed
`/api/peer/mailbox/replica` JSON route returns 404. The canonical routes return 404 on the public
API listener. Any non-POST method on either canonical path also returns 404.

Plain HTTP is rejected by default because it exposes otherwise opaque mailbox metadata.
`allowInsecureHttpPeerTransport=true` is a development-only escape hatch for an isolated
Docker network or a deployment where an authenticated outer transport terminates immediately
in front of XNode.

Operational invariants:

- PRQ1, MQR2, JSON and cross-operation frames are rejected; no translation exists;
- both RIP1/MIP1 proofs must verify Storage role/capability, exact router signing keys, epoch and
  the configured membership commitment; sender/recipient RouterIds are distinct identities,
  distinct from their independently bound and mutually distinct signing keys;
- Store binds the exact canonical MEO1 placement preimage; Tombstone must resolve the identical
  durable Store context; the exact router pair must be present in the authoritative placement
  selection allowlist;
- created-at has zero future skew and at most the protocol's fixed past-age window;
- replay is reserved before mutation in an exclusive crash-safe journal; an exact completed retry
  returns the cached verified MRR2 and a pending crash claim resumes idempotently. Persisted exact
  scopes remain retryable after the initial freshness window and retain their original effective
  reservation timestamp; an unknown stale request allocates no replay record;
- replay GC uses the authoritative epoch retirement time plus the protocol-fixed seven-day
  retention interval;
- replay startup and every sender/receiver reserve path run priority-ordered bounded collection
  before reporting capacity, so a full journal containing retired completed state remains live;
- every replay record is semantically validated at startup even when its retention boundary is in
  the future: the P10I state machine must accept its status/timestamp/epoch/retention ordering,
  Pending carries no response, and Completed carries an exact canonical MRR2-domain response;
- each Store mutation has one durable record with expiry/retention metadata. Pending Store is
  exclusive to its exact replay nonce. Tombstone advances that same record through
  `tombstone-pending` to `tombstoned`, so no two-file gap can admit a duplicate Store; startup
  validates exact epoch-plus-seven-day retention and state-specific nonce/timestamp fields,
  reconciles deletion, and bounded GC removes only state past its live/replay boundary;
- the sender coordinator accepts only the exact local and recipient MIP1-keyed MRR2 pair and
  the recipient endpoint must exactly match its verified RIP1 RPC endpoint plus the operation
  route, and emits native PRQ2-only MQR3. One receipt, timeout or invalid evidence is never quorum;
- host-global and per-operation fixed-window/concurrency admission happens before body parsing or
  cryptography. Request body, content type/encoding, at-most-15-second deadline, per-operation
  concurrency/rate and 120/minute verified-sender limits come from `MailboxWireHttpContract`;
- replay and mutation leases plus full corruption validation are resolved during hosted startup
  and are included in `/health/ready`; the first peer request is never the readiness probe;
- Windows ACLs are replaced and verified as service-account-only; Unix modes are verified as
  `0700` for directories and `0600` for files;
- on Windows, journal replacement uses `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`. Durable
  deletion first write-through-renames to an anonymous `.deleted` tombstone, which startup
  removes after a crash. Unix replacement/deletion fsyncs the file and parent directory;
- metrics and status contain counts only: no router id, membership capability, mailbox, placement
  route, operation id, ciphertext or receipt bytes are logged or labeled.

Ordinary onion peer replay remains process-memory-only. `/status` reports
`onionPeerReplay=volatile-explicit-debt`; P10C does not claim durable onion replay.

### Native MAU2 client adapter

The client routes accept only MAU2 carrying an authenticated canonical `MEO1`, `MBR2`, or `MBA2`
body and return `MQR3`, `MRP1`, or `MAR1`. They are mapped only by the explicit survival
Development composition. Production composition still requires reviewed authority and key
custody. There is no MCP1 envelope, V1 request decoder, translation, or fallback route.

The adapter ledger stores native MRR2 evidence and native MQR3 completion. Development ACK emits
the exact MBA2-ordered MQR3 list in MAR1; no MQR2 transcode is permitted.

The adapter reports `StoreReady`, `RetrieveReady`, and `AcknowledgeReady` independently;
aggregate `Ready` is true only when all three are ready. Status also exposes durable-replay and
tombstone-fanout configuration instead of overclaiming readiness. When used in a test
composition it reserves
`(epoch, blindedMailboxId, operationId)`, request digest and a per-mailbox monotonic cursor before
fanout, persists the full opaque `MEO1`, and accepts only the deterministic replica ids selected
for the exact membership/placement context. Two native context-bound `MRR2` receipts and the
ledger-allocated next global monotonic coordinator sequence are durably bound in one mutation
before `MQR3` signing. Request hashes and fanout responses have no sequence authority.
Replica receipt clocks are independent: each accepted time must be no earlier than the persisted
request acceptance, and each durable time must be no earlier than its own accepted time and
strictly before the common expiry. Equality between local and remote timestamps is not required.

The host reserves canonical-outcome capacity for the endpoint maximum before the first
ledger/blob/peer access. It persists exact MQR3/MRP1/MAR1 (or coarse MTO1 terminal state) before
completing replay with the outcome digest. A host-global per-operation pre-auth limiter keeps no
IP partitions; the post-verify limiter keys only a domain-separated hash of operation plus holder.

Exact concurrent retries are single-flight. Restart recovery either resumes the exact persisted
completion statement or fails closed; one coordinator sequence cannot sign two statements.
Only the exact durable PendingSame claim may acquire a recovery execution. PendingPrior and a
concurrent in-process InFlight request perform no worker or outcome mutation.
Cached `MQR3` bytes are not trusted as a cache hit: signatures, coordinator identity/sequence,
replica set and all request/membership bindings are reverified on every retry. Ledger loading
rejects non-canonical keys/hex, duplicate or rewound cursors/sequences, and inconsistent
state/receipt combinations.

E and E+1 use distinct membership commitments. Blob, size and remaining-TTL preflight occurs
before reserving a cursor, and expired operation records are cleaned without reusing cursor or
coordinator authorities. Conflicting operation-id reuse within an epoch/mailbox is rejected.
The two commitments must differ. `maxCursorAuthorities` bounds live per-mailbox authorities;
unused authorities compact into a durable retired cursor floor rather than remaining as
unbounded dictionary keys. `maxConcurrentSingleFlights` bounds unique active operations while
exact-operation waiters share one reference-counted entry.

The ledger owns `.adapter.lock` with exclusive file sharing for its complete lifetime. A second
ledger for the same directory, or a second adapter claim on one ledger, fails startup. Dispose
the adapter first and ledger second during orderly shutdown; only then can a replacement runtime
acquire the directory.

The native MAU2 runtime is the authorization boundary. It verifies the exact operation, operation
id, epoch, mailbox/placement/membership authority, canonical request digest, holder signature,
replay counter and claim digest before a worker can run. Readiness requires the strict decoder,
Ed25519 verifier, durable replay journal and durable canonical outcome store.

`MBR2` pagination is a stable high-water snapshot. The signed `XCT1` token binds the mailbox and
authority context, last cursor, snapshot high-water, page-size ceiling, expiry and exact page ACK
digest. It verifies against any currently authorized replica key to permit failover. If a replica
does not possess the durable snapshot data it fails closed; clients restart at cursor zero and
deduplicate locally.

`MBA2` reserves all targets and logical tombstones atomically before signing or fanout. Quorum
failure therefore hides the ciphertext from later retrieval but leaves retryable durable journal
state. Every item completes as a native Tombstone `MRR2` quorum and a native `MQR3`; exact retries
resume or return persisted, reverified bytes through the latest item expiry, including
multi-item ACKs with staggered TTLs. A new operation id for an already tombstoned cursor is
rejected and cannot create another journal or fanout. Retrieval emits MRP1, and Development ACK
returns exact MBA2-ordered MQR3 receipts in MAR1. The node never infers or persists client-side
`Delivered`.

Physical ciphertext cleanup is bounded after a durable ACK and repeated on initialization.
Deletion failure does not roll back a logical tombstone or ACK receipt; the ledger marks the blob
clean only after the exact delete and parent-directory durability barrier succeed. Ledger schema
v3 is intentionally incompatible with v2, whose records lack the canonical blob/placement/
membership evidence needed for safe retrieval and tombstones. Operation capacity counts stores,
ACK operation records and each ACK item.

Do not expose client mailbox endpoints in production. XNode can now consume the public PMA1
issuer/epoch/NodeIngress-SPKI substrate, but it deliberately remains unready until a separate
hash-bound revocation artifact can answer serial-level decisions. A survival-only Development
composition exists for honest two-XNode interoperability testing. The activation decision is frozen in
`docs/adr/0006-mailbox-client-activation-blocker.md`.

`MailboxClient` remains fail-closed by default:

```json
{
  "MailboxClient": {
    "enabled": false
  }
}
```

Setting it to `true` from JSON, environment variables or command-line configuration prevents host
construction in production while the revocation artifact gate is open. In Development it also requires `MailboxClientAdapter:Enabled=true`,
`Mailbox:Enabled=true`, and an explicit `developmentFixture` containing a pinned 16-byte network
id, issuer public key and generation/validity window, coordinator base URL, current/next
placement ids and their SHA-256 commitments, two distinct replica ids and matching Ed25519 public
keys, current/next local and remote canonical base64 MIP1 proofs, and revoked serials. E/E+1
membership commitments and validity windows live in `MailboxClientAdapter`. The node key must
match the local proof; there is no remote or client private-key field. Proof descriptors provide
the remote peer RPC endpoint. `coordinatorUrl` must be an origin-only URL whose host and port
exactly match `Node.PublicHost` and `Node.PublicPort`; it is intentionally independent from the
container bind address in `Node.ApiListenUrl`. LAN HTTP is accepted only inside this explicit
Development composition. `/status` and `/health/ready` expose
`starting`, `ready`, or fail-closed startup state and never report enabled before the durable
ledgers and adapter initialize.

### Production PMA1 authority substrate

The production-only public authority loader is configured independently from route activation:

```json
{
  "MailboxClientProductionAuthority": {
    "enabled": true,
    "artifactPath": "/run/secrets/deep/mailbox-authority.pma1",
    "revocationArtifactPath": "/run/secrets/deep/mailbox-revocation.pmr1",
    "topologyArtifactPath": "/run/secrets/deep/mailbox-topology.pmt1",
    "selectionArtifactDirectory": "/run/secrets/deep/selections",
    "readinessBlindedPlacementId": "<64 lowercase hex>",
    "readinessSelectionInputCommitment": "<64 lowercase hex>",
    "artifactTrustRoot": "/run/secrets/deep",
    "lastKnownGoodPath": "/var/lib/xnode/mailbox-authority/authority.pml1",
    "closureDirectory": "/var/lib/xnode/production-mailbox-closures",
    "closureStateHmacKeyPath": "/var/lib/xnode/secrets/closure-state-hmac.key",
    "closurePublisherEd25519PublicKey": "<64 lowercase hex>",
    "pinnedMrXPublicKeySha256": "<64 lowercase hex>",
    "expectedNetworkId": "<32 lowercase hex>",
    "clockSkewSeconds": 60,
    "maximumArtifactBytes": 65536,
    "maximumRevocationArtifactBytes": 131072,
    "maximumTopologyArtifactBytes": 4997504,
    "maximumSelectionArtifactBytes": 8840,
    "maximumStoredClosures": 100000,
    "maximumClosureStoreBytes": 536870912,
    "maximumClosureVersionsPerSelection": 4,
    "maximumClosureLineagesPerSelection": 4,
    "maximumClosureReservations": 128,
    "maximumClosureReservationLifetimeSeconds": 86400,
    "minimumClosureReservationLifetimeSeconds": 60,
    "closureScheduleAccountingOverheadBytes": 1024
  }
}
```

This section is rejected outside `Production`. All paths must be absolute; PMA1, PMR1, global PMT1
and the per-selection PMS1 directory must stay inside the explicit immutable trust root, while the LKG must stay inside
`Node:DataDirectory`. Every
ancestor from each file to that trust root is checked before each open and may be writable only by
the service identity. On Linux all public artifacts are owner-only `0400` regular files and the
pre-provisioned PML3 LKG is `0600`; no traversed path may be a symlink. On Windows files and
ancestors must have the exact service owner and protected non-inherited service-only ACLs, with the
public artifacts read-only. PML3 contains
only generations and SHA-256 chain state, never a private/signing key, holder, capability,
mailbox id, or endpoint.

Startup performs canonical PMA1 decode, pinned Mr. X key-hash and Ed25519 verification, then
canonical PMR1 verification with the same clock observation and skew. PMR1 must match the exact
network, authority binding, issuer, revocation generation/head/previous-head/times and snapshot
hash declared by PMA1; its issuer signature is verified before an unknown MCG2 serial may return
`false`. PMA1, PMR1, PMT1, PMS1, LKG and lock opens reject final-path links and compare native file identity
before/during/after validation. The lock is either exclusively created or opened only after exact
validation; an unchecked `OpenOrCreate` path is never used. XNode then verifies issuer-signed PMT1
against that exact authority and a caller-bound readiness PMS1 against the same time observation.
Only after all four artifacts verify does XNode atomically replace and durably flush one combined
LKG. The accepted immutable authority, revocation, topology and readiness-selection bundle is
published with one reference swap only after persistence. Separate authority and topology anchors
permit independent exact successors and idempotent restart; rollback, forks, mismatches and
partial successor publication fail closed without advancing the durable bundle.
Diagnostics expose only coarse state and generations, not paths, endpoints, pins, hashes or
exception text.

Registry-independent refresh uses only constant-path binary POST endpoints. The public
`/api/production-mailbox/closure` request is exactly 208 bytes and binds a timestamp, nonce,
selection commitment and exact durable old-PMS hash to an Ed25519 proof by the mailbox owner. Neither path nor query contains a
mailbox-derived identifier; ASP.NET request-body logging is not enabled and responses carry
`Cache-Control: no-store`. The peer-only preposition endpoint accepts a bounded PMP1 command,
not a bare closure: a dedicated pinned publisher signs its timestamp, nonce, exact envelope hash
and target replica id. PMP1 also has two fixed canonical legacy-replica slots. Registry may fill
them only with the strictly sorted, unique old-current replica ids from the exact previously
committed PMS1. They must not overlap the PSS1 old-next/new selections; XNode rejects redundant,
zero, duplicate, non-canonical or unsigned changes, and accepts a legacy target only when the
signed set contains it. The host also enforces the inverse listener rule: the PMP1 route returns 404
on the public API listener and is reachable only on the configured peer RPC port. The envelope
always contains exact PMA1/PMR1/PMT1/PMS1/PSS1; PSS1 is
mandatory because this cache is used only for LKG advancement.

Before a proactive rotation sweep, Registry reserves conservative capacity through peer-only
`POST /api/peer/production-mailbox/closure-capacity`. The request is an exact 208-byte PMB1
publisher-signed reserve/renew/release command bound to a random opaque cohort id, target replica,
monotonic revision, expiry, count and bytes. XNode returns an exact 248-byte PMB2 receipt signed by
the target node. PMP1 is a clean-break 280-byte header and binds the same cohort id; a zero cohort
is allowed only for ordinary unreserved publication, while a non-zero cohort atomically transfers
the positive schedule count/byte delta from unused reservation headroom to actual store usage.
The byte charge includes the configured conservative per-schedule filesystem/framing overhead.
Exact command and schedule replay never double-charge. Renewal cannot reduce already consumed
capacity; release or expiry frees only unused balance, and actual schedules remain charged until
their ordinary safe expiry GC. The HMAC ledger is only a rebuildable cache. Each cohort has a
content-addressed PBF1 floor containing the complete authoritative reservation state, monotonic
state generation and predecessor marker hash; startup rejects marker forks and rebuilds any stale
or replayed ledger from the highest exact chain. PBT1 binds both schedule hashes and before/after
floor hashes/generations and recovers in journal→schedule→floor→ledger order. A bounded terminal
floor is retained after release/expiry before deletion, so recently replayed pre-release ledgers
cannot restore headroom. Full rollback of the complete protected closure directory beyond that
tombstone retention remains an operator/storage-integrity boundary and is not a hardware monotonic
counter guarantee. Registry must keep fresh PMB2 receipts from every required replica with its configured
renewal margin; expiry or renewal failure freezes further cohort publication rather than admitting
part of a rotation.

PMB1 freshness is required for every mutation. After publisher signature and exact target
verification, an exact command hash that is already the authoritative cohort floor may recover its
byte-identical PMB2 after PMB1 expiry or restart. This is a read-only lost-response path: it does
not extend expiry, change counters, renew or resurrect released capacity. Unknown, changed,
same-revision-fork and superseded expired commands are rejected coarsely.

If an unreleased reservation has already auto-expired into a terminal floor, the node accepts only
its authenticated exact revision-successor Release. The returned PMB2 binds that Release command,
reports reserved equal to consumed, preserves every actual schedule charge, and cannot renew or
resurrect capacity. This lets Registry finish durable post-cutover cleanup after a long outage.

If Registry remains unavailable until the bounded terminal floor is garbage-collected, it uses the
peer-only constant-path `POST /api/peer/production-mailbox/closure-capacity-reconciliation`. The
exact 504-byte publisher-signed PMB3 embeds the last exact node-signed PMB2 and binds cohort,
target, revision and command/receipt hashes. XNode returns an exact 272-byte node-signed PMB4
`AbsentTerminal` only after a read-only authoritative floor/ledger/schedule accounting check under
the process lock. A live floor, pending transfer, invalid prior receipt, fork, corrupt ledger or
stale accounting returns a coarse 400. The endpoint never reserves, releases, renews or extends
capacity, is peer-listener-only and returns `Cache-Control: no-store`.

Each route lineage occupies one bounded, atomically replaced schedule file under sharded
HMAC(selection commitment)/HMAC(selection commitment + durable old-PMS hash) directories, so
neither stable value is present in filesystem names. Different devices at different durable old-PMS
anchors can coexist and PMQ1 selects one exact lineage. Exact replay is idempotent. Every existing
entry is semantically verified before a candidate is appended. The
candidate must advance authority, topology and epoch/generation while preserving the exact network,
owner, blinded route, selection commitment and original durable old-PMS/authority/topology anchor.
Rollback, same-generation forks, renamed cross-route files and commands for another replica fail
closed under an in-process gate plus a native cross-process store lock. Two XNode processes must
not normally share a closure directory, but if they do, the lock serializes reconciliation and
schedule append rather than allowing the last writer to win.
Startup and every mutation reconcile count and bytes through stable no-follow handles, reject
unsafe/reparse/identity-swapped files, and refuse stores above both configured
caps. Fetch returns the highest forward entry whose PSS1 window is live and never serves a future
entry early. Startup globally removes only schedules whose every entry is expired beyond skew.
Mutation performs selection-local expiry compaction first and runs the global expired scan only on
count/byte pressure; an ambiguous file or directory delete/parent flush fails the attempt and the
next locked reconciliation resumes from exact disk state. Empty lineage/selection/shard directories
are removed durably, and startup bounds then sweeps the empty tree deepest-first; an over-bound tree
fails closed for operator inspection. A schedule containing any live or future proof is never evicted. Clients
still perform full PSS/LKG verification and do not trust the cache.
An orphan `*.tmp` atomic-write file makes startup fail closed instead of disappearing from byte
accounting. Inspect the interrupted write and remove the orphan only after confirming the adjacent
canonical route file is intact; restart then performs a fresh authoritative scan.

`maximumClosureVersionsPerSelection` is an availability horizon, not merely a storage tuning
number. Since PSS1 is limited to 24 hours, four contiguous overlapping versions can cover at most
about four days of complete Registry/issuer outage. Operators must reserve both the global count
and byte caps for every current and future version before promotion. Gaps between signed windows
remain real outages. The 365-day OfflineCheckpoint old-anchor age permits recovery of a long-offline
client after infrastructure returns; it does not promise 365 days of control-plane outage. Survival
Beta must advertise only the configured, prepositioned contiguous horizon.
`maximumClosureLineagesPerSelection` separately bounds simultaneous device/LKG anchors for the
same stable selection commitment; exceeding it fails before any new schedule is written.

After the complete bundle verifies, diagnostics report `authorityRevocationReady=true`,
`topologyArtifactVerified=true`, and `productionMailboxRoutesReady=true`. Each mailbox operation
still fails closed unless its own commitment-named PMS1 verifies for the requested blinded
placement. The runtime recomputes rendezvous ranking, requires exactly two distinct replicas and
canonical MIP1/RIP1 proofs, binds the proof route to the PMT HTTPS origin, and enforces the current
or next SPKI pin during TLS. Raw mailbox identifiers, selection inputs and replica IDs are not
logged or exposed. Official-managed PMA1 still requires public HTTPS; explicit user-managed
private-HTTPS policy remains supported.

Client HTTP is binary-only:

| Operation | POST route | MAU2 inner body | Request bytes | Success response | Success |
|---|---|---|---:|---|---:|
| Store | `/api/client/mailbox/v2/store` | MEO1 | 608..82344 | `application/vnd.deep.mailbox.mqr3` | 200 |
| Retrieve | `/api/client/mailbox/v2/retrieve` | MBR2 | 536..792 | `application/vnd.deep.mailbox.mrp1` | 200 |
| Acknowledge | `/api/client/mailbox/v2/acknowledge` | MBA2 | 576..4792 | `application/vnd.deep.mailbox.mar1` | 200 |

All three request media types are `application/vnd.deep.mailbox.mau2`.

Failures have empty bodies: malformed 400, authentication 401, authorization 403, replay/
idempotency conflict 409, missing length 411, too large 413, media type/encoding 415, admission
429, dependency/quorum unavailable 503, and deadline 504. Exact byte limits, deadlines and
admission ceilings come from `MailboxWireHttpContract`.

The active native mailbox package closure is under `vendor/production-successor-1059184`, produced
by two byte-identical normalized archive builds from accepted `deep-protocol` source
`105918421eb5621bec86aeaac56013b269472aa7`:

- `Deep.Protocol.0.4.0-production.1059184.nupkg` —
  `e4c29cd2de20d7863cdb7af993468953208e6a8097cee4de2a7cdfb468918c7f`
- `Deep.Protocol.Abstractions.0.4.0-production.1059184.nupkg` —
  `dcb00f2646b5a8bcf907f3936f761a00a6f0f360386e6631cd6e6513c711efe8`
- `Deep.Protocol.MembershipRoutes.0.4.0-production.1059184.nupkg` —
  `c2c1f3a5179cc10d32ed479225d730b9961fc7fbe7bd2e328b96f2a3fab1447b`
- `Deep.Protocol.Protobuf.0.4.0-production.1059184.nupkg` —
  `8912fa06c207bf48cddd251347ab7e7544c03485dff4222a3ec2fb86b8f13a56`

Core/runtime/test projects resolve the exact PMA1+PMR1+PMT1/PMS1 version from the local feed in locked mode.
`XNode.ProfileGenerator` and its tests remain isolated on the exact older P04/ProfileCarrier
closure because that carrier requires it.

The native MAU2 client adapter is active when the validated mailbox-client activation plan maps
the development routes documented above. Startup remains fail-closed until the peer runtime,
authenticated capability runtime, operation ledger, and native adapter all report ready.

The active replay journal is stored below
`<Node.DataDirectory>/mailbox-capability-replay-v3/replay.json`, which resolves to the existing
`/state` volume in survival containers. It uses an exclusive process lease, same-directory
write-through replacement and file/parent durability barriers. A crash after reservation leaves
an explicit `Pending` record; it is never silently retried as new, and only recovery with the
exact claim can complete it. Diagnostics expose counts only, never issuer, serial, operation,
request or capability bytes.

Side-effect-free post-verification cancellation may instead persist `Released`. This is not a
deletion: the counter floor and exact claim digest survive restart, exact retry can reserve it
again, lower and same-counter conflicting claims remain rejected, and only a higher counter can
advance. Records are collected only after grant/authoritative epoch validity plus the fixed
seven-day replay-retention interval. A host background worker processes at most 1024 entries per
minute. It durably marks a bounded replay batch expired first, removes only the exact matching
canonical outcomes, and then finalizes those replay markers. Interrupted batches resume safely
after restart, and the equality boundary remains retained. Diagnostics include Pending,
Completed, Released and remaining-capacity counts. Long-lived issuer-key validity does not pin
expired individual grants, and issuer authorities must never reuse a capability serial.

Replay schema v3 also stores the accepted wall-clock high-watermark. Capability validity and
collection use `max(observedTime, durableFloor)`, and the floor never decreases. Rollback up to
60 seconds is absorbed by the floor; larger rollback rejects capability verification until the
clock recovers. Because the messenger is pre-production, older replay schemas are rejected
unchanged rather than migrated.

For MBR2 and MBA2, cryptographic capability verification occurs before delivery admission,
replica-authority selection, continuation processing, or mailbox-specific ledger/blob access.
Therefore a forged but canonically framed request cannot probe mailbox presence or spend storage
I/O. Cancellation before the first durable effect releases only a new reservation. Cancellation
after ACK reservation, local storage, or peer mutation preserves Pending; exact restart retry
resumes the ledger and completes replay without duplicating remote work.
