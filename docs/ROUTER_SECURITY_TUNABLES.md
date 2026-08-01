# Router Security Tunables

`Runtime` settings in `src/XNode/appsettings.json` protect the public session and peer RPC surfaces. Environment variable names use ASP.NET Core double underscores, for example `Runtime__MaxPeerRequestBodyBytes`.

| Setting | Default | Purpose |
| --- | ---: | --- |
| `MaxPeerRequestBodyBytes` | 262144 | Kestrel request cap for `/api/session/rpc` and `/api/peer/onion`. |
| `MaxRpcPayloadBytes` | 131072 | Maximum JSON-RPC payload accepted by `RouterRuntime`. |
| `MaxOnionEnvelopeBytes` | 98304 | Maximum encrypted onion request. |
| `MaxOnionLayerBytes` | 98304 | Maximum decrypted onion layer. |
| `MaxStoragePayloadBytes` | 81920 | Maximum body forwarded to storage through an onion layer. |
| `MaxRelayContactsPerResponse` | 500 | Cap for `fetch_rcs`. |
| `PublicApiPermitLimit` | 240 | Per-source-IP fixed-window limit for peer/session ingress. |
| `PublicApiRateLimitWindow` | 00:01:00 | Ingress rate-limit window. Requests are rejected immediately; they are never queued. |
| `AllowLoopbackPeerEndpoints` | false | Legacy setting. Any `true` value now fails startup; loopback onion peers are always blocked. |
| `EnablePrivatePeerEndpoints` | false | Enables exact RFC1918 peer tuples only after all non-production guards pass. |
| `ProductionPublicPeerPorts` | `[443]` | Exact HTTPS ports eligible for production public peer RPC after endpoint-ownership proof. |
| `AllowPublicPeerEndpoints` | true | Non-production composition switch. Set false for an isolated private-only UAT; Production ignores true and remains fail-closed. |
| `PrivatePeerNetworkIdentity` | empty | Must exactly match `Node:Network`, which must be one of `uat`, `testnet`, `local`, `development`, or `ci`. |
| `PrivatePeerEndpointAllowlist` | empty | Exact tuples of `routerId`, literal RFC1918 IPv4 `/32`, port, and `/api/peer/onion` path. |
| `EnablePrivateAllowlistMembership` | false | Non-production private-only mode in which a fresh signed contact matching an exact allowlist tuple may become registered membership. Configuration alone never creates a member. |

Outbound peer HTTP accepts only HTTP(S) endpoints bound to a fresh, signed, registered relay contact. Literal loopback, shared-address, link-local, documentation, multicast, unspecified, and metadata ranges are rejected. DNS is checked at connection time and only a publicly routable resolved address is dialed; proxy use and redirect following are disabled.

Production peer contacts must advertise a publicly routable endpoint whose path is exactly `/api/peer/onion` and whose query is empty. Private hostnames never receive an exception: a hostname resolving or rebinding to a private address is blocked during the socket connect decision.

For a Docker/UAT topology that cannot advertise public addresses, configure exact tuples:

```json
{
  "Node": {
    "network": "uat"
  },
  "Runtime": {
    "enablePrivatePeerEndpoints": true,
    "enablePrivateAllowlistMembership": true,
    "privatePeerNetworkIdentity": "uat",
    "allowPublicPeerEndpoints": false,
    "privatePeerEndpointAllowlist": [
      {
        "routerId": "1111111111111111111111111111111111111111111111111111111111111111",
        "ipAddress": "172.20.0.11",
        "port": 8081,
        "path": "/api/peer/onion"
      }
    ]
  }
}
```

The host environment must also be explicitly non-production, for example
`DOTNET_ENVIRONMENT=UAT` (or `ASPNETCORE_ENVIRONMENT=UAT`). ASP.NET Core defaults to
`Production` when neither value is set, so the exception will intentionally fail startup
until the UAT environment identity is explicit.

Each router needs one tuple for every private recipient it may contact. The advertised relay contact must use that same literal address, port, path, and router identity. Neighboring addresses, a different port/path/router, loopback, IPv6 ULA, and non-RFC1918 addresses do not match.

### Three-router UAT allowlist matrix

A three-router private-only UAT requires the complete 3 x 3
node-to-recipient matrix below. Each row is the allowlist loaded by that
router; each cell is one exact recipient tuple. `A_ID`, `B_ID`, and `C_ID`
stand for the full 64-character router IDs.

| Configuration loaded by | Recipient A | Recipient B | Recipient C |
| --- | --- | --- | --- |
| Router A | `A_ID, 10.20.30.40, 8080, /api/peer/onion` | `B_ID, 10.20.30.41, 8081, /api/peer/onion` | `C_ID, 10.20.30.42, 8082, /api/peer/onion` |
| Router B | `A_ID, 10.20.30.40, 8080, /api/peer/onion` | `B_ID, 10.20.30.41, 8081, /api/peer/onion` | `C_ID, 10.20.30.42, 8082, /api/peer/onion` |
| Router C | `A_ID, 10.20.30.40, 8080, /api/peer/onion` | `B_ID, 10.20.30.41, 8081, /api/peer/onion` | `C_ID, 10.20.30.42, 8082, /api/peer/onion` |

All nine cells are required. In particular, each row includes the router's
own tuple because route assembly validates the local entry hop with the same
policy used for remote socket connections. This matrix is an inventory, not
a CIDR or port-range rule; generate each row from the same reviewed source of
truth and render the full router IDs in the deployed JSON.

With `AllowPublicPeerEndpoints=false`, omission or mismatch of any tuple needed
by a three-hop route returns `path-not-found`. A registered public relay cannot
replace the missing private hop because the effective public authorizer is
`DenyAll`. This is intentional fail-closed behavior and must not be worked
around by enabling public peers.

### Signed private membership bootstrap

`EnablePrivateAllowlistMembership=true` is the chain-free bootstrap contract
for an isolated UAT. It is disabled by default and fails startup unless private
endpoints are enabled, public peers are disabled, signed contacts are required,
the explicit non-production network identities match, the public authorizer is
`DenyAll`, and the allowlist has exactly three entries with one unique endpoint
per unique router ID,
including the local router.

The allowlist is only an authorization boundary. It does not create contacts
or membership. On startup the router derives its public ID from the configured
Ed25519 seed; a mismatch with `Node:RouterId` is fatal. The router then creates,
signs, validates, and registers its own exact contact.

An operator-controlled host bootstrap must:

1. fetch `/api/network/contact` from each of the three loopback router APIs;
2. verify every contact signature, freshness, router ID, and exact RPC endpoint;
3. submit all three contacts to every router with `/api/session/rpc`, method
   `store_rc`, using the signed contact as the request payload;
4. require each signed RPC response to succeed;
5. confirm `/status` reports
   `router.privateMembership.enabled=true`,
   `expectedRelays=3`, `registeredRelays=3`, and `ready=true`;
6. request `storage_route` and verify exactly the three expected unique IDs.

`store_rc` verifies signature and freshness before checking the exact private
tuple. Unsigned, expired, public, neighboring, wrong-port, wrong-path, or
wrong-router contacts are not stored as membership. Membership insertion and
contact storage occur under the same NodeDb state gate.

While the membership is incomplete, `/health/ready` returns `503` and
`storage_route` returns `path-not-found`. Once all configured IDs have fresh,
valid, exact signed contacts with route-wide unique X25519 public keys, the
registered set equals that configured set,
Xray is ready, and authorization remains `DenyAll`, readiness returns `200`.

The process fails startup when this feature is enabled under `Production`, when `Node:Network` is `mainnet`, when the two network identities do not match, or when any tuple is malformed. The default is empty and disabled. Do not set these values in a production configuration overlay.

For a private-only UAT, also set `Runtime:AllowPublicPeerEndpoints=false`.
This installs the deny-all public authorizer while retaining exact RFC1918
tuples. Network policy must additionally deny public egress as defense in
depth.

Expected authorization and readiness signals, assuming the runtime and
transport themselves are healthy:

| Deployment mode | `/status` authorization fields | `/health/ready` |
| --- | --- | --- |
| Non-production private-only UAT without membership mode | `publicPeerAuthorizationMode="DenyAll"`, `productionPublicRoutingReady=true` | `200` when runtime and transport are healthy; route availability is a separate signal |
| Non-production private membership UAT | Above fields plus `router.privateMembership.ready` | `503` until exact signed membership is complete, then `200` |
| Non-production public-enabled test (`AllowPublicPeerEndpoints=true`) | `publicPeerAuthorizationMode="UnverifiedNonProduction"`, `productionPublicRoutingReady=true` | `200`; not a production security posture |
| Production safe fallback | `publicPeerAuthorizationMode="DenyAll"`, `productionPublicRoutingReady=false` | `503`; public routing is intentionally unavailable |

## Production public peer proof

Production public peer RPC is fail-closed. A public contact must use HTTPS, use
an explicitly configured `ProductionPublicPeerPorts` value (443 by default),
and pass an `IPublicPeerEndpointAuthorizer` decision bound to the router ID and
endpoint. The executable currently installs the deny-all authorizer in
Production. A registry consumer must provide a reviewed challenge/receipt that
proves control of the endpoint with the same router identity and binds the
resolved public address before public peer forwarding can be enabled. The
resolved-address decision is repeated immediately before socket connection.
A signed relay contact alone is not proof that the signer controls the
advertised public host.

Production construction also requires an
`IProductionPublicPeerEndpointAuthorizer`. The generic non-production
allow-all implementation does not implement that capability and is rejected
at startup.

`/health/ready` and `/status` expose the effective public-peer authorization
mode. A Production process using the safe `DenyAll` fallback is deliberately
not ready (HTTP 503), because it cannot forward public peer traffic. Only the
future `VerifiedTickets` mode can make Production public routing ready.

IPv6 peer resolution accepts only assigned global-unicast space and rejects
NAT64, Teredo, 6to4, ORCHID, benchmarking, documentation, ULA, link-local and
other special-purpose ranges. This validation is repeated immediately before
the socket connection.
