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
| `PrivatePeerNetworkIdentity` | empty | Must exactly match `Node:Network`, which must be one of `uat`, `testnet`, `local`, `development`, or `ci`. |
| `PrivatePeerEndpointAllowlist` | empty | Exact tuples of `routerId`, literal RFC1918 IPv4 `/32`, port, and `/api/peer/onion` path. |

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
    "privatePeerNetworkIdentity": "uat",
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

The process fails startup when this feature is enabled under `Production`, when `Node:Network` is `mainnet`, when the two network identities do not match, or when any tuple is malformed. The default is empty and disabled. Do not set these values in a production configuration overlay.
