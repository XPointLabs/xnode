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
| `AllowLoopbackPeerEndpoints` | false | Allows only loopback peers for explicit local/test runs. Do not enable in production. |

Outbound peer HTTP accepts only HTTP(S) endpoints bound to a fresh, signed, registered relay contact. Literal loopback, private, shared-address, link-local, documentation, multicast, and metadata ranges are rejected. DNS is checked at connection time and only a publicly routable resolved address is dialed; proxy use and redirect following are disabled.

Production peer contacts must advertise a publicly routable `/api/peer/onion` endpoint. Existing test-only loopback topology must explicitly set `Runtime__AllowLoopbackPeerEndpoints=true`; private LAN and Docker bridge addresses are not production relay endpoints.
