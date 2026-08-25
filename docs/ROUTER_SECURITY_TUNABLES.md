# Privacy routing security tunables

The XNode host exposes only the Deep-native managed ingress and authenticated privacy peer relay
surface. Direct MAU2 client HTTP routes are
also not registered; an exit invokes the native mailbox runtime in process.

## `Node` managed ingress listener

| Setting | Default | Constraint |
| --- | ---: | --- |
| `ManagedIngressH2ListenUrl` | empty | Optional absolute root-only HTTP(S) URL for a dedicated HTTP/2-only managed-ingress listener. Its port must be distinct from `ApiListenUrl` and `PeerRpcListenUrl`. |

When enabled, the dedicated port serves only the frame and capability paths. Literal IP,
`localhost`, and host-name wildcard binding follow the existing `UseUrls` host semantics. The API
and peer listeners retain HTTP/1 support; the configuration fails closed before host startup for a
malformed URL or port collision.

## `PrivacyRouting` settings

| Setting | Default | Constraint |
| --- | ---: | --- |
| `Enabled` | `false` | A disabled node is live but fails readiness. Key/contact/peer fields must be empty while disabled. |
| `X25519PrivateKeyPath` | empty | Existing absolute secret file containing exactly 64 lowercase hex characters and a nonzero independent X25519 scalar. Never derive it from Ed25519. |
| `PublicPeerBaseUrl` | empty | Canonical origin used for the signed native privacy contact. HTTPS outside the local Development exception. |
| `MaximumConcurrentRequests` | `64` | `1..4096`, shared by public and peer privacy ingress. No queue. |
| `RequestsPerMinute` | `600` | `1..1000000`, process-wide fixed one-minute window. |
| `RequestTimeoutSeconds` | `30` | `1..120`. |
| `ReplyPaddingBlockBytes` | `4096` | Power of two in `256..65536`. |
| `ReplayCapacity` | `65536` | `1000..10000000`; fail closed when full. |
| `ReplayTtlSeconds` | `300` | `120..3600`. Applies to peer nonces and decrypted hop replay IDs. |
| `AllowInsecureHttpPeerTransport` | `false` | `true` is accepted only under ASP.NET Core `Development`. |
| `Peers` | empty | Must contain at least one unique, non-self router ID bound to one canonical origin. |

Each HTTPS peer requires two different lowercase 32-byte hex SPKI SHA-256 pins:
`CurrentSpkiSha256` and `NextSpkiSha256`. Certificate-chain validation must also succeed. Redirects
and proxies are disabled. DNS is resolved at connect time; production permits only publicly
routable results. The isolated Development lane may resolve exact configured origins to private
addresses. Loopback, link-local/metadata, multicast and unspecified results remain blocked.

For Development-only HTTP peers, both SPKI fields must be empty. This exception exists only for
the isolated six-node survival network. UAT and Production reject it at startup.

## Wire and resource bounds

- public: HTTP/2 `POST /api/ingress/v1/frame`;
- peer: HTTP/2 `POST /api/peer/privacy/v1/frame` on the peer listener;
- capability discovery: HTTP/2 `GET /api/ingress/v1/capabilities`;
- body: one opaque frame, exact `Content-Length`, `64..1572864` bytes;
- content type and accept: `application/vnd.xpoint.deep.ingress-opaque-v1`;
- content coding, query, early data, cookies, identity/billing/tracing headers and redirects:
  forbidden.

The endpoint performs bounded streaming admission before opening or forwarding the frame. Canonical
`DIE1` errors preserve whether rejection happened before forwarding or the outcome became unknown
after forwarding. A relay chooses the next origin only from `Peers` by the decrypted router ID;
the encrypted frame cannot supply a URL.

Peer relay requests are Ed25519 signed over sender router ID, recipient router ID, canonical
13-digit timestamp, random 16-byte nonce and SHA-256 of the opaque frame. The sender must be in the
configured peer inventory. A duplicate transport nonce returns outcome-unknown because a previous
attempt may already have forwarded.

## Acceptance checks

1. Start with a missing, uppercase, zero or Ed25519-reused X25519 key and confirm fail-closed
   startup.
2. Test an unknown/self next router and confirm no outbound request occurs.
3. Test current and next SPKI pins independently, a redirect, DNS rebinding and a private/metadata
   result outside Development.
4. Exhaust concurrency, rate and replay bounds and confirm bounded `DIE1` failures.
5. Confirm direct `/api/client/mailbox/v2/*` URLs return `404`.
6. Confirm a valid three-hop request returns a sealed `DRS1` carrying canonical `DPR1`, while the
   terminal MAU2 operation still requires the existing 2-of-2 durable mailbox quorum.
