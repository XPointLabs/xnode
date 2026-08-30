# XNode

Production images are published to `ghcr.io/xpointlabs/xnode` only through the
manual **Publish production image** GitHub Actions workflow. A push to `main`
never publishes or changes a release tag.

.NET implementation of the Deep XNode runtime, with VLESS/Xray available as
the client-to-node masked ingress transport.

Release status (2026-08-30): XNode can terminate VLESS/Reality and forward to
managed ingress, but the current MAUI mailbox client still calls its signed
entry origin directly over HTTPS. Server capability alone is not end-to-end
anti-blocking evidence; client binding remains a release blocker.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing router runtime, transport, registry heartbeat, or deployment behavior.
- Keep mock Xray paths development/test-only; release rehearsal must use the no-mock profile.

## Projects

- `XNode`: runnable ASP.NET Core Linux service with health, status, Deep-native managed ingress, privacy relay, and in-process MAU2 mailbox exit.
- `XNode.Core`: durable mailbox/replication primitives and remaining node infrastructure.
- `XNode.Transport.Vless`: Xray config generator and supervised Xray sidecar process.
- `XNode.Registry`: registry payload model, registration heartbeat client, and client bootstrap generation.
- `XNode.Tests`: unit tests for mailbox durability, protocol pins, Xray config, registry, and bootstrap.
- `XNode.IntegrationTests`: privacy routing, mailbox restart/recovery, authority, and transport integration tests.

## Run Locally

```bash
dotnet run --project src/XNode
curl http://127.0.0.1:8080/health/ready
curl --http2 https://node.example/api/ingress/v1/capabilities
```

Set `Vless__MockProcess=true` and `Vless__XrayExecutablePath=mock` when developing without an Xray binary.

## Verification

Run the full unit and integration suite:

```bash
pwsh eng/Verify-Dnp1ProtocolClosure.ps1
dotnet test XNode.slnx
```

`XNode.ProfileGenerator` restores the frozen DNP1 exact-three package contour
from the repository-local `vendor/dnp1-survival-9a7eaed/packages` feed. The
gate rejects package additions, changed bytes, non-exact dependency ranges,
legacy Abstractions/Protobuf packages, and a network source for
`Deep.Protocol*`.

## Linux Publish

```bash
dotnet publish src/XNode/XNode.csproj \
  --configuration Release \
  --runtime linux-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  --output artifacts/xnode-linux-x64
```

See [docs/operator.md](docs/operator.md) for deployment notes.
