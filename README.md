# XNode

Production images are published to `ghcr.io/xpointlabs/xnode` only through the
manual **Publish production image** GitHub Actions workflow. A push to `main`
never publishes or changes a release tag.

.NET implementation of the Deep XNode runtime, with VLESS/Xray used only as
the client-to-node ingress transport.

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
dotnet test XNode.slnx
```

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
