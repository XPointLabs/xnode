# XNode

.NET port of the XNode runtime with Session Router semantics above the transport layer and VLESS/Xray used only as the client-to-node ingress transport.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing router runtime, transport, registry heartbeat, or deployment behavior.
- Use [`docs/SESSION_PORTING.md`](docs/SESSION_PORTING.md) for Session router/path/bootstrap migration rules.
- Keep mock Xray paths development/test-only; release rehearsal must use the no-mock profile.

## Projects

- `XNode`: runnable ASP.NET Core Linux service with health, status, client bootstrap, and session RPC ingress.
- `XNode.Core`: NodeDb, path selection, runtime, config load/render, and Session RPC models.
- `XNode.Transport.Vless`: Xray config generator and supervised Xray sidecar process.
- `XNode.Registry`: registry payload model, registration heartbeat client, and client bootstrap generation.
- `XNode.Tests`: unit tests for path selection, NodeDb, config, Xray config, and bootstrap.
- `XNode.IntegrationTests`: runtime restart/recovery and fake storage backend integration tests.

## Run Locally

```bash
dotnet run --project src/XNode
curl http://127.0.0.1:8080/health/ready
curl http://127.0.0.1:8080/api/bootstrap/client
```

Set `Vless__MockProcess=true` and `Vless__XrayExecutablePath=mock` when developing without an Xray binary.

## C3 Resilience Baseline

Run full verification (unit + integration + C3 soak/chaos/load scenario):

```bash
dotnet test XNode.slnx
```

C3 artifacts are written to:

- `artifacts/test-results/c3/latest.json`
- `artifacts/test-results/c3/latest.md`

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
