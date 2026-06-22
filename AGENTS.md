# Agent Specification - XNode

Last updated: 2026-06-10.

## Mission

`xnode` owns the Deep messenger node runtime: node database, path selection, runtime status, Session RPC ingress, VLESS/Xray transport supervision, registry heartbeat, and client bootstrap generation.

It is a new XNode implementation with Session-compatible behavior above the transport layer.

## Source Of Truth

- Workspace entry point: `../prompts/00_Agent_Entry_Point.md`.
- Operator docs: `docs/operator.md`.
- Session porting rules: `docs/SESSION_PORTING.md`.
- Registry API contract: `../deep-registry-api/AGENTS.md`.
- DevOps no-mock and multi-node rehearsal: `../deep-devops/AGENTS.md`.

## Ownership Boundaries

Owned here:

- `XNode.Core`: NodeDb, storage backend, path selection, runtime, config, Session RPC models.
- `XNode.Transport.Vless`: VLESS profile validation, Xray config generation, Xray supervisor.
- `XNode.Registry`: registry payloads, heartbeat client, bootstrap documents.
- `XNode`: ASP.NET service endpoints and health/readiness.
- Unit and integration tests for runtime/path/transport/registry behavior.

Not owned here:

- Registry state lifecycle beyond heartbeat payloads.
- Staking semantics.
- Protocol codec/crypto.
- Compose orchestration and release gates.

## New Deep Solution Rules

Router changes must preserve these runtime invariants:

- readiness reflects actual transport and runtime state,
- no-mock release profile uses a real Xray executable,
- path selection avoids duplicate relays and respects healthy node inventory,
- NodeDb persistence survives restart and handles corruption predictably,
- bootstrap documents contain enough transport metadata for clients to connect.

Do not add a release feature that works only with `Vless__MockProcess=true`.

## Session Compatibility Rules

Session behavior to preserve:

- client bootstrap shape and path-selection semantics,
- service-node registration/heartbeat expectations,
- onion/path routing abstractions at the RPC boundary,
- transport metadata sufficient for Session-style client ingress.

VLESS/Xray is a Deep transport choice. Keep Session semantics above that layer independent from Xray internals.

## Required Verification

```powershell
dotnet test XNode.slnx
```

For transport release-profile work, also validate through DevOps:

```powershell
powershell -ExecutionPolicy Bypass -File ..\deep-devops\scripts\test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock
powershell -ExecutionPolicy Bypass -File ..\deep-devops\scripts\multi-node-rehearsal.ps1
```

## Acceptance Gates

A router change is complete only when:

- unit and integration tests cover the touched behavior,
- readiness and runtime status expose enough diagnostics,
- no-mock release rehearsal remains possible,
- registry payload changes are reflected in registry/devops/e2e docs or tests,
- operator docs are updated for config changes.

## Stop-The-Line Conditions

- Release readiness can be true while transport is mocked.
- Bootstrap documents lack required transport metadata.
- NodeDb corruption causes silent data loss without diagnostics.
- Path selection can produce duplicate hops for multi-hop paths.
- Registry heartbeat changes without matching registry/e2e coverage.

## Agent Workflow

1. Read this file, `docs/SESSION_PORTING.md`, and relevant tests.
2. Identify whether the change is core runtime, transport, registry heartbeat, or ASP.NET endpoint.
3. Add focused tests before changing runtime behavior.
4. Run `dotnet test XNode.slnx`.
5. Run DevOps no-mock/multi-node checks for release-path changes.
6. Update operator docs and porting spec when behavior or config changes.
