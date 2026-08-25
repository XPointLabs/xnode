# XNode agent rules

The workspace rules in `../AGENTS.md` apply. This file contains only node-runtime deltas.

## Owns

- Node persistence, runtime state, health/readiness and bounded path selection.
- Production transport ingress/supervision and authenticated peer forwarding.
- Registry heartbeat, signed bootstrap/profile generation and mailbox route closure cache.
- Unit and integration tests for node, transport, profile and registry behavior.

Registry state lifecycle belongs in `deep-registry-api`; protocol bytes/crypto belong in
`deep-protocol`; Docker/release topology belongs in `deep-devops`.

## Repository rules

- Production readiness reflects the actual transport process and authority state; mock Xray is
  local-test-only and can never satisfy UAT/release evidence.
- Path selection rejects duplicate, unhealthy or unauthorized hops and remains deterministic for
  a fixed inventory.
- Bootstrap/heartbeat documents are signed, canonical and contain only supported Deep-native
  transport metadata. Do not add Session/onion compatibility aliases or fallback RPC paths.
- Persistent state survives restart; incompatible/corrupt state fails closed with quarantine and
  diagnostics rather than migration or silent loss.
- Update registry consumers, DevOps topology/evidence and `docs/operator.md` for config or payload
  changes.

## Verify

```powershell
dotnet test XNode.slnx
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external `
  -ManagedExternalProfile backend-external -RequireRouterNoMock
```

Run `../deep-devops/scripts/multi-node-rehearsal.ps1` for path, peer or release transport changes.
