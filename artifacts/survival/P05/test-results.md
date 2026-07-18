# P05 verification

Status: design/simulator green; ADR **PROPOSED / NOT-APPROVED**.

| Check | Result |
| --- | --- |
| Focused simulator Release | PASS, 16/16, 0 failed, 0 skipped |
| Full `XNode.slnx` Release | PASS, unit 100/100 and integration 30/30 |
| Production source delta | PASS, zero files under `src/` |
| Docker/network | NOT RUN; not required and prohibited by P05 scope |
| No-mock/multi-node rehearsal | NOT RUN; no release-path or product runtime change |
| Independent architecture review | PENDING |

Focused command:

```powershell
dotnet test tests\XNode.Tests\XNode.Tests.csproj `
  --configuration Release `
  --filter FullyQualifiedName~StoragePlacementSimulatorTests `
  --no-restore
```

Full command:

```powershell
dotnet test XNode.slnx --configuration Release --no-restore
```

The focused tests cover 4/20/100/1000-member nonce independence, balance and add-one minimal
remapping, plus removal stability, separate route/replica inputs, one-replica loss, stale read,
split epoch, exact/conflicting retry and tombstone dominance.

