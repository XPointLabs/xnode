# P05 verification

Status: design/simulator green; ADR **PROPOSED / NOT-APPROVED**.

| Check | Result |
| --- | --- |
| Focused simulator Release | PASS, 11/11, 0 failed, 0 skipped |
| Full `XNode.slnx` Release | PASS, unit 95/95 and integration 30/30 |
| Production source delta | PASS, zero files under `src/` |
| Docker/network | NOT RUN; not required and prohibited by P05 scope |
| No-mock/multi-node rehearsal | NOT RUN; no release-path or product runtime change |
| Independent architecture review | PENDING |

Focused command:

```powershell
powershell -ExecutionPolicy Bypass -File eng\verify-p05-simulator.ps1 -Configuration Release
```

The wrapper uses the corrected filter, parses TRX counters and fails if total/executed is zero;
`dotnet test` alone can return exit code zero for a filter that matches nothing.

Full command:

```powershell
dotnet test XNode.slnx --configuration Release --no-restore
```

The corrected focused tests cover binary 32-byte route/16-byte replica types, a pinned owner
vector, 4/20/100/1000-member nonce independence/balance/minimal remapping, exact receipt bindings,
alternating AB/BC/AC prefixes, stale concurrent head rejection, unknown-result retry, signed
high-water/contiguous per-record evidence, omission rejection, exact tombstone target, E/E+1
continuity gaps and separate legacy mirror gaps.
