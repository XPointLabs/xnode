# S00 — bounded native Windows replacement

Date: 2026-10-03. Baseline: XNode
`76dd0dbc50e861d22da7b9f8b3dc060142c012f3`; Protocol
`de1c2205cec0521bc3052c84dbada22d0a0f12e0`.

## Reproduction and correction

The unchanged five-case claim/restart selection first passed, then failed on its
second run: the concurrent exhaustion scenario reached a non-success result.
The harness now checks the expected status before the signature verifier, keeping
all original placement/signature/claim assertions. A transparent observer wraps
the actual native barrier, rethrows errors and emits only operation category,
file kind, exception class and numeric code; no paths/identifiers/bytes.
On the fifth observed run, the real failure was:
`OutcomeUnknown / OutcomeUnknown; replace:claim-state:Win32Exception:5`.
This links the previously ambiguous non-success to native replacement, but does
not identify the process or ACL condition responsible for the intermittent denial.

Six new Windows filesystem cases ran against the single-attempt barrier: five
failed and the missing-source case passed. Actual `FileStream` handles deny
native rename for source and destination. They are not simulated Win32 results.
The controlled transient cases release the held handle after the first denial;
permanent locks and read-only protection remain in place. The internal delay
seam controls only waiting, not the actual native syscall or its return value.

The product barrier retries only the same flushed source and exact destination,
unchanged native flags, for error 5/32/33 while the source still exists. Four
attempts / three waits (10/20/40 ms) are a finite local I/O budget, not a new
request lifetime. No source recreation, ACL/protection change, copy/delete
fallback, destination-based success inference or authority bypass is added.
Missing source, permanent denial and unrelated errors throw. Existing caller
read-back, uncertain-write fencing and exact-operation recovery remain mandatory.
Unix replacement and logical deletion paths are unchanged.
Native API behavior and error definitions:
[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw),
[Win32 error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).

## Gates

```powershell
dotnet test tests/XNode.Tests/XNode.Tests.csproj -c Release -p:DeepProtocolSourceCutover=true --no-restore --filter FullyQualifiedName~MailboxDurabilityBarrierTests --logger trx --results-directory artifacts/s00/native-replace-regression-after --verbosity quiet
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true --no-restore --filter 'FullyQualifiedName~DeepIdV2PreKeyClaimRuntimeTests|FullyQualifiedName~DeepIdV2ClaimJournalTests|FullyQualifiedName~DeepIdV2InventoryLineageTests' --logger trx --results-directory artifacts/s00/native-replace-connected-after --verbosity quiet
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore -m:1 -warnaserror --verbosity quiet
# Six separate --no-build/--no-restore repetitions of the actual concurrent
# exhaustion scenario, each with its own native-replace-repeat-after-N TRX.
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-build --no-restore -m:1 --logger trx --results-directory artifacts/s00/native-replace-full-after --verbosity quiet
../deep-devops/scripts/test-env.ps1 -Suite smoke -BackendMode external -ManagedExternalProfile backend-external -RequireRouterNoMock -RunArtifactDirectory '<absolute fresh child of deep-devops/artifacts>'
```

Final native regression 6/6 on Windows; connected claim/journal/lineage selection
49/49; six separate concurrent runs each pass 1/1. These are overlapping tests,
not additive unique coverage. Release source build: 0 warnings / 0 errors.
The Windows-guarded syscall cases do not qualify that behavior on another OS.
Full node suite: 907 pass / 1 fail / 0 skips (908 total), exit 1:
Integration 528/1, ProfileGenerator 107/0 and Unit 272/0. The sole failure is
the existing B8 one-time-invitation prerequisite, not deleted or changed into
a positive fixture. Package/current mailbox closure remains unqualified.

Isolated external smoke exits 0: fixture validation and ten runner/contract tests,
actual non-mocked Xray and all runtime hard/soft checks pass; manifested artifact
secret scan passes. Its temporary containers/volumes were removed; six existing
deep-dev containers remain. Three pre-existing external Node Dockerfile
`InvalidDefaultArgInFrom` warnings are not .NET build warnings. No multi-node
rerun: no path/peer/framing/release-composition change. Linux smoke does not
qualify the Windows syscall, current mailbox admission or device delivery.

| Ignored local evidence | SHA-256 |
| --- | --- |
| Original selection failure | `cc8474d643b24b1502886c2846ac871750be03f33963cc0eb5a10383febacf74` |
| Observed native error 5 | `30ca99ce53c8dfa11233955bc712577b0db05a08eb48e683955b81bcf677fb35` |
| Native regression before | `d82d623664cee45fb31e2e9c9b3164d3a02f28c7fe91bd4d4a73dd5b7f36a3b8` |
| Native regression after | `6cd822a0fd4c216e29439976eb41a38d6ff85b8afec9925466f2d2a9d935c81c` |
| Connected selection | `4f4a2289c6ab74d9f208527caad4a93f23e04304aad072b9651025813e5a5a28` |
| Concurrent repeat 1 | `09b74b751dedc1905ddc13580d2764467eaf1bfd5c897bfc0592d4a21736d2bf` |
| Concurrent repeat 2 | `a9f1f5af60ab6700a5134b0181ddfcca2b569c487fe0e406050c54bc13e19464` |
| Concurrent repeat 3 | `9217392d6a1cc2b9ea7213f4c24c0bae1f038e8beba6697d85d528812db3c115` |
| Concurrent repeat 4 | `f61c512706177039480b89595380b92a0bb96a9e97ac0651934ca8e3c5c01ced` |
| Concurrent repeat 5 | `7899a8f1b2dc87bf3797336af2ada82390a54a429442fff5769412389d488e7c` |
| Concurrent repeat 6 | `1e5525ab04673ea3dc797696c00f0ce4134e34cda233133e4dcb8d0cac178631` |
| Full Integration | `5e53f65f4f22978b03e3345bc85e79170b2a0816a960bb3e2db160df178dbd51` |
| Full ProfileGenerator | `586d5184347f03957b23635efa9ddedc4acd57ca5b2d18e349b2b49daaf72e9b` |
| Full Unit | `42c00c7b59643814bfffe24fe4bbd8cd4024185d9556c9c6c9fdf17f4ebd8bfd` |
| External runtime gate | `d220539b8bbfda82bdd80c2b47574b4b4db885fc240b9025e8baf5c885cae88f` |

S00 B8/current package closure and S01 node/peer/lifecycle contracts remain open
in [NEXT-SPRINT](../../../docs/NEXT-SPRINT.md). This is local storage/recovery
evidence, not full E2E or release qualification. Production, devices, operator
secrets, registered node keys and signed authority inputs were not changed.
