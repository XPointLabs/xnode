# S00 / B8 — owned DID2 one-time object

Owner: Mr. X. Inputs: Protocol `e2a596b3decbc3300f57ea07e6a07046801673e8`,
XNode `3f06723d92ea9d9bffb5b34ff8821caf73b72c1e`, workspace
`94bb0b64db0db9db2100dea94336ea424841f2cf`.
Scope follows [DR-0088](../../../docs/survival-program/decisions/DR-0088-did2-owned-one-time-contact-object.md)
and the sole [S00–S13 plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
This is local signed producer/encryption/restore evidence, not publication,
private coordination, client custody, shipping composition or physical E2E.

## Connected implementation

The actual fixture authors/verifies PQ-root DID2, current account/device/directory,
NET/time, witness threshold and the owned kind-2 XIR1 route. The same existing
DCB1/DCR1 author signs the one-time object and validates all support/prekey
descriptors. Existing DIA1 framing/domain/AEAD are unchanged; no new crypto,
wire/version allocation, authority adapter or usage-limit-only conversion.
The disposable candidate's secret invitation and ciphertext are never given
to witnesses or a publication callback. Existing reusable callers/fixtures keep
their original behavior; their scenarios/assertions are not removed.

The object APIs and remaining export limitations are mapped in
[Protocol's runbook](../../../deep-protocol/docs/one-time-contact-object.md).
Registry/publication request V3 remains permanent-only; the missing signed
key-free locator/object/expiry commitment and actual protected client intent
must still be implemented. This does **not** close B8 or activate one-time QR.

## Focused evidence

`DeepIdV2OneTimeContactObjectTests` passes **24/24 / 0 skips** on fresh Release
source-cutover binaries. Coverage includes independent locator-domain and AEAD
comparison; exact signed object restore; copied/disposable secret exports;
changed invitation ID/locator/key/network/bundle/expiry; valid AEAD with wrong
inner scope; nonce/tag/truncated/trailing/oversized ciphertext; unknown DIA1
version/suite/hostile length before clock; another genuine DID2 route; actual
proof expiry and a backwards post-await clock that is still individually current;
cancellation and rejection by permanent restore. There is no fake verified
capability, bypass signer or fabricated one-time XPA.

The first 18-case diagnostic had 15 pass / 3 fail: the independent test hash
omitted the existing SHA256-D LP32, and two exact exception expectations used
the base type instead of the real freshness exception. The clock regression
was sharpened to stay individually current and reach the post-await continuity
check. Neither production locator bytes nor verifier rejection was weakened.
The corrected 18 cases passed, then six independent hostile cases were added.
Terminal expanded evidence:
`artifacts/s00-one-time-object/expanded/owned-one-time-expanded.trx`.
SHA-256 `b86875316254b59dbd58a68c7261f5727873ae88aa7e90300ff773616b89ac38`.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore --filter FullyQualifiedName~DeepIdV2OneTimeContactObjectTests --logger trx
dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-restore -warnaserror
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true -p:ShouldUnsetParentConfigurationAndPlatform=false --no-build --logger trx
```

Final XNode/Protocol Release builds: **0 warnings / 0 errors**. Full XNode
completes with **1117 pass / 1 fail / 0 skips** (1118 total). Integration:
738 pass / 1 fail, 739 total, **25m8s**; unit 272/272, profile 107/107.
All 24 new one-time cases and all 198 current mailbox/MGR cases pass.
The sole failure remains
`ContactServiceOpaqueFacadeTests.PublishedClosureCommitsOneTimeInviteAndSuccessExactReplays`:
the signed one-time publication prerequisite B8 is still absent. The full command
exits 1, not a green release gate; the original claim/replay assertion is retained.

Final XNode TRX under `artifacts/s00-one-time-object/full`:

| File | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_08_30_54_net10.0.trx` (profile) | `4c18adcbd41347381a96fcc7392e6a3ef962434443430c2d892082762178064e` |
| `nikit_SURFACE-LT_2026-10-04_08_30_54_net10.0[1].trx` (integration) | `27360c976b1c86e9680766084fdfb95ea5cfd493dae7fed264bd3fefe41a2210` |
| `nikit_SURFACE-LT_2026-10-04_08_30_55_net10.0.trx` (unit) | `904065227337d48f44cc137b68cdc5cdcd09e6965d0e37503204dd211bdaea51` |

## Protocol gates and limits

Full `Deep.Protocol.slnx -c Release --no-build`: **2079 pass / 1 fail / 12 skips**;
membership 131/131, carrier 105/105, main 1843 pass / 1 fail / 12 skips.
The unchanged package witness failure still finds retired MCG2 in assembly
bytes. `Test-ProductionProtocolGraph.ps1 -Configuration Release` still fails
on unchanged MAU2 source. Neither is a new object failure or a green package gate.
The existing provider/capture skips are not installed-platform evidence.

Reviewed mechanical repin covers the two edited normative sources, production
source inventory and 86 moved anchors. Allocations/anchor text hashes remain
unchanged; strict generator/check and registry tests pass. Evidence ownership
classification passes exact314/package219/final95, mapped=0/packageMissing=219;
this is **not** a package-complete ownership gate. Unchanged Shared/Registry
full gates and installed NuGet consumers were not requalified.

Final Protocol TRX under `artifacts/s00-one-time-object/full`:

| File | SHA-256 |
| --- | --- |
| `nikit_SURFACE-LT_2026-10-04_08_31_24_net10.0.trx` (membership) | `6e3a58db96cef12c4d5ab3268478d2c6827a0930aedd382c7b226fade66439e1` |
| `nikit_SURFACE-LT_2026-10-04_08_31_24_net10.0[1].trx` (carrier) | `9105fece269a0cfc517fdb980981e28a653f205ff0c80803066a52e17d75e874` |
| `nikit_SURFACE-LT_2026-10-04_08_31_24_net10.0[2].trx` (main) | `54a98b2ec9a3a8aa9ee0fc7c1598763a36404d35c143a8965a7f536a5e299bb4` |

## Environment

Production, registered node keys, operator secrets and device/account data
are unchanged. The managed-external real-Xray smoke passes with no failed
hard/soft checks, mocked=false and no runtime warnings; three existing Node
Dockerfile InvalidDefaultArgInFrom warnings remain outside .NET compilation.
The first three-node rehearsal hit the smoke project's local port, ended with
failure evidence and cleaned its own project. It was rerun only after both
processes were terminal and cleanup was verified. The rerun passes with three
actual running/non-mocked Xray processes and no reconciliation issues. Its
privacy endpoints still correctly return 503 without ready current authority;
no successful one-time publication or physical delivery is inferred.
Both private projects/volumes were cleaned; the six existing deep-dev containers
were retained.

| Final local environment evidence | SHA-256 |
| --- | --- |
| `deep-devops/artifacts/s00-one-time-object-20261004/runtime.gate.json` | `f314aa7cab3c378d8882e0c59ee92614038fc3b54dec4a7718a4b87ce3c18d46` |
| `deep-devops/artifacts/rehearsals/multi-node/20261004T033503799Z-389b2315fd3b/test-results/multi-node-topology.json` | `6cbd52861e1e2e64bcd8bc857ae5553aa3d98e17751daa1c129c840a3a98475d` |

Matching final commits and remaining B8/S01–S13 blockers belong only to
[NEXT-SPRINT](../../../docs/NEXT-SPRINT.md).
