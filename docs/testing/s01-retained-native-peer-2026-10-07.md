# S01 native retained-read peer producer

Date: 2026-10-07. Sole contract:
[CONTACT-RESOLVER §3.7.3](../../../docs/architecture/CONTACT-RESOLVER-V1.md#373-current-retained-retrieve-issuance),
[DR-0104](../../../docs/survival-program/decisions/DR-0104-current-retained-retrieve-issuance.md).
This is one producer increment of the unfinished accepted-object/retained-route
S01 batch, not S02/S04, shipping activation or physical acceptance.

The actual DID2 peer composition owns private RPC18 and receipt7. It verifies
a fresh exact holder-signed Retrieve XMG2, independently rereads the real current
publication source/descriptor key, and uses the native DR-0103 document/root
around read-back and signing. A copied route/hash/horizon cannot mint its
signature. The local callback runs outside the storage lock; any intervening
document/root replacement or durable revision change invalidates completion.
Existing prekey RPC12–17 and the current139-byte evidence purpose are unchanged.

The bounded private result is facts only. Two actual signatures are consumed by
the closed Protocol retained-issuance verifier; it does not create native holder
custody, a Registry database exchange, historical node admission or ACK authority.
The public AcquireMailboxGrant caller still uses its current-route path: this
increment does not enable an implicit retained fallback or new public operation.

## Commands and observed evidence

Restore: `dotnet restore XNode.slnx -p:DeepProtocolSourceCutover=true --verbosity quiet`,
terminal0. Release solution build:
`dotnet build XNode.slnx -c Release -p:DeepProtocolSourceCutover=true --no-restore -m:1 --verbosity quiet`,
terminal0, zero warnings/errors. This is a source-cutover build, not approval of
the pinned shipping package graph. The earlier default no-restore command failed
with329 errors because existing source-cutover assets did not match the default
package graph; no production fallback or assertions were changed to hide it.

Final Release focused command:

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release `
  -p:DeepProtocolSourceCutover=true --no-build --no-restore -m:1 `
  --filter 'FullyQualifiedName~RetainedMailboxRouteStoreTests|FullyQualifiedName~Did2ContactServiceCompositionTests' `
  --logger 'trx;LogFileName=retained-native-peer-focused.trx' `
  --results-directory artifacts/s01-retained-native-peer-final/focused --verbosity quiet
```

Observed terminal0:147 Passed/0 Failed/0 Skipped.36 new executions cover actual
native two-store read/signature after cold reopen, real pinned TLS/H2, lost read
and receipt responses, wrong pin before peer IO, missing independent admission,
all five substituted tuple fields, Deposit/current-purpose cross-feed, source
loss/time/cancel/data replacement after signing, native root/document/revision
fences and hostile bounded result frames. Initial Debug focused93/0/0 and final
Debug147/0/0 are separate receipts, not Release evidence. Intermediate test
compilation errors (ambiguous digest name and enum/int xUnit1010 inputs) were
fixed at the fixture boundary; no failed execution was relabelled Passed.

Mandatory isolated external/no-mock smoke completed terminal0 under the fresh
project `deep-s01-retained-native-peer-20261007`; evidence is in DevOps
`artifacts/s01-retained-native-peer-smoke-20261007-01`.

| Receipt | SHA256 |
| --- | --- |
| runtime.gate.json | `633E8B272FBDEE85814BF9C6D4F12642422ADEC09CC9AE8C04728C75383E101D` |
| runtime.snapshot.json | `E1AB875AE988D3C3E56E6317A4BBCA7F5F87BDE35659E005EDE16D765390BABB` |

Mandatory multi-node rehearsal completed terminal0, no mock, three running real
Xray nodes. Evidence: DevOps
`artifacts/rehearsals/multi-node/20261007T122203616Z-89f97947050c/test-results/multi-node-topology.json`,
SHA256 `8AE5B8CDBDB8FCA513CB11F76E4530035B08BEE35BC31E7D2357889D8727015B`.
This infrastructure lane intentionally reports privacy503 without verified
authority; it is not the actual retained peer/Registry/client composition.
Only the two isolated temporary projects were cleaned. Six pre-existing dev
containers/data were preserved. Neither Docker receipt proves physical delivery.

The original full Release solution run completed terminal0:1330 Passed/0 Failed/
0 Skipped (Integration972, ProfileGenerator107, Unit251). Separate post-terminal
qualification completed terminal0: exact union of all1294 prior cases plus36
new cases, including all147 focused cases; complete unique result/definition/
execution-entry mappings and1462 captured source/binary inputs unchanged.
Original capture:
`artifacts/s01-retained-native-peer-final/inputs.json`, SHA256
`25CE8729319B0A9D535D82D81AF660A18157E2DC0C50C515BD55691F9E943013`.
The captured original `qualify.ps1` remains unchanged: its terminal1 failure
expected1331 instead of1330, a manual arithmetic error. Separate
`qualify-exact-union.ps1` verifies the exact prior/focused case and method union,
not a relaxed count, against the same original manifest and receipts. Its SHA256
is `AA3E3F27B29501018E74545F19A636FBCB68487DBA440958EC5B2ED0D028A433`.
No source/test input was changed or recaptured and no replacement full was run.
Original full command:

```powershell
dotnet test XNode.slnx -c Release -p:DeepProtocolSourceCutover=true `
  --no-build --no-restore -m:1 --logger trx `
  --results-directory artifacts/s01-retained-native-peer-final/full --verbosity quiet
```

| Original receipt | SHA256 |
| --- | --- |
| focused/retained-native-peer-focused.trx | `09F6E837FCC033F526CBAE030A80B21D9F32D94FD20A53D0EBDBFDAB4F78D224` |
| full/nikit_SURFACE-LT_2026-10-07_17_22_55_net10.0.trx (Integration972) | `C6178667EF69E4935B2766D8700EA4CB5AE85C9A43661429541D141056CC3865` |
| full/nikit_SURFACE-LT_2026-10-07_18_04_13_net10.0.trx (Profile107) | `3007F189974A982EB9D0ECB1EBC59F4B04ADB125492C05B3B55BB008D1A5DC97` |
| full/nikit_SURFACE-LT_2026-10-07_18_04_39_net10.0.trx (Unit251) | `3C13CAB5F310705A62834E1B397773553C35250EB3BE2B1CEAEE47D4B46B2283` |

Root contact-machine gate passed. Initial governance14/2/0 failed because newly
implemented target slots made two hostile fixtures hit the duplicate-allocation
guard before their intended wrong-owner diagnostic. The fixtures now separate
wrong ownership from duplicate numbers; two additional duplicate guard tests
were added, without changing the production gate. Final root governance30/0/0.
Selected changed Node source/artifact secret scan passed; final counts are in
the local security summary. These counts
are not a release catalog or package qualification.

## Still required in the same S01 batch

Actual retained forwarding/Registry winner-kind/horizon/current-authority scope,
held Shared owner/result installation, genuinely elapsed original-route fixture,
typed original-selection Retrieve/ACK and matching accepted-object horizon.
No renewal/cleanup/retirement, production deploy/reset, registered identity
change, device E2E, GitHub Release or main merge is performed by this increment.
