# S05: bounded verified observation context reuse

Owner: Mr. X. Status: focused source candidate; full/rehearsal/device gates open.

Registry's canonical S05 full failed two actual private-issuer/native-mailbox
cases, with peer timeout/unknown outcome. The isolated pair repeated one failure.
Transparent existing observations showed tens of complete source verifications
inside a single Store and several seconds of source work. This justified reducing
repeated cryptographic reconstruction, not widening the peer deadline or dropping
floor/proof/revocation checks.

The observational path now reuses a previously minted immutable network context
for less than one second when the complete closed-framed source digest and actual
authority/floors still match. Its original lease must remain live. The independent
proof and floor are checked twice as before; every source read, clock/issuer check,
protected floor read-back, native operation lease and release fence remains.
Acquisition and changed inputs still use the full verifier. A cache hit never
refreshes its resource timestamp or authority lifetime. Only the resource timer
is test-injectable; Protocol's trusted-time/proof clocks are unchanged.
The operator guide owns configuration consequences. No wire/API allocation,
durable state generation, installed key or deadline changed.

The native issuer pair passed2/0/0, native0, under the first matching source:
Registry receipt
`artifacts/s00/s05-native-mailbox-remediation-02-d8cb18f8d1d544b3896c45c523790518/nikit_SURFACE-LT_2026-10-14_11_42_35_net10.0.trx`.
SHA256: `C408C9BE464F9303E9C92C7C7FB97437A5C841A732F7EAC003F777DEF4D4827A`.
Initial Store total elapsed was7407ms/7819ms; this is total fixture work, not
peer RTT, production performance SLO or physical E2E. The actual configured peer
timeout was not changed. The prior failed receipts remain separate.

Current node matching scope passed27/0/0, native0, common exact mappings:
`artifacts/s05-observation-context-reuse-20261014/nikit_SURFACE-LT_2026-10-14_11_45_43_net10.0.trx`.
SHA256: `6605AC3223CC020DE7BCE790385277256964A98E26D7BD49D2116276210C69F8`.
The existing runtime negatives cover issuer change, proof failure/expiry, lost
floor, rollback, stop and caller cancellation. The added deterministic resource
timer case proves context reuse, full re-verification after expiry, unchanged
proof acquisition count/floor, and rejection/clearing after proof failure.
Common native interval:2026-10-14T06:45:20.2914279Z–2026-10-14T06:45:47.3688066Z.
Windows PowerShell5.1 / SDK10.0.301. This scoped source run is not canonical
full, TLS topology, production ingress/rehearsal, installed clients or stage acceptance.

## Subsequent custody-path remediation

The isolated native Store phase trace found hundreds of protected-floor reads;
Unprotect/decode accounted for less than100ms, while filesystem work accounted
for several seconds. No plaintext/key cache was introduced. Enumeration now
checks the directory ancestry once and each entry for reparse points, retaining
the complete path/security check immediately before every protected read.
Windows ancestry traversal uses fresh `DirectoryInfo.Attributes` objects and
the explicit missing-entry sentinel rather than throwing for absent descendants.
Access/I/O errors still propagate; ordinary `Exists` is not a trust check.
No lifetime, replay/revocation guard or deadline was changed.

Focused Node run passed89/0/0, native0, with common exact TRX mappings:
`artifacts/s05-custody-path-read-20261014/nikit_SURFACE-LT_2026-10-14_12_48_10_net10.0.trx`.
SHA256: `7E7380C85180A7F6B7646260E13511E0190CEC18039490B82083F4A34FC0DC50`.
Native interval:2026-10-14T07:47:54.8827104Z–2026-10-14T07:48:31.3643803Z.
The two other filtered project receipts have exact zero counters, not additional
tests. The new cases check exception-free missing-path traversal and six warm
revocation-record link substitutions, including dangling targets. Existing
ancestor-link/no-cross-read-cache, corrupt/missing floor, rollback, revocation,
clock/issuer/observation negatives remain in the matching scope.

Registry's matching native pair passed2/0/0, wrapper/native0:
`artifacts/s00/s05-native-store-attribute-query-01-53189587167940b88b644452c13c63e9/nikit_SURFACE-LT_2026-10-14_12_49_57_net10.0.trx`.
SHA256: `866BADFB7B7D6F5FF7A7816F7491D4F9895E0333D1306B58A5F6CC481173777E`.
Actual Store elapsed was10309ms/9175ms under the unchanged15-second ingress
deadline and5-second peer timeout. These are isolated timings, not production
SLO or proof of full-load remediation. Required full/rehearsal gates remain open.

## Exact replay is not an uncertain write

Registry full03 passed both previously failing native mailbox cycles, but failed
the real Program/TLS control scenario during its protected-clock rollback:
`ActualTlsProofAcquisitionAndSignedControlReachNodeConsumers`. The background
refresh could verify an unchanged MGR1 while that clock changed. Both native
Advance and historical CatchUp incorrectly set the owner's write-fault flag
after a failed read-back even when exact replay had attempted no write.

Four deterministic reproduction cases failed0/4/0, native1, at the subsequent
protected read with that erroneous fault. Receipt:
`artifacts/s05-no-write-replay-reproduction-20261014/nikit_SURFACE-LT_2026-10-14_12_59_23_net10.0.trx`.
SHA256: `9317471CD15AC077E631FE76DBC7BE2A6CB4F58FA5EB87BAB6BAD10019EA8555`.
They inject clock rollback/cancellation at the first post-plan protected read,
not an arbitrary timing sleep, in both current and historical exact replay.

The owner now faults after verification failure only if a replacement was
attempted. Exceptions still propagate; no authority is released. Signed-conflict
latching and all changed-floor uncertain-write handling remain unchanged.
Protected bytes must remain identical and current admission must still reject
the rolled-back clock; no reset or compatibility reader is involved.

Expanded matching scope passed110/0/0, native0, common exact mappings:
`artifacts/s05-custody-no-write-replay-20261014/nikit_SURFACE-LT_2026-10-14_13_00_16_net10.0.trx`.
SHA256: `C1D3737570492F137347CBB7A949E6676EA9A5618DA18963A907DC83F45FB1C2`.
Native interval:2026-10-14T08:00:00.0106603Z–2026-10-14T08:00:34.3478529Z.
The two other filtered project receipts contain exact zero counters. Existing
signed forks/removals, replacement interruption, corruption, floors, cancellation,
clock/context/expiry and actual HTTP refresh beyond64 steps remain in scope.
Canonical Registry/Node full and transport/rehearsal remain required.

## Final review: retain the original Windows error distinction

Registry full04 qualified395/0/7 with402 exact mappings, all native stages0 and
2833 unchanged inputs. That receipt is for its captured intermediate source,
not the final stricter guard below. During review, the proposed exception-free
`DirectoryInfo.Attributes` optimization was withdrawn: .NET's missing sentinel
also suppresses device-not-ready, unlike the original `File.GetAttributes` path.
See [the .NET10 attribute implementation](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/Common/src/System/IO/FileSystem.Attributes.Windows.cs).
The corresponding newly introduced optimization-only assertion was removed,
not any original product/hostile-input test. No native interop or new dependency
was introduced. The entry-enumeration optimization, complete per-read ancestry/
file-security checks, observation context reuse and exact-replay fix remain.

Final matching source passed109/0/0, native0, common exact mappings:
`artifacts/s05-final-custody-guard-20261014/nikit_SURFACE-LT_2026-10-14_13_06_39_net10.0.trx`.
SHA256: `6AD2A03056296C74EAF107E8B13EFD13C0D5302C844955FDD712986D00F3CD12`.
Native interval:2026-10-14T08:06:24.4250251Z–2026-10-14T08:06:56.6770518Z.
Both other project receipts have exact zero counters. Use this final receipt
and the prior accepted Node full for the canonical Node reference union, not
the withdrawn optimization-only case. Registry final full05 and Node full/
managed-external smoke/rehearsal still remain required before acceptance.

## Coherent path/floor/native-replacement batch

The proof-floor Windows reader repeatedly resolved `LinkTarget` for ordinary
files and parents. It now checks each entry's attributes, expected file/directory
type and exact trust-root containment instead; reparse, missing and I/O errors
still reject before protected read. Linux retains its old branch. The shared
path helper also normalizes once and walks parent strings with unchanged fresh
attribute/error checks. No protected bytes, authority floor, lease fence or
deadline is cached or skipped, and no native dependency was introduced.
The behavior is supported by [Microsoft's link-attribute contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw).

A first matching batch retained109/1/0/native1:
`artifacts/s05-string-path-current-20261014/nikit_SURFACE-LT_2026-10-14_13_25_38_net10.0.trx`.
The actual HTTP/native catch-up failed in `MoveFileEx` with access denied after
the original70ms retry budget, not in a link assertion. Two deterministic
held-source/destination reproductions failed0/2/0/native1:
`artifacts/s05-native-replace-window-reproduction-20261014/nikit_SURFACE-LT_2026-10-14_13_31_44_net10.0.trx`.
The native resource window now retains the original fast delays and extends the
same exact replacement to seven bounded10..640ms waits (1270ms total). Permanent
locks, read-only ACL/protection, lost source and uncertain committed bytes remain
failures. This does not extend any signed lifetime or peer/ingress timeout.

Final connected Node source scope passed139/0/0, native0, common exact mappings:
`artifacts/s05-path-floor-native-batch-20261014/nikit_SURFACE-LT_2026-10-14_13_33_44_net10.0.trx`
(131/0/0, SHA256`C8386BCC9E10C7336B03ADA21D07935E4FDDAA62E3CA1BD2A77CDF7C837436C6`),
and`nikit_SURFACE-LT_2026-10-14_13_34_03_net10.0.trx`
(8/0/0, SHA256`F9232D9A4194632343F6FDCD72CF0CA2AA2DB0663CE635E36374D96022743C08`).
The middle project receipt has exact zero counters. Native interval:
2026-10-14T08:33:34.7104487Z–2026-10-14T08:34:03.8774879Z.
The scope includes six warm proof-floor link substitutions/dangling targets,
existing proof/corruption/pin/clock/rollback guards, both delayed native locks,
and unchanged permanent/read-only/missing-source failure assertions with the
new exact bounded resource schedule.

Matching Registry Program/current/retained TLS-native scope passed3/0/0,
native/wrapper0, with explicit isolated phase profiling:
`artifacts/s00/s05-path-floor-native-connected-01-efd77ad46e504951969e94b66a719a5f/nikit_SURFACE-LT_2026-10-14_13_36_09_net10.0.trx`.
SHA256:`115629C82CA0F628140CAA3083984E1EC192607D3BE5083A81069F0B4F6BAF98`.
Store elapsed6791ms/8348ms; all257 lease checks and514 grant-context checks
still occurred. Phases are inclusive and may include other work on the three
owned hosts; they are not a production SLO. The2048-walk timing test asserts
fresh link rejection, not a hardware timing threshold, and its concurrent scope
timings must not be compared as a standalone benchmark. Required Registry
full06, Node full/transport/rehearsal and all remaining S05 criteria are separate.

## Canonical Node full qualification

Final source full01 completed **1499/0/0**,1499 exact result mappings,
build/preflight/native/qualification0,2180 unchanged inputs, FullAccepted=true.
Run:`artifacts/test-gate-20261014/s05-native-lifecycle-full-01/`.
Windows PowerShell5.1 / SDK10.0.301; native interval:
2026-10-14T08:58:57.2871100Z–2026-10-14T09:37:47.2596603Z.
The common runner qualified the exact union of the previously accepted three
full receipts and the three current matching receipts, with no allowed FAIL/skip.

Receipts under`full/`:

- `nikit_SURFACE-LT_2026-10-14_13_59_28_net10.0.trx`:1135/0/0;
  SHA256`A49D78D9DD352A21F113B3700ECA268893CB9ED0D39237E7C1E6E7236BD45B68`.
- `nikit_SURFACE-LT_2026-10-14_14_35_47_net10.0.trx`:107/0/0;
  SHA256`6235B98D91093FD8CB662518F5982D5C05B971266FBCCBC3BAB87A60ADBD3F76`.
- `nikit_SURFACE-LT_2026-10-14_14_36_15_net10.0.trx`:257/0/0;
  SHA256`789DCF0C15F05C68E4F0F5399369A350FE1E1A654E9DC61897E4B372CE8F32EC`.

Required managed-external no-mock smoke and multi-node rehearsal are next,
followed by final package review/commits. Their infrastructure scope is not
current two-client or physical delivery acceptance. Registry full07 separately
passed395/0/7; the observed70ms cold Store margin remains a performance risk.
S05 operational rotation/retained-volume criteria and all device flows are open.
