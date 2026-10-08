# S01 native Store path safety — 2026-10-08

Status: focused checks, matching full Node/Registry source matrices and required
Docker gates passed. Not shipping activation, production or device E2E.

## Change and boundary

The Registry configured-native cycle repeatedly read protected MGR1 and
operation custody. A local sampled-thread trace identified repeated ancestor
`LinkTarget` resolution in `FileMailboxGrantRevocationStore.RejectLinks` as a
hot path. Windows now reads entry attributes on every ancestor instead of
opening each ordinary entry to resolve its target. No ancestor cache is used.
The non-Windows implementation is unchanged. Reparse points, including file,
directory and dangling links, reject; access failures still propagate. Only
not-yet-created path components may be absent before explicit writes.

No protected read-back, serialization, descriptor/holder/issuer signature,
revocation, expiry, replay, durability, quorum or deadline check is removed.
There is no new wire, state generation, migration or public authority API.
Windows entry-attribute semantics are documented by
[Microsoft](https://learn.microsoft.com/en-us/windows/win32/fileio/symbolic-link-effects-on-file-systems-functions#getfileattributes).

## Focused evidence

Actual Release/source-cutover build and tests:

- Path safety: 9/0/0, including existing/missing regular paths, file/directory
  links with existing/missing targets, missing descendants and a link installed
  after a successful check. Receipt
  `artifacts/s01-native-store-path-safety-focused/nikit_SURFACE-LT_2026-10-08_13_53_57_net10.0.trx`.
- Native MGR1 store/lifecycle tests: 46/0/0, preserving corrupt/missing/split
  state, authenticated conflicts, crash and escaped-lease checks. Receipt
  `artifacts/s01-native-store-protected-read-focused/nikit_SURFACE-LT_2026-10-08_13_54_27_net10.0.trx`.
- Registry actual HTTPS/private issuer/configured native cycle: 1/0/0. Initial
  Store took 7,402 ms after the change versus 10,805 ms in the immediately prior
  untraced focused profile. Clock, random selected pair and system load differ:
  this is a local observation, not a performance SLO or proof of the historical
  full-run failure's exclusive cause. Store budget remains 15 seconds.

Registry transparent test observers forward the actual source, security,
durability and descriptor-pinned peer owners. Timing sums use Stopwatch ticks,
not per-call rounded milliseconds. Bounded first-chance output contains only
exception type/HResult/code-owner names, never messages or private values.
Four expected missing-entry exceptions were observed during the successful
post-change Store; they are not failed custody checks.

Full Node acceptance includes all prior 1,354 cases and the 9 new cases on
unchanged captured inputs. Required external/no-mock Docker smoke and multi-node
checks follow that terminal, not its start. Connected Registry accounts for
all 371 original cases (7 existing Windows platform skips). Prior FAIL receipts
remain intact; this bounded source qualification does not close S01 or release.

The fresh Registry full subsequently passed364/0/7 with actual test and
qualification exits0, all371 exact original cases and3718 inputs unchanged.
Initial Store completed in11017ms under the unchanged15-second budget. Exact
receipts and remaining boundaries belong to the
[Registry checkpoint](../../../deep-registry-api/docs/testing/s01-retained-private-issuer-2026-10-07.md#native-store-path-optimization-and-matching-full--2026-10-08).

## Matching full and Docker terminal

`artifacts/s01-retained-public-join/path-safety-full-01/terminal.json` records
actual Shared prerequisite verification0, build0 (zero warnings/errors), test0
and qualification0. Started `2026-10-08T09:02:19.6601858Z`, finished
`2026-10-08T09:28:05.7598634Z`. Full **1,363/0/0**, exact required case/method/
assembly and execution mappings, all2,191 captured inputs unchanged. Manifest
SHA256 `32AFF4411C3DD7EC8859C94959A3E89B567BFD8245BEDA6655135F543D45416D`.

| Receipt under that run directory | Cases | SHA256 |
| --- | --- | --- |
| nikit_SURFACE-LT_2026-10-08_14_02_54_net10.0.trx | 1,003 integration | `B4049B022F20EF3601D3BC41BBE175D8393990CE5FD82BFAFAE94A6CFAA2CA6F` |
| nikit_SURFACE-LT_2026-10-08_14_26_30_net10.0.trx | 107 profile | `C7FFA277F2386FBC51125112019833B9CE1F89B7064C0AE3D14644286CF3E4B8` |
| nikit_SURFACE-LT_2026-10-08_14_26_52_net10.0.trx | 253 unit | `CB36AB6B91ADEC43CBB4156FC1E19F0D297F3AE3E4424EA26116D2630A27BFC9` |

After the actual Node terminal, the DevOps wrapper independently rechecked its
unchanged inputs/results, then ran external/no-mock smoke0 and multi-node0.
Receipt: `../deep-devops/artifacts/s01-native-store-path-gates-20261008/terminal.json`,
finished `2026-10-08T09:29:46.4173145Z`; node runner/qualification/smoke/multi-node
actual exits0. All six original dev-container identities were preserved.
Only disposable smoke/rehearsal containers, volumes and networks were removed
by their native scripts. No production deploy/reset or registered key change.
Infrastructure PASS does not prove retained delivery or shipping readiness.

The accepted horizon source batch can now proceed to its remaining S01 known
send/read floor retirement and dependency fences. Package/API/resource closure,
Linux native provider, selected-entry/owned clients and devices remain separate
open gates; source acceptance cannot waive them.
