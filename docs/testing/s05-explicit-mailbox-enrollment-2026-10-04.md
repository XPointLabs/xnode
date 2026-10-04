# S05 explicit new-node mailbox enrollment

Product source: `b3d37807993b83f705149d319622fc7da0923dd6`.
Protocol source: `8989ad6a787cdc8194106a5130fcfa832608e252`.
This implements one necessary provisioning boundary from the unified plan and
DR-0083/0087, not S05 completion, production activation or physical E2E.

## Connected behavior

The explicit `current-mailbox-enroll` Program command uses the actual configured
directory-proof/network source and the same native mailbox factory. It does not
start listeners or hosted services, synthesize current authority, generate keys
or remove the Development/UAT source guard. The command captures two bounded
canonical MGR1 inputs before network callbacks and uses a cooperative 30-second
budget. Public errors are closed labels, without exceptions/paths/identifiers.

Before the first protected enrollment write, the receiver checks actual local
descriptor signing custody, genuinely new operation data/protection and both
signed role genesis records against the verified host. Native writers repeat
their checks. Both roles then authorize enrollment of the existing operation
document; normal non-enrolling host recovery must succeed before command success.
Preflight is not a mutation capability or a multi-file transaction. Interrupted
state is preserved/unready and repeated enrollment rejects. Unknown protected
operation records are rejected, not collected. Normal startup still cannot
enroll. The operator procedure belongs solely to
[operator.md](../operator.md#current-mailbox-host-composition-candidate).

## Terminal local evidence

Warnings-as-errors focused integration selection completes exit0: **32 passed /
0 failed /0 skipped**,1s. All integration test sources compile, no whitelist.
The actual factory test now uses the connected explicit enrollment path instead
of three manual role/ledger calls. The valid case checks normal startup rejection
before enrollment, all native owners, repeat enrollment rejection, cold reopen,
zero client replay scopes and byte-identical retained key-ring files. Negative
cases cover wrong Retrieve role/signature, wrong descriptor signing key,
pre-cancelled enrollment, existing/interrupted operation data, interrupted and
unknown independent protection. All reject before either role/root enrollment;
test-owned hostile bytes remain unchanged and ordinary recovery remains unready.

Command input tests cover missing/extra/duplicate/unknown switches, relative
paths, owned exact input copies, hostile canonical/trailing bytes and oversized
files. An actual `dotnet XNode.dll current-mailbox-enroll --reset` process exits1
with only the closed rejection message, before host startup. Positive tests use
in-process signed issuer/time/source fixtures, not a real independent observer
or Registry/socket/deployed provisioning.

```powershell
dotnet test tests/XNode.IntegrationTests/XNode.IntegrationTests.csproj -c Release --no-restore -m:1 -p:DeepProtocolSourceCutover=true -warnaserror --filter 'FullyQualifiedName~CurrentMailboxHostCompositionTests|FullyQualifiedName~CurrentMailboxEnrollmentCommandTests|FullyQualifiedName~MailboxOperationCustodyTests' --logger trx --results-directory artifacts/s05-explicit-mailbox-enrollment/focused-complete
```

The last filter term matches no test: the **32** executed cases are the actual
factory/configuration and command-input tests above, not an additional operation
custody suite. The required unfiltered `XNode.slnx` full run completes exit0 on
the fixed product source: **1238 passed /0 failed /0 skipped** (integration859,
profile107, unit272), integration29m46s, without filters or compile whitelists.
This receipt, not the earlier full1224 matrix, qualifies this local source. The solution maps external
Protocol references to Debug and Node projects to Release; source-cutover is not
a uniformly Release shipping package matrix.

Real-Xray transport smoke completes exit0,10/10 fixture-runner contract checks
and zero runtime failed checks. It rebuilds source-cutover XNode but uses the
disabled-mailbox development transport boundary, not this positive enrollment
or message delivery. Its disposable resources are removed; all six existing
deep-dev containers remain running. The required three-node rehearsal is run
separately after smoke cleanup to avoid shared-port interference and completes
exit0: three registered nodes, real non-mocked Xray, zero reconciliation issues.
Contact503 correctly remains fail-closed without verified current authority;
this is not positive enrollment or physical mailbox evidence. Disposable
rehearsal resources are cleaned, with the existing six-container dev scope retained.

| Local receipt | SHA-256 |
| --- | --- |
| `artifacts/s05-explicit-mailbox-enrollment/focused-complete/nikit_SURFACE-LT_2026-10-04_21_16_09_net10.0.trx` | `38710deb765eb7d70afc2bf64096dddd62468c874f3837756a28293b89c51087` |
| DevOps `artifacts/s05-explicit-mailbox-enrollment/transport-smoke/runtime.gate.json` | `66baa316551dd43f6117e136edf2d657100052c4d260e1e8d24ba2c58ca61ce2` |
| DevOps `artifacts/s05-explicit-mailbox-enrollment/transport-smoke/runtime.snapshot.json` | `b03a2da387f658048884a4ae451c918c4e29e6c584d3dfc22180dc0eb864701d` |
| DevOps `artifacts/rehearsals/multi-node/20261004T162359912Z-cc85110d492b/test-results/multi-node-topology.json` | `dfce0aee76ceb6063e89272de3756831548cd232a981f93b9ea727b6a51c0ec0` |
| Full integration859 `artifacts/s05-explicit-mailbox-enrollment/full-final/nikit_SURFACE-LT_2026-10-04_21_21_03_net10.0.trx` | `a722a86ccb34701abc149c4299d22492b870454b02247980de87ae942b8eeb83` |
| Full profile107 `artifacts/s05-explicit-mailbox-enrollment/full-final/nikit_SURFACE-LT_2026-10-04_21_50_55_net10.0.trx` | `7690771c488b3f995eb6c36f50dc646670cc771268f7ea6e576437952f7be44a` |
| Full unit272 `artifacts/s05-explicit-mailbox-enrollment/full-final/nikit_SURFACE-LT_2026-10-04_21_51_22_net10.0.trx` | `381806394ddb55dc56f8b9335e0ef0b4ec2282a54edf7fa893e087d0801cfab8` |

## Still open

Issuer MGR1 production authoring/distribution/renewal, actual configured source
socket qualification, consistent deployed provisioning, whole-host recovery,
object horizon/retained-route activation and the installed shipping graph remain
unfinished. Initial enrollment does not extend role freshness or sign a
successor. No production host, device, account or operator secret was modified.
Physical contacts/messages/attachments/groups qualification stays0/4. The
single execution sequence remains the
[implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
