# Store recovery host lifetime — 2026-10-18

During the real two-CLI group candidate, one local node restarted during
invitation/control delivery. Sanitized Docker observations showed one restart
on node1 and node3, and node3 logs contained `BackgroundService failed`,
`BackgroundServiceExceptionBehavior`/`StopHost` and the sealed
`Deep.Protocol.DeepExtension.PrivacyRouting.OnionBoundaryException` through
`XPointOnionCapabilityProducer.VerifyDtt`/`CurrentMailboxStoreRecoveryWorker`.
Request-side copies of the same refusal are not counted as separate crashes.

The Store recovery worker already converted expected current-authority and
custody failures to unavailable/backoff, but omitted this distinct Protocol
exception type. It now catches that type at the worker boundary. Original
admitted intent/custody remain unchanged; no old proof, expiry extension,
authority substitution, blanket host-ignore policy or readiness success is
introduced. Other unexpected exceptions retain the normal host behavior.

Regression obtains an actual sealed exception from the real Protocol verifier
with expired signed fixture authority (no new constructor/reflection/raw-proof
factory), then checks repeated unavailable, unchanged native ledger/HTTP effects,
closed logging and cancellable hosted lifetime. The normal source build has no
test seam added for this fix.

Evidence: `artifacts/cli-owned-groups-20261018/worker-03`:
20 PASS/0skip/native0, zero compiler warnings/errors. The preceding worker01/02
were compile failures in the new test, preserved rather than classified as PASS.

Supported local operator Build/Up receipts are in
`../deep-devops/artifacts/cli-owned-groups-20261018/node-build-01` and
`node-up-01`. All9 retained services/55 mounts matched, zero mount differences,
no reset or production action. Real CLI continuation is owned by the
[CLI checkpoint](../../../deep-cli/docs/testing/cli-groups-2026-10-18.md).
Supported `node-verify-01` passed: Registry proof ready,3 verified ONION nodes,
11-second recovery observation. CLI `e2e-08` then passed34 cold processes with
zero failed steps on the same retained group/accounts. Updated nodes were
healthy with restart count0 at the final bounded observation.
These focused/connected observations do not replace the canonical full,
sustained transport/rehearsal or release gates.
