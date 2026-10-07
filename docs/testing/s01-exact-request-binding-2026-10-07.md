# S01 exact acquisition request binding — Node source gate

Date: 2026-10-07. Normative owner:
[DR-0102](../../../docs/survival-program/decisions/DR-0102-exact-mailbox-request-route-binding.md).
Private coordination/ONION consumers and retained lookup use the signed exact
route. The added actual signed-publication test checks wrong-intent NotFound,
original-intent Found, defensive exported hash copies and no durable mutation.
Lookup is still not protected rollback authority, renewed issuance or transport
Retrieve/ACK evidence. No private node generation or registered key changed.

Release source-cutover solution build0, zero warnings/errors. Focused60/0/0,
terminal0, TRX SHA256 `AB455C3E033FCD153A30615393E7116AED59D8572A7015398D2B675DC8C13E07`.
Initial compilation attempts used unavailable helper/friend surfaces and
produced no acceptance; the fixture now mutates bounded canonical public bytes
and holder-resigns them, without changing product accessibility or guards.

Mandatory original native solution full completed terminal0: **1242/0/0**,
Integration885, ProfileGenerator107, Unit250. Post-terminal qualifier completed0,
preserving all1241 prior exact cases/outcomes and2337 immutable inputs unchanged.
Prelaunch input manifest2337 entries/hash
`41EEBB99CBBADEA2F2B95408ABFFB6E7C01BDA9090C0DE9A136FFF4B19BDF4CD`.
No product/test/normative input was edited or rebuilt during the run.
The xUnit metadata/multiset correction, original validator and separately pinned
post-terminal validator are described in the
[Protocol receipt](../../../deep-protocol/docs/testing/s01-exact-request-binding-2026-10-07.md).

| Receipt under artifacts/s01-exact-request-binding/full | SHA256 |
| --- | --- |
| nikit_SURFACE-LT_2026-10-07_12_59_24_net10.0.trx | `2CC49F9518AA9E0B18D73B0B0695619DABAA1E860DAF7960688C2912922B90BC` |
| nikit_SURFACE-LT_2026-10-07_13_29_51_net10.0.trx | `C673A7E8FCDCC327CD32FBCBB387BC73FB7D4DFB154126F9989FC0835D24A5EF` |
| nikit_SURFACE-LT_2026-10-07_13_30_12_net10.0.trx | `870894DB176551939935492CBADF3031C286A9A793C2C48B375129D571E0A070` |

Mandatory isolated external/no-mock Docker smoke completed0 after the operator
restarted Docker Desktop (engine28.3.3). Fresh Compose project:
`deep-s01-exact-request-binding-20261007`. Fixture validation,10 infrastructure
tests, all4 hard/5 soft checks passed;7 services healthy, transportRunning,
mockfalse, no runtime gate warnings. Node used current Protocol source-cutover;
Registry used the existing local-cutover package lane, not uniform shipping
acceptance. Three existing Dockerfile ARG warnings remain. Push/device delivery
was not tested. Cleanup removed only this isolated project's containers/network
and7 temporary smoke volumes; six original dev containers/data were retained.

| Receipt under deep-devops/artifacts/s01-exact-request-binding-smoke-20261007-01 | SHA256 |
| --- | --- |
| runtime.gate.json | `1E06B9E2EE4CFB667AF1E656424D8D6EF10303C6AE605B7B0C0CD96D9D76E92E` |
| runtime.snapshot.json | `11909EBF54C2464124258FB69C6DEE44E86DDDB24DF67F3954CFDD7E4F88755E` |
| compose.topology.redacted.json | `D47A263614C5DDAC9AAAC8607CED9B769A63FCFA02BC23EE6225A31DC008AA66` |

Matched Node/Registry/Protocol/Shared/client rebuild is required; no old request
reader exists. No production deployment/reset, certbot/staking change, GitHub
Release, main merge or physical E2E claim occurred. S01 remains open.
