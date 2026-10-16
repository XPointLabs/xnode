# S05 — private grant hop diagnosis

Date: 2026-10-16. Physical business acceptance remains0/4.

The retained Android37 account passed network verification and entered new
retained-grant acquisition, then observed OutcomeUnknown. Local closed node
metadata at16:08:50Z reports `HttpsMailboxGrantAuthorityClient.AuthorizeAsync`
as the terminal cause, followed by two bounded relay504 responses. These times
are consistent with the device attempt, not an identifier-based correlation or
proof of noncommit. The new exact pending issuer request must remain retained.

Read-only GET probes from the exit-node container to its configured private
issuer origin returned liveness200 and private-endpoint405 with successful TLS
validation. This proves connectivity and endpoint presence, not grant issuance.
No request body, certificate bypass, account reset or production mutation.

The typed HTTP client now emits one bounded closed failure record per10s:
validation/HTTP/response/body phase, numeric response status (0 before response)
and a fixed category. It never logs the exception object/message, endpoint,
request, identity, holder or capability. Existing exceptions and uncertainty
remain unchanged, including when the diagnostic sink throws. No wire, deadline,
trust, replay or persistence change is allocated by this instrumentation.

Native receipts under `artifacts/s05-private-grant-hop-20261016/`:

- `node-01`:21PASS/11FAIL/native1. Exact field-set assertions sorted with the
  current culture, putting `{OriginalFormat}` first. Original receipt retained.
- `node-02`:32PASS/0FAIL/0skip/native0, no compiler warning/error. Ordinal field
  comparison verifies the same exact set; actual failure status, closed labels,
  no exception argument and a throwing logger are checked. Existing malformed,
  bound, signer-custody and retained-forwarding refusals remain enforced.

Windows PowerShell5.1/SDK10.0.301. This is focused source evidence only. Matching
local deployment, preserved-mount smoke and exact pending device retry remain
required. Registry-side classification is owned by its
[checkpoint](../../../deep-registry-api/docs/testing/s05-private-grant-hop-2026-10-16.md).
