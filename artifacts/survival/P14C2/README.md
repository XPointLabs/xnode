# P14C2 sanitized evidence carrier

Accepted source:

`cd9d20a8ec8346d171d4cd070dde170aa5f471d7`

Accepted source tree:

`e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59`

Decisions:

- `XNODE-SHARED-CARRIER-GO`
- `BYTE-IDENTITY-GO`
- `PRODUCTION-SIGNER-NO-GO`
- `CLIENT-VERIFIER-PENDING`
- `SELF-HOSTED-RUNTIME-NO-GO`

Human decision owner: Mr. X.

Two final, independently labelled reviews examined the exact accepted source
and returned `GO` with `P0/P1/P2/P3 = 0/0/0/0`. Earlier NO-GO findings and
their exact closing commits are retained in `evidence.json`.

This directory is evidence-only. It contains no source, test, vendor, script
or binary copies. It also contains no absolute paths, timestamps, host or user
names, endpoints, network identifiers, credentials, seeds, private keys,
signature bytes, raw exceptions or sensitive test values.

Files:

- `evidence.json` — complete source chain, review findings, package and golden
  identities, gates, boundary decisions and artifact hashes.
- `SHA256SUMS` — SHA-256 of the exact payload files and line-ending policy.
- `CONTENT_SHA256` — SHA-256 of the exact UTF-8 bytes of `SHA256SUMS`.

The final evidence commit is reported externally to avoid a self-referential
commit hash inside the carrier.
