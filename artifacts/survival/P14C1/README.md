# P14C1 sanitized evidence carrier

Decision:

`DORMANT-PROFILE-COMPOSER-GO`

Production boundaries:

- `PRODUCTION-SIGNER-NO-GO`
- `CLIENT-VERIFIER-NO-GO`
- `SELF-HOSTED-RUNTIME-NO-GO`

Human decision owner: Mr. X.

This carrier binds evidence to source commit
`eff452368fa4cb1324c5b3c8ee06e2f10e96b835`. The carrier commit contains
evidence only and is not the source revision under review.

The evidence is deliberately sanitized. It contains no absolute paths, user
or machine names, timestamps, durations, service endpoints, network
identifiers, signature bytes, test seeds, raw exceptions, credentials or
secret material.

## Result

Two final independent reviews returned `GO`, each with
`P0/P1/P2/P3 = 0/0/0/0`.

The dormant composer is deterministic, isolated from the runtime graph and
limited to creating an unsigned carrier plus exact P04-framed signing
requests. It does not create or receive private keys, publish profiles,
activate client trust or enable a self-hosted runtime.

## Files

- `evidence.json` — source chain, reviews, contract, scans and test evidence.
- `closure-packages.json` — the verified 22-package offline closure.
- `REPRODUCE.md` — relative commands pinned to the accepted source commit.
- `SHA256SUMS` — SHA-256 for all payload files, including this README and
  the local line-ending policy.
- `CONTENT_SHA256` — SHA-256 of the exact UTF-8 bytes of `SHA256SUMS`.

The carrier commit SHA is intentionally not embedded in these files because
doing so would make the commit self-referential. It is reported alongside the
content hash after the evidence-only commit is created.
