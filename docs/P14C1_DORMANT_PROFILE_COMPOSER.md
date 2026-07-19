# P14C1 dormant self-hosted profile composer

Status:

`DORMANT-PROFILE-COMPOSER-GO / PRODUCTION-SIGNER-NO-GO /
CLIENT-VERIFIER-NO-GO / SELF-HOSTED-RUNTIME-NO-GO`

Human decision owner: Mr. X.

## Boundary

`XNode.ProfileGenerator` is an isolated class library. It is present in the
solution for build and test only. The XNode runtime, dependency injection,
endpoints, configuration and transport projects do not reference it.

The library never creates or receives private keys. It produces exact P04
domain-framed signing requests and accepts public signatures plus an external
P04 `IMembershipSignatureVerifier`. P04 remains the sole authority for
canonical trust bytes, domains, hashes, signer roles, quorum policy, validity,
network binding, revisions and verification.

The outer profile is an unsigned deterministic carrier. It adds no signing
domain, signed JSON, root format, operator override or endpoint override.

## P04 pin

- Package: `Deep.Protocol 0.3.0-p04.b887fa0`
- Source commit: `b887fa088f486390be182cac4cbcb59b60ce8931`
- `Deep.Protocol` SHA-256:
  `8ef4e70ad0b6c1cc0087f25c0313d6ab6a5387d16246679e4c10a3c00898a442`
- Contract: `Deep.Protocol/P04-canonical-v1`

The accepted packages, manifest and golden fixture are under `vendor/p04`.
The exact package version is locked and source-mapped to that local directory.

## Deterministic framing version 1

All integers are unsigned. `varuint` is minimal unsigned LEB128.

1. ASCII magic `DPF1`
2. version byte `1`
3. component-count byte
4. total component-body length as minimal `varuint`
5. each component: type byte, byte length as minimal `varuint`, exact bytes

Fixed component order:

1. canonical P04 genesis
2. deterministic public P04 genesis approvals, sorted by signer ID
3. canonical P04 signed delegation envelope
4. one or more canonical P04 signed bridge envelopes, ordered by sequence and
   canonical bytes

Genesis approvals contain only public P04 signature fields: count, P04 domain,
16-byte signer ID, minimal signature length and signature bytes. This carrier
encoding is not signed and defines no new trust semantics.

The composer requires exactly 3 distinct root approvals for genesis and the
delegation, and exactly 2 distinct online approvals for each bridge. Every
artifact is then verified through P04.

## Bounds and presentation

- file payload: 48 KiB maximum
- individual component: 16 KiB maximum
- component count: 16 maximum
- QR text: 2,048 ASCII characters maximum
- derived labels and summaries: 96 UTF-8 bytes maximum

The fingerprint is SHA-256 of the exact canonical P04 genesis. Compatibility
comes from the signed genesis protocol range. Display text is fixed-format and
derived from those values. QR text is a base64url representation of the exact
file bytes with prefix `deep-profile-v1:`. When it exceeds 2,048 characters,
the result is file-only; it is never truncated.

The inspector exists only to validate and round-trip this producer contract.
It is not a client trust import, persistence or activation API.

## Production prohibition

The deterministic signature scheme under the dedicated test project is
test-only public fixture behavior. It is not an approved cryptographic profile
or production signer/verifier. Production signing, client activation and
self-hosted runtime remain blocked pending external cryptographic/profile
review and their separately owned tasks.
