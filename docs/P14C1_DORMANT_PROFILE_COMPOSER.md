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

P14C3 rebinds the shared carrier to
`Deep.Protocol.ProfileCarrier 0.2.0-p14.69a712a` from exact accepted protocol
source `69a712a894b024a09859096025c2bb8fe68a642e`. The package adds a dormant
verify-only Ed25519 adapter and transition-decision surface. XNode runtime,
dependency injection, endpoints and configuration neither reference nor
construct either surface. Runtime registration, signing and profile activation
remain prohibited.

### Complete offline closure

`vendor/p04/offline-closure-manifest.json` is the manifest-driven closure of
all three P14C lock files (generator, tests and the Linux execution probe).
`scripts/p14c-offline.NuGet.Config` has one
repository-local source, `vendor/p04/packages`, and no HTTP or nuget.org
fallback. It is passed only to the P14C offline verification script. The
repository root has no NuGet override, so ordinary solution restores retain
their baseline source behavior. The generator and its test project add only
the pinned P04 vendor directory as a project-scoped restore source so a normal
whole-solution restore can resolve their private dependency.

The production-library P04 graph is:

- `Deep.Protocol`, `Deep.Protocol.Abstractions` and
  `Deep.Protocol.Protobuf` `0.3.0-p04.b887fa0`;
- `Google.Protobuf` `3.32.1`;
- `Sodium.Core` `1.4.1`;
- native `libsodium` `1.0.22`.

The libsodium package carries Windows ARM64, x64 and x86 assets as well as
Linux, macOS, Android and Apple ARM64 assets. Presence in the accepted P04
dependency graph does not approve a production signature algorithm, verifier,
key source or ceremony. Sodium/libsodium remain transitive contract
dependencies under `PRODUCTION-SIGNER-NO-GO`.

The remaining closure packages are exact test SDK, test-host, JSON and xUnit
dependencies and never compile into the generator library.

The repository pins .NET SDK `10.0.301` in `global.json` with roll-forward
disabled. That SDK selects .NETCore, ASP.NET Core and WindowsDesktop Windows
ARM64 runtime packs at `10.0.9`; those exact packs are present in the closure.
They are architecture restore inputs, not application references or runtime
activation.

Run `scripts/verify-p14c-offline.ps1` with .NET SDK `10.0.301` installed. It
rejects hidden index state and materializes the exact requested commit and tree
through a local clone with copied objects, no hardlinks, alternates, global Git
configuration or network protocol. Every materialized file is checked against
its committed blob before the gate creates empty package and HTTP-cache
directories, disables HTTP through dead proxies, restores in
locked mode, builds and tests without incremental inputs, and cross-restores
and builds the generator for Windows ARM64. It verifies that assets,
intermediate/output files and package metadata remain under that work root,
that all 23 package entries came from the vendor source, that the HTTP cache is empty,
and that the SDK download dependencies are the three manifest-pinned `10.0.9`
runtime packs. The temporary work root is removed afterward without changing
repository `bin` or `obj` state.

Run `scripts/verify-solution-clean-restore.ps1` for the separate normal-source
regression gate. It performs a clean-cache restore and non-incremental Release
build of `XNode.slnx` from another exact local Git snapshot without applying
the P14C offline configuration. Both scripts accept `-ExpectedHead` and
`-ExpectedTree` to bind their source authority explicitly.

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

These are reachable canonical boundaries rather than predicate-only claims.
Tests compose and inspect an exact 49,152-byte profile containing exactly 16
components. A canonical 1,524-byte profile produces exactly 2,048 QR
characters and round-trips to identical file bytes; a canonical 1,525-byte
profile is file-only.

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
