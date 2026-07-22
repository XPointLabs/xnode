# P14C3 XNode activation-trust package rebind

Status:

`P14C3-SOURCE-REVIEW-PENDING / XNODE-RUNTIME-REGISTRATION-NO-GO /
PRODUCTION-SIGNER-NO-GO / PROFILE-ACTIVATION-NO-GO /
EXTERNAL-CRYPTO-PROFILE-REVIEW-PENDING`

Human decision owner: **Mr. X**.

## Exact boundary

P14C3 starts from accepted P14C2 source
`cd9d20a8ec8346d171d4cd070dde170aa5f471d7` with tree
`e27c1d7c2517bd9d1bcdfbacda8c68c57a2ced59`. It rebinds only the
dormant `XNode.ProfileGenerator` package consumer to exact accepted P14E2
carrier `Deep.Protocol.ProfileCarrier 0.2.0-p14.69a712a`.

The package is bound to:

- P14E2 source `69a712a894b024a09859096025c2bb8fe68a642e`, tree
  `d83bbdd001b723738357689bbb2150a51357cb3b`;
- sanitized evidence carrier `071b5b300bcba3796d621720fb8f21cfdd5eb882`,
  tree `ecbfc7747452709fb82aaf85fa912ba13b61d4ad`;
- 29,399 raw bytes and SHA-256
  `fb0feca6bc1734b3a0ac26910421ccdddb24a6a03c1f83972a9b5685e6785498`;
- NuGet SHA-512
  `x9LZb8nAUE/XQWQS2ZGBGLbPt2FivGRVc9y1xvlsr02CKHaU6scklrBsOebxj/NiTG66QgFCK7Gd7qFEoRe5zw==`;
- normalized OPC identity
  `baadb33d07dfeb139f0d3ffdfd5bbd41587c02963f8434208fb7718a73733e0f`;
- DLL SHA-256
  `20489ac15239af11207a0daa670545b975c03eaebb78297adf956af45daa7034`;
- PDB SHA-256
  `80f2210e6c61050e2a4edbbf1fa4181ca0d7285d124073fa0d9aa9a77307542a`.

`eng/Verify-P14C3Package.ps1` uses the exact accepted self-contained normalized
OPC verifier and validates the raw package, source identities, three exact
dependencies, all consumer locks/manifests and singleton vendored package.
`eng/Test-P14C3PackageGate.ps1` proves rejection of path drift, byte
substitution, raw repacking, source-commit drift, dependency expansion, lock
drift (including the execution probe) and the old evidence-carrier identity.
The offline closure covers all three locks and 23 manifest entries.

The static provenance gate requires clean, exact local materializations of the
P14E2 source and sanitized evidence commits. It runs the accepted P14E2 evidence
verifier against the exact package vendored here, without network access.
`P14C3_SOURCE_INTEGRITY=PASS` denotes only the bounded source check and
`P14C3_P14E2_PROVENANCE_STATIC_GATE=PASS` only the cross-repository provenance
check. Canonical acceptance remains pending until every command below passes.

## Compatibility and runtime isolation

All accepted P14C2 DPF1 fixtures retain their exact byte lengths and SHA-256
values. The unchanged golden, maximum-size, QR boundary, ordering, malformed,
privacy and error-category suites exercise the same composer and inspector
after the package rebind.

The new Ed25519 verifier and transition-decision API are library surfaces only.
No XNode runtime project references `XNode.ProfileGenerator` or the carrier,
and no runtime source constructs either new type. P14C3 adds no `Program`, DI,
endpoint, configuration, transport, signer, key custody, profile I/O or
activation change.

## Actual Linux execution gate

`eng/P14C3.Ed25519Probe` is a test-only executable. One generic committed IL
publish contains both exact libsodium native assets and executes unchanged in
both actual processes. It verifies the RFC 8032 empty-message provider KAT,
the exact P04 fixed-tag KAT and negative signature/key/domain/scalar cases. It
then proves process OS/architecture and hashes the native module actually
loaded into that process.

The execution gate uses only these locally present digest-addressed images,
with `--pull never`:

- Linux ARM64: `mcr.microsoft.com/dotnet/aspnet@sha256:e3736b0d423db99c6988e1ddf5ea725c14b12579bb120024e5ff7ff204a14080`;
- Linux x64: `mcr.microsoft.com/dotnet/aspnet@sha256:1f51d2d65ace46d6395e773fb4cfc1c74d36fb4f08e5cf996e7f6961b45e9283`.

Containers have a unique nonce/name/label, no network, read-only root,
no capabilities and exact owned cleanup. The gate neither enumerates nor
changes unrelated Docker resources. It mounts only the clean committed probe
publish. Runtime receipts are written outside Git and must be sanitized again
before any later evidence-carrier commit.

## Required source verification

After the GREEN commit, use its exact SHA and tree:

```powershell
dotnet restore XNode.slnx --locked-mode -p:NuGetAudit=false
dotnet test tests/XNode.ProfileGenerator.Tests/XNode.ProfileGenerator.Tests.csproj -c Debug --no-restore
dotnet test tests/XNode.ProfileGenerator.Tests/XNode.ProfileGenerator.Tests.csproj -c Release --no-restore
dotnet test XNode.slnx -c Debug --no-restore
dotnet test XNode.slnx -c Release --no-restore
dotnet build XNode.slnx -c Release --no-restore
# The inherited whole-solution baseline exits nonzero with exactly 72 existing
# diagnostics: 68 CHARSET and 4 IMPORTS. The GREEN delta must remain zero.
dotnet format XNode.slnx --verify-no-changes --no-restore
eng/Test-P14C3PackageGate.ps1
eng/Verify-P14C3Source.ps1 -ExpectedHead <SHA> -ExpectedTree <TREE>
eng/Verify-P14C3StaticProvenance.ps1 -ExpectedHead <SHA> -ExpectedTree <TREE> `
  -P14E2SourceRepositoryRoot C:\W\deep-survival\wave08\deep-protocol-p14-activation-trust `
  -P14E2EvidenceRepositoryRoot C:\W\deep-survival\wave08\deep-protocol-p14e2-evidence
eng/Verify-P14C3LinuxExecution.ps1 -ExpectedHead <SHA> -ExpectedTree <TREE>
```

Also run the two existing isolated restore gates. Acceptance requires two
independent exact-source GO reviews and then a separate sanitized RED/GREEN
evidence carrier with independent review. Package publication, GitHub push,
runtime registration, production signing and profile activation are outside
this iteration.
