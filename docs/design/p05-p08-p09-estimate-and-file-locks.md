# P05 follow-on estimate and file-lock map

Status: planning only. Decision owner: **Mr. X**. Approved ADR SHA:
**NOT-APPROVED**. Do not start P08/P09 from this document.

Estimates are engineering days after all named dependencies are accepted and available locally.
They exclude external security review, production key ceremony, app-store review and long-running
field beta.

## Sequence and estimates

| Work package | Scope | Estimate | Required predecessor |
| --- | --- | ---: | --- |
| P08 | Versioned HRW placement, P04D roster consumer, legacy/shadow flags, property/integration evidence | 5-8 days + 2 review days | Approved P05, P04D |
| P09A | One durable ciphertext replica, atomic persistence, signing, TTL/tombstones, corruption/backup tests | 12-18 days + 3 review days | Approved P05, P03B crypto/key profile |
| P09B | N3/W2/R2 coordinator, bounded fan-out, read repair, overlap/rollback, chaos | 12-18 days + 4 review days | P08 and P09A accepted |
| P09C | Shared client adapter, receipt verification, persistent outbox integration, mobile/Windows tests | 10-15 days + 3 review days | P07A, P09B, P10B |
| Integration/soak reserve | 100k deterministic writes, restart/corruption, mixed-version, no-mock lab | 8-12 days | P09A-C integrated |

Likely critical path: 47-74 engineering days before external review/field beta. P08 and early P09A
can overlap only where their locked files do not intersect and after the ADR is approved.

## Product ownership

- `xnode`: placement, replica runtime, coordinator, durable local storage, readiness and aggregate
  metrics.
- `deep-protocol`: only new canonical leaf/placement/epoch binding and cross-language vectors that
  cannot be expressed by existing P03B/P04 bytes.
- `deep-client-shared`: P09C capability presentation, receipt verification and outbox adapter.
- `deep-devops`: compose/deployment, secrets mounting and rehearsal; never the product storage
  implementation.
- `deep-tests-e2e`: cross-client and chaos acceptance.
- Mr. X: ADR acceptance, migration phase transitions and rollback/retirement decisions.

## File locks

### P08 exclusive locks

- `src/XNode.Core/Runtime/RouterRuntime.cs`
- `src/XNode.Core/Runtime/RouterRuntimeOptions.cs`
- `src/XNode.Core/Storage/Placement/**` (new)
- `src/XNode.Core/Storage/Membership/**` (new P04D adapter)
- `src/XNode/Program.cs`
- `src/XNode/appsettings*.json`
- `tests/XNode.Tests/Storage/Placement/**` (new)
- placement sections in `tests/XNode.IntegrationTests/Runtime/RouterRuntimeIntegrationTests.cs`
- `docs/operator.md` and `docs/SESSION_PORTING.md`

P08 may port the test-only P05 simulator into production only after approval; it must not add
replica persistence or fan-out.

### P09A exclusive locks

- `src/XNode.Storage/**` (new project)
- `tests/XNode.Storage.Tests/**` (new project)
- `src/XNode/Storage/ReplicaEndpoints.cs` (new)
- replica-only configuration types and schema/migration files
- replica data-directory, backup, corruption and signing-identity docs

P09A must not edit `RouterRuntime.cs`, placement types or coordinator files. If solution/DI changes
touch `XNode.slnx`, `src/XNode/XNode.csproj` or `Program.cs`, one named integrator takes those files
after P08 lands; they are not concurrently edited.

### P09B exclusive locks

- `src/XNode.Core/Storage/Replication/**` (new)
- `src/XNode/Storage/HttpStorageReplicaClient.cs` (new)
- `src/XNode.Core/Runtime/RouterRuntime.cs`
- coordinator DI/readiness/status sections in `src/XNode/Program.cs`
- coordinator sections in `tests/XNode.IntegrationTests/Runtime/RouterRuntimeIntegrationTests.cs`
- `tests/XNode.IntegrationTests/Storage/Replication/**` (new)
- replication migration/operator docs

P09B begins only after P08/P09A are accepted, so these are sequential locks.

### P09C locks in `deep-client-shared`

- new `src/**/Storage/Mailbox/**` adapter namespace
- persistent outbox repository/migration files named in the P09C invocation
- receipt-verifier and membership-placement binding files
- corresponding unit/integration tests

P09C does not edit XNode runtime files.

### Integration locks

- `deep-devops` compose/storage service names and release gates: one DevOps integrator only
- `deep-tests-e2e` storage fixtures/scenarios: one E2E integrator only
- mobile/Windows test scenario manifests: one cross-platform test owner

## Stop conditions before implementation

- `APPROVED_ADR_SHA` remains `NOT-APPROVED`.
- P04D cannot supply an immutable verified full roster bound to `MSM1`.
- P08 has no reviewed golden vectors binding P03B `OperationId` to P04 epoch/roster/placement, and
  no approved replacement receipt wrapper.
- Production P03B replica/coordinator crypto and key distribution are unapproved.
- The owner would be the DevOps compatibility service rather than an XNode product runtime.
- Any design needs raw Session IDs, sender-recipient pairs, wallet IDs or sender master secrets.
- Rollback is claimed while the old epoch lacks continuous W2 mirror evidence.
