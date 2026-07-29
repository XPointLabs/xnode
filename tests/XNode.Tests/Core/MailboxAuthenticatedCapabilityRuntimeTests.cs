using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class MailboxAuthenticatedCapabilityRuntimeTests : IDisposable
{
    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_000);
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"xnode-p03b2-runtime-{Guid.NewGuid():N}");
    private readonly MailboxClientCanonicalOutcomeStore _outcomes;

    public MailboxAuthenticatedCapabilityRuntimeTests()
    {
        _outcomes = new MailboxClientCanonicalOutcomeStore(_directory);
    }

    [Fact]
    public void ValidMau2_UsesEd25519AndRecoversExactDurableOutcome()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);

        var first = runtime.Verify(fixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            first.ReplayDisposition);
        using var outcomeReservation = _outcomes.Reserve(
            first.OutcomeKey,
            MailboxAuthenticatedOperation.Store,
            first.RetainUntilUnixSeconds,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        var stored = _outcomes.PutTerminal(
            outcomeReservation,
            MailboxClientTerminalOutcome.DurableStateRejected);
        runtime.CompletePersistedOutcome(first);

        var replay = runtime.Verify(fixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.IdempotentCompleted,
            replay.ReplayDisposition);
        Assert.Equal(
            MailboxClientTerminalOutcome.DurableStateRejected,
            replay.RecoveredOutcome?.Terminal);
        Assert.Equal(stored.CanonicalBytes.ToArray(), replay.RecoveredOutcome?.CanonicalBytes.ToArray());
        Assert.True(runtime.Status.Ready);
        Assert.True(runtime.Status.StrictMau2Decoder);
        Assert.True(runtime.Status.Ed25519Verifier);
        Assert.True(runtime.Status.DurableAtomicReplay);
        Assert.True(runtime.Status.DurableCanonicalOutcomes);
    }

    [Fact]
    public void MalformedOversizedWrongOperationAndBodyDigest_FailBeforeAuthorization()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);

        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(fixture.Encoded.AsMemory(0, fixture.Encoded.Length - 1)));
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(new byte[
                16 +
                MailboxAuthenticatedCapabilityLimits.PresentationLength +
                MailboxClientLimits.MaximumPageBytes +
                1]));

        var wrongOperation = fixture.Encoded.ToArray();
        wrongOperation[5] = (byte)MailboxAuthenticatedOperation.Retrieve;
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(wrongOperation));

        var tamperedBody = fixture.Encoded.ToArray();
        tamperedBody[^1] ^= 1;
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(tamperedBody));

        var wrongEpoch = fixture.Encoded.ToArray();
        var bodyOffset = 16 + MailboxAuthenticatedCapabilityLimits.PresentationLength;
        BinaryPrimitives.WriteUInt64BigEndian(wrongEpoch.AsSpan(bodyOffset + 8), 8);
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(wrongEpoch));
        Assert.Equal(0, journal.Diagnostics.ScopeCount);
    }

    [Fact]
    public void CompletedReplayWithoutExactDurableOutcome_FailsClosed()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);
        var first = runtime.Verify(fixture.Encoded);
        journal.CompleteAtomically(
            first.Verified.Capability.ReplayClaim,
            Bytes(0xf3, 32));

        Assert.Throws<MailboxClientCanonicalOutcomeMissingException>(() =>
            runtime.Verify(fixture.Encoded));
    }

    [Fact]
    public void InFlightReplayWithPersistedOutcome_RepairsDigestAndRecoversExactBytes()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);
        var first = runtime.Verify(fixture.Encoded);
        using var outcomeReservation = _outcomes.Reserve(
            first.OutcomeKey,
            MailboxAuthenticatedOperation.Store,
            first.RetainUntilUnixSeconds,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        var stored = _outcomes.PutTerminal(
            outcomeReservation,
            MailboxClientTerminalOutcome.OperationConflict);

        var recovered = runtime.Verify(fixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            recovered.ReplayDisposition);
        Assert.Equal(
            stored.CanonicalBytes.ToArray(),
            recovered.RecoveredOutcome?.CanonicalBytes.ToArray());

        var completed = runtime.Verify(fixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.IdempotentCompleted,
            completed.ReplayDisposition);
        Assert.Equal(
            stored.CanonicalBytes.ToArray(),
            completed.RecoveredOutcome?.CanonicalBytes.ToArray());
    }

    [Fact]
    public void CompletedReplayWithMismatchedOutcomeDigest_FailsClosed()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);
        var first = runtime.Verify(fixture.Encoded);
        using var outcomeReservation = _outcomes.Reserve(
            first.OutcomeKey,
            MailboxAuthenticatedOperation.Store,
            first.RetainUntilUnixSeconds,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        _outcomes.PutTerminal(
            outcomeReservation,
            MailboxClientTerminalOutcome.OperationConflict);
        journal.CompleteAtomically(
            first.Verified.Capability.ReplayClaim,
            Bytes(0x5a, 32));

        Assert.Throws<InvalidDataException>(() =>
            runtime.Verify(fixture.Encoded));
    }

    [Fact]
    public void OutcomeCapacityIsReservedBeforeExecutionAndCanAbortWithoutSideEffects()
    {
        var constrainedRoot = Path.Combine(_directory, "constrained");
        using var outcomes = new MailboxClientCanonicalOutcomeStore(
            constrainedRoot,
            new MailboxClientCanonicalOutcomeStoreOptions
            {
                MaximumEntries = 1,
                MaximumBytes =
                    MailboxClientCanonicalOutcomeStore.HeaderLength
                    + MailboxWireHttpContract.Store.MaximumResponseBytes
            });
        using var journal = new DurableMailboxCapabilityReplayJournal(constrainedRoot);
        var firstFixture = Frame(replayCounter: 11);
        var runtime = Runtime(firstFixture, journal, outcomes: outcomes);
        var first = runtime.Verify(firstFixture.Encoded);
        Assert.True(runtime.TryAcquireExecution(first));
        runtime.ReserveOutcomeCapacity(
            first,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        runtime.PersistTerminal(
            first,
            MailboxClientTerminalOutcome.DurableStateRejected);

        var secondFixture = Frame(replayCounter: 12);
        var second = runtime.Verify(secondFixture.Encoded);
        Assert.True(runtime.TryAcquireExecution(second));
        Assert.Throws<MailboxClientCanonicalOutcomeCapacityException>(() =>
            runtime.ReserveOutcomeCapacity(
                second,
                MailboxWireHttpContract.Store.MaximumResponseBytes));
        Assert.False(second.SideEffectsStarted);
        runtime.AbortIfNew(second);

        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            runtime.Verify(secondFixture.Encoded).ReplayDisposition);
    }

    [Fact]
    public void ActiveExecutionRejectsConcurrentInFlightButAllowsBoundedRecoveryOwner()
    {
        var fixture = Frame(replayCounter: 11);
        var higherFixture = Frame(replayCounter: 12);
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);
        var first = runtime.Verify(fixture.Encoded);
        Assert.True(runtime.TryAcquireExecution(first));

        var concurrent = runtime.Verify(fixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            concurrent.ReplayDisposition);
        Assert.False(runtime.TryAcquireExecution(concurrent));
        var blockedHigher = runtime.Verify(higherFixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            blockedHigher.ReplayDisposition);
        Assert.False(runtime.TryAcquireExecution(blockedHigher));

        runtime.EndExecution(first);
        Assert.False(runtime.TryAcquireExecution(blockedHigher));
        Assert.True(runtime.TryAcquireExecution(concurrent));
        runtime.EndExecution(concurrent);

        var restartedRuntime = Runtime(fixture, journal);
        var afterRestart = restartedRuntime.Verify(fixture.Encoded);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            afterRestart.ReplayDisposition);
        Assert.True(restartedRuntime.TryAcquireExecution(afterRestart));
        restartedRuntime.EndExecution(afterRestart);
    }

    [Fact]
    public void AbortOnlyReleasesNewReservationBeforeSideEffects()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(fixture, journal);

        var safe = runtime.Verify(fixture.Encoded);
        runtime.AbortIfNew(safe);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            runtime.Verify(fixture.Encoded).ReplayDisposition);

        using var secondJournal = new DurableMailboxCapabilityReplayJournal(
            Path.Combine(_directory, "side-effect-journal"));
        var sideEffectRuntime = Runtime(fixture, secondJournal);
        var started = sideEffectRuntime.Verify(fixture.Encoded);
        started.MarkSideEffectsStarted();
        sideEffectRuntime.AbortIfNew(started);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            sideEffectRuntime.Verify(fixture.Encoded).ReplayDisposition);
    }

    [Fact]
    public void IssuerHolderGenerationLifecycleAndRevocationFailures_AreFailClosed()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);

        var issuerTamper = fixture.Encoded.ToArray();
        issuerTamper[16 + 72 + 208] ^= 1;
        var issuerError = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            Runtime(fixture, journal).Verify(issuerTamper));
        Assert.Equal(
            MailboxAuthenticatedCapabilityError.InvalidIssuerSignature,
            issuerError.Error);

        var holderTamper = fixture.Encoded.ToArray();
        holderTamper[16 + 344] ^= 1;
        var holderError = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            Runtime(fixture, journal).Verify(holderTamper));
        Assert.Equal(
            MailboxAuthenticatedCapabilityError.InvalidHolderSignature,
            holderError.Error);

        var generationError = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            Runtime(
                fixture,
                journal,
                minimumGeneration: fixture.Grant.Generation + 1).Verify(fixture.Encoded));
        Assert.Equal(
            MailboxAuthenticatedCapabilityError.GenerationRejected,
            generationError.Error);

        var lifecycleError = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            Runtime(
                fixture,
                journal,
                allowedLifecycle: MailboxCapabilityLifecycle.Overlap).Verify(fixture.Encoded));
        Assert.Equal(
            MailboxAuthenticatedCapabilityError.UntrustedIssuer,
            lifecycleError.Error);

        var revokedError = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            Runtime(fixture, journal, revoked: true).Verify(fixture.Encoded));
        Assert.Equal(MailboxAuthenticatedCapabilityError.Revoked, revokedError.Error);
        Assert.Equal(0, journal.Diagnostics.ScopeCount);
    }

    [Fact]
    public void UnconfiguredAuthority_IsNotReadyAndCannotTrustAttackerGrant()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = new MailboxAuthenticatedCapabilityRuntime(
            new RejectAllMailboxCapabilityAuthoritySource(),
            new RejectAllMailboxCapabilityRevocationPolicy(),
            journal,
            _outcomes,
            new FixedClock(Now));

        Assert.False(runtime.Status.Ready);
        Assert.False(runtime.Status.AuthorityConfigured);
        Assert.False(runtime.Status.RevocationPolicyConfigured);
        var error = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(fixture.Encoded));
        Assert.Equal(MailboxAuthenticatedCapabilityError.UntrustedIssuer, error.Error);
        Assert.Equal(0, journal.Diagnostics.ScopeCount);
    }

    [Fact]
    public void GrantExpiry_NotLongLivedIssuerValidity_DrivesCapacityRecovery()
    {
        var fixture = Frame();
        using var journal = new DurableMailboxCapabilityReplayJournal(
            _directory,
            new DurableMailboxCapabilityReplayJournalOptions
            {
                MaximumScopes = 1
            });
        var runtime = Runtime(fixture, journal);
        var verified = runtime.Verify(fixture.Encoded);
        PersistTerminal(runtime, verified);

        var retainedUntil = journal.RetainUntilUnixSeconds(
            fixture.Grant.ExpiresAtUnixSeconds);
        Assert.Equal(0, journal.CollectExpiredForTestsOnly(retainedUntil));
        Assert.Equal(
            1,
            journal.CollectExpiredForTestsOnly(retainedUntil + 1));
        Assert.Equal(0, journal.Diagnostics.ScopeCount);

        Assert.Equal(
            MailboxCapabilityAtomicReplayState.NewReserved,
            journal.EvaluateAndReserve(
                new MailboxCapabilityAtomicReplayClaim
                {
                    ClaimDigest = Bytes(0x31, 32),
                    IssuerPublicKey = Bytes(0x32, 32),
                    Serial = Bytes(0x33, 16),
                    Epoch = 8,
                    Generation = 10,
                    Operation = MailboxAuthenticatedOperation.Store,
                    OperationId = Bytes(0x34, 16),
                    ReplayCounter = 1,
                    RequestDigest = Bytes(0x35, 32)
                },
                nowUnixSeconds: retainedUntil + 1,
                retainUntilUnixSeconds: retainedUntil + 100).State);
    }

    [Fact]
    public void CompletedTerminalOutcome_DoesNotStrandHigherReplayCounter()
    {
        var firstFrame = Frame(replayCounter: 11);
        var higherFrame = Frame(replayCounter: 12);
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        var runtime = Runtime(firstFrame, journal);
        var first = runtime.Verify(firstFrame.Encoded);
        PersistTerminal(runtime, first);

        var higher = runtime.Verify(higherFrame.Encoded);

        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            higher.ReplayDisposition);
    }

    [Fact]
    public void ForwardCollectionThenRestartRollback_CannotRevalidateCollectedGrant()
    {
        var fixture = Frame();
        var clock = new FixedClock(Now);
        using (var journal = new DurableMailboxCapabilityReplayJournal(_directory))
        {
            var runtime = Runtime(fixture, journal, clock: clock);
            var verified = runtime.Verify(fixture.Encoded);
            PersistTerminal(runtime, verified);
            var collectedAt = journal.RetainUntilUnixSeconds(
                fixture.Grant.ExpiresAtUnixSeconds) + 1;
            clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(checked((long)collectedAt));
            Assert.Equal(1, journal.CollectExpiredForTestsOnly(collectedAt));
        }

        clock.UtcNow = Now;
        using var restarted = new DurableMailboxCapabilityReplayJournal(_directory);
        var rolledBack = Runtime(fixture, restarted, clock: clock);
        var error = Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            rolledBack.Verify(fixture.Encoded));
        Assert.Equal(
            MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation,
            error.Error);
        Assert.Equal(0, restarted.Diagnostics.ScopeCount);
    }

    [Fact]
    public void BoundedRollback_UsesDurableFloorAndCannotExtendGrantValidity()
    {
        var fixture = Frame();
        var acceptedTime = fixture.Grant.ExpiresAtUnixSeconds + 1;
        var clock = new FixedClock(
            DateTimeOffset.FromUnixTimeSeconds(checked((long)acceptedTime)));
        using var journal = new DurableMailboxCapabilityReplayJournal(_directory);
        _ = journal.CollectExpiredForTestsOnly(acceptedTime);
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(
            checked((long)fixture.Grant.ExpiresAtUnixSeconds - 49));
        var runtime = Runtime(fixture, journal, clock: clock);

        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            runtime.Verify(fixture.Encoded));
        Assert.Equal(
            acceptedTime,
            journal.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
        Assert.Equal(0, journal.Diagnostics.ScopeCount);
    }

    public void Dispose()
    {
        _outcomes.Dispose();
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private MailboxAuthenticatedCapabilityRuntime Runtime(
        FrameFixture fixture,
        DurableMailboxCapabilityReplayJournal journal,
        ulong? minimumGeneration = null,
        MailboxCapabilityLifecycle? allowedLifecycle = null,
        bool revoked = false,
        IClock? clock = null,
        MailboxClientCanonicalOutcomeStore? outcomes = null) => new(
            new FixedAuthority(
                fixture.Grant,
                minimumGeneration ?? fixture.Grant.Generation,
                allowedLifecycle ?? fixture.Grant.Lifecycle),
            new FixedRevocations(revoked),
            journal,
            outcomes ?? _outcomes,
            clock ?? new FixedClock(Now));

    private void PersistTerminal(
        MailboxAuthenticatedCapabilityRuntime runtime,
        MailboxAuthenticatedRuntimeReservation reservation)
    {
        using var outcomeReservation = _outcomes.Reserve(
            reservation.OutcomeKey,
            reservation.Verified.Binding.Operation,
            reservation.RetainUntilUnixSeconds,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        _outcomes.PutTerminal(
            outcomeReservation,
            MailboxClientTerminalOutcome.DurableStateRejected);
        runtime.CompletePersistedOutcome(reservation);
    }

    private static FrameFixture Frame(ulong replayCounter = 11)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var placement = new BlindedPlacementId(Range(0x90, 32));
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(
            new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(Range(0x20, 32)),
                PlacementId = placement,
                OperationId = Range(0xd0, 16),
                DeduplicationDigest = Range(0xe0, 32),
                CreatedAtUnixSeconds = 1_000,
                ExpiresAtUnixSeconds = 1_060,
                Ciphertext = Range(1, 64)
            });
        var grant = crypto.SignGrant(
            new MailboxAuthenticatedGrant
            {
                Domain = MailboxCapabilityDomain.Deposit,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = Range(0x70, 16),
                Epoch = 7,
                Generation = 9,
                Serial = Range(0x80, 16),
                NotBeforeUnixSeconds = 900,
                ExpiresAtUnixSeconds = 1_100,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = MailboxPlacementCommitment.Compute(placement),
                MembershipCommitment = Range(0xb0, 32),
                IssuerPublicKey = crypto.GetPublicKey(issuerSeed),
                HolderPublicKey = crypto.GetPublicKey(holderSeed),
                IssuerSignature = ReadOnlyMemory<byte>.Empty
            },
            issuerSeed);
        var presentation = crypto.SignPresentation(
            grant,
            binding,
            replayCounter,
            holderSeed);
        var encoded = MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = presentation
            });
        return new(encoded, grant);
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed record FrameFixture(byte[] Encoded, MailboxAuthenticatedGrant Grant);

    private sealed class FixedAuthority(
        MailboxAuthenticatedGrant grant,
        ulong minimumGeneration,
        MailboxCapabilityLifecycle allowedLifecycle) : IMailboxCapabilityAuthoritySource
    {
        public bool IsConfigured => true;

        public bool TryResolve(
            MailboxCapabilityAuthorityQuery query,
            out MailboxAuthenticatedVerificationPolicy? policy)
        {
            policy = new MailboxAuthenticatedVerificationPolicy
            {
                NetworkId = grant.NetworkId.ToArray(),
                Epoch = grant.Epoch,
                PlacementCommitment = grant.PlacementCommitment.ToArray(),
                MembershipCommitment = grant.MembershipCommitment.ToArray(),
                NowUnixSeconds = 0,
                MinimumGeneration = minimumGeneration,
                TrustedIssuers =
                [
                    new MailboxCapabilityIssuerAuthority
                    {
                        PublicKey = grant.IssuerPublicKey.ToArray(),
                        Domain = grant.Domain,
                        AllowedLifecycle = allowedLifecycle,
                        MinimumGeneration = minimumGeneration,
                        MaximumGeneration = 20,
                        ValidFromUnixSeconds = 800,
                        ValidUntilUnixSeconds = 1_000_000
                    }
                ]
            };
            return true;
        }
    }

    private sealed class FixedRevocations(bool revoked)
        : IMailboxCapabilityRevocationPolicy
    {
        public bool IsConfigured => true;

        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => revoked;
    }
}
