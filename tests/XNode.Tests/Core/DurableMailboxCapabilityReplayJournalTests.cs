using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class DurableMailboxCapabilityReplayJournalTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"xnode-p03b2-replay-{Guid.NewGuid():N}");

    [Fact]
    public void NewPendingCompletedConflictStaleAndRestart_AreFailClosed()
    {
        var claim = Claim(counter: 7, claimByte: 0x11);
        using (var journal = Journal())
        {
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.NewReserved,
                Evaluate(journal, claim).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.PendingSame,
                Evaluate(journal, claim).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.Conflict,
                Evaluate(journal,
                    claim with { ClaimDigest = Bytes(0x12, 32) }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.StaleReplay,
                Evaluate(journal,
                    claim with { ReplayCounter = 6 }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.PendingPrior,
                Evaluate(journal,
                    claim with
                    {
                        ReplayCounter = 8,
                        ClaimDigest = Bytes(0x13, 32)
                    }).State);

            journal.CompleteAtomically(claim, Bytes(0x91, 48));
            var cached = Evaluate(journal, claim);
            Assert.Equal(MailboxCapabilityAtomicReplayState.CompletedSame, cached.State);
            Assert.Equal(Bytes(0x91, 48), cached.CachedOutcome.ToArray());
        }

        using var restarted = Journal();
        var afterRestart = Evaluate(restarted, claim);
        Assert.Equal(MailboxCapabilityAtomicReplayState.CompletedSame, afterRestart.State);
        Assert.Equal(Bytes(0x91, 48), afterRestart.CachedOutcome.ToArray());
        Assert.Equal(
            new MailboxCapabilityReplayJournalDiagnostics(1, 0, 1, 0, 99_999, 1_000),
            restarted.Diagnostics);
    }

    [Fact]
    public void CrashAfterAtomicMove_RecoversExplicitPendingReservation()
    {
        var claim = Claim(counter: 1, claimByte: 0x21);
        Assert.Throws<IOException>(() =>
        {
            using var crashing = new DurableMailboxCapabilityReplayJournal(
                _directory,
                durability: new ThrowAfterMoveDurability());
            _ = Evaluate(crashing, claim);
        });

        using var recovered = Journal();
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.PendingSame,
            Evaluate(recovered, claim).State);
        Assert.Equal(1, recovered.Diagnostics.PendingCount);

        recovered.CompleteAtomically(claim, Bytes(0x92, 32));
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.CompletedSame,
            Evaluate(recovered, claim).State);
    }

    [Fact]
    public void CorruptJournalAndConcurrentOwner_FailClosed()
    {
        using (var owner = Journal())
        {
            Assert.Throws<InvalidOperationException>(() => Journal());
        }

        var journalDirectory = Path.Combine(_directory, "mailbox-capability-replay-v3");
        Directory.CreateDirectory(journalDirectory);
        File.WriteAllText(Path.Combine(journalDirectory, "replay.json"), "{\"schemaVersion\":99}");
        Assert.Throws<InvalidDataException>(() => Journal());
    }

    [Fact]
    public void PersistedAndDiagnosticState_DoesNotExposeRawAuthorityOrOperationFields()
    {
        var claim = Claim(counter: 3, claimByte: 0x31);
        using var journal = Journal();
        _ = Evaluate(journal, claim);

        var persisted = File.ReadAllText(Path.Combine(
            _directory,
            "mailbox-capability-replay-v3",
            "replay.json"));
        Assert.DoesNotContain(
            Convert.ToHexString(claim.IssuerPublicKey.Span),
            persisted,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            Convert.ToHexString(claim.Serial.Span),
            persisted,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            Convert.ToHexString(claim.OperationId.Span),
            persisted,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            Convert.ToHexString(claim.RequestDigest.Span),
            persisted,
            StringComparison.OrdinalIgnoreCase);

        var diagnostics = journal.Diagnostics.ToString();
        Assert.DoesNotContain("Issuer", diagnostics, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OperationId", diagnostics, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ScopeCapacity_IsDurablyBounded()
    {
        using var journal = new DurableMailboxCapabilityReplayJournal(
            _directory,
            new DurableMailboxCapabilityReplayJournalOptions { MaximumScopes = 1 });
        _ = Evaluate(journal, Claim(counter: 1, claimByte: 0x41));
        Assert.Throws<InvalidOperationException>(() =>
            Evaluate(journal, Claim(
                counter: 1,
                claimByte: 0x42,
                serialByte: 0x52)));
        Assert.Equal(1, journal.Diagnostics.ScopeCount);
    }

    [Fact]
    public void ReleasedReservation_PreservesFloorAcrossRestartAndAllowsOnlySafeProgress()
    {
        var claim = Claim(counter: 7, claimByte: 0x61);
        using (var journal = Journal())
        {
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.NewReserved,
                Evaluate(journal, claim).State);
            journal.AbortAtomically(claim);
            Assert.Equal(1, journal.Diagnostics.ReleasedCount);
        }

        using (var restarted = Journal())
        {
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.StaleReplay,
                Evaluate(restarted,
                    claim with { ReplayCounter = 6 }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.Conflict,
                Evaluate(restarted,
                    claim with { ClaimDigest = Bytes(0x62, 32) }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.NewReserved,
                Evaluate(restarted, claim).State);
            restarted.AbortAtomically(claim);
        }

        using var restartedAgain = Journal();
        var higher = claim with
        {
            ReplayCounter = 8,
            ClaimDigest = Bytes(0x63, 32)
        };
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.NewReserved,
            Evaluate(restartedAgain, higher).State);
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.StaleReplay,
            Evaluate(restartedAgain, claim).State);
    }

    [Fact]
    public void ExpiredValidityRetention_RecoversCapacity()
    {
        using var journal = new DurableMailboxCapabilityReplayJournal(
            _directory,
            new DurableMailboxCapabilityReplayJournalOptions
            {
                MaximumScopes = 1
            });
        var retainedUntil = journal.RetainUntilUnixSeconds(101);
        _ = journal.EvaluateAndReserve(
            Claim(counter: 1, claimByte: 0x71),
            nowUnixSeconds: 100,
            retainUntilUnixSeconds: retainedUntil);
        journal.CompleteAtomically(
            Claim(counter: 1, claimByte: 0x71),
            Bytes(0x72, 32));
        Assert.Equal(
            1,
            journal.CollectExpiredForTestsOnly(retainedUntil + 1));

        var replacement = journal.EvaluateAndReserve(
            Claim(counter: 1, claimByte: 0x73, serialByte: 0x74),
            nowUnixSeconds: retainedUntil + 1,
            retainUntilUnixSeconds: journal.RetainUntilUnixSeconds(200));

        Assert.Equal(MailboxCapabilityAtomicReplayState.NewReserved, replacement.State);
        Assert.Equal(
            new MailboxCapabilityReplayJournalDiagnostics(
                1,
                1,
                0,
                0,
                0,
                retainedUntil + 1),
            journal.Diagnostics);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public void PreProductionLegacySchemas_AreRejectedWithoutMigration(int legacyVersion)
    {
        var claim = Claim(counter: 4, claimByte: 0x75);
        using (var journal = Journal())
        {
            _ = Evaluate(journal, claim);
        }

        var path = Path.Combine(
            _directory,
            "mailbox-capability-replay-v3",
            "replay.json");
        var schema3 = File.ReadAllText(path);
        var legacy = schema3.Replace(
            "\"schemaVersion\":3",
            $"\"schemaVersion\":{legacyVersion}",
            StringComparison.Ordinal);
        File.WriteAllText(path, legacy);

        Assert.Throws<InvalidDataException>(() =>
        {
            using var rejected = new DurableMailboxCapabilityReplayJournal(_directory);
        });
        Assert.Equal(legacy, File.ReadAllText(path));
    }

    [Fact]
    public void ConcurrentAcceptedTimes_NeverMoveDurableFloorBackwardOrLoseClaims()
    {
        using var journal = new DurableMailboxCapabilityReplayJournal(
            _directory,
            new DurableMailboxCapabilityReplayJournalOptions
            {
                MaximumScopes = 100
            });

        Parallel.For(0, 51, index =>
        {
            var value = checked((byte)(0x80 + index));
            _ = journal.EvaluateAndReserve(
                Claim(
                    counter: 1,
                    claimByte: value,
                    serialByte: value),
                nowUnixSeconds: checked((ulong)(2_000 + index)),
                retainUntilUnixSeconds: ulong.MaxValue);
        });

        Assert.Equal(51, journal.Diagnostics.ScopeCount);
        Assert.Equal(2_050UL, journal.Diagnostics.AcceptedTimeHighWatermarkUnixSeconds);
    }

    [Fact]
    public void ConcurrentIdenticalAndConflictingClaims_HaveOneDurableWinner()
    {
        using var journal = Journal();
        var claim = Claim(counter: 9, claimByte: 0x22);
        var identical = new System.Collections.Concurrent.ConcurrentBag<
            MailboxCapabilityAtomicReplayState>();
        Parallel.For(0, 20, _ =>
            identical.Add(Evaluate(journal, claim).State));
        Assert.Equal(
            1,
            identical.Count(state =>
                state == MailboxCapabilityAtomicReplayState.NewReserved));
        Assert.Equal(
            19,
            identical.Count(state =>
                state == MailboxCapabilityAtomicReplayState.PendingSame));

        journal.AbortAtomically(claim);
        var conflicts = new System.Collections.Concurrent.ConcurrentBag<
            MailboxCapabilityAtomicReplayState>();
        Parallel.For(0, 20, index =>
        {
            var contender = claim with
            {
                ReplayCounter = 10,
                ClaimDigest = Bytes(checked((byte)(0x30 + index)), 32)
            };
            conflicts.Add(Evaluate(journal, contender).State);
        });
        Assert.Equal(
            1,
            conflicts.Count(state =>
                state == MailboxCapabilityAtomicReplayState.NewReserved));
        Assert.Equal(
            19,
            conflicts.Count(state =>
                state == MailboxCapabilityAtomicReplayState.Conflict));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private DurableMailboxCapabilityReplayJournal Journal() => new(_directory);

    private static MailboxCapabilityAtomicReplayEvaluation Evaluate(
        DurableMailboxCapabilityReplayJournal journal,
        MailboxCapabilityAtomicReplayClaim claim,
        ulong nowUnixSeconds = 1_000) =>
        journal.EvaluateAndReserve(
            claim,
            nowUnixSeconds,
            retainUntilUnixSeconds: ulong.MaxValue);

    private static MailboxCapabilityAtomicReplayClaim Claim(
        ulong counter,
        byte claimByte,
        byte serialByte = 0x51) => new()
        {
            ClaimDigest = Bytes(claimByte, 32),
            IssuerPublicKey = Bytes(0x61, 32),
            Serial = Bytes(serialByte, 16),
            Epoch = 7,
            Generation = 9,
            Operation = MailboxAuthenticatedOperation.Store,
            OperationId = Bytes(0x71, 16),
            ReplayCounter = counter,
            RequestDigest = Bytes(0x81, 32)
        };

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class ThrowAfterMoveDurability : IMailboxDurabilityBarrier
    {
        public void FlushFileAndParentDirectory(string path) =>
            throw new IOException("simulated durability barrier crash");

        public void FlushParentDirectory(string deletedPath) =>
            throw new IOException("simulated durability barrier crash");
    }

    private sealed class FixedClock(ulong nowUnixSeconds) : IClock
    {
        public DateTimeOffset UtcNow { get; } =
            DateTimeOffset.FromUnixTimeSeconds(checked((long)nowUnixSeconds));
    }
}
