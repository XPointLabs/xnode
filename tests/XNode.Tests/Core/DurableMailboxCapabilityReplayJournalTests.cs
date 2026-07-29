using Deep.Protocol.DeepExtension.MailboxCapabilities;
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
                journal.EvaluateAndReserve(claim).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.PendingSame,
                journal.EvaluateAndReserve(claim).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.Conflict,
                journal.EvaluateAndReserve(
                    claim with { ClaimDigest = Bytes(0x12, 32) }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.StaleReplay,
                journal.EvaluateAndReserve(
                    claim with { ReplayCounter = 6 }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.PendingPrior,
                journal.EvaluateAndReserve(
                    claim with
                    {
                        ReplayCounter = 8,
                        ClaimDigest = Bytes(0x13, 32)
                    }).State);

            journal.CompleteAtomically(claim, Bytes(0x91, 48));
            var cached = journal.EvaluateAndReserve(claim);
            Assert.Equal(MailboxCapabilityAtomicReplayState.CompletedSame, cached.State);
            Assert.Equal(Bytes(0x91, 48), cached.CachedOutcome.ToArray());
        }

        using var restarted = Journal();
        var afterRestart = restarted.EvaluateAndReserve(claim);
        Assert.Equal(MailboxCapabilityAtomicReplayState.CompletedSame, afterRestart.State);
        Assert.Equal(Bytes(0x91, 48), afterRestart.CachedOutcome.ToArray());
        Assert.Equal(
            new MailboxCapabilityReplayJournalDiagnostics(1, 0, 1, 0, 99_999),
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
            _ = crashing.EvaluateAndReserve(claim);
        });

        using var recovered = Journal();
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.PendingSame,
            recovered.EvaluateAndReserve(claim).State);
        Assert.Equal(1, recovered.Diagnostics.PendingCount);

        recovered.CompleteAtomically(claim, Bytes(0x92, 32));
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.CompletedSame,
            recovered.EvaluateAndReserve(claim).State);
    }

    [Fact]
    public void CorruptJournalAndConcurrentOwner_FailClosed()
    {
        using (var owner = Journal())
        {
            Assert.Throws<InvalidOperationException>(() => Journal());
        }

        var journalDirectory = Path.Combine(_directory, "mailbox-capability-replay-v2");
        Directory.CreateDirectory(journalDirectory);
        File.WriteAllText(Path.Combine(journalDirectory, "replay.json"), "{\"schemaVersion\":99}");
        Assert.Throws<InvalidDataException>(() => Journal());
    }

    [Fact]
    public void PersistedAndDiagnosticState_DoesNotExposeRawAuthorityOrOperationFields()
    {
        var claim = Claim(counter: 3, claimByte: 0x31);
        using var journal = Journal();
        _ = journal.EvaluateAndReserve(claim);

        var persisted = File.ReadAllText(Path.Combine(
            _directory,
            "mailbox-capability-replay-v2",
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
        _ = journal.EvaluateAndReserve(Claim(counter: 1, claimByte: 0x41));
        Assert.Throws<InvalidOperationException>(() =>
            journal.EvaluateAndReserve(Claim(
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
                journal.EvaluateAndReserve(claim).State);
            journal.AbortAtomically(claim);
            Assert.Equal(1, journal.Diagnostics.ReleasedCount);
        }

        using (var restarted = Journal())
        {
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.StaleReplay,
                restarted.EvaluateAndReserve(
                    claim with { ReplayCounter = 6 }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.Conflict,
                restarted.EvaluateAndReserve(
                    claim with { ClaimDigest = Bytes(0x62, 32) }).State);
            Assert.Equal(
                MailboxCapabilityAtomicReplayState.NewReserved,
                restarted.EvaluateAndReserve(claim).State);
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
            restartedAgain.EvaluateAndReserve(higher).State);
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.StaleReplay,
            restartedAgain.EvaluateAndReserve(claim).State);
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

        var replacement = journal.EvaluateAndReserve(
            Claim(counter: 1, claimByte: 0x73, serialByte: 0x74),
            nowUnixSeconds: retainedUntil + 1,
            retainUntilUnixSeconds: journal.RetainUntilUnixSeconds(200));

        Assert.Equal(MailboxCapabilityAtomicReplayState.NewReserved, replacement.State);
        Assert.Equal(
            new MailboxCapabilityReplayJournalDiagnostics(1, 1, 0, 0, 0),
            journal.Diagnostics);
    }

    [Fact]
    public void SchemaV1Records_MigrateFailClosedWithoutInventingCollectionBoundary()
    {
        var claim = Claim(counter: 4, claimByte: 0x75);
        using (var journal = Journal())
        {
            _ = journal.EvaluateAndReserve(claim);
        }

        var path = Path.Combine(
            _directory,
            "mailbox-capability-replay-v2",
            "replay.json");
        var persisted = File.ReadAllText(path)
            .Replace("\"schemaVersion\":2", "\"schemaVersion\":1", StringComparison.Ordinal);
        persisted = System.Text.RegularExpressions.Regex.Replace(
            persisted,
            ",\"retainUntilUnixSeconds\":18446744073709551615",
            "");
        File.WriteAllText(path, persisted);

        using var migrated = Journal();
        Assert.Equal(
            MailboxCapabilityAtomicReplayState.PendingSame,
            migrated.EvaluateAndReserve(claim).State);
        Assert.Equal(0, migrated.CollectExpired(ulong.MaxValue));
        Assert.Equal(1, migrated.Diagnostics.PendingCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private DurableMailboxCapabilityReplayJournal Journal() => new(_directory);

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
}
