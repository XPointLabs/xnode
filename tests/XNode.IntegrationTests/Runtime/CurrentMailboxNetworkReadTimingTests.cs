namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxNetworkReadTimingTests
{
    [Fact]
    public void AggregatesGateAndPolicyTimeAsClosedNumericWorkOnly()
    {
        var clock = new ResourceClock(); CurrentMailboxDiagnostics.WorkSummary? work = null;
        using (CurrentMailboxDiagnostics.BeginWork(value => work = value))
        using (var timing = new CurrentMailboxNetworkReadTiming(_ => { }, clock))
        {
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.GateWait)) clock.Timestamp += 7;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.MailboxVerify)) clock.Timestamp += 11;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.MailboxReadback)) clock.Timestamp += 13;
        }
        Assert.NotNull(work); Assert.Equal(7L, work.NetworkGateMs); Assert.Equal(24L, work.MailboxPolicyMs);
        Assert.Equal(0L, work.LeaseChecks);
    }

    [Fact]
    public void MeasuresEveryClosedPhaseAndReportsOnlyBoundedWorkOnce()
    {
        var clock = new ResourceClock();
        var reports = new List<CurrentMailboxNetworkReadTiming.Result>();
        var timing = new CurrentMailboxNetworkReadTiming(reports.Add, clock);
        foreach (var phase in Enum.GetValues<CurrentMailboxNetworkReadTiming.Phase>())
        {
            using var measurement = timing.Measure(phase);
            clock.Timestamp += 10 + (int)phase;
        }
        timing.Dispose(); timing.Dispose();
        var actual = Assert.Single(reports);
        Assert.Equal(231, actual.TotalMs);
        Assert.Equal(CurrentMailboxNetworkReadTiming.Phase.ProofReadback, actual.Slowest);
        Assert.Equal(23, actual.SlowestMs);
        Assert.Equal(10, actual.GateWaitMs);
        Assert.Equal(12, actual.ProofAcquireMs);
        Assert.Equal(16, actual.NetworkVerifyMs);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObserverCannotReplaceAnOriginalCancelledWait(bool reportThrows)
    {
        var clock = new ResourceClock();
        var error = new OperationCanceledException();
        var reports = 0;
        CurrentMailboxNetworkReadTiming.Result? observed = null;
        var actual = Assert.Throws<OperationCanceledException>((Action)(() =>
        {
            using var timing = new CurrentMailboxNetworkReadTiming(work =>
            {
                reports++;
                observed = work;
                if (reportThrows) throw new IOException("Private observer failure");
            }, clock);
            using var wait = timing.Measure(CurrentMailboxNetworkReadTiming.Phase.GateWait);
            clock.Timestamp += 30;
            throw error;
        }));
        Assert.Same(error, actual); Assert.Equal(1, reports);
        Assert.NotNull(observed);
        Assert.Equal(CurrentMailboxNetworkReadTiming.Phase.GateWait, observed.Slowest);
        Assert.Equal(30, observed.GateWaitMs);
        Assert.Equal(0, observed.ProofAcquireMs);
    }

    [Fact]
    public void ClampsDurationAndDoesNotCountADisposedMeasurementTwice()
    {
        var clock = new ResourceClock();
        CurrentMailboxNetworkReadTiming.Result? actual = null;
        using (var timing = new CurrentMailboxNetworkReadTiming(work => actual = work, clock))
        {
            var phase = timing.Measure(CurrentMailboxNetworkReadTiming.Phase.NetworkVerify);
            clock.Timestamp = 10_000_000;
            phase.Dispose(); phase.Dispose();
        }
        Assert.NotNull(actual);
        Assert.Equal(3_600_000, actual.TotalMs);
        Assert.Equal(3_600_000, actual.NetworkVerifyMs);
        Assert.Equal(0, actual.GateWaitMs);
    }

    private sealed class ResourceClock : TimeProvider
    {
        internal long Timestamp;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Timestamp;
    }
}
