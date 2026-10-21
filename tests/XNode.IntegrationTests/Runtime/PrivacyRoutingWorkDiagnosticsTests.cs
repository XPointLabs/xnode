using Microsoft.Extensions.Logging;

namespace XNode.IntegrationTests.Runtime;

public sealed class PrivacyRoutingWorkDiagnosticsTests
{
    [Fact]
    public void ReportsAllClosedPhasesAsNumbersOnce()
    {
        var clock = new ResourceClock(); var logger = new RecordingLogger();
        var observer = new PrivacyRoutingWorkDiagnostics(logger, clock);
        var work = Assert.IsType<PrivacyRoutingWorkDiagnostics.Work>(observer.Begin());
        clock.Timestamp += 110;
        work.Next(PrivacyRoutingWorkDiagnostics.Phase.Open); clock.Timestamp += 220;
        work.Next(PrivacyRoutingWorkDiagnostics.Phase.Forward); clock.Timestamp += 330;
        work.Next(PrivacyRoutingWorkDiagnostics.Phase.Dispatch); clock.Timestamp += 440;
        work.Next(PrivacyRoutingWorkDiagnostics.Phase.Seal); clock.Timestamp += 550;
        work.Dispose(); work.Dispose();
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(new[] { "TotalMs", "BindingMs", "OpenMs", "ForwardMs", "DispatchMs", "SealMs" }, entry.Keys);
        Assert.Equal(new long[] { 1650, 110, 220, 330, 440, 550 }, entry.Values.Cast<long>());
    }

    [Fact]
    public void SuppressesFastWorkAndThrottlesSlowWorkForTenResourceSeconds()
    {
        var clock = new ResourceClock(); var logger = new RecordingLogger();
        var observer = new PrivacyRoutingWorkDiagnostics(logger, clock);
        using (observer.Begin()) clock.Timestamp += 999;
        Assert.Empty(logger.Entries);
        using (observer.Begin()) clock.Timestamp += 1000;
        using (observer.Begin()) clock.Timestamp += 1000;
        Assert.Single(logger.Entries);
        clock.Timestamp += 9000;
        using (observer.Begin()) clock.Timestamp += 1000;
        Assert.Equal(2, logger.Entries.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DisabledOrMissingSinkDoesNotAllocateWork(bool missing)
    {
        var logger = missing ? null : new RecordingLogger { Enabled = false };
        Assert.Null(new PrivacyRoutingWorkDiagnostics(logger).Begin());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SinkCannotReplaceOriginalFailure(bool enabledThrows)
    {
        var clock = new ResourceClock();
        var logger = new RecordingLogger { EnabledThrows = enabledThrows, LogThrows = true };
        var observer = new PrivacyRoutingWorkDiagnostics(logger, clock);
        var original = new OperationCanceledException();
        var actual = Assert.Throws<OperationCanceledException>((Action)(() =>
        {
            using var work = observer.Begin();
            clock.Timestamp += 2000;
            throw original;
        }));
        Assert.Same(original, actual);
    }

    [Fact]
    public void ResourceClockFailureCannotReplaceOriginalFailure()
    {
        var clock = new ResourceClock();
        var observer = new PrivacyRoutingWorkDiagnostics(new RecordingLogger(), clock);
        var original = new IOException();
        var actual = Assert.Throws<IOException>((Action)(() =>
        {
            using var work = observer.Begin();
            clock.Throws = true;
            work?.Next(PrivacyRoutingWorkDiagnostics.Phase.Open);
            throw original;
        }));
        Assert.Same(original, actual);
        Assert.Null(observer.Begin());
    }

    [Fact]
    public void ClampsExtremeResourceDuration()
    {
        var clock = new ResourceClock(); var logger = new RecordingLogger();
        using (new PrivacyRoutingWorkDiagnostics(logger, clock).Begin()) clock.Timestamp += 10_000_000;
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(3_600_000L, entry["TotalMs"]);
        Assert.Equal(3_600_000L, entry["BindingMs"]);
    }

    private sealed class ResourceClock : TimeProvider
    {
        internal long Timestamp;
        internal bool Throws;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Throws ? throw new IOException() : Timestamp;
    }

    private sealed class RecordingLogger : ILogger
    {
        internal bool Enabled = true;
        internal bool EnabledThrows;
        internal bool LogThrows;
        internal List<Dictionary<string, object?>> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => EnabledThrows ? throw new IOException() : Enabled;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (LogThrows) throw new IOException();
            Assert.Null(exception);
            var fields = Assert.IsAssignableFrom<IEnumerable<KeyValuePair<string, object?>>>(state);
            Entries.Add(fields.Where(field => field.Key != "{OriginalFormat}")
                .ToDictionary(field => field.Key, field => field.Value));
        }
    }
}
