namespace XNode;

// Resource-wall measurements only. This observer owns no request, identity,
// authority, cancellation or route, and cannot change a transport result.
internal sealed class PrivacyRoutingWorkDiagnostics(ILogger? logger, TimeProvider? timeProvider = null)
{
    internal enum Phase { Binding, Open, Forward, Dispatch, Seal }
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly object reportGate = new();
    private long? lastReport;

    internal Work? Begin()
    {
        try { return logger?.IsEnabled(LogLevel.Warning) == true ? new Work(this) : null; }
        catch { return null; }
    }

    private void Report(long started, long[] durations)
    {
        try
        {
            var now = clock.GetTimestamp();
            var total = Elapsed(started, now);
            if (total < 1000) return;
            lock (reportGate)
            {
                if (lastReport is { } previous && clock.GetElapsedTime(previous, now) < TimeSpan.FromSeconds(10)) return;
                lastReport = now;
            }
            logger?.LogWarning("ONION work: totalMs={TotalMs}; bindingMs={BindingMs}; openMs={OpenMs}; forwardMs={ForwardMs}; dispatchMs={DispatchMs}; sealMs={SealMs}.",
                total, durations[0], durations[1], durations[2], durations[3], durations[4]);
        }
        catch { /* Diagnostics never replace the original outcome or exception. */ }
    }

    private long Elapsed(long from, long until) =>
        Math.Clamp((long)clock.GetElapsedTime(from, until).TotalMilliseconds, 0, 3_600_000);

    internal sealed class Work : IDisposable
    {
        private readonly PrivacyRoutingWorkDiagnostics owner;
        private readonly long started;
        private readonly long[] durations = new long[5];
        private long phaseStarted;
        private Phase phase;
        private int disposed;

        internal Work(PrivacyRoutingWorkDiagnostics owner)
        {
            this.owner = owner;
            started = phaseStarted = owner.clock.GetTimestamp();
        }

        internal void Next(Phase next)
        {
            if (Volatile.Read(ref disposed) != 0) return;
            try
            {
                var now = owner.clock.GetTimestamp();
                durations[(int)phase] = Math.Min(3_600_000, durations[(int)phase] + owner.Elapsed(phaseStarted, now));
                phaseStarted = now;
                phase = next;
            }
            catch { /* Resource clock failure has no authority. */ }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            try
            {
                var now = owner.clock.GetTimestamp();
                durations[(int)phase] = Math.Min(3_600_000, durations[(int)phase] + owner.Elapsed(phaseStarted, now));
                owner.Report(started, durations);
            }
            catch { /* Resource clock failure cannot change the original outcome. */ }
        }
    }
}
