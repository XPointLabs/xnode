namespace XNode;

// Per-call scheduling measurements only. No authority, resource identity,
// exception, cancellation source or request is retained by this observer.
internal sealed class CurrentMailboxNetworkReadTiming(Action<CurrentMailboxNetworkReadTiming.Result> report,
    TimeProvider? timeProvider = null) : IDisposable
{
    internal enum Phase { GateWait, FloorRead, ProofAcquire, AuthorityRead, ProofObserve,
        SourceRead, NetworkVerify, ContextReuse, MailboxVerify, FloorCommit, FloorReadback,
        SourceReadback, MailboxReadback, ProofReadback }
    internal sealed record Result(long TotalMs, Phase Slowest, long SlowestMs,
        long GateWaitMs, long ProofAcquireMs, long NetworkVerifyMs);
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private readonly long started = (timeProvider ?? TimeProvider.System).GetTimestamp();
    private readonly long[] durations = new long[Enum.GetValues<Phase>().Length];
    private int disposed;

    internal IDisposable Measure(Phase phase) => new Measurement(this, phase, clock.GetTimestamp());
    private long Elapsed(long stamp) => Math.Clamp((long)clock.GetElapsedTime(stamp).TotalMilliseconds, 0, 3_600_000);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        try
        {
            var slowest = 0;
            for (var i = 1; i < durations.Length; i++)
                if (durations[i] > durations[slowest]) slowest = i;
            report(new(Elapsed(started), (Phase)slowest, durations[slowest],
                durations[(int)Phase.GateWait], durations[(int)Phase.ProofAcquire], durations[(int)Phase.NetworkVerify]));
        }
        catch { /* Optional diagnostics cannot alter an original result or failure. */ }
    }
    private sealed class Measurement(CurrentMailboxNetworkReadTiming owner, Phase phase, long started) : IDisposable
    {
        private int disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0)
                owner.durations[(int)phase] = Math.Min(3_600_000, owner.durations[(int)phase] + owner.Elapsed(started));
        }
    }
}
