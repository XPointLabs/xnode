using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace XNode;

// Optional resource observations only. Closed phase names, no identifiers,
// payloads, paths, authority time, activity context or outgoing trace headers.
internal static class CurrentMailboxDiagnostics
{
    internal const string MeterName = "XPoint.XNode.CurrentMailbox";
    private static readonly Meter Meter = new(MeterName);
    internal static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("phase.duration", "ms");

    internal static IDisposable? Measure(string phase) => Duration.Enabled ? new Measurement(phase) : null;

    private sealed class Measurement(string phase) : IDisposable
    {
        private readonly long started = Stopwatch.GetTimestamp();
        public void Dispose() => Duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds,
            new KeyValuePair<string, object?>("phase", phase));
    }
}
