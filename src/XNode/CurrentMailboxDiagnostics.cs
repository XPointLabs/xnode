using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace XNode;

// Optional resource/failure observations only. Closed phase names, no identifiers,
// payloads, paths, authority time, activity context or outgoing trace headers.
internal static class CurrentMailboxDiagnostics
{
    internal const string MeterName = "XPoint.XNode.CurrentMailbox";
    private static readonly Meter Meter = new(MeterName);
    internal static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("phase.duration", "ms");

    internal static IDisposable? Measure(string phase) => Duration.Enabled ? new Measurement(phase) : null;

    internal static string AuthorityFailureCheck(Exception? error)
    {
        // Only the built-in exception getter and an existing finite Protocol
        // diagnostic label. Never invoke subclass getters or stringify values.
        if (error?.GetType() != typeof(System.Security.Cryptography.CryptographicException)) return "Unclassified";
        return error.Data["Deep.MailboxAuthority.Check"] is string value && value is
            "Lifecycle" or "Network" or "Generation" or "IssuerKey" or "IssuerNotBefore" or "GrantNotBefore" or
            "GrantExpiry" or "PolicyExpiry" or "NetworkExpiry" or "Lifetime" or "Signature" ? value : "Unclassified";
    }

    // Only owned code metadata, never exception text/data, source filenames or
    // caller/third-party type names. Callers keep logging failures non-fatal.
    internal static (string Method, int Il) FailureLocation(Exception? error)
    {
        if (error is null) return ("unavailable", -1);
        var trace = new StackTrace(error, false);
        for (var index = 0; index < Math.Min(trace.FrameCount, 32); index++)
        {
            var frame = trace.GetFrame(index); var method = frame?.GetMethod(); var type = method?.DeclaringType;
            var assembly = type?.Assembly.GetName().Name;
            if (assembly is not ("XNode" or "XNode.Core" or "Deep.Protocol" or "Deep.Protocol.MembershipRoutes")) continue;
            var origin = (type!.DeclaringType is { } parent ? parent.Name + "+" : "") + type.Name + "." + method!.Name;
            if (origin.Length is > 0 and <= 240 && origin.All(ch => char.IsAsciiLetterOrDigit(ch) || "_.+<>`".Contains(ch)))
                return (origin, Math.Clamp(frame!.GetILOffset(), -1, 1048575));
        }
        return ("unavailable", -1);
    }

    private sealed class Measurement(string phase) : IDisposable
    {
        private readonly long started = Stopwatch.GetTimestamp();
        public void Dispose() => Duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds,
            new KeyValuePair<string, object?>("phase", phase));
    }
}
