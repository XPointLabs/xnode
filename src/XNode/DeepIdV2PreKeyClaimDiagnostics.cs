using System.Diagnostics;
using System.Security.Cryptography;

namespace XNode;

// Closed observations only. No request, identity, exception text/Data or trust
// decisions. A failed diagnostic sink must not alter the original outcome.
internal sealed class DeepIdV2PreKeyClaimDiagnostics(ILogger? logger)
{
    private long previous;
    internal void Report(string phase, Exception error)
    {
        if (logger is null) return;
        try
        {
            var now = Stopwatch.GetTimestamp(); var last = Volatile.Read(ref previous);
            if (last != 0 && Stopwatch.GetElapsedTime(last, now) < TimeSpan.FromSeconds(10) ||
                Interlocked.CompareExchange(ref previous, now, last) != last) return;
            phase = phase is "Terminal" or "Reservation" or "PeerReceive" ? phase : "Unclassified";
            for (var depth = 0; error is not null && depth < 3; depth++, error = error.InnerException!)
            {
                var category = error switch
                {
                    CryptographicException => "Cryptographic",
                    InvalidDataException => "InvalidData",
                    IOException => "Io",
                    OperationCanceledException => "Cancelled",
                    UnauthorizedAccessException => "Unauthorized",
                    InvalidOperationException => "InvalidOperation",
                    FormatException => "Format",
                    ArgumentException => "Argument",
                    _ => "Other"
                };
                var location = CurrentMailboxDiagnostics.FailureLocation(error);
                logger.LogWarning("DID2 claim incomplete: phase={Phase}; category={Category}; method={Method}; il={Il}; depth={Depth}; original custody retained.",
                    phase, category, location.Method, location.Il, depth);
            }
        }
        catch { /* Never change the original mutation/uncertainty result. */ }
    }
}
