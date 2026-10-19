using System.Diagnostics;
using System.Security.Cryptography;

namespace XNode;

// Diagnostic phase is local execution state, never a route/identity/payload.
internal sealed class PrivacyRoutingFailureDiagnostics(ILogger? logger)
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
            phase = phase is "Binding" or "Open" or "Forward" or "Dispatch" or "Seal" or "ContactAdmission" ? phase : "Unclassified";
            for (var depth = 0; error is not null && depth < 3; depth++, error = error.InnerException!)
            {
                var category = error switch
                {
                    CryptographicException => "Cryptographic", InvalidDataException => "InvalidData",
                    IOException => "Io", OperationCanceledException => "Cancelled",
                    UnauthorizedAccessException => "Unauthorized", InvalidOperationException => "InvalidOperation",
                    _ => "Other"
                };
                var location = CurrentMailboxDiagnostics.FailureLocation(error);
                object authorityCheck = error switch
                {
                    GroupControlAuthorityUnavailableException group => group.Rejection,
                    ContactAdmissionIntervalException contact => contact.Rejection,
                    _ => GroupControlAuthorityRejection.Unclassified
                };
                logger.LogWarning("ONION processing incomplete: phase={Phase}; category={Category}; method={Method}; il={Il}; depth={Depth}; authorityCheck={AuthorityCheck}.",
                    phase, category, location.Method, location.Il, depth, authorityCheck);
            }
        }
        catch { /* Observations never change the original transport outcome. */ }
    }
}
