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
    private static readonly AsyncLocal<Work?> CurrentWork = new();

    internal static IDisposable? Measure(string phase) => Duration.Enabled || CurrentWork.Value is not null
        ? new Measurement(phase, CurrentWork.Value) : null;

    internal static IDisposable BeginWork(Action<WorkSummary> report) => new Work(report);
    internal sealed record WorkSummary(long LeaseChecks, long LeaseMs, long AuthorityMs,
        long HostMs, long GrantMs, long NativeJoinMs, long RevocationMs, long OperationMs,
        long LineageMs, long SourceFilesMs, long FloorMs, long ProofObserveMs, long NetworkVerifyMs);

    private sealed class Work : IDisposable
    {
        private readonly Work? parent = CurrentWork.Value;
        private readonly Action<WorkSummary> report;
        private readonly object gate = new();
        private long checks, lease, authority, host, grant, native, revocation, operation;
        private long lineage, sourceFiles, floor, proofObserve, networkVerify;
        private bool disposed;
        internal Work(Action<WorkSummary> report) { this.report = report; CurrentWork.Value = this; }
        internal void Record(string phase, double ms)
        {
            lock (gate)
            {
                if (disposed) return;
                var elapsed = Math.Clamp((long)ms, 0, 3600000);
                switch (phase)
                {
                    case "lease-check": checks++; lease += elapsed; break;
                    case "authority-source": authority += elapsed; break;
                    case "authority-lineage": lineage += elapsed; break;
                    case "network-source-files": sourceFiles += elapsed; break;
                    case "network-floor-read" or "network-floor-readback": floor += elapsed; break;
                    case "proof-observe": proofObserve += elapsed; break;
                    case "network-verify": networkVerify += elapsed; break;
                    case "host-verify": host += elapsed; break;
                    case "grant-context-check": grant += elapsed; break;
                    case "peer-replay-join" or "peer-native-join": native += elapsed; break;
                    case "revocation-decode" or "revocation-file-read" or "revocation-floor-read" or
                        "revocation-path-check" or "revocation-security-check" or "revocation-unprotect": revocation += elapsed; break;
                    case "operation-commit" or "operation-prepare" or "operation-verify": operation += elapsed; break;
                }
            }
        }
        public void Dispose()
        {
            WorkSummary result;
            lock (gate)
            {
                if (disposed) return;
                disposed = true;
                result = new(checks, lease, authority, host, grant, native, revocation, operation,
                    lineage, sourceFiles, floor, proofObserve, networkVerify);
            }
            if (ReferenceEquals(CurrentWork.Value, this)) CurrentWork.Value = parent;
            try { report(result); } catch { /* Timing never replaces the original outcome. */ }
        }
    }

    internal static string AuthorityFailureCheck(Exception? error)
    {
        if (error?.GetType() == typeof(Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxPeerReplicationException))
            return error.Data["Deep.MailboxPeer.Forwarding.Check"] is string peer &&
                peer is "OriginRole" or "OriginAdmission" or "DurabilityOrder" or "ObjectExpiry" or "DurableFuture"
                ? peer : "Unclassified";
        // Only the built-in exception getter and an existing finite Protocol
        // diagnostic label. Never invoke subclass getters or stringify values.
        if (error?.GetType() != typeof(System.Security.Cryptography.CryptographicException)) return "Unclassified";
        return error.Data["Deep.MailboxAuthority.Check"] is string value && value is
            "Lifecycle" or "Network" or "Generation" or "IssuerKey" or "IssuerNotBefore" or "GrantNotBefore" or
            "GrantExpiry" or "PolicyExpiry" or "NetworkExpiry" or "Lifetime" or "Signature" ? value : "Unclassified";
    }

    internal static InvalidDataException MutationRejection(string? error)
    {
        // Informative local metadata only; never propagate the supplied text.
        var label = error switch
        {
            "mailbox-peer-store-context-conflict" => "StoreContext",
            "mailbox-peer-tombstone-context-conflict" => "TombstoneContext",
            "mailbox-peer-expiry-overflow" => "ExpiryOverflow",
            "invalid-mailbox-blob" => "InvalidBlob",
            "mailbox-blob-size-rejected" => "BlobSize",
            "mailbox-ciphertext-not-canonical" => "CiphertextCanonical",
            "mailbox-blob-ttl-rejected" => "BlobTtl",
            "mailbox-blob-digest-mismatch" => "BlobDigest",
            "mailbox-storage-corrupt" => "StorageCorrupt",
            "mailbox-blob-id-conflict" => "BlobConflict",
            "mailbox-capacity-exhausted" => "Capacity",
            _ => "Unclassified"
        };
        var result = new InvalidDataException("Current peer durable mutation was rejected.");
        result.Data["Deep.MailboxMutation.Check"] = label;
        return result;
    }

    internal static string MutationFailureCheck(Exception? error)
    {
        if (error?.GetType() != typeof(InvalidDataException)) return "Unclassified";
        return error.Data["Deep.MailboxMutation.Check"] is string value && value is
            "StoreContext" or "TombstoneContext" or "ExpiryOverflow" or "InvalidBlob" or "BlobSize" or
            "CiphertextCanonical" or "BlobTtl" or "BlobDigest" or "StorageCorrupt" or "BlobConflict" or "Capacity"
            ? value : "Unclassified";
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

    private sealed class Measurement(string phase, Work? work) : IDisposable
    {
        private readonly long started = Stopwatch.GetTimestamp();
        public void Dispose()
        {
            var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            work?.Record(phase, elapsed);
            if (Duration.Enabled) Duration.Record(elapsed, new KeyValuePair<string, object?>("phase", phase));
        }
    }
}
