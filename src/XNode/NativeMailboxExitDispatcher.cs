using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

public enum NativeMailboxDispatchCertainty
{
    Completed = 0,
    RejectedBeforeForward = 1,
    OutcomeUnknownAfterForward = 2
}

public sealed record NativeMailboxDispatchResult(
    int StatusCode,
    ReadOnlyMemory<byte> CanonicalBody,
    NativeMailboxDispatchCertainty Certainty = NativeMailboxDispatchCertainty.Completed)
{
    public bool Success => Certainty == NativeMailboxDispatchCertainty.Completed
        && StatusCode == StatusCodes.Status200OK;
    public static NativeMailboxDispatchResult RejectedBeforeForward() => new(
        StatusCodes.Status503ServiceUnavailable, ReadOnlyMemory<byte>.Empty,
        NativeMailboxDispatchCertainty.RejectedBeforeForward);
    public static NativeMailboxDispatchResult OutcomeUnknownAfterForward() => new(
        StatusCodes.Status504GatewayTimeout, ReadOnlyMemory<byte>.Empty,
        NativeMailboxDispatchCertainty.OutcomeUnknownAfterForward);
}

public interface INativeMailboxExitDispatcher
{
    Task<NativeMailboxDispatchResult> DispatchAsync(
        VerifiedCanonicalOnionRequest request, CancellationToken cancellationToken);
}

public interface ILocalNativeMailboxExitDispatcher
{
    Task<NativeMailboxDispatchResult> DispatchAsync(OnionOperation privacyOperation,
        ReadOnlyMemory<byte> canonicalMau3, CancellationToken cancellationToken);
}

/// <summary>ONION terminal ingress into the actual current native owners.
/// Missing current composition is unavailable, never a retired adapter fallback.
/// Program activation remains fenced by the independent lifecycle requirements.</summary>
public sealed class NativeMailboxExitDispatcher(IServiceProvider services)
    : INativeMailboxExitDispatcher, ILocalNativeMailboxExitDispatcher
{
    // Resource budgeting only, never authorization time or a replay floor.
    private readonly MailboxClientIngressLimiter limiter = new();
    private long failureLogTimestamp;
    private long workLogTimestamp;

    public Task<NativeMailboxDispatchResult> DispatchAsync(
        VerifiedCanonicalOnionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return DispatchCoreAsync(request.Operation, request.CanonicalBytes, cancellationToken);
    }
    Task<NativeMailboxDispatchResult> ILocalNativeMailboxExitDispatcher.DispatchAsync(
        OnionOperation privacyOperation, ReadOnlyMemory<byte> canonicalMau3,
        CancellationToken cancellationToken) =>
        DispatchCoreAsync(privacyOperation, canonicalMau3, cancellationToken);

    private async Task<NativeMailboxDispatchResult> DispatchCoreAsync(OnionOperation privacyOperation,
        ReadOnlyMemory<byte> canonicalMau3, CancellationToken cancellationToken)
    {
        using var work = CurrentMailboxDiagnostics.BeginWork(ReportWork);
        (MailboxAuthenticatedOperation operation, MailboxHttpEndpointContract contract) = privacyOperation switch
        {
            OnionOperation.Store => (MailboxAuthenticatedOperation.Store, MailboxWireHttpContract.Store),
            OnionOperation.Retrieve => (MailboxAuthenticatedOperation.Retrieve, MailboxWireHttpContract.Retrieve),
            OnionOperation.Acknowledge => (MailboxAuthenticatedOperation.Ack, MailboxWireHttpContract.Acknowledge),
            _ => throw new ArgumentOutOfRangeException(nameof(privacyOperation))
        };
        cancellationToken.ThrowIfCancellationRequested();
        if (canonicalMau3.Length < contract.MinimumRequestBytes)
            return Failure(MailboxHttpFailure.MalformedCanonicalBody);
        if (canonicalMau3.Length > contract.MaximumRequestBytes)
            return Failure(MailboxHttpFailure.PayloadTooLarge);
        if (!limiter.TryEnter(contract, checked((ulong)(Stopwatch.GetTimestamp() / Stopwatch.Frequency)), out var lease))
            return Failure(MailboxHttpFailure.RateOrConcurrencyExceeded);

        using (lease)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(contract.RequestTimeoutSeconds));
            // Capture before dependency callbacks. Unknown versions and outer
            // mismatches consume ingress budget, but cannot touch native owners.
            var captured = canonicalMau3.ToArray();
            try
            {
                if (MailboxAuthenticatedClientRequestCodec.Decode(captured).Binding.Operation != operation)
                    return Failure(MailboxHttpFailure.MalformedCanonicalBody);
            }
            catch (MailboxAuthenticatedCapabilityException)
            { return Failure(MailboxHttpFailure.MalformedCanonicalBody); }

            try
            {
                var receiver = services.GetService<CurrentMailboxReplicaReceiver>();
                var coordinator = services.GetService<CurrentMailboxReplicationCoordinator>();
                if (receiver is null || coordinator is null)
                    return NativeMailboxDispatchResult.RejectedBeforeForward();
                coordinator.RequireReceiver(receiver);
                deadline.Token.ThrowIfCancellationRequested();
                switch (operation)
                {
                    case MailboxAuthenticatedOperation.Store:
                    {
                        var result = await coordinator.StoreClientAsync(captured, deadline.Token).ConfigureAwait(false);
                        if (result.Status != MailboxPeerQuorumStatus.Durable) ReportUnknown("quorum", null);
                        return result.Status == MailboxPeerQuorumStatus.Durable
                            ? Success(result.CanonicalMqr3) : NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
                    }
                    case MailboxAuthenticatedOperation.Retrieve:
                        return Success(await receiver.RetrieveClientAsync(captured, deadline.Token).ConfigureAwait(false));
                    case MailboxAuthenticatedOperation.Ack:
                        return Success(await coordinator.AcknowledgeClientAsync(captured, deadline.Token).ConfigureAwait(false));
                    default:
                        throw new InvalidOperationException("Unsupported current mailbox operation.");
                }
            }
            catch (CurrentMailboxHolderRateLimitException)
            { return Failure(MailboxHttpFailure.RateOrConcurrencyExceeded); }
            catch (MailboxAuthenticatedCapabilityException error)
            { return Failure(AuthenticatedFailure(error.Error)); }
            catch (OperationCanceledException error) when (cancellationToken.IsCancellationRequested)
            { ReportUnknown("caller-cancelled", error); throw; }
            catch (OperationCanceledException error) when (deadline.IsCancellationRequested)
            { ReportUnknown("native-deadline", error); return NativeMailboxDispatchResult.OutcomeUnknownAfterForward(); }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException
                or InvalidOperationException or ArgumentException or OverflowException or CryptographicException
                or MailboxPeerReplicationException or MailboxGrantRevocationFloorException
                or MailboxPeerReplayCapacityException or MailboxPeerMutationCapacityException or MailboxClientLedgerCapacityException
                or MailboxClientOperationConflictException
                or MailboxClientException or MailboxClientCanonicalOutcomePersistenceException
                or MailboxClientCanonicalOutcomeCapacityException or MailboxClientCanonicalOutcomeConflictException
                or MailboxClientCanonicalOutcomeMissingException)
            {
                // Callbacks can fail after either store committed. An exception
                // never proves absence of effects or permits a replacement send.
                ReportUnknown("native-failure", error);
                return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
            }
        }
    }

    private void ReportWork(CurrentMailboxDiagnostics.WorkSummary work)
    {
        try
        {
            var logger = services.GetService<ILogger<NativeMailboxExitDispatcher>>();
            if (logger is null || !logger.IsEnabled(LogLevel.Warning) || work.LeaseMs < 1000) return;
            var now = Stopwatch.GetTimestamp(); var last = Volatile.Read(ref workLogTimestamp);
            if (last != 0 && Stopwatch.GetElapsedTime(last, now) < TimeSpan.FromSeconds(10) ||
                Interlocked.CompareExchange(ref workLogTimestamp, now, last) != last) return;
            logger.LogWarning("Current mailbox work: leaseChecks={LeaseChecks}; leaseMs={LeaseMs}; authorityMs={AuthorityMs}; hostMs={HostMs}; grantMs={GrantMs}; nativeJoinMs={NativeJoinMs}; revocationMs={RevocationMs}; operationMs={OperationMs}.",
                work.LeaseChecks, work.LeaseMs, work.AuthorityMs, work.HostMs, work.GrantMs,
                work.NativeJoinMs, work.RevocationMs, work.OperationMs);
            logger.LogWarning("Current mailbox authority work: lineageMs={Lineage}; sourceFilesMs={SourceFiles}; floorMs={Floor}; proofObserveMs={ProofObserve}; networkVerifyMs={NetworkVerify}; gateMs={Gate}; policyMs={Policy}.",
                work.LineageMs, work.SourceFilesMs, work.FloorMs, work.ProofObserveMs, work.NetworkVerifyMs, work.NetworkGateMs, work.MailboxPolicyMs);
        }
        catch { /* Resource observation cannot change the native result. */ }
    }

    private void ReportUnknown(string stage, Exception? error)
    {
        // Diagnostic scheduling only. No raw exception, Message/Data/ToString,
        // request, route, holder, payload, path or authority time enters logging.
        // In particular an absent/broken logger cannot change cancellation or
        // the original uncertain result. At most one event per actual10s.
        try
        {
            var logger = services.GetService<ILogger<NativeMailboxExitDispatcher>>();
            if (logger is null || !logger.IsEnabled(LogLevel.Warning)) return;
            var previous = Volatile.Read(ref failureLogTimestamp);
            if (previous != 0 && Stopwatch.GetElapsedTime(previous) < TimeSpan.FromSeconds(10)) return;
            if (Interlocked.CompareExchange(ref failureLogTimestamp, Stopwatch.GetTimestamp(), previous) != previous) return;
            var cause = error; var depth = 0;
            while (depth < 3 && cause?.InnerException is { } inner) { cause = inner; depth++; }
            var category = cause switch
            {
                null => "quorum-not-durable",
                OperationCanceledException => "cancelled", TimeoutException => "timeout",
                MailboxGrantRevocationFloorException => "revocation-floor",
                CryptographicException => "cryptographic-rejection",
                MailboxClientOperationConflictException => "operation-conflict",
                MailboxClientCanonicalOutcomeMissingException => "outcome-missing",
                MailboxClientCanonicalOutcomeConflictException => "outcome-conflict",
                MailboxClientCanonicalOutcomePersistenceException => "outcome-persistence",
                MailboxClientCanonicalOutcomeCapacityException => "outcome-capacity",
                MailboxClientLedgerCapacityException => "ledger-capacity",
                MailboxPeerReplicationException => "peer-replication",
                MailboxPeerReplayCapacityException or MailboxPeerMutationCapacityException => "peer-capacity",
                MailboxClientException => "mailbox-codec",
                UnauthorizedAccessException => "authorization-rejection",
                IOException => "custody-or-io",
                _ => "configuration-or-state"
            };
            var location = CurrentMailboxDiagnostics.FailureLocation(cause);
            logger.LogWarning("Current mailbox terminal incomplete: stage={Stage}; kind={Kind}; depth={Depth}; method={CodeMethod}; il={Il}; mutationCheck={MutationCheck}; authorityCheck={AuthorityCheck}; completion remains unknown.",
                stage, category, depth, location.Method, location.Il, CurrentMailboxDiagnostics.MutationFailureCheck(cause),
                CurrentMailboxDiagnostics.AuthorityFailureCheck(cause));
        }
        catch { /* Observations cannot replace the original result/exception. */ }
    }

    private static NativeMailboxDispatchResult Success(ReadOnlyMemory<byte> bytes) =>
        new(StatusCodes.Status200OK, bytes);
    private static NativeMailboxDispatchResult Failure(MailboxHttpFailure failure) =>
        new(MailboxWireHttpContract.StatusCode(failure), ReadOnlyMemory<byte>.Empty);
    private static MailboxHttpFailure AuthenticatedFailure(MailboxAuthenticatedCapabilityError error) => error switch
    {
        MailboxAuthenticatedCapabilityError.InvalidIssuerSignature or
        MailboxAuthenticatedCapabilityError.InvalidHolderSignature => MailboxHttpFailure.AuthenticationFailed,
        MailboxAuthenticatedCapabilityError.UntrustedIssuer or
        MailboxAuthenticatedCapabilityError.Revoked or
        MailboxAuthenticatedCapabilityError.GenerationRejected => MailboxHttpFailure.AuthorizationFailed,
        MailboxAuthenticatedCapabilityError.OutsideValidityWindow => MailboxHttpFailure.ExpiredOrStale,
        MailboxAuthenticatedCapabilityError.ReplayRejected or
        MailboxAuthenticatedCapabilityError.ReplayConflict => MailboxHttpFailure.ReplayOrIdempotencyConflict,
        MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation => MailboxHttpFailure.DependencyUnavailable,
        _ => MailboxHttpFailure.MalformedCanonicalBody
    };
}
