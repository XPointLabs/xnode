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
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            { throw; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested)
            { return NativeMailboxDispatchResult.OutcomeUnknownAfterForward(); }
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
                return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
            }
        }
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
