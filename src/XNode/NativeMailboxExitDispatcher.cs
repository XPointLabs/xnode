using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core;
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
    public bool Success =>
        Certainty == NativeMailboxDispatchCertainty.Completed
        && StatusCode == StatusCodes.Status200OK;

    public static NativeMailboxDispatchResult RejectedBeforeForward() => new(
        StatusCodes.Status503ServiceUnavailable,
        ReadOnlyMemory<byte>.Empty,
        NativeMailboxDispatchCertainty.RejectedBeforeForward);

    public static NativeMailboxDispatchResult OutcomeUnknownAfterForward() => new(
        StatusCodes.Status504GatewayTimeout,
        ReadOnlyMemory<byte>.Empty,
        NativeMailboxDispatchCertainty.OutcomeUnknownAfterForward);
}

public interface INativeMailboxExitDispatcher
{
    Task<NativeMailboxDispatchResult> DispatchAsync(
        PrivacyRoutingOperation privacyOperation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken);
}

public interface ILocalNativeMailboxExitDispatcher
{
    Task<NativeMailboxDispatchResult> DispatchAsync(
        PrivacyRoutingOperation privacyOperation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken);
}

public sealed class NativeMailboxExitDispatcher
    : INativeMailboxExitDispatcher,
      ILocalNativeMailboxExitDispatcher
{
    private readonly IServiceProvider _services;

    public NativeMailboxExitDispatcher(IServiceProvider services)
    {
        _services = services;
    }

    public async Task<NativeMailboxDispatchResult> DispatchAsync(
        PrivacyRoutingOperation privacyOperation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken)
    {
        (MailboxAuthenticatedOperation operation, MailboxHttpEndpointContract contract) =
            privacyOperation switch
        {
            PrivacyRoutingOperation.Store =>
                (MailboxAuthenticatedOperation.Store, MailboxWireHttpContract.Store),
            PrivacyRoutingOperation.Retrieve =>
                (MailboxAuthenticatedOperation.Retrieve, MailboxWireHttpContract.Retrieve),
            PrivacyRoutingOperation.Acknowledge =>
                (MailboxAuthenticatedOperation.Ack, MailboxWireHttpContract.Acknowledge),
            _ => throw new ArgumentOutOfRangeException(nameof(privacyOperation))
        };

        var readiness = _services.GetRequiredService<MailboxClientRuntimeReadiness>();
        if (!readiness.Ready)
        {
            return Failure(MailboxHttpFailure.DependencyUnavailable);
        }

        if (canonicalMau2.Length < contract.MinimumRequestBytes)
        {
            return Failure(MailboxHttpFailure.MalformedCanonicalBody);
        }

        if (canonicalMau2.Length > contract.MaximumRequestBytes)
        {
            return Failure(MailboxHttpFailure.PayloadTooLarge);
        }

        var clock = _services.GetRequiredService<IClock>();
        var limiter = _services.GetRequiredService<MailboxClientIngressLimiter>();
        if (!limiter.TryEnter(
                contract,
                checked((ulong)clock.UtcNow.ToUnixTimeSeconds()),
                out var lease))
        {
            return Failure(MailboxHttpFailure.RateOrConcurrencyExceeded);
        }

        using (lease)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(contract.RequestTimeoutSeconds));
            MailboxAuthenticatedRuntimeReservation? authenticated = null;
            try
            {
                var runtime = _services.GetRequiredService<
                    MailboxAuthenticatedCapabilityRuntime>();
                try
                {
                    authenticated = runtime.Verify(canonicalMau2);
                }
                catch (MailboxAuthenticatedCapabilityException exception)
                {
                    return Failure(AuthenticatedFailure(exception.Error));
                }

                if (authenticated.Verified.Binding.Operation != operation)
                {
                    return Failure(MailboxHttpFailure.MalformedCanonicalBody);
                }

                var holderLimiter = _services.GetRequiredService<
                    MailboxClientVerifiedHolderLimiter>();
                if (!holderLimiter.TryAccept(
                        authenticated.Verified.Capability.Grant.HolderPublicKey.Span,
                        operation,
                        checked((ulong)clock.UtcNow.ToUnixTimeSeconds())))
                {
                    return Failure(MailboxHttpFailure.RateOrConcurrencyExceeded);
                }

                if (authenticated.RecoveredOutcome is not null)
                {
                    return MapRecoveredOutcome(authenticated.RecoveredOutcome);
                }

                if (!runtime.TryAcquireExecution(authenticated))
                {
                    return Failure(MailboxHttpFailure.DependencyUnavailable);
                }

                runtime.ReserveOutcomeCapacity(
                    authenticated,
                    contract.MaximumResponseBytes);
                var adapter = _services.GetRequiredService<MailboxClientStoreAdapter>();
                switch (operation)
                {
                    case MailboxAuthenticatedOperation.Store:
                    {
                        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(
                            authenticated.Verified.Binding.CanonicalRequest.Span);
                        var result = await adapter.StoreVerifiedAsync(
                            authenticated,
                            envelope,
                            deadline.Token);
                        if (result.Status == MailboxClientStoreStatus.Durable)
                        {
                            return MapRecoveredOutcome(runtime.PersistSuccess(
                                authenticated,
                                result.DurableQuorumReceipt,
                                contract.MaximumResponseBytes));
                        }

                        return CompleteStoreFailure(runtime, authenticated, result);
                    }
                    case MailboxAuthenticatedOperation.Retrieve:
                    {
                        var retrieve = MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                            authenticated.Verified.Binding.CanonicalRequest.Span);
                        var result = await adapter.RetrieveVerifiedAsync(
                            authenticated,
                            retrieve,
                            deadline.Token);
                        if (result.Status == MailboxClientRetrieveStatus.Success)
                        {
                            return MapRecoveredOutcome(runtime.PersistSuccess(
                                authenticated,
                                result.CanonicalPage,
                                contract.MaximumResponseBytes));
                        }

                        return CompleteRetrieveFailure(runtime, authenticated, result);
                    }
                    case MailboxAuthenticatedOperation.Ack:
                    {
                        var acknowledge =
                            MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                                authenticated.Verified.Binding.CanonicalRequest.Span);
                        var result = await adapter.AcknowledgeVerifiedAsync(
                            authenticated,
                            acknowledge,
                            deadline.Token);
                        if (result.Status == MailboxClientAckStatus.Durable)
                        {
                            var response = MailboxAggregateAckCodec.EncodeMqr3(
                                new MailboxAggregateAckResponse
                                {
                                    Epoch = acknowledge.Epoch,
                                    OperationId = acknowledge.OperationId.ToArray(),
                                    TombstoneQuorums = result.Receipts
                                        .Select(static receipt =>
                                            (ReadOnlyMemory<byte>)receipt
                                                .DurableQuorumReceipt.ToArray())
                                        .ToArray()
                                });
                            return MapRecoveredOutcome(runtime.PersistSuccess(
                                authenticated,
                                response,
                                contract.MaximumResponseBytes));
                        }

                        return CompleteAckFailure(runtime, authenticated, result);
                    }
                    default:
                        return Failure(MailboxHttpFailure.MalformedCanonicalBody);
                }
            }
            catch (EndOfStreamException)
            {
                return Failure(MailboxHttpFailure.MalformedCanonicalBody);
            }
            catch (MailboxAuthenticatedCapabilityException)
            {
                return Failure(MailboxHttpFailure.MalformedCanonicalBody);
            }
            catch (OperationCanceledException) when (
                deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                return Failure(MailboxHttpFailure.DeadlineExceeded);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or ArgumentException or OverflowException
                    or InvalidDataException or UnauthorizedAccessException
                    or InvalidOperationException or MailboxPeerReplicationException
                    or MailboxClientCanonicalOutcomePersistenceException
                    or MailboxClientCanonicalOutcomeCapacityException
                    or MailboxClientCanonicalOutcomeConflictException
                    or MailboxClientCanonicalOutcomeMissingException)
            {
                return Failure(MailboxHttpFailure.DependencyUnavailable);
            }
            finally
            {
                if (authenticated is not null)
                {
                    _services.GetRequiredService<MailboxAuthenticatedCapabilityRuntime>()
                        .CleanupRequest(authenticated);
                }
            }
        }
    }

    private static NativeMailboxDispatchResult CompleteStoreFailure(
        MailboxAuthenticatedCapabilityRuntime runtime,
        MailboxAuthenticatedRuntimeReservation authenticated,
        MailboxClientStoreResult result)
    {
        switch (result.Status)
        {
            case MailboxClientStoreStatus.Unauthorized:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.AuthorizationRejected);
                return Failure(MailboxHttpFailure.AuthorizationFailed);
            case MailboxClientStoreStatus.Conflict:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.OperationConflict);
                return Failure(MailboxHttpFailure.ReplayOrIdempotencyConflict);
            case MailboxClientStoreStatus.Malformed:
            case MailboxClientStoreStatus.Rejected:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.DurableStateRejected);
                return Failure(MailboxHttpFailure.DependencyUnavailable);
            default:
                return Failure(MailboxHttpFailure.DependencyUnavailable);
        }
    }

    private static NativeMailboxDispatchResult CompleteRetrieveFailure(
        MailboxAuthenticatedCapabilityRuntime runtime,
        MailboxAuthenticatedRuntimeReservation authenticated,
        MailboxClientRetrieveResult result)
    {
        switch (result.Status)
        {
            case MailboxClientRetrieveStatus.Unauthorized:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.AuthorizationRejected);
                return Failure(MailboxHttpFailure.AuthorizationFailed);
            case MailboxClientRetrieveStatus.Malformed:
            case MailboxClientRetrieveStatus.Rejected:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.DurableStateRejected);
                return Failure(MailboxHttpFailure.DependencyUnavailable);
            default:
                return Failure(MailboxHttpFailure.DependencyUnavailable);
        }
    }

    private static NativeMailboxDispatchResult CompleteAckFailure(
        MailboxAuthenticatedCapabilityRuntime runtime,
        MailboxAuthenticatedRuntimeReservation authenticated,
        MailboxClientAckResult result)
    {
        switch (result.Status)
        {
            case MailboxClientAckStatus.Unauthorized:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.AuthorizationRejected);
                return Failure(MailboxHttpFailure.AuthorizationFailed);
            case MailboxClientAckStatus.Conflict:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.OperationConflict);
                return Failure(MailboxHttpFailure.ReplayOrIdempotencyConflict);
            case MailboxClientAckStatus.Malformed:
            case MailboxClientAckStatus.Rejected:
                runtime.PersistTerminal(authenticated,
                    MailboxClientTerminalOutcome.DurableStateRejected);
                return Failure(MailboxHttpFailure.DependencyUnavailable);
            default:
                return Failure(MailboxHttpFailure.DependencyUnavailable);
        }
    }

    private static NativeMailboxDispatchResult MapRecoveredOutcome(
        MailboxClientCanonicalOutcome outcome)
    {
        if (outcome.Kind == MailboxClientCanonicalOutcomeKind.Success)
        {
            return new NativeMailboxDispatchResult(
                StatusCodes.Status200OK,
                outcome.CanonicalBytes);
        }

        return Failure(outcome.Terminal switch
        {
            MailboxClientTerminalOutcome.AuthorizationRejected =>
                MailboxHttpFailure.AuthorizationFailed,
            MailboxClientTerminalOutcome.OperationConflict =>
                MailboxHttpFailure.ReplayOrIdempotencyConflict,
            _ => MailboxHttpFailure.DependencyUnavailable
        });
    }

    private static MailboxHttpFailure AuthenticatedFailure(
        MailboxAuthenticatedCapabilityError error) => error switch
        {
            MailboxAuthenticatedCapabilityError.InvalidIssuerSignature or
            MailboxAuthenticatedCapabilityError.InvalidHolderSignature =>
                MailboxHttpFailure.AuthenticationFailed,
            MailboxAuthenticatedCapabilityError.UntrustedIssuer or
            MailboxAuthenticatedCapabilityError.Revoked or
            MailboxAuthenticatedCapabilityError.GenerationRejected =>
                MailboxHttpFailure.AuthorizationFailed,
            MailboxAuthenticatedCapabilityError.OutsideValidityWindow =>
                MailboxHttpFailure.ExpiredOrStale,
            MailboxAuthenticatedCapabilityError.ReplayRejected or
            MailboxAuthenticatedCapabilityError.ReplayConflict =>
                MailboxHttpFailure.ReplayOrIdempotencyConflict,
            MailboxAuthenticatedCapabilityError.InvalidReplayEvaluation =>
                MailboxHttpFailure.DependencyUnavailable,
            _ => MailboxHttpFailure.MalformedCanonicalBody
        };

    private static NativeMailboxDispatchResult Failure(MailboxHttpFailure failure) =>
        new(MailboxWireHttpContract.StatusCode(failure), ReadOnlyMemory<byte>.Empty);
}
