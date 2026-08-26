using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core;

namespace XNode;

public enum PrivacyRuntimeOutcome
{
    Completed = 1,
    MalformedBeforeForward = 2,
    ReplayedBeforeForward = 3,
    SaturatedBeforeForward = 4,
    UnauthorizedNextHopBeforeForward = 5,
    UnavailableBeforeForward = 6,
    OutcomeUnknownAfterForward = 7
}

public sealed record PrivacyRuntimeResult(
    PrivacyRuntimeOutcome Outcome,
    ReadOnlyMemory<byte> OpaqueReply)
{
    public static PrivacyRuntimeResult Of(PrivacyRuntimeOutcome outcome) =>
        new(outcome, ReadOnlyMemory<byte>.Empty);
}

public sealed class PrivacyRoutingRuntime
{
    private readonly PrivacyRoutingConfiguration _configuration;
    private readonly PrivacyRoutingReplayGuard _replay;
    private readonly IPrivacyPeerClient _peerClient;
    private readonly INativeMailboxExitDispatcher _mailbox;
    private readonly RouterNodeOptions _node;
    private readonly IClock _clock;

    public PrivacyRoutingRuntime(
        PrivacyRoutingConfiguration configuration,
        PrivacyRoutingReplayGuard replay,
        IPrivacyPeerClient peerClient,
        INativeMailboxExitDispatcher mailbox,
        RouterNodeOptions node,
        IClock clock)
    {
        _configuration = configuration;
        _replay = replay;
        _peerClient = peerClient;
        _mailbox = mailbox;
        _node = node;
        _clock = clock;
    }

    public async Task<PrivacyRuntimeResult> ProcessAsync(
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken)
    {
        if (!_configuration.Enabled)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.UnavailableBeforeForward);
        }

        PrivacyRoutingOpenedLayer layer;
        try
        {
            layer = PrivacyRoutingRequestCodec.Open(
                frame.Span,
                _configuration.PrivateKeySpan);
        }
        catch (PrivacyRoutingProtocolException)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.MalformedBeforeForward);
        }

        var replay = _replay.TryAccept(layer.ReplayId.Span, _clock.UtcNow);
        if (replay == PrivacyRoutingReplayResult.Replayed)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.ReplayedBeforeForward);
        }

        if (replay == PrivacyRoutingReplayResult.Saturated)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.SaturatedBeforeForward);
        }

        if (layer is PrivacyRoutingRelayLayer relay)
        {
            RouterId nextRouterId;
            try
            {
                nextRouterId = RouterId.FromBytes(relay.NextRouterId.Span);
            }
            catch (ArgumentException)
            {
                return PrivacyRuntimeResult.Of(
                    PrivacyRuntimeOutcome.MalformedBeforeForward);
            }

            if (nextRouterId == _node.GetRouterId()
                || !_configuration.Peers.TryGetValue(nextRouterId, out var peer))
            {
                return PrivacyRuntimeResult.Of(
                    PrivacyRuntimeOutcome.UnauthorizedNextHopBeforeForward);
            }

            var forwarded = await _peerClient.ForwardAsync(
                peer,
                relay.InnerFrame,
                cancellationToken);
            return forwarded.Failure switch
            {
                PrivacyForwardFailure.None => new PrivacyRuntimeResult(
                    PrivacyRuntimeOutcome.Completed,
                    forwarded.OpaqueReply),
                PrivacyForwardFailure.RejectedBeforeForward =>
                    PrivacyRuntimeResult.Of(
                        PrivacyRuntimeOutcome.UnavailableBeforeForward),
                _ => PrivacyRuntimeResult.Of(
                    PrivacyRuntimeOutcome.OutcomeUnknownAfterForward)
            };
        }

        if (layer is not PrivacyRoutingExitLayer exit)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.MalformedBeforeForward);
        }

        NativeMailboxDispatchResult dispatched;
        try
        {
            dispatched = await _mailbox.DispatchAsync(
                exit.Operation,
                exit.Payload,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.OutcomeUnknownAfterForward);
        }

        if (dispatched.Certainty == NativeMailboxDispatchCertainty.RejectedBeforeForward)
        {
            return PrivacyRuntimeResult.Of(PrivacyRuntimeOutcome.UnavailableBeforeForward);
        }

        var terminal = dispatched.Success
            ? PrivacyRoutingTerminalResult.Success(
                exit.Operation,
                dispatched.CanonicalBody.Span)
            : PrivacyRoutingTerminalResult.Failure(
                exit.Operation,
                MapFailure(dispatched.StatusCode));
        var dpr1 = PrivacyRoutingResultCodec.Encode(terminal);
        try
        {
            var reply = PrivacyRoutingResponseCodec.Seal(
                exit,
                dpr1,
                _configuration.ReplyPaddingBlockBytes);
            return new PrivacyRuntimeResult(
                PrivacyRuntimeOutcome.Completed,
                reply);
        }
        catch (PrivacyRoutingProtocolException)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.OutcomeUnknownAfterForward);
        }
    }

    internal static PrivacyRoutingFailureCode MapFailure(int statusCode) =>
        statusCode switch
        {
            StatusCodes.Status400BadRequest or
            StatusCodes.Status405MethodNotAllowed or
            StatusCodes.Status411LengthRequired or
            StatusCodes.Status413PayloadTooLarge or
            StatusCodes.Status415UnsupportedMediaType =>
                PrivacyRoutingFailureCode.MalformedRequest,
            StatusCodes.Status401Unauthorized =>
                PrivacyRoutingFailureCode.AuthenticationRejected,
            StatusCodes.Status403Forbidden =>
                PrivacyRoutingFailureCode.AuthorizationRejected,
            StatusCodes.Status409Conflict =>
                PrivacyRoutingFailureCode.Conflict,
            StatusCodes.Status429TooManyRequests =>
                PrivacyRoutingFailureCode.CapacityExceeded,
            StatusCodes.Status503ServiceUnavailable =>
                PrivacyRoutingFailureCode.Unavailable,
            StatusCodes.Status504GatewayTimeout =>
                PrivacyRoutingFailureCode.OutcomeUnknown,
            _ => PrivacyRoutingFailureCode.InternalFailure
        };
}
