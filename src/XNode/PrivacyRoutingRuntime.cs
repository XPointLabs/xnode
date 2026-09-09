using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;

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

internal sealed class OnionHostReceiveBinding
{
    private readonly byte[] localNodeId;
    private readonly byte[] keyHandleId;

    internal OnionHostReceiveBinding(
        VerifiedOnionNetworkContext network,
        OnionReceivePosition position,
        ReadOnlySpan<byte> localNodeId,
        ReadOnlySpan<byte> keyHandleId)
    {
        Network = network ?? throw new ArgumentNullException(nameof(network));
        if (localNodeId.Length != 32 || localNodeId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The local ONION node id must be a nonzero 32-byte value.",
                nameof(localNodeId));
        }

        if (keyHandleId.Length != 32 || keyHandleId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The local ONION key handle id must be a nonzero 32-byte value.",
                nameof(keyHandleId));
        }

        if (position is < OnionReceivePosition.Ingress or > OnionReceivePosition.Exit)
        {
            throw new ArgumentOutOfRangeException(nameof(position));
        }

        Position = position;
        this.localNodeId = localNodeId.ToArray();
        this.keyHandleId = keyHandleId.ToArray();
    }

    internal VerifiedOnionNetworkContext Network { get; }
    internal OnionReceivePosition Position { get; }
    internal ReadOnlyMemory<byte> LocalNodeId => localNodeId.ToArray();
    internal ReadOnlyMemory<byte> KeyHandleId => keyHandleId.ToArray();
}

internal interface IOnionHostReceiveBindingSource
{
    ValueTask<OnionHostReceiveBinding> GetCurrentAsync(
        CancellationToken cancellationToken);
}

/// <summary>
/// Protocol-owned ONION processing hosted by XNode. The public constructor remains
/// deliberately fail-closed; production composition must supply the atomically
/// verified authority, durable replay, opaque-key and codec boundary.
/// </summary>
public sealed class PrivacyRoutingRuntime
{
    private readonly PrivacyRoutingConfiguration configuration;
    private readonly IPrivacyPeerClient peerClient;
    private readonly INativeMailboxExitDispatcher terminalDispatcher;
    private readonly PrivacyRoutingProductionCapability? productionCapability;
    private readonly OnionKeyAgreementAuthority? keyAgreement;
    private readonly OnionReplayAuthority? replay;
    private readonly PrivacyRoutingCodec? codec;

    public bool ProductionCapabilityAvailable =>
        configuration.Enabled
        && productionCapability?.IsVerified == true
        && keyAgreement is not null
        && replay is not null
        && codec is not null;

    public PrivacyRoutingRuntime(
        PrivacyRoutingConfiguration configuration,
        IPrivacyPeerClient peerClient,
        INativeMailboxExitDispatcher terminalDispatcher)
        : this(
            configuration,
            peerClient,
            terminalDispatcher,
            productionCapability: null,
            keyAgreement: null,
            replay: null,
            codec: null)
    {
    }

    internal PrivacyRoutingRuntime(
        PrivacyRoutingConfiguration configuration,
        IPrivacyPeerClient peerClient,
        INativeMailboxExitDispatcher terminalDispatcher,
        PrivacyRoutingProductionCapability? productionCapability,
        OnionKeyAgreementAuthority? keyAgreement,
        OnionReplayAuthority? replay,
        PrivacyRoutingCodec? codec)
    {
        this.configuration = configuration
            ?? throw new ArgumentNullException(nameof(configuration));
        this.peerClient = peerClient
            ?? throw new ArgumentNullException(nameof(peerClient));
        this.terminalDispatcher = terminalDispatcher
            ?? throw new ArgumentNullException(nameof(terminalDispatcher));
        this.productionCapability = productionCapability;
        this.keyAgreement = keyAgreement;
        this.replay = replay;
        this.codec = codec;
        var protocolBoundaryCount =
            (productionCapability is null ? 0 : 1)
            + (keyAgreement is null ? 0 : 1)
            + (replay is null ? 0 : 1)
            + (codec is null ? 0 : 1);
        if (protocolBoundaryCount is not 0 and not 4)
        {
            throw new ArgumentException(
                "The verified ONION protocol boundary must be supplied atomically.");
        }
    }

    public async Task<PrivacyRuntimeResult> ProcessAsync(
        ReadOnlyMemory<byte> frame,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!configuration.Enabled
            || productionCapability is null
            || keyAgreement is null
            || replay is null
            || codec is null)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.UnavailableBeforeForward);
        }

        try
        {
            var binding = await productionCapability.GetCurrentAsync(cancellationToken)
                .ConfigureAwait(false);
            if (binding is null)
            {
                return PrivacyRuntimeResult.Of(
                    PrivacyRuntimeOutcome.UnavailableBeforeForward);
            }

            var keyHandle = keyAgreement.BindKeyHandle(binding.KeyHandleId);
            var localNodeKey = OnionLocalNodeKeyFactory.Bind(
                binding.Network,
                binding.Position,
                binding.LocalNodeId,
                keyHandle);
            var receive = OnionReceiveContextSelector.Select(frame, localNodeKey);
            await using var replayLease = await replay.BeginOpenAsync(
                    receive,
                    frame,
                    cancellationToken)
                .ConfigureAwait(false);
            using var opened = await codec.OpenAsync(
                    frame,
                    receive,
                    replayLease,
                    cancellationToken)
                .ConfigureAwait(false);

            if (opened is OpenedOnionRelay relay)
            {
                return await ForwardAsync(relay, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (opened is not OpenedOnionExit exit)
            {
                return PrivacyRuntimeResult.Of(
                    PrivacyRuntimeOutcome.MalformedBeforeForward);
            }

            return await DispatchAndSealAsync(exit, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OnionBoundaryException exception)
        {
            return PrivacyRuntimeResult.Of(MapBoundaryFailure(exception.Code));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.OutcomeUnknownAfterForward);
        }
        catch (Exception exception) when (
            exception is InvalidDataException
                or InvalidOperationException
                or IOException
                or UnauthorizedAccessException
                or CryptographicException)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.UnavailableBeforeForward);
        }
    }

    private async Task<PrivacyRuntimeResult> ForwardAsync(
        OpenedOnionRelay relay,
        CancellationToken cancellationToken)
    {
        var forwarded = await peerClient.ForwardAsync(
                relay.NextHop,
                relay.InnerFrame,
                cancellationToken)
            .ConfigureAwait(false);
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

    private async Task<PrivacyRuntimeResult> DispatchAndSealAsync(
        OpenedOnionExit exit,
        CancellationToken cancellationToken)
    {
        var dispatched = await terminalDispatcher.DispatchAsync(
                exit.Request,
                cancellationToken)
            .ConfigureAwait(false);
        if (dispatched.Certainty
            == NativeMailboxDispatchCertainty.RejectedBeforeForward)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.UnavailableBeforeForward);
        }

        if (dispatched.Certainty
            == NativeMailboxDispatchCertainty.OutcomeUnknownAfterForward)
        {
            return PrivacyRuntimeResult.Of(
                PrivacyRuntimeOutcome.OutcomeUnknownAfterForward);
        }

        var terminal = dispatched.Success
            ? OnionTerminalPayloadVerifierV1.VerifySuccess(
                exit.Request,
                dispatched.CanonicalBody)
            : OnionTerminalPayloadVerifierV1.VerifyFailure(
                exit.Request,
                MapTerminalFailure(dispatched.StatusCode));
        var reply = await codec!.SealAsync(
                exit.ReplyContext,
                terminal,
                cancellationToken)
            .ConfigureAwait(false);
        return new PrivacyRuntimeResult(
            PrivacyRuntimeOutcome.Completed,
            reply);
    }

    private static PrivacyRuntimeOutcome MapBoundaryFailure(string code) => code switch
    {
        "receive-frame-invalid" or
        "replay-lease-mismatch" => PrivacyRuntimeOutcome.MalformedBeforeForward,
        "replay-rejected" => PrivacyRuntimeOutcome.ReplayedBeforeForward,
        "receive-next-hop-mismatch" or
        "receive-next-hop-duplicate" or
        "next-hop-context-mismatch" or
        "next-hop-origin-invalid" =>
            PrivacyRuntimeOutcome.UnauthorizedNextHopBeforeForward,
        "replay-commit-ambiguous" =>
            PrivacyRuntimeOutcome.OutcomeUnknownAfterForward,
        _ => PrivacyRuntimeOutcome.UnavailableBeforeForward
    };

    internal static OnionFailureCode MapTerminalFailure(int statusCode) =>
        statusCode switch
        {
            StatusCodes.Status400BadRequest or
            StatusCodes.Status405MethodNotAllowed or
            StatusCodes.Status411LengthRequired or
            StatusCodes.Status413PayloadTooLarge or
            StatusCodes.Status415UnsupportedMediaType =>
                OnionFailureCode.MalformedRequest,
            StatusCodes.Status401Unauthorized =>
                OnionFailureCode.AuthenticationRejected,
            StatusCodes.Status403Forbidden =>
                OnionFailureCode.AuthorizationRejected,
            StatusCodes.Status409Conflict =>
                OnionFailureCode.Conflict,
            StatusCodes.Status429TooManyRequests =>
                OnionFailureCode.CapacityExceeded,
            StatusCodes.Status503ServiceUnavailable =>
                OnionFailureCode.Unavailable,
            StatusCodes.Status504GatewayTimeout =>
                OnionFailureCode.OutcomeUnknown,
            _ => OnionFailureCode.InternalFailure
        };
}
