using System.Globalization;
using System.Net;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Microsoft.AspNetCore.Http.Features;
using XNode.Core;

namespace XNode;

public static class PrivacyRoutingHttpEndpoint
{
    public static async Task<IResult> HandlePublicAsync(
        HttpContext context,
        PrivacyRoutingConfiguration configuration,
        PrivacyIngressLimiter limiter,
        PrivacyRoutingRuntime runtime,
        IClock clock,
        int apiListenerPort,
        CancellationToken cancellationToken)
    {
        if (!configuration.Enabled || context.Connection.LocalPort != apiListenerPort)
        {
            return Results.NotFound();
        }

        try
        {
            ManagedIngressH2Contract.ValidateFrameRequest(RequestMetadata(context.Request));
        }
        catch (ManagedIngressContractException exception)
        {
            return ContractFailure(exception, context.Request.ContentLength);
        }

        return await ReceiveAndProcessAsync(
            context,
            configuration,
            limiter,
            runtime,
            clock,
            cancellationToken);
    }

    public static async Task<IResult> HandlePeerAsync(
        HttpContext context,
        PrivacyRoutingConfiguration configuration,
        PrivacyIngressLimiter limiter,
        PrivacyPeerReplayGuard peerReplay,
        PrivacyRoutingRuntime runtime,
        RouterNodeOptions node,
        IClock clock,
        int peerListenerPort,
        CancellationToken cancellationToken)
    {
        if (!configuration.Enabled
            || context.Connection.LocalPort != peerListenerPort
            || context.Request.Protocol != "HTTP/2"
            || !HttpMethods.IsPost(context.Request.Method)
            || !context.Request.Path.Equals(PrivacyRoutingOptions.PeerFramePath)
            || context.Request.QueryString.HasValue
            || !string.Equals(
                context.Request.ContentType,
                ManagedIngressH2Contract.OpaqueMediaType,
                StringComparison.Ordinal)
            || !string.Equals(
                context.Request.Headers.Accept.ToString(),
                ManagedIngressH2Contract.OpaqueMediaType,
                StringComparison.Ordinal)
            || context.Request.Headers.ContentEncoding.Count != 0
            || context.Request.ContentLength is null or
                < ManagedIngressLimits.MinimumOpaqueFrameBytes or
                > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            return Results.NotFound();
        }

        if (!TryReadPeerAuthentication(
                context.Request,
                out var authentication))
        {
            return Results.Unauthorized();
        }

        if (!limiter.TryEnter(clock.UtcNow, out var lease))
        {
            return Failure(
                StatusCodes.Status429TooManyRequests,
                ManagedIngressErrorClass.Saturated,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: true,
                retryAfterSeconds: 1);
        }

        using (lease)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            deadline.CancelAfter(configuration.RequestTimeout);
            try
            {
                var frame = await ReadBodyAsync(context.Request, deadline.Token);
                if (!PrivacyPeerAuthenticator.Verify(
                        authentication,
                        node.GetRouterId(),
                        frame,
                        clock.UtcNow,
                        out var sender,
                        out var nonce)
                    || !configuration.Peers.ContainsKey(sender))
                {
                    return Results.Unauthorized();
                }

                if (!peerReplay.TryAccept(
                        sender,
                        nonce,
                        authentication.TimestampUnixMilliseconds,
                        clock.UtcNow))
                {
                    return Failure(
                        StatusCodes.Status504GatewayTimeout,
                        ManagedIngressErrorClass.UpstreamOutcomeUnknown,
                        ManagedIngressOutcomeCertainty.UnknownAfterForward,
                        retryable: true);
                }

                return RuntimeResult(await runtime.ProcessAsync(frame, deadline.Token));
            }
            catch (Exception exception) when (
                exception is EndOfStreamException or ManagedIngressContractException)
            {
                return Failure(
                    StatusCodes.Status400BadRequest,
                    ManagedIngressErrorClass.MalformedFrame,
                    ManagedIngressOutcomeCertainty.BeforeForward,
                    retryable: false);
            }
            catch (OperationCanceledException) when (
                deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                return Failure(
                    StatusCodes.Status503ServiceUnavailable,
                    ManagedIngressErrorClass.Unavailable,
                    ManagedIngressOutcomeCertainty.BeforeForward,
                    retryable: true,
                    retryAfterSeconds: 1);
            }
        }
    }

    public static IResult HandleCapabilities(
        HttpContext context,
        PrivacyRoutingConfiguration configuration,
        int apiListenerPort)
    {
        if (context.Connection.LocalPort != apiListenerPort)
        {
            return Results.NotFound();
        }

        try
        {
            ManagedIngressH2Contract.ValidateCapabilityRequest(
                RequestMetadata(context.Request));
            var document = configuration.Enabled
                ? ManagedIngressCapabilityDocument.V1Ready()
                : new ManagedIngressCapabilityDocument
                {
                    Ready = false,
                    RetryAfterSeconds = 1
                };
            var encoded = ManagedIngressCapabilityDocumentCodec.Encode(document);
            return Results.Bytes(encoded, ManagedIngressH2Contract.CapabilitiesMediaType);
        }
        catch (ManagedIngressContractException exception)
        {
            return ContractFailure(exception, context.Request.ContentLength);
        }
    }

    private static async Task<IResult> ReceiveAndProcessAsync(
        HttpContext context,
        PrivacyRoutingConfiguration configuration,
        PrivacyIngressLimiter limiter,
        PrivacyRoutingRuntime runtime,
        IClock clock,
        CancellationToken cancellationToken)
    {
        if (!limiter.TryEnter(clock.UtcNow, out var lease))
        {
            return Failure(
                StatusCodes.Status429TooManyRequests,
                ManagedIngressErrorClass.Saturated,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: true,
                retryAfterSeconds: 1);
        }

        using (lease)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            deadline.CancelAfter(configuration.RequestTimeout);
            try
            {
                var frame = await ReadBodyAsync(context.Request, deadline.Token);
                return RuntimeResult(await runtime.ProcessAsync(frame, deadline.Token));
            }
            catch (Exception exception) when (
                exception is EndOfStreamException or ManagedIngressContractException)
            {
                return Failure(
                    StatusCodes.Status400BadRequest,
                    ManagedIngressErrorClass.MalformedFrame,
                    ManagedIngressOutcomeCertainty.BeforeForward,
                    retryable: false);
            }
            catch (OperationCanceledException) when (
                deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                return Failure(
                    StatusCodes.Status503ServiceUnavailable,
                    ManagedIngressErrorClass.Unavailable,
                    ManagedIngressOutcomeCertainty.BeforeForward,
                    retryable: true,
                    retryAfterSeconds: 1);
            }
        }
    }

    private static IResult RuntimeResult(PrivacyRuntimeResult result) =>
        result.Outcome switch
        {
            PrivacyRuntimeOutcome.Completed => Results.Bytes(
                result.OpaqueReply.ToArray(),
                ManagedIngressH2Contract.OpaqueMediaType),
            PrivacyRuntimeOutcome.MalformedBeforeForward or
            PrivacyRuntimeOutcome.ReplayedBeforeForward => Failure(
                StatusCodes.Status400BadRequest,
                ManagedIngressErrorClass.MalformedFrame,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: false),
            PrivacyRuntimeOutcome.SaturatedBeforeForward => Failure(
                StatusCodes.Status429TooManyRequests,
                ManagedIngressErrorClass.Saturated,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: true,
                retryAfterSeconds: 1),
            PrivacyRuntimeOutcome.UnauthorizedNextHopBeforeForward => Failure(
                StatusCodes.Status421MisdirectedRequest,
                ManagedIngressErrorClass.WrongOrigin,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: true),
            PrivacyRuntimeOutcome.UnavailableBeforeForward => Failure(
                StatusCodes.Status503ServiceUnavailable,
                ManagedIngressErrorClass.Unavailable,
                ManagedIngressOutcomeCertainty.BeforeForward,
                retryable: true,
                retryAfterSeconds: 1),
            _ => Failure(
                StatusCodes.Status504GatewayTimeout,
                ManagedIngressErrorClass.UpstreamOutcomeUnknown,
                ManagedIngressOutcomeCertainty.UnknownAfterForward,
                retryable: true)
        };

    private static ManagedIngressRequestMetadata RequestMetadata(HttpRequest request)
    {
        var supplemental = new List<ManagedIngressHeader>();
        foreach (var header in request.Headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Accept", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)
                || header.Key.Equals("Early-Data", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            supplemental.Add(new ManagedIngressHeader(
                header.Key.ToLowerInvariant(),
                header.Value.ToString()));
        }

        return new ManagedIngressRequestMetadata(
            request.Method,
            request.Path.Value ?? "",
            request.QueryString.Value?.TrimStart('?') ?? "",
            request.Protocol == "HTTP/2" ? HttpVersion.Version20 : HttpVersion.Version11,
            request.ContentType ?? "",
            request.Headers.Accept.ToString(),
            request.Headers.ContentEncoding.SingleOrDefault(),
            request.ContentLength ?? -1,
            string.Equals(request.Headers["Early-Data"].ToString(), "1", StringComparison.Ordinal),
            supplemental,
            request.Scheme,
            request.Host.Value ?? "");
    }

    private static async Task<byte[]> ReadBodyAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        var length = request.ContentLength
            ?? throw new EndOfStreamException("Content-Length is required.");
        var admission = new ManagedIngressStreamingAdmission(length);
        var body = new byte[checked((int)length)];
        var offset = 0;
        while (offset < body.Length)
        {
            var read = await request.Body.ReadAsync(
                body.AsMemory(offset),
                cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("The opaque frame was truncated.");
            }

            admission.Append(body.AsSpan(offset, read));
            offset += read;
        }

        var extra = new byte[1];
        if (await request.Body.ReadAsync(extra, cancellationToken) != 0)
        {
            throw new ManagedIngressContractException(
                ManagedIngressContractError.FrameLengthOutOfRange,
                "The opaque frame exceeded Content-Length.");
        }

        admission.Complete();
        return body;
    }

    private static bool TryReadPeerAuthentication(
        HttpRequest request,
        out PrivacyPeerAuthenticationHeaders authentication)
    {
        authentication = null!;
        if (!TrySingle(request, PrivacyPeerAuthenticator.SenderHeader, out var sender)
            || !TrySingle(request, PrivacyPeerAuthenticator.RecipientHeader, out var recipient)
            || !TrySingle(request, PrivacyPeerAuthenticator.TimestampHeader, out var timestamp)
            || !TrySingle(request, PrivacyPeerAuthenticator.NonceHeader, out var nonce)
            || !TrySingle(request, PrivacyPeerAuthenticator.SignatureHeader, out var signature)
            || !long.TryParse(
                timestamp,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var timestampUnixMilliseconds)
            || timestamp.Length != 13
            || timestamp[0] == '0'
            || !timestamp.All(static character => character is >= '0' and <= '9'))
        {
            return false;
        }

        authentication = new PrivacyPeerAuthenticationHeaders(
            sender,
            recipient,
            timestampUnixMilliseconds,
            nonce,
            signature);
        return true;
    }

    private static bool TrySingle(HttpRequest request, string name, out string value)
    {
        value = "";
        if (!request.Headers.TryGetValue(name, out var values) || values.Count != 1)
        {
            return false;
        }

        value = values[0] ?? "";
        return value.Length != 0;
    }

    private static IResult ContractFailure(
        ManagedIngressContractException exception,
        long? declaredLength)
    {
        if (exception.Error == ManagedIngressContractError.UnsupportedResponseType)
        {
            return Failure(406, ManagedIngressErrorClass.UnsupportedResponseType,
                ManagedIngressOutcomeCertainty.BeforeForward, retryable: false);
        }

        if (exception.Error == ManagedIngressContractError.UnsupportedMediaType)
        {
            return Failure(415, ManagedIngressErrorClass.UnsupportedMediaType,
                ManagedIngressOutcomeCertainty.BeforeForward, retryable: false);
        }

        if (exception.Error == ManagedIngressContractError.EarlyDataRejected)
        {
            return Failure(425, ManagedIngressErrorClass.EarlyDataRejected,
                ManagedIngressOutcomeCertainty.BeforeForward, retryable: true);
        }

        if (exception.Error == ManagedIngressContractError.FrameLengthOutOfRange
            && declaredLength > ManagedIngressLimits.MaximumOpaqueFrameBytes)
        {
            return Failure(413, ManagedIngressErrorClass.FrameTooLarge,
                ManagedIngressOutcomeCertainty.BeforeForward, retryable: false);
        }

        return Failure(400, ManagedIngressErrorClass.MalformedFrame,
            ManagedIngressOutcomeCertainty.BeforeForward, retryable: false);
    }

    private static IResult Failure(
        int statusCode,
        ManagedIngressErrorClass errorClass,
        ManagedIngressOutcomeCertainty certainty,
        bool retryable,
        int retryAfterSeconds = 0)
    {
        var body = ManagedIngressErrorCodec.Encode(new ManagedIngressErrorFrame(
            errorClass,
            certainty,
            retryable,
            retryAfterSeconds));
        return new ManagedIngressErrorResult(statusCode, body, retryAfterSeconds);
    }
}

internal sealed class ManagedIngressErrorResult(
    int statusCode,
    byte[] body,
    int retryAfterSeconds) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = statusCode;
        httpContext.Response.ContentType = ManagedIngressH2Contract.ErrorMediaType;
        httpContext.Response.ContentLength = body.Length;
        httpContext.Response.Headers.CacheControl = "no-store";
        if (retryAfterSeconds != 0)
        {
            httpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(
                CultureInfo.InvariantCulture);
        }

        await httpContext.Response.Body.WriteAsync(body, httpContext.RequestAborted);
    }
}
