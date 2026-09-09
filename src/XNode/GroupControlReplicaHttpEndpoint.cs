using System.Globalization;
using System.Security.Cryptography;
using XNode.Core;

namespace XNode;

internal static class GroupControlReplicaHttpEndpoint
{
    internal static async Task<IResult> HandleAsync(
        HttpContext context,
        GroupControlServiceHostCompositionPlan plan,
        GroupControlServiceOptions options,
        GroupControlReplicaReplayGuard replayGuard,
        GroupControlReplicaRequestReceiver receiver,
        RouterNodeOptions node,
        IClock clock,
        int peerListenerPort,
        CancellationToken cancellationToken)
    {
        if (!plan.MapReplicaEndpoint
            || context.Connection.LocalPort != peerListenerPort
            || !context.Request.IsHttps
            || !HttpMethods.IsPost(context.Request.Method)
            || !string.Equals(context.Request.Protocol, "HTTP/2", StringComparison.Ordinal)
            || !string.Equals(
                context.Request.ContentType,
                GroupControlReplicaHttpContract.MediaType,
                StringComparison.Ordinal)
            || context.Request.ContentLength is not long length
            || length is < 348 or > GroupControlReplicaWireCodec.MaximumRequestBytes)
        {
            return Results.NotFound();
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.ReplicaTimeout);
        try
        {
            var body = new byte[checked((int)length)];
            await context.Request.Body.ReadExactlyAsync(body, deadline.Token);
            var command = GroupControlReplicaWireCodec.DecodeRequest(body);
            var headers = ReadHeaders(context.Request);
            var local = node.GetRouterId();
            if (!GroupControlReplicaPeerAuthenticator.VerifyRequest(
                    headers,
                    local,
                    command.CorrelationId.Span,
                    body,
                    clock.UtcNow,
                    out var sender,
                    out var nonce)
                || !replayGuard.TryAccept(
                    sender,
                    nonce,
                    headers.TimestampUnixMilliseconds,
                    clock.UtcNow))
            {
                return Results.NotFound();
            }

            var result = await receiver.ReceiveAsync(
                command,
                sender,
                deadline.Token).ConfigureAwait(false);
            var exact = GroupControlReplicaWireCodec.Encode(result);
            var responseAuthentication = GroupControlReplicaPeerAuthenticator.SignResponse(
                local,
                sender,
                node.GetEd25519PrivateKey(),
                command.CorrelationId.Span,
                exact,
                clock.UtcNow);
            AddHeaders(context.Response, responseAuthentication);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Bytes(exact, GroupControlReplicaHttpContract.MediaType);
        }
        catch (OperationCanceledException) when (
            deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or ArgumentException
            or UnauthorizedAccessException
            or InvalidOperationException
            or IOException
            or CryptographicException)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static GroupControlReplicaAuthenticationHeaders ReadHeaders(HttpRequest request) => new(
        Single(request, GroupControlReplicaPeerAuthenticator.SenderHeader),
        Single(request, GroupControlReplicaPeerAuthenticator.RecipientHeader),
        long.TryParse(
            Single(request, GroupControlReplicaPeerAuthenticator.TimestampHeader),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var timestamp) ? timestamp : long.MinValue,
        Single(request, GroupControlReplicaPeerAuthenticator.NonceHeader),
        Single(request, GroupControlReplicaPeerAuthenticator.CorrelationHeader),
        Single(request, GroupControlReplicaPeerAuthenticator.SignatureHeader));

    private static string Single(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out var values) && values.Count == 1
            ? values[0] ?? ""
            : "";

    private static void AddHeaders(
        HttpResponse response,
        GroupControlReplicaAuthenticationHeaders headers)
    {
        response.Headers[GroupControlReplicaPeerAuthenticator.SenderHeader] = headers.SenderReplicaId;
        response.Headers[GroupControlReplicaPeerAuthenticator.RecipientHeader] = headers.RecipientReplicaId;
        response.Headers[GroupControlReplicaPeerAuthenticator.TimestampHeader] =
            headers.TimestampUnixMilliseconds.ToString(CultureInfo.InvariantCulture);
        response.Headers[GroupControlReplicaPeerAuthenticator.NonceHeader] = headers.Nonce;
        response.Headers[GroupControlReplicaPeerAuthenticator.CorrelationHeader] = headers.Correlation;
        response.Headers[GroupControlReplicaPeerAuthenticator.SignatureHeader] = headers.Signature;
    }
}

internal static class GroupControlReplicaEndpointMapping
{
    internal static IEndpointRouteBuilder MapGroupControlReplicaEndpoint(
        this IEndpointRouteBuilder endpoints,
        GroupControlServiceHostCompositionPlan plan,
        int peerListenerPort)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.MapReplicaEndpoint)
        {
            return endpoints;
        }

        endpoints.MapPost(GroupControlReplicaHttpContract.Route, (
            HttpContext context,
            GroupControlServiceOptions options,
            GroupControlReplicaReplayGuard replay,
            GroupControlReplicaRequestReceiver receiver,
            RouterNodeOptions node,
            IClock clock,
            CancellationToken cancellationToken) => GroupControlReplicaHttpEndpoint.HandleAsync(
                context,
                plan,
                options,
                replay,
                receiver,
                node,
                clock,
                peerListenerPort,
                cancellationToken));
        return endpoints;
    }
}
