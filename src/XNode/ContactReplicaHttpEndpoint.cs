using System.Globalization;
using System.Security.Cryptography;
using XNode.Core;
using XNode.Core.ContactResolver;

namespace XNode;

internal static class ContactReplicaHttpEndpoint
{
    internal static async Task<IResult> HandleAsync(
        HttpContext context,
        ContactServiceHostCompositionPlan plan,
        ContactServicePersistenceOptions options,
        ContactReplicaReplayGuard replayGuard,
        ContactReplicaRequestReceiver receiver,
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
                ContactReplicaHttpContract.MediaType,
                StringComparison.Ordinal)
            || context.Request.ContentLength is not long length
            || length is < 236 or > ContactReplicaWireCodec.MaximumRequestBytes)
        {
            return Results.NotFound();
        }

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.ReplicaTimeout);
        try
        {
            var body = new byte[checked((int)length)];
            await context.Request.Body.ReadExactlyAsync(body, deadline.Token);
            var command = ContactReplicaWireCodec.DecodeRequest(body);
            var headers = ReadHeaders(context.Request);
            var local = node.GetRouterId();
            if (!ContactReplicaPeerAuthenticator.VerifyRequest(
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
            var exact = ContactReplicaWireCodec.Encode(result);
            var responseAuthentication = ContactReplicaPeerAuthenticator.SignResponse(
                local,
                sender,
                node.GetEd25519PrivateKey(),
                command.CorrelationId.Span,
                exact,
                clock.UtcNow);
            AddHeaders(context.Response, responseAuthentication);
            context.Response.Headers.CacheControl = "no-store";
            return Results.Bytes(exact, ContactReplicaHttpContract.MediaType);
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
            or CryptographicException
            or ContactServiceReceiptAuthorityException)
        {
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }
    }

    private static ContactReplicaAuthenticationHeaders ReadHeaders(HttpRequest request) => new(
        Single(request, ContactReplicaPeerAuthenticator.SenderHeader),
        Single(request, ContactReplicaPeerAuthenticator.RecipientHeader),
        long.TryParse(
            Single(request, ContactReplicaPeerAuthenticator.TimestampHeader),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var timestamp) ? timestamp : long.MinValue,
        Single(request, ContactReplicaPeerAuthenticator.NonceHeader),
        Single(request, ContactReplicaPeerAuthenticator.CorrelationHeader),
        Single(request, ContactReplicaPeerAuthenticator.SignatureHeader));

    private static string Single(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out var values) && values.Count == 1
            ? values[0] ?? ""
            : "";

    private static void AddHeaders(
        HttpResponse response,
        ContactReplicaAuthenticationHeaders headers)
    {
        response.Headers[ContactReplicaPeerAuthenticator.SenderHeader] = headers.SenderReplicaId;
        response.Headers[ContactReplicaPeerAuthenticator.RecipientHeader] = headers.RecipientReplicaId;
        response.Headers[ContactReplicaPeerAuthenticator.TimestampHeader] =
            headers.TimestampUnixMilliseconds.ToString(CultureInfo.InvariantCulture);
        response.Headers[ContactReplicaPeerAuthenticator.NonceHeader] = headers.Nonce;
        response.Headers[ContactReplicaPeerAuthenticator.CorrelationHeader] = headers.Correlation;
        response.Headers[ContactReplicaPeerAuthenticator.SignatureHeader] = headers.Signature;
    }
}

internal static class ContactReplicaEndpointMapping
{
    internal static IEndpointRouteBuilder MapContactReplicaEndpoint(
        this IEndpointRouteBuilder endpoints,
        ContactServiceHostCompositionPlan plan,
        int peerListenerPort)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.MapReplicaEndpoint)
        {
            return endpoints;
        }

        endpoints.MapPost(ContactReplicaHttpContract.Route, (
            HttpContext context,
            ContactServicePersistenceOptions options,
            ContactReplicaReplayGuard replay,
            ContactReplicaRequestReceiver receiver,
            RouterNodeOptions node,
            IClock clock,
            CancellationToken cancellationToken) => ContactReplicaHttpEndpoint.HandleAsync(
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
