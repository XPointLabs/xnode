using System.Globalization;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core;

namespace XNode;

public static class MailboxAuthorityForwardingHttpEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpContext context,
        MailboxAuthorityForwardingConfiguration configuration,
        MailboxAuthorityForwardingIngressLimiter limiter,
        MailboxAuthorityForwardingReplayGuard peerReplay,
        ILocalNativeMailboxExitDispatcher localDispatcher,
        RouterNodeOptions node,
        IClock clock,
        int peerListenerPort,
        CancellationToken cancellationToken)
    {
        if (!configuration.AuthorityIngressEnabled
            || context.Connection.LocalPort != peerListenerPort
            || context.Request.Protocol != "HTTP/2"
            || !HttpMethods.IsPost(context.Request.Method)
            || !MailboxAuthorityForwardingHttpContract.TryOperation(
                context.Request.Path,
                out var operation)
            || context.Request.QueryString.HasValue)
        {
            return Results.NotFound();
        }

        var contract = MailboxAuthorityForwardingHttpContract.Contract(operation);
        if (!string.Equals(
                context.Request.ContentType,
                contract.RequestContentType,
                StringComparison.Ordinal)
            || !string.Equals(
                context.Request.Headers.Accept.ToString(),
                contract.ResponseContentType,
                StringComparison.Ordinal)
            || context.Request.Headers.ContentEncoding.Count != 0
            || context.Request.ContentLength is null
                or < 0
            || context.Request.ContentLength < contract.MinimumRequestBytes
            || context.Request.ContentLength > contract.MaximumRequestBytes
            || !TryReadAuthentication(
                context.Request,
                out var authentication))
        {
            return Results.NotFound();
        }

        if (!limiter.TryEnter(clock.UtcNow, out var lease))
        {
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }

        using (lease)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(contract.RequestTimeoutSeconds));
            try
            {
                var body = new byte[checked((int)context.Request.ContentLength.Value)];
            await context.Request.Body.ReadExactlyAsync(body, deadline.Token);
                var extra = new byte[1];
                if (await context.Request.Body.ReadAsync(extra, deadline.Token) != 0)
                {
                    return Results.StatusCode(StatusCodes.Status400BadRequest);
                }

                if (!MailboxAuthorityForwardingAuthenticator.Verify(
                    authentication,
                    node.GetRouterId(),
                    operation,
                    body,
                    clock.UtcNow,
                    out var sender,
                    out var nonce)
                || !configuration.AllowedExitRouterIds.Contains(sender))
                {
                    return Results.Unauthorized();
                }

                if (!peerReplay.TryAccept(
                    sender,
                    nonce,
                    authentication.TimestampUnixMilliseconds,
                    clock.UtcNow))
                {
                    return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
                }

                var result = await localDispatcher.DispatchAsync(
                operation,
                body,
                deadline.Token);
                return result.Success
                    ? Results.Bytes(result.CanonicalBody.ToArray(), contract.ResponseContentType)
                    : Results.StatusCode(result.StatusCode);
            }
            catch (EndOfStreamException)
            {
                return Results.StatusCode(StatusCodes.Status400BadRequest);
            }
            catch (OperationCanceledException) when (
                deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                return Results.StatusCode(StatusCodes.Status504GatewayTimeout);
            }
        }
    }

    private static bool TryReadAuthentication(
        HttpRequest request,
        out MailboxAuthorityForwardingAuthenticationHeaders authentication)
    {
        authentication = null!;
        if (!TrySingle(request, MailboxAuthorityForwardingAuthenticator.SenderHeader, out var sender)
            || !TrySingle(request, MailboxAuthorityForwardingAuthenticator.RecipientHeader, out var recipient)
            || !TrySingle(request, MailboxAuthorityForwardingAuthenticator.TimestampHeader, out var timestamp)
            || !TrySingle(request, MailboxAuthorityForwardingAuthenticator.NonceHeader, out var nonce)
            || !TrySingle(request, MailboxAuthorityForwardingAuthenticator.SignatureHeader, out var signature)
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

        authentication = new MailboxAuthorityForwardingAuthenticationHeaders(
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
}
