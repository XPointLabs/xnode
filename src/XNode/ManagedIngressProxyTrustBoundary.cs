using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace XNode;

internal static class ManagedIngressProxyTrustBoundary
{
    private const string ForwardedProtoHeaderName = "X-Forwarded-Proto";

    public static IApplicationBuilder UseManagedIngressProxyTrustBoundary(
        this IApplicationBuilder app,
        NodeListenerPlan listeners)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(listeners);

        return app.Use((context, next) => InvokeAsync(context, next, listeners));
    }

    internal static async Task InvokeAsync(
        HttpContext context,
        RequestDelegate next,
        NodeListenerPlan listeners)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(listeners);

        if (listeners.ManagedIngress is null
            || context.Connection.LocalPort != listeners.ManagedIngress.Url.Port)
        {
            await next(context);
            return;
        }

        var remoteAddress = context.Connection.RemoteIpAddress;
        if (remoteAddress is null
            || !listeners.ManagedIngressTrustedProxyAddresses.Contains(remoteAddress))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var forwardedProto = context.Request.Headers[ForwardedProtoHeaderName];
        if (forwardedProto.Count != 1
            || !string.Equals(
                forwardedProto[0],
                Uri.UriSchemeHttps,
                StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        context.Request.Scheme = Uri.UriSchemeHttps;
        context.Request.Headers.Remove(ForwardedProtoHeaderName);
        await next(context);
    }
}
