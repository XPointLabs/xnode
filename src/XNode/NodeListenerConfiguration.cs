using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using XNode.Core;

namespace XNode;

internal enum NodeListenerBindKind
{
    Localhost,
    Address,
    AnyIp
}

internal sealed record NodeListenerBinding(
    Uri Url,
    HttpProtocols Protocols,
    NodeListenerBindKind BindKind,
    IPAddress? Address = null);

internal sealed record NodeListenerPlan(
    NodeListenerBinding Api,
    NodeListenerBinding Peer,
    NodeListenerBinding? ManagedIngress)
{
    public int ManagedIngressPort => ManagedIngress?.Url.Port ?? Api.Url.Port;

    public void Configure(KestrelServerOptions kestrel)
    {
        ArgumentNullException.ThrowIfNull(kestrel);

        ConfigureBinding(kestrel, Api);
        ConfigureBinding(kestrel, Peer);
        if (ManagedIngress is not null)
        {
            ConfigureBinding(kestrel, ManagedIngress);
        }
    }

    private static void ConfigureBinding(
        KestrelServerOptions kestrel,
        NodeListenerBinding binding)
    {
        void ConfigureListenOptions(ListenOptions listen)
        {
            listen.Protocols = binding.Protocols;
            if (binding.Url.Scheme == Uri.UriSchemeHttps)
            {
                listen.UseHttps();
            }
        }

        switch (binding.BindKind)
        {
            case NodeListenerBindKind.Localhost:
                kestrel.ListenLocalhost(
                    binding.Url.Port,
                    ConfigureListenOptions);
                break;
            case NodeListenerBindKind.Address:
                kestrel.Listen(
                    binding.Address
                        ?? throw new InvalidOperationException(
                            "A literal listener address is required."),
                    binding.Url.Port,
                    ConfigureListenOptions);
                break;
            case NodeListenerBindKind.AnyIp:
                kestrel.ListenAnyIP(
                    binding.Url.Port,
                    ConfigureListenOptions);
                break;
            default:
                throw new InvalidOperationException("Unsupported listener bind kind.");
        }
    }
}

internal static class NodeListenerConfiguration
{
    public static NodeListenerPlan Create(RouterNodeOptions node)
    {
        ArgumentNullException.ThrowIfNull(node);

        var api = ParseExistingListener(node.ApiListenUrl, "Node:ApiListenUrl");
        var peer = ParseExistingListener(node.PeerRpcListenUrl, "Node:PeerRpcListenUrl");
        if (api.Url.Port == peer.Url.Port)
        {
            throw new InvalidOperationException(
                "Node API and peer RPC listeners must use different ports.");
        }

        if (string.IsNullOrWhiteSpace(node.ManagedIngressH2ListenUrl))
        {
            return new NodeListenerPlan(api, peer, null);
        }

        var managedIngress = ParseManagedIngressListener(
            node.ManagedIngressH2ListenUrl);
        if (managedIngress.Url.Port == api.Url.Port
            || managedIngress.Url.Port == peer.Url.Port)
        {
            throw new InvalidOperationException(
                "Node managed ingress, API, and peer RPC listeners must use different ports.");
        }

        return new NodeListenerPlan(api, peer, managedIngress);
    }

    private static NodeListenerBinding ParseExistingListener(
        string value,
        string configurationName)
    {
        if (!TryParseListenerUrl(value, strict: false, out var uri))
        {
            throw new InvalidOperationException(
                $"{configurationName} must be an absolute HTTP(S) listener URL.");
        }

        return CreateBinding(uri, HttpProtocols.Http1AndHttp2);
    }

    private static NodeListenerBinding ParseManagedIngressListener(string value)
    {
        if (!TryParseListenerUrl(value, strict: true, out var uri))
        {
            throw new InvalidOperationException(
                "Node:ManagedIngressH2ListenUrl must be an absolute canonical HTTP(S) origin URL.");
        }

        return CreateBinding(uri, HttpProtocols.Http2);
    }

    private static bool TryParseListenerUrl(
        string? value,
        bool strict,
        out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrEmpty(value)
            || strict && !string.Equals(value, value.Trim(), StringComparison.Ordinal)
            || !Uri.TryCreate(value, UriKind.Absolute, out var candidate)
            || candidate.Scheme != Uri.UriSchemeHttp
                && candidate.Scheme != Uri.UriSchemeHttps
            || string.IsNullOrEmpty(candidate.Host)
            || !string.IsNullOrEmpty(candidate.UserInfo)
            || candidate.AbsolutePath != "/"
            || !string.IsNullOrEmpty(candidate.Query)
            || !string.IsNullOrEmpty(candidate.Fragment))
        {
            return false;
        }

        uri = candidate;
        return true;
    }

    private static NodeListenerBinding CreateBinding(
        Uri uri,
        HttpProtocols protocols)
    {
        if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return new NodeListenerBinding(
                uri,
                protocols,
                NodeListenerBindKind.Localhost);
        }

        var host = uri.Host.TrimStart('[').TrimEnd(']');
        if (IPAddress.TryParse(host, out var address))
        {
            return new NodeListenerBinding(
                uri,
                protocols,
                NodeListenerBindKind.Address,
                address);
        }

        // This matches UseUrls semantics: non-IP host names are bind wildcards,
        // while Host filtering remains an HTTP-layer concern.
        return new NodeListenerBinding(
            uri,
            protocols,
            NodeListenerBindKind.AnyIp);
    }
}
