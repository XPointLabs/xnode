using XNode.Core;
using XNode.Core.Onion;
using XNode.Core.Runtime;
using XNode.Transport.Vless;

public sealed class LocalRelayContactProvider : ILocalRelayContactProvider
{
    private readonly RouterNodeOptions _nodeOptions;
    private readonly VlessTransportOptions _transportOptions;
    private readonly IClock _clock;

    public LocalRelayContactProvider(
        RouterNodeOptions nodeOptions,
        VlessTransportOptions transportOptions,
        IClock clock)
    {
        _nodeOptions = nodeOptions;
        _transportOptions = transportOptions;
        _clock = clock;
    }

    public RelayContact Create()
    {
        var privateKey = _nodeOptions.GetEd25519PrivateKey();
        var onionKeys = OnionCrypto.DeriveNodeKeysFromEd25519Seed(privateKey);
        var now = _clock.UtcNow;
        var contact = new RelayContact
        {
            RouterId = _nodeOptions.GetRouterId(),
            PublicHost = string.IsNullOrWhiteSpace(_transportOptions.PublicHost)
                ? _nodeOptions.PublicHost
                : _transportOptions.PublicHost,
            PublicIp = string.IsNullOrWhiteSpace(_nodeOptions.PublicIp) ? null : _nodeOptions.PublicIp.Trim(),
            PublicPort = _transportOptions.PublicPort == 0 ? _nodeOptions.PublicPort : _transportOptions.PublicPort,
            X25519PublicKey = OnionCrypto.Hex(onionKeys.PublicKey),
            RpcEndpoint = NormalizePeerRpcEndpoint(),
            SignedAt = now,
            ExpiresAt = now.Add(RelayContact.Lifetime),
            RouterVersion = typeof(LocalRelayContactProvider).Assembly.GetName().Version?.ToString() ?? "0.0.0",
            IsReachable = _transportOptions.Enabled,
            Capabilities = _transportOptions.Capabilities
                .Append("onion-v1")
                .Append("session-rpc")
                .Where(static capability => !string.IsNullOrWhiteSpace(capability))
                .Select(static capability => capability.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ToArray()
        };

        return RelayContactSigner.Sign(contact, privateKey);
    }

    private string NormalizePeerRpcEndpoint()
    {
        if (!string.IsNullOrWhiteSpace(_nodeOptions.PublicPeerRpcEndpoint))
        {
            return NormalizeEndpoint(_nodeOptions.PublicPeerRpcEndpoint);
        }

        var host = string.IsNullOrWhiteSpace(_nodeOptions.PublicIp)
            ? _nodeOptions.PublicHost
            : _nodeOptions.PublicIp;
        if (!string.IsNullOrWhiteSpace(host) && _nodeOptions.PublicPeerRpcPort is > 0 and <= 65535)
        {
            var builder = new UriBuilder(Uri.UriSchemeHttp, host, _nodeOptions.PublicPeerRpcPort)
            {
                Path = "/api/peer/onion"
            };
            return NormalizeEndpoint(builder.Uri.ToString());
        }

        throw new InvalidOperationException(
            "Node:PublicPeerRpcEndpoint or Node:PublicIp with Node:PublicPeerRpcPort is required.");
    }

    private static string NormalizeEndpoint(string endpoint)
    {
        var trimmed = endpoint.Trim().TrimEnd('/');
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException("Node:PublicPeerRpcEndpoint must be an absolute http(s) URL.");
        }

        return trimmed;
    }
}
