using System.Net;
using System.Net.Sockets;

namespace XNode.Core.Runtime;

public sealed class PeerEndpointPolicy
{
    public const string OnionPeerPath = "/api/peer/onion";

    private static readonly HashSet<string> TestNetworkIdentities = new(StringComparer.OrdinalIgnoreCase)
    {
        "uat",
        "testnet",
        "local",
        "development",
        "ci"
    };

    private readonly HashSet<PrivatePeerEndpointTuple> _privatePeerEndpoints;

    private PeerEndpointPolicy(IEnumerable<PrivatePeerEndpointTuple> privatePeerEndpoints)
    {
        _privatePeerEndpoints = privatePeerEndpoints.ToHashSet();
    }

    public static PeerEndpointPolicy PublicOnly() => new([]);

    public static PeerEndpointPolicy Create(
        RouterRuntimeOptions runtimeOptions,
        RouterNodeOptions nodeOptions,
        string environmentName)
    {
        ArgumentNullException.ThrowIfNull(runtimeOptions);
        ArgumentNullException.ThrowIfNull(nodeOptions);

        if (runtimeOptions.AllowLoopbackPeerEndpoints)
        {
            throw new InvalidOperationException(
                "Runtime:AllowLoopbackPeerEndpoints is no longer supported; loopback onion peers are always blocked.");
        }

        var configuredEntries = runtimeOptions.PrivatePeerEndpointAllowlist ?? [];
        if (!runtimeOptions.EnablePrivatePeerEndpoints)
        {
            if (configuredEntries.Count > 0)
            {
                throw new InvalidOperationException(
                    "Runtime:PrivatePeerEndpointAllowlist must be empty when private peer endpoints are disabled.");
            }

            return PublicOnly();
        }

        if (string.Equals(environmentName, "Production", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Private peer endpoints are forbidden in the Production environment.");
        }

        var nodeNetwork = nodeOptions.Network?.Trim() ?? "";
        var configuredNetwork = runtimeOptions.PrivatePeerNetworkIdentity?.Trim() ?? "";
        if (!TestNetworkIdentities.Contains(nodeNetwork)
            || !string.Equals(nodeNetwork, configuredNetwork, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Private peer endpoints require an explicit matching non-production test network identity.");
        }

        if (configuredEntries.Count == 0)
        {
            throw new InvalidOperationException(
                "Runtime:PrivatePeerEndpointAllowlist must contain at least one exact tuple when enabled.");
        }

        var tuples = new List<PrivatePeerEndpointTuple>(configuredEntries.Count);
        foreach (var entry in configuredEntries)
        {
            if (!XNode.Core.RouterId.TryParse(entry.RouterId, out var routerId))
            {
                throw new InvalidOperationException("A private peer allowlist entry contains an invalid routerId.");
            }

            if (!IPAddress.TryParse(entry.IpAddress?.Trim(), out var address)
                || address.AddressFamily != AddressFamily.InterNetwork
                || !IsRfc1918(address))
            {
                throw new InvalidOperationException(
                    "Private peer allowlist addresses must be literal RFC1918 IPv4 /32 addresses.");
            }

            if (entry.Port is < 1 or > 65535)
            {
                throw new InvalidOperationException("A private peer allowlist entry contains an invalid port.");
            }

            if (!string.Equals(entry.Path, OnionPeerPath, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Private peer allowlist paths must be exactly '{OnionPeerPath}'.");
            }

            tuples.Add(new PrivatePeerEndpointTuple(routerId, address.ToString(), entry.Port, OnionPeerPath));
        }

        if (tuples.Distinct().Count() != tuples.Count)
        {
            throw new InvalidOperationException("Private peer allowlist entries must be unique.");
        }

        return new PeerEndpointPolicy(tuples);
    }

    public bool TryValidatePeerEndpoint(RouterId recipientRouterId, Uri uri, out string error)
    {
        if (!TryValidateUriShape(uri, out error))
        {
            return false;
        }

        if (!string.Equals(uri.AbsolutePath, OnionPeerPath, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Query))
        {
            error = "invalid-onion-peer-endpoint";
            return false;
        }

        if (!IPAddress.TryParse(uri.Host, out var address))
        {
            return true;
        }

        if (IsPubliclyRoutable(address, allowLoopback: false))
        {
            return true;
        }

        if (IsPrivateTupleAllowed(recipientRouterId, uri, address))
        {
            return true;
        }

        error = "blocked-onion-peer-endpoint";
        return false;
    }

    public bool IsResolvedAddressAllowed(
        RouterId recipientRouterId,
        Uri requestUri,
        IPAddress resolvedAddress)
    {
        if (!TryValidatePeerEndpoint(recipientRouterId, requestUri, out _))
        {
            return false;
        }

        if (IsPubliclyRoutable(resolvedAddress, allowLoopback: false))
        {
            return true;
        }

        // A hostname can never claim a private exception. This pins the connect
        // decision to the literal IP that was validated in the signed route.
        return IPAddress.TryParse(requestUri.Host, out var literalAddress)
            && literalAddress.Equals(resolvedAddress)
            && IsPrivateTupleAllowed(recipientRouterId, requestUri, resolvedAddress);
    }

    public static bool TryValidateUri(Uri uri, bool allowLoopback, out string error)
    {
        if (!TryValidateUriShape(uri, out error))
        {
            return false;
        }

        if (IPAddress.TryParse(uri.Host, out var address)
            && !IsPubliclyRoutable(address, allowLoopback))
        {
            error = "blocked-onion-peer-endpoint";
            return false;
        }

        return true;
    }

    private static bool TryValidateUriShape(Uri uri, out string error)
    {
        error = string.Empty;
        if (!uri.IsAbsoluteUri
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Fragment)
            || string.IsNullOrWhiteSpace(uri.Host))
        {
            error = "invalid-onion-peer-endpoint";
            return false;
        }

        return true;
    }

    private bool IsPrivateTupleAllowed(RouterId recipientRouterId, Uri uri, IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.AddressFamily == AddressFamily.InterNetwork
            && IsRfc1918(address)
            && _privatePeerEndpoints.Contains(new PrivatePeerEndpointTuple(
                recipientRouterId,
                address.ToString(),
                uri.Port,
                uri.AbsolutePath));
    }

    private static bool IsRfc1918(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            || (bytes[0] == 192 && bytes[1] == 168);
    }

    public static bool IsPubliclyRoutable(IPAddress address, bool allowLoopback)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address))
        {
            return allowLoopback;
        }

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var first = bytes[0];
            var second = bytes[1];
            return first switch
            {
                0 or 10 or 127 => false,
                100 when second is >= 64 and <= 127 => false,
                169 when second == 254 => false,
                172 when second is >= 16 and <= 31 => false,
                192 when second is 0 or 2 or 88 or 168 => false,
                198 when second is 18 or 19 or 51 => false,
                203 when second is 0 or 113 => false,
                >= 224 => false,
                _ => true
            };
        }

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.IPv6None)
            || address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal
            || address.IsIPv6Multicast)
        {
            return false;
        }

        // fc00::/7 is unique-local; 2001:db8::/32 is documentation-only.
        if ((bytes[0] & 0xfe) == 0xfc
            || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8))
        {
            return false;
        }

        return true;
    }

    private readonly record struct PrivatePeerEndpointTuple(
        RouterId RouterId,
        string IpAddress,
        int Port,
        string Path);
}
