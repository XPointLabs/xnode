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
    private readonly HashSet<int> _productionPublicPeerPorts;
    private readonly IPublicPeerEndpointAuthorizer _publicPeerEndpointAuthorizer;
    private readonly bool _isProduction;

    public PublicPeerAuthorizationMode PublicAuthorizationMode =>
        _publicPeerEndpointAuthorizer.Mode;

    public bool IsProductionPublicRoutingReady =>
        !_isProduction
        || PublicAuthorizationMode == PublicPeerAuthorizationMode.VerifiedTickets;

    private PeerEndpointPolicy(
        IEnumerable<PrivatePeerEndpointTuple> privatePeerEndpoints,
        IEnumerable<int> productionPublicPeerPorts,
        IPublicPeerEndpointAuthorizer publicPeerEndpointAuthorizer,
        bool isProduction)
    {
        _privatePeerEndpoints = privatePeerEndpoints.ToHashSet();
        _productionPublicPeerPorts = productionPublicPeerPorts.ToHashSet();
        _publicPeerEndpointAuthorizer = publicPeerEndpointAuthorizer;
        _isProduction = isProduction;
    }

    public static PeerEndpointPolicy PublicOnly() => new(
        [],
        [443],
        AllowAllPublicPeerEndpointAuthorizer.Instance,
        isProduction: false);

    public static PeerEndpointPolicy Create(
        RouterRuntimeOptions runtimeOptions,
        RouterNodeOptions nodeOptions,
        string environmentName,
        IPublicPeerEndpointAuthorizer publicPeerEndpointAuthorizer)
    {
        ArgumentNullException.ThrowIfNull(runtimeOptions);
        ArgumentNullException.ThrowIfNull(nodeOptions);
        ArgumentNullException.ThrowIfNull(publicPeerEndpointAuthorizer);

        var isProduction = string.Equals(environmentName, "Production", StringComparison.OrdinalIgnoreCase);
        if (isProduction
            && publicPeerEndpointAuthorizer is not IProductionPublicPeerEndpointAuthorizer)
        {
            throw new InvalidOperationException(
                "Production requires a fail-closed or proof-capable public peer endpoint authorizer.");
        }

        var publicPorts = runtimeOptions.ProductionPublicPeerPorts ?? [];
        if (publicPorts.Count == 0
            || publicPorts.Any(static port => port is < 1 or > 65535)
            || publicPorts.Distinct().Count() != publicPorts.Count)
        {
            throw new InvalidOperationException(
                "Runtime:ProductionPublicPeerPorts must contain unique valid ports.");
        }

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

            return new PeerEndpointPolicy([], publicPorts, publicPeerEndpointAuthorizer, isProduction);
        }

        if (isProduction)
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

        return new PeerEndpointPolicy(tuples, publicPorts, publicPeerEndpointAuthorizer, isProduction);
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
            return TryAuthorizePublicEndpoint(recipientRouterId, uri, out error);
        }

        if (IsPubliclyRoutable(address, allowLoopback: false))
        {
            return TryAuthorizePublicEndpoint(recipientRouterId, uri, out error);
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
            return _publicPeerEndpointAuthorizer.IsResolvedAddressAuthorized(
                recipientRouterId,
                requestUri,
                resolvedAddress);
        }

        // A hostname can never claim a private exception. This pins the connect
        // decision to the literal IP that was validated in the signed route.
        return IPAddress.TryParse(requestUri.Host, out var literalAddress)
            && literalAddress.Equals(resolvedAddress)
            && IsPrivateTupleAllowed(recipientRouterId, requestUri, resolvedAddress);
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

    private bool TryAuthorizePublicEndpoint(RouterId recipientRouterId, Uri uri, out string error)
    {
        if (_isProduction
            && (uri.Scheme != Uri.UriSchemeHttps || !_productionPublicPeerPorts.Contains(uri.Port)))
        {
            error = "blocked-onion-peer-endpoint";
            return false;
        }

        if (!_publicPeerEndpointAuthorizer.IsAuthorized(recipientRouterId, uri))
        {
            error = "unverified-onion-peer-endpoint";
            return false;
        }

        error = string.Empty;
        return true;
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

        // Only 2000::/3 is globally assigned unicast. Explicitly reject
        // special-purpose ranges inside it; ranges outside it include NAT64.
        if ((bytes[0] & 0xe0) != 0x20
            || HasPrefix(bytes, "2001::", 32)             // Teredo and IETF protocol assignments.
            || HasPrefix(bytes, "2001:2::", 48)           // Benchmarking.
            || HasPrefix(bytes, "2001:10::", 28)          // ORCHID.
            || HasPrefix(bytes, "2001:20::", 28)          // ORCHIDv2.
            || HasPrefix(bytes, "2001:db8::", 32)         // Documentation.
            || HasPrefix(bytes, "2002::", 16)             // 6to4.
            || HasPrefix(bytes, "3fff::", 20))             // Documentation.
        {
            return false;
        }

        return true;
    }

    private static bool HasPrefix(byte[] addressBytes, string prefix, int prefixLength)
    {
        var prefixBytes = IPAddress.Parse(prefix).GetAddressBytes();
        var wholeBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;
        for (var index = 0; index < wholeBytes; index++)
        {
            if (addressBytes[index] != prefixBytes[index])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xff << (8 - remainingBits));
        return (addressBytes[wholeBytes] & mask) == (prefixBytes[wholeBytes] & mask);
    }

    private readonly record struct PrivatePeerEndpointTuple(
        RouterId RouterId,
        string IpAddress,
        int Port,
        string Path);
}

public interface IPublicPeerEndpointAuthorizer
{
    PublicPeerAuthorizationMode Mode { get; }

    bool IsAuthorized(RouterId routerId, Uri endpoint);

    bool IsResolvedAddressAuthorized(RouterId routerId, Uri endpoint, IPAddress resolvedAddress);
}

public interface IProductionPublicPeerEndpointAuthorizer : IPublicPeerEndpointAuthorizer
{
}

public enum PublicPeerAuthorizationMode
{
    UnverifiedNonProduction,
    DenyAll,
    VerifiedTickets
}

public sealed class AllowAllPublicPeerEndpointAuthorizer : IPublicPeerEndpointAuthorizer
{
    public static AllowAllPublicPeerEndpointAuthorizer Instance { get; } = new();

    private AllowAllPublicPeerEndpointAuthorizer()
    {
    }

    public PublicPeerAuthorizationMode Mode =>
        PublicPeerAuthorizationMode.UnverifiedNonProduction;

    public bool IsAuthorized(RouterId routerId, Uri endpoint) => true;

    public bool IsResolvedAddressAuthorized(
        RouterId routerId,
        Uri endpoint,
        IPAddress resolvedAddress) => true;
}

public sealed class DenyAllPublicPeerEndpointAuthorizer : IProductionPublicPeerEndpointAuthorizer
{
    public static DenyAllPublicPeerEndpointAuthorizer Instance { get; } = new();

    private DenyAllPublicPeerEndpointAuthorizer()
    {
    }

    public PublicPeerAuthorizationMode Mode =>
        PublicPeerAuthorizationMode.DenyAll;

    public bool IsAuthorized(RouterId routerId, Uri endpoint) => false;

    public bool IsResolvedAddressAuthorized(
        RouterId routerId,
        Uri endpoint,
        IPAddress resolvedAddress) => false;
}
