using System.Net;
using XNode.Core;

namespace XNode;

public sealed class DevelopmentUatPrivatePeerAddressOptions
{
    internal const string RequiredScope = "DEVELOPMENT-UAT-ONLY";

    public string Scope { get; set; } = "";

    public List<string> Addresses { get; set; } = [];

    public DevelopmentUatPrivatePeerAddressPolicy ValidateAndLoad(
        RouterNodeOptions node,
        bool isDevelopment,
        bool isProduction)
    {
        ArgumentNullException.ThrowIfNull(node);
        var configured = Addresses ?? [];
        var hasScope = !string.IsNullOrWhiteSpace(Scope);
        if (!hasScope && configured.Count == 0)
            return DevelopmentUatPrivatePeerAddressPolicy.Disabled;
        if (!hasScope
            || configured.Count is < 1 or > 16
            || !string.Equals(Scope, RequiredScope, StringComparison.Ordinal)
            || isDevelopment
            || !isProduction
            || !string.Equals(node.Network, "local", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Private peer addresses require the exact Production local DEVELOPMENT-UAT-ONLY binding.");
        }

        var addresses = new List<IPAddress>(configured.Count);
        var canonical = new HashSet<string>(StringComparer.Ordinal);
        foreach (var value in configured)
        {
            if (string.IsNullOrWhiteSpace(value)
                || !IPAddress.TryParse(value, out var address)
                || address.IsIPv4MappedToIPv6
                || address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                    && address.ScopeId != 0
                || !string.Equals(value, address.ToString(), StringComparison.Ordinal)
                || !PeerNetworkAddressGuard.IsPrivate(address)
                || !canonical.Add(address.ToString()))
            {
                throw new InvalidOperationException(
                    "Development UAT private peer addresses must be unique canonical private IP literals.");
            }
            addresses.Add(address);
        }

        return new DevelopmentUatPrivatePeerAddressPolicy(addresses);
    }
}

public sealed class DevelopmentUatPrivatePeerAddressPolicy
{
    public static DevelopmentUatPrivatePeerAddressPolicy Disabled { get; } = new([]);

    private readonly IPAddress[] addresses;

    internal DevelopmentUatPrivatePeerAddressPolicy(IEnumerable<IPAddress> addresses)
    {
        this.addresses = addresses.Select(static address => new IPAddress(
            address.GetAddressBytes())).ToArray();
    }

    public bool Enabled => addresses.Length != 0;

    internal bool Allows(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        return PeerNetworkAddressGuard.IsPrivate(address)
            && addresses.Any(candidate => candidate.Equals(address));
    }
}
