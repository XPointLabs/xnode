using System.Net;

namespace XNode.Core;

public static class QuorumCoordinatorAccess
{
    public static bool IsAllowed(IPAddress? remoteAddress, string? configuredNetworks)
    {
        if (remoteAddress is null || string.IsNullOrWhiteSpace(configuredNetworks))
        {
            return false;
        }

        var normalizedRemote = remoteAddress.IsIPv4MappedToIPv6
            ? remoteAddress.MapToIPv4()
            : remoteAddress;

        foreach (var entry in configuredNetworks.Split(
                     new[] { ',', ';', ' ', '\r', '\n', '\t' },
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (IPAddress.TryParse(entry, out var address))
            {
                var normalizedAddress = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
                if (normalizedAddress.Equals(normalizedRemote))
                {
                    return true;
                }

                continue;
            }

            if (IPNetwork.TryParse(entry, out var network) && network.Contains(normalizedRemote))
            {
                return true;
            }
        }

        return false;
    }
}
