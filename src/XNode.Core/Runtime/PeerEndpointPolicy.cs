using System.Net;

namespace XNode.Core.Runtime;

public static class PeerEndpointPolicy
{
    public static bool TryValidateUri(
        Uri uri,
        bool allowLoopback,
        bool allowPrivate,
        out string error)
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

        if (IPAddress.TryParse(uri.Host, out var address)
            && !IsPermitted(address, allowLoopback, allowPrivate))
        {
            error = "blocked-onion-peer-endpoint";
            return false;
        }

        return true;
    }

    public static bool IsPermitted(IPAddress address, bool allowLoopback, bool allowPrivate)
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
            if (first == 10
                || (first == 172 && second is >= 16 and <= 31)
                || (first == 192 && second == 168))
            {
                return allowPrivate;
            }

            return first switch
            {
                0 or 127 => false,
                100 when second is >= 64 and <= 127 => false,
                169 when second == 254 => false,
                192 when second is 0 or 2 or 88 => false,
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
}
