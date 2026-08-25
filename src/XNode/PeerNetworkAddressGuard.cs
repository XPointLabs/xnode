using System.Net;
using System.Net.Sockets;

namespace XNode;

internal static class PeerNetworkAddressGuard
{
    public static bool IsPubliclyRoutable(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address))
            return false;

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
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

        if (address.AddressFamily != AddressFamily.InterNetworkV6
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.IPv6None)
            || address.IsIPv6LinkLocal
            || address.IsIPv6SiteLocal
            || address.IsIPv6Multicast)
            return false;

        return (bytes[0] & 0xe0) == 0x20
            && !HasPrefix(bytes, "2001::", 32)
            && !HasPrefix(bytes, "2001:2::", 48)
            && !HasPrefix(bytes, "2001:10::", 28)
            && !HasPrefix(bytes, "2001:20::", 28)
            && !HasPrefix(bytes, "2001:db8::", 32)
            && !HasPrefix(bytes, "2002::", 16)
            && !HasPrefix(bytes, "3fff::", 20);
    }

    public static bool IsPrivate(IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
            return false;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
                || bytes[0] == 192 && bytes[1] == 168;
        }

        return address.AddressFamily == AddressFamily.InterNetworkV6
            && address.IsIPv6UniqueLocal;
    }

    private static bool HasPrefix(byte[] addressBytes, string prefix, int prefixLength)
    {
        var prefixBytes = IPAddress.Parse(prefix).GetAddressBytes();
        var wholeBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;
        for (var index = 0; index < wholeBytes; index++)
        {
            if (addressBytes[index] != prefixBytes[index])
                return false;
        }

        if (remainingBits == 0)
            return true;
        var mask = (byte)(0xff << (8 - remainingBits));
        return (addressBytes[wholeBytes] & mask) == (prefixBytes[wholeBytes] & mask);
    }
}
