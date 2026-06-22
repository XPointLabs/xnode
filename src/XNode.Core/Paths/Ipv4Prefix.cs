using System.Buffers.Binary;
using System.Net;

namespace XNode.Core.Paths;

internal readonly record struct Ipv4Prefix(uint Network, uint Mask)
{
    public static Ipv4Prefix FromAddress(IPAddress address, int prefixLength)
    {
        if (prefixLength is < 0 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(prefixLength), "IPv4 prefix must be between 0 and 32.");
        }

        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out var written) || written != 4)
        {
            throw new ArgumentException("Expected an IPv4 address.", nameof(address));
        }

        var value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        return new Ipv4Prefix(value & mask, mask);
    }

    public bool Contains(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        if (!address.TryWriteBytes(bytes, out var written) || written != 4)
        {
            return false;
        }

        var value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        return (value & Mask) == Network;
    }
}
