using System.Buffers.Binary;
using System.Security.Cryptography;

namespace XNode.Core.PrivacyRouting;

internal readonly struct OnionHash32 : IEquatable<OnionHash32>, IComparable<OnionHash32>
{
    private readonly ulong a;
    private readonly ulong b;
    private readonly ulong c;
    private readonly ulong d;

    internal OnionHash32(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32)
        {
            throw new ArgumentException("A 32-byte ONION identifier is required.", nameof(value));
        }

        byte aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        if (aggregate == 0)
        {
            throw new ArgumentException("An all-zero ONION identifier is invalid.", nameof(value));
        }

        a = BinaryPrimitives.ReadUInt64BigEndian(value);
        b = BinaryPrimitives.ReadUInt64BigEndian(value[8..]);
        c = BinaryPrimitives.ReadUInt64BigEndian(value[16..]);
        d = BinaryPrimitives.ReadUInt64BigEndian(value[24..]);
    }

    internal void Write(Span<byte> destination)
    {
        if (destination.Length < 32)
        {
            throw new ArgumentException("The destination is too small.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt64BigEndian(destination, a);
        BinaryPrimitives.WriteUInt64BigEndian(destination[8..], b);
        BinaryPrimitives.WriteUInt64BigEndian(destination[16..], c);
        BinaryPrimitives.WriteUInt64BigEndian(destination[24..], d);
    }

    public bool Equals(OnionHash32 other)
    {
        Span<byte> left = stackalloc byte[32];
        Span<byte> right = stackalloc byte[32];
        Write(left);
        other.Write(right);
        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    public override bool Equals(object? obj) => obj is OnionHash32 other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(a, b, c, d);

    public int CompareTo(OnionHash32 other)
    {
        var result = a.CompareTo(other.a);
        if (result != 0) return result;
        result = b.CompareTo(other.b);
        if (result != 0) return result;
        result = c.CompareTo(other.c);
        return result != 0 ? result : d.CompareTo(other.d);
    }
}
