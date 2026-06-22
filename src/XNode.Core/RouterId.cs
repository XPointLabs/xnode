using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace XNode.Core;

[JsonConverter(typeof(RouterIdJsonConverter))]
public readonly record struct RouterId : IComparable<RouterId>
{
    public const int ByteLength = 32;
    public const int HexLength = ByteLength * 2;

    private readonly string? _value;

    public RouterId(string value)
    {
        if (!IsValidHex(value))
        {
            throw new ArgumentException("RouterId must be a 32-byte lower or upper case hex string.", nameof(value));
        }

        _value = value.ToLowerInvariant();
    }

    public string Value => _value ?? string.Empty;

    public static RouterId FromHex(string value) => new(value);

    public static RouterId FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != ByteLength)
        {
            throw new ArgumentException($"RouterId must contain {ByteLength} bytes.", nameof(bytes));
        }

        return new RouterId(Convert.ToHexString(bytes).ToLowerInvariant());
    }

    public byte[] ToBytes()
    {
        if (Value.Length != HexLength)
        {
            throw new InvalidOperationException("Cannot convert an empty RouterId to bytes.");
        }

        return Convert.FromHexString(Value);
    }

    public int CompareTo(RouterId other) => StringComparer.Ordinal.Compare(Value, other.Value);

    public override string ToString() => Value;

    public static bool TryParse(string? value, out RouterId routerId)
    {
        if (value is not null && IsValidHex(value))
        {
            routerId = new RouterId(value);
            return true;
        }

        routerId = default;
        return false;
    }

    private static bool IsValidHex(string value)
    {
        if (value.Length != HexLength)
        {
            return false;
        }

        foreach (var c in value)
        {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex)
            {
                return false;
            }
        }

        return true;
    }
}

public sealed class RouterIdJsonConverter : JsonConverter<RouterId>
{
    public override RouterId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (!RouterId.TryParse(value, out var routerId))
        {
            throw new JsonException("Expected a 32-byte hex router id.");
        }

        return routerId;
    }

    public override void Write(Utf8JsonWriter writer, RouterId value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.Value);
    }
}
