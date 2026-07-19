using System.Buffers;

namespace XNode.ProfileGenerator;

internal static class ProfileFraming
{
    private static ReadOnlySpan<byte> Magic => "DPF1"u8;
    public const byte Version = 1;

    public static byte[] Encode(IReadOnlyList<ProfileComponent> components)
    {
        if (components.Count is 0 or > ProfileComposerLimits.MaximumComponents)
            throw ProfileErrors.Bounds();

        var bodyLength = 0;
        foreach (var component in components)
        {
            if (component.Bytes.Length is 0 or > ProfileComposerLimits.MaximumComponentBytes)
                throw ProfileErrors.Bounds();
            bodyLength = checked(bodyLength + 1 + VarUIntLength((uint)component.Bytes.Length) +
                component.Bytes.Length);
        }

        var totalLength = checked(
            Magic.Length + 2 + VarUIntLength((uint)bodyLength) + bodyLength);
        if (!ProfileComposerLimits.IsFilePayloadLengthAllowed(totalLength))
            throw ProfileErrors.Bounds();

        var writer = new ArrayBufferWriter<byte>(totalLength);
        Write(writer, Magic);
        WriteByte(writer, Version);
        WriteByte(writer, checked((byte)components.Count));
        WriteVarUInt(writer, (uint)bodyLength);
        foreach (var component in components)
        {
            WriteByte(writer, (byte)component.Kind);
            WriteVarUInt(writer, (uint)component.Bytes.Length);
            Write(writer, component.Bytes);
        }
        return writer.WrittenSpan.ToArray();
    }

    public static IReadOnlyList<ProfileComponent> Decode(ReadOnlySpan<byte> encoded)
    {
        if (!ProfileComposerLimits.IsFilePayloadLengthAllowed(encoded.Length) ||
            encoded.Length < Magic.Length + 3)
            throw ProfileErrors.Framing();

        var reader = new ProfileReader(encoded);
        if (!reader.ReadFixed(Magic.Length).SequenceEqual(Magic))
            throw ProfileErrors.Framing();
        if (reader.ReadByte() != Version)
            throw ProfileErrors.Framing();
        var count = reader.ReadByte();
        if (count is 0 or > ProfileComposerLimits.MaximumComponents)
            throw ProfileErrors.Framing();
        var bodyLength = reader.ReadVarUInt();
        if (bodyLength != reader.Remaining)
            throw ProfileErrors.Framing();

        var result = new ProfileComponent[count];
        for (var index = 0; index < count; index++)
        {
            var kind = (ProfileComponentKind)reader.ReadByte();
            if (!Enum.IsDefined(kind))
                throw ProfileErrors.Framing();
            var length = reader.ReadVarUInt();
            if (length is 0 or > ProfileComposerLimits.MaximumComponentBytes)
                throw ProfileErrors.Framing();
            result[index] = new ProfileComponent(
                kind,
                reader.ReadFixed(checked((int)length)).ToArray());
        }
        if (reader.Remaining != 0)
            throw ProfileErrors.Framing();
        return result;
    }

    private static int VarUIntLength(uint value)
    {
        var length = 1;
        while (value >= 0x80)
        {
            value >>= 7;
            length++;
        }
        return length;
    }

    private static void WriteVarUInt(IBufferWriter<byte> writer, uint value)
    {
        do
        {
            var next = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
                next |= 0x80;
            WriteByte(writer, next);
        } while (value != 0);
    }

    private static void WriteByte(IBufferWriter<byte> writer, byte value)
    {
        var span = writer.GetSpan(1);
        span[0] = value;
        writer.Advance(1);
    }

    private static void Write(IBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private ref struct ProfileReader
    {
        private readonly ReadOnlySpan<byte> _source;
        private int _offset;

        public ProfileReader(ReadOnlySpan<byte> source)
        {
            _source = source;
            _offset = 0;
        }

        public int Remaining => _source.Length - _offset;

        public byte ReadByte()
        {
            if (Remaining < 1)
                throw ProfileErrors.Framing();
            return _source[_offset++];
        }

        public ReadOnlySpan<byte> ReadFixed(int length)
        {
            if (length < 0 || Remaining < length)
                throw ProfileErrors.Framing();
            var result = _source.Slice(_offset, length);
            _offset += length;
            return result;
        }

        public uint ReadVarUInt()
        {
            uint value = 0;
            var shift = 0;
            var count = 0;
            while (true)
            {
                if (count == 5)
                    throw ProfileErrors.Framing();
                var current = ReadByte();
                count++;
                if (count == 5 && (current & 0xf0) != 0)
                    throw ProfileErrors.Framing();
                value |= (uint)(current & 0x7f) << shift;
                if ((current & 0x80) == 0)
                {
                    if (count != VarUIntLength(value))
                        throw ProfileErrors.Framing();
                    return value;
                }
                shift += 7;
            }
        }
    }
}
