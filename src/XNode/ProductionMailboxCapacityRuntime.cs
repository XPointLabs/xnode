using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace XNode;

public enum ProductionMailboxCapacityOperation : byte
{
    ReserveOrRenew = 1,
    Release = 2
}

public sealed record ProductionMailboxCapacityCommand(
    ProductionMailboxCapacityOperation Operation,
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> CohortId,
    ReadOnlyMemory<byte> TargetReplicaId,
    uint ReservedClosureCount,
    ulong ReservedBytes,
    ulong Revision,
    ReadOnlyMemory<byte> PublisherSignature);

public static class ProductionMailboxCapacityCommandCodec
{
    private static ReadOnlySpan<byte> Magic => "PMB1"u8;
    private static ReadOnlySpan<byte> SignatureDomain =>
        "Deep/PMB1/capacity-command/v1"u8;
    public const int EncodedLength = 208;

    public static byte[] Encode(ProductionMailboxCapacityCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return EncodeCore(Freeze(value, allowZeroSignature: false));
    }

    private static byte[] EncodeCore(ProductionMailboxCapacityCommand value)
    {
        var output = new byte[EncodedLength];
        Magic.CopyTo(output);
        output[4] = 1;
        output[5] = (byte)value.Operation;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8),
            value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16),
            value.ExpiresAtUnixSeconds);
        value.Nonce.Span.CopyTo(output.AsSpan(24));
        value.CohortId.Span.CopyTo(output.AsSpan(56));
        value.TargetReplicaId.Span.CopyTo(output.AsSpan(88));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(120),
            value.ReservedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(124),
            value.ReservedBytes);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(132), value.Revision);
        value.PublisherSignature.Span.CopyTo(output.AsSpan(140));
        return output;
    }

    public static ProductionMailboxCapacityCommand Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength
            || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(204, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox capacity command header is invalid.");
        var value = new ProductionMailboxCapacityCommand(
            (ProductionMailboxCapacityOperation)encoded[5],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            encoded.Slice(88, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[120..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[124..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[132..]),
            encoded.Slice(140, 64).ToArray());
        Validate(value);
        return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxCapacityCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var frozen = Freeze(value, allowZeroSignature: true);
        var encoded = EncodeCore(frozen with { PublisherSignature = new byte[64] });
        var output = new byte[SignatureDomain.Length + 140];
        SignatureDomain.CopyTo(output);
        encoded.AsSpan(0, 140).CopyTo(output.AsSpan(SignatureDomain.Length));
        return output;
    }

    public static bool VerifyPublisher(
        ProductionMailboxCapacityCommand value, ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32) return false;
        try
        {
            var frozen = Freeze(value, allowZeroSignature: false);
            var encoded = EncodeCore(frozen with { PublisherSignature = new byte[64] });
            var signingBytes = new byte[SignatureDomain.Length + 140];
            SignatureDomain.CopyTo(signingBytes);
            encoded.AsSpan(0, 140).CopyTo(
                signingBytes.AsSpan(SignatureDomain.Length));
            return PublicKeyAuth.VerifyDetached(frozen.PublisherSignature.ToArray(),
                signingBytes, publicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or ArgumentException)
        { return false; }
    }

    private static void Validate(
        ProductionMailboxCapacityCommand value, bool allowZeroSignature = false)
    {
        if (value.Operation is not (ProductionMailboxCapacityOperation.ReserveOrRenew
                or ProductionMailboxCapacityOperation.Release)
            || value.TimestampUnixSeconds == 0 || value.ExpiresAtUnixSeconds == 0
            || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.Revision == 0 || Invalid(value.Nonce, 32)
            || Invalid(value.CohortId, 32) || Invalid(value.TargetReplicaId, 32)
            || value.PublisherSignature.Length != 64
            || !allowZeroSignature
                && value.PublisherSignature.Span.IndexOfAnyExcept((byte)0) < 0
            || value.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
                && (value.ReservedClosureCount == 0 || value.ReservedBytes == 0)
            || value.Operation == ProductionMailboxCapacityOperation.Release
                && (value.ReservedClosureCount != 0 || value.ReservedBytes != 0))
            throw new InvalidDataException(
                "Production mailbox capacity command fields are invalid.");
    }

    private static ProductionMailboxCapacityCommand Freeze(
        ProductionMailboxCapacityCommand value, bool allowZeroSignature)
    {
        if (value.Nonce.Length != 32 || value.CohortId.Length != 32
            || value.TargetReplicaId.Length != 32
            || value.PublisherSignature.Length != 64)
            throw new InvalidDataException(
                "Production mailbox capacity command fields are invalid.");
        var frozen = value with
        {
            Nonce = value.Nonce.ToArray(),
            CohortId = value.CohortId.ToArray(),
            TargetReplicaId = value.TargetReplicaId.ToArray(),
            PublisherSignature = value.PublisherSignature.ToArray()
        };
        Validate(frozen, allowZeroSignature);
        return frozen;
    }

    private static bool Invalid(ReadOnlyMemory<byte> value, int length) =>
        value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0;
}

public sealed record ProductionMailboxCapacityReceipt(
    ProductionMailboxCapacityOperation Operation,
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> CohortId,
    ReadOnlyMemory<byte> TargetReplicaId,
    uint ReservedClosureCount,
    ulong ReservedBytes,
    uint ConsumedClosureCount,
    ulong ConsumedBytes,
    ulong Revision,
    ReadOnlyMemory<byte> CommandSha256,
    ReadOnlyMemory<byte> NodeSignature);

public static class ProductionMailboxCapacityReceiptCodec
{
    private static ReadOnlySpan<byte> Magic => "PMB2"u8;
    private static ReadOnlySpan<byte> SignatureDomain =>
        "Deep/PMB2/capacity-receipt/v1"u8;
    public const int EncodedLength = 248;

    public static byte[] Encode(ProductionMailboxCapacityReceipt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return EncodeCore(Freeze(value, allowZeroSignature: false));
    }

    private static byte[] EncodeCore(ProductionMailboxCapacityReceipt value)
    {
        var output = new byte[EncodedLength];
        Magic.CopyTo(output); output[4] = 1; output[5] = (byte)value.Operation;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8),
            value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16),
            value.ExpiresAtUnixSeconds);
        value.CohortId.Span.CopyTo(output.AsSpan(24));
        value.TargetReplicaId.Span.CopyTo(output.AsSpan(56));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(88),
            value.ReservedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(92), value.ReservedBytes);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(100),
            value.ConsumedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(104), value.ConsumedBytes);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(112), value.Revision);
        value.CommandSha256.Span.CopyTo(output.AsSpan(120));
        value.NodeSignature.Span.CopyTo(output.AsSpan(152));
        return output;
    }

    public static ProductionMailboxCapacityReceipt Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(216, 32).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox capacity receipt header is invalid.");
        var value = new ProductionMailboxCapacityReceipt(
            (ProductionMailboxCapacityOperation)encoded[5],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[88..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[92..]),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[100..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[104..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[112..]),
            encoded.Slice(120, 32).ToArray(), encoded.Slice(152, 64).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxCapacityReceipt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var frozen = Freeze(value, allowZeroSignature: true);
        var encoded = EncodeCore(frozen with { NodeSignature = new byte[64] });
        var output = new byte[SignatureDomain.Length + 152];
        SignatureDomain.CopyTo(output);
        encoded.AsSpan(0, 152).CopyTo(output.AsSpan(SignatureDomain.Length));
        return output;
    }

    public static bool VerifyNode(
        ProductionMailboxCapacityReceipt value, ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32) return false;
        try
        {
            var frozen = Freeze(value, allowZeroSignature: false);
            var encoded = EncodeCore(frozen with { NodeSignature = new byte[64] });
            var signingBytes = new byte[SignatureDomain.Length + 152];
            SignatureDomain.CopyTo(signingBytes);
            encoded.AsSpan(0, 152).CopyTo(
                signingBytes.AsSpan(SignatureDomain.Length));
            return PublicKeyAuth.VerifyDetached(frozen.NodeSignature.ToArray(),
                signingBytes, publicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or ArgumentException)
        { return false; }
    }

    private static void Validate(
        ProductionMailboxCapacityReceipt value, bool allowZeroSignature = false)
    {
        if (value.Operation is not (ProductionMailboxCapacityOperation.ReserveOrRenew
                or ProductionMailboxCapacityOperation.Release)
            || value.TimestampUnixSeconds == 0 || value.ExpiresAtUnixSeconds == 0
            || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.Revision == 0 || Invalid(value.CohortId, 32)
            || Invalid(value.TargetReplicaId, 32) || Invalid(value.CommandSha256, 32)
            || value.NodeSignature.Length != 64
            || !allowZeroSignature
                && value.NodeSignature.Span.IndexOfAnyExcept((byte)0) < 0
            || value.ConsumedClosureCount > value.ReservedClosureCount
            || value.ConsumedBytes > value.ReservedBytes
            || value.Operation == ProductionMailboxCapacityOperation.Release
                && (value.ReservedClosureCount != value.ConsumedClosureCount
                    || value.ReservedBytes != value.ConsumedBytes))
            throw new InvalidDataException(
                "Production mailbox capacity receipt fields are invalid.");
    }

    private static ProductionMailboxCapacityReceipt Freeze(
        ProductionMailboxCapacityReceipt value, bool allowZeroSignature)
    {
        if (value.CohortId.Length != 32 || value.TargetReplicaId.Length != 32
            || value.CommandSha256.Length != 32 || value.NodeSignature.Length != 64)
            throw new InvalidDataException(
                "Production mailbox capacity receipt fields are invalid.");
        var frozen = value with
        {
            CohortId = value.CohortId.ToArray(),
            TargetReplicaId = value.TargetReplicaId.ToArray(),
            CommandSha256 = value.CommandSha256.ToArray(),
            NodeSignature = value.NodeSignature.ToArray()
        };
        Validate(frozen, allowZeroSignature);
        return frozen;
    }

    private static bool Invalid(ReadOnlyMemory<byte> value, int length) =>
        value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0;
}

public sealed record ProductionMailboxCapacityReconciliationCommand(
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> CohortId,
    ReadOnlyMemory<byte> TargetReplicaId,
    ulong LastKnownRevision,
    ReadOnlyMemory<byte> LastCanonicalReceipt,
    ReadOnlyMemory<byte> LastReceiptSha256,
    ReadOnlyMemory<byte> LastCommandSha256,
    ReadOnlyMemory<byte> PublisherSignature);

public static class ProductionMailboxCapacityReconciliationCommandCodec
{
    private static ReadOnlySpan<byte> Magic => "PMB3"u8;
    private static ReadOnlySpan<byte> SignatureDomain =>
        "Deep/PMB3/capacity-reconciliation-command/v1"u8;
    public const int EncodedLength = 504;

    public static byte[] Encode(ProductionMailboxCapacityReconciliationCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return EncodeCore(Freeze(value, false));
    }

    public static ProductionMailboxCapacityReconciliationCommand Decode(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Capacity reconciliation command header is invalid.");
        var value = new ProductionMailboxCapacityReconciliationCommand(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            encoded.Slice(88, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[120..]),
            encoded.Slice(128, ProductionMailboxCapacityReceiptCodec.EncodedLength).ToArray(),
            encoded.Slice(376, 32).ToArray(), encoded.Slice(408, 32).ToArray(),
            encoded.Slice(440, 64).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(
        ProductionMailboxCapacityReconciliationCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var frozen = Freeze(value, true);
        var encoded = EncodeCore(frozen with { PublisherSignature = new byte[64] });
        var output = new byte[SignatureDomain.Length + 440];
        SignatureDomain.CopyTo(output);
        encoded.AsSpan(0, 440).CopyTo(output.AsSpan(SignatureDomain.Length));
        return output;
    }

    public static bool VerifyPublisher(
        ProductionMailboxCapacityReconciliationCommand value,
        ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32) return false;
        try
        {
            var frozen = Freeze(value, false);
            return PublicKeyAuth.VerifyDetached(frozen.PublisherSignature.ToArray(),
                GetSigningBytes(frozen), publicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or ArgumentException)
        { return false; }
    }

    private static byte[] EncodeCore(
        ProductionMailboxCapacityReconciliationCommand value)
    {
        var output = new byte[EncodedLength];
        Magic.CopyTo(output); output[4] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.Nonce.Span.CopyTo(output.AsSpan(24));
        value.CohortId.Span.CopyTo(output.AsSpan(56));
        value.TargetReplicaId.Span.CopyTo(output.AsSpan(88));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(120), value.LastKnownRevision);
        value.LastCanonicalReceipt.Span.CopyTo(output.AsSpan(128));
        value.LastReceiptSha256.Span.CopyTo(output.AsSpan(376));
        value.LastCommandSha256.Span.CopyTo(output.AsSpan(408));
        value.PublisherSignature.Span.CopyTo(output.AsSpan(440));
        return output;
    }

    private static ProductionMailboxCapacityReconciliationCommand Freeze(
        ProductionMailboxCapacityReconciliationCommand value, bool allowZeroSignature)
    {
        if (value.Nonce.Length != 32 || value.CohortId.Length != 32
            || value.TargetReplicaId.Length != 32
            || value.LastCanonicalReceipt.Length != ProductionMailboxCapacityReceiptCodec.EncodedLength
            || value.LastReceiptSha256.Length != 32 || value.LastCommandSha256.Length != 32
            || value.PublisherSignature.Length != 64)
            throw new InvalidDataException("Capacity reconciliation command fields are invalid.");
        var frozen = value with
        {
            Nonce = value.Nonce.ToArray(), CohortId = value.CohortId.ToArray(),
            TargetReplicaId = value.TargetReplicaId.ToArray(),
            LastCanonicalReceipt = value.LastCanonicalReceipt.ToArray(),
            LastReceiptSha256 = value.LastReceiptSha256.ToArray(),
            LastCommandSha256 = value.LastCommandSha256.ToArray(),
            PublisherSignature = value.PublisherSignature.ToArray()
        };
        Validate(frozen, allowZeroSignature); return frozen;
    }

    private static void Validate(ProductionMailboxCapacityReconciliationCommand value,
        bool allowZeroSignature = false)
    {
        var receipt = ProductionMailboxCapacityReceiptCodec.Decode(
            value.LastCanonicalReceipt.Span);
        if (value.TimestampUnixSeconds == 0 || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.LastKnownRevision == 0 || value.Nonce.Span.IndexOfAnyExcept((byte)0) < 0
            || value.CohortId.Span.IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Span.IndexOfAnyExcept((byte)0) < 0
            || value.LastReceiptSha256.Span.IndexOfAnyExcept((byte)0) < 0
            || value.LastCommandSha256.Span.IndexOfAnyExcept((byte)0) < 0
            || value.PublisherSignature.Length != 64
            || !allowZeroSignature && value.PublisherSignature.Span.IndexOfAnyExcept((byte)0) < 0
            || receipt.Revision != value.LastKnownRevision
            || !CryptographicOperations.FixedTimeEquals(receipt.CohortId.Span, value.CohortId.Span)
            || !CryptographicOperations.FixedTimeEquals(receipt.TargetReplicaId.Span,
                value.TargetReplicaId.Span)
            || !CryptographicOperations.FixedTimeEquals(receipt.CommandSha256.Span,
                value.LastCommandSha256.Span)
            || !CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(value.LastCanonicalReceipt.Span), value.LastReceiptSha256.Span))
            throw new InvalidDataException("Capacity reconciliation command fields are invalid.");
    }
}

public enum ProductionMailboxCapacityReconciliationStatus : byte
{
    AbsentTerminal = 1
}

public sealed record ProductionMailboxCapacityReconciliationReceipt(
    ProductionMailboxCapacityReconciliationStatus Status,
    ulong TimestampUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> CohortId,
    ReadOnlyMemory<byte> TargetReplicaId,
    ulong LastKnownRevision,
    ReadOnlyMemory<byte> LastReceiptSha256,
    ReadOnlyMemory<byte> LastCommandSha256,
    uint AccountedClosureCount,
    ulong AccountedBytes,
    ReadOnlyMemory<byte> AuthoritativeStateSha256,
    ReadOnlyMemory<byte> NodeSignature);

public static class ProductionMailboxCapacityReconciliationReceiptCodec
{
    private static ReadOnlySpan<byte> Magic => "PMB4"u8;
    private static ReadOnlySpan<byte> SignatureDomain =>
        "Deep/PMB4/capacity-reconciliation-receipt/v1"u8;
    public const int EncodedLength = 272;

    public static byte[] Encode(ProductionMailboxCapacityReconciliationReceipt value)
    { ArgumentNullException.ThrowIfNull(value); return EncodeCore(Freeze(value, false)); }

    public static ProductionMailboxCapacityReconciliationReceipt Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(164, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Capacity reconciliation receipt header is invalid.");
        var value = new ProductionMailboxCapacityReconciliationReceipt(
            (ProductionMailboxCapacityReconciliationStatus)encoded[5],
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[16..]),
            encoded.Slice(24, 32).ToArray(), encoded.Slice(56, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[88..]),
            encoded.Slice(96, 32).ToArray(), encoded.Slice(128, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[160..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[168..]),
            encoded.Slice(176, 32).ToArray(), encoded.Slice(208, 64).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxCapacityReconciliationReceipt value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var frozen = Freeze(value, true);
        var encoded = EncodeCore(frozen with { NodeSignature = new byte[64] });
        var output = new byte[SignatureDomain.Length + 208];
        SignatureDomain.CopyTo(output); encoded.AsSpan(0, 208)
            .CopyTo(output.AsSpan(SignatureDomain.Length)); return output;
    }

    public static bool VerifyNode(ProductionMailboxCapacityReconciliationReceipt value,
        ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32) return false;
        try
        {
            var frozen = Freeze(value, false);
            return PublicKeyAuth.VerifyDetached(frozen.NodeSignature.ToArray(),
                GetSigningBytes(frozen), publicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or ArgumentException) { return false; }
    }

    private static byte[] EncodeCore(ProductionMailboxCapacityReconciliationReceipt value)
    {
        var output = new byte[EncodedLength]; Magic.CopyTo(output); output[4] = 1;
        output[5] = (byte)value.Status;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8), value.TimestampUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(16), value.ExpiresAtUnixSeconds);
        value.CohortId.Span.CopyTo(output.AsSpan(24));
        value.TargetReplicaId.Span.CopyTo(output.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(88), value.LastKnownRevision);
        value.LastReceiptSha256.Span.CopyTo(output.AsSpan(96));
        value.LastCommandSha256.Span.CopyTo(output.AsSpan(128));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(160), value.AccountedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(168), value.AccountedBytes);
        value.AuthoritativeStateSha256.Span.CopyTo(output.AsSpan(176));
        value.NodeSignature.Span.CopyTo(output.AsSpan(208)); return output;
    }

    private static ProductionMailboxCapacityReconciliationReceipt Freeze(
        ProductionMailboxCapacityReconciliationReceipt value, bool allowZeroSignature)
    {
        if (value.CohortId.Length != 32 || value.TargetReplicaId.Length != 32
            || value.LastReceiptSha256.Length != 32 || value.LastCommandSha256.Length != 32
            || value.AuthoritativeStateSha256.Length != 32 || value.NodeSignature.Length != 64)
            throw new InvalidDataException("Capacity reconciliation receipt fields are invalid.");
        var frozen = value with
        {
            CohortId = value.CohortId.ToArray(), TargetReplicaId = value.TargetReplicaId.ToArray(),
            LastReceiptSha256 = value.LastReceiptSha256.ToArray(),
            LastCommandSha256 = value.LastCommandSha256.ToArray(),
            AuthoritativeStateSha256 = value.AuthoritativeStateSha256.ToArray(),
            NodeSignature = value.NodeSignature.ToArray()
        };
        Validate(frozen, allowZeroSignature); return frozen;
    }

    private static void Validate(ProductionMailboxCapacityReconciliationReceipt value,
        bool allowZeroSignature = false)
    {
        if (value.Status != ProductionMailboxCapacityReconciliationStatus.AbsentTerminal
            || value.TimestampUnixSeconds == 0 || value.ExpiresAtUnixSeconds <= value.TimestampUnixSeconds
            || value.LastKnownRevision == 0 || value.CohortId.Span.IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Span.IndexOfAnyExcept((byte)0) < 0
            || value.LastReceiptSha256.Span.IndexOfAnyExcept((byte)0) < 0
            || value.LastCommandSha256.Span.IndexOfAnyExcept((byte)0) < 0
            || value.AuthoritativeStateSha256.Span.IndexOfAnyExcept((byte)0) < 0
            || !allowZeroSignature && value.NodeSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidDataException("Capacity reconciliation receipt fields are invalid.");
    }
}

internal sealed record ProductionMailboxCapacityReservation(
    ReadOnlyMemory<byte> CohortId,
    ReadOnlyMemory<byte> TargetReplicaId,
    ulong Revision,
    ulong StateGeneration,
    bool Terminal,
    uint ReservedClosureCount,
    ulong ReservedBytes,
    uint ConsumedClosureCount,
    ulong ConsumedBytes,
    ulong ExpiresAtUnixSeconds,
    ulong RetainUntilUnixSeconds,
    ReadOnlyMemory<byte> LastCommandSha256,
    ReadOnlyMemory<byte> PredecessorMarkerSha256,
    ReadOnlyMemory<byte> LastCanonicalReceipt);

internal static class ProductionMailboxCapacityLedgerCodec
{
    private static ReadOnlySpan<byte> Magic => "PBL1"u8;
    private static ReadOnlySpan<byte> MacDomain =>
        "Deep/PBL1/capacity-ledger/v1"u8;
    private const int HeaderLength = 40;
    internal const int RecordLength = 436;

    internal static byte[] Encode(
        IReadOnlyList<ProductionMailboxCapacityReservation> reservations,
        ReadOnlySpan<byte> hmacKey,
        int maximumReservations)
    {
        ArgumentNullException.ThrowIfNull(reservations);
        if (hmacKey.Length != 32 || reservations.Count > maximumReservations)
            throw new InvalidDataException("Production mailbox capacity ledger is invalid.");
        var frozen = reservations.Select(Freeze)
            .OrderBy(static value => Convert.ToHexString(value.CohortId.Span),
                StringComparer.Ordinal)
            .ToArray();
        for (var index = 1; index < frozen.Length; index++)
            if (frozen[index - 1].CohortId.Span.SequenceEqual(frozen[index].CohortId.Span))
                throw new InvalidDataException("Production mailbox capacity cohort is duplicated.");
        var output = new byte[checked(HeaderLength + frozen.Length * RecordLength)];
        Magic.CopyTo(output); output[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), checked((ushort)frozen.Length));
        var offset = HeaderLength;
        foreach (var value in frozen)
        {
            EncodeRecord(value, output.AsSpan(offset, RecordLength));
            offset += RecordLength;
        }
        ComputeMac(output, hmacKey).CopyTo(output.AsSpan(8));
        return output;
    }

    internal static IReadOnlyList<ProductionMailboxCapacityReservation> Decode(
        ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> hmacKey,
        int maximumReservations)
    {
        if (encoded.Length < HeaderLength || hmacKey.Length != 32
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 1
            || encoded[5] != 0)
            throw new InvalidDataException("Production mailbox capacity ledger header is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded[6..]);
        if (count > maximumReservations
            || encoded.Length != checked(HeaderLength + count * RecordLength)
            || !CryptographicOperations.FixedTimeEquals(encoded.Slice(8, 32),
                ComputeMac(encoded, hmacKey)))
            throw new InvalidDataException("Production mailbox capacity ledger is invalid.");
        var values = new ProductionMailboxCapacityReservation[count];
        var offset = HeaderLength;
        for (var index = 0; index < count; index++)
        {
            values[index] = DecodeRecord(encoded.Slice(offset, RecordLength));
            offset += RecordLength;
        }
        var canonical = Encode(values, hmacKey, maximumReservations);
        if (!canonical.AsSpan().SequenceEqual(encoded))
            throw new InvalidDataException("Production mailbox capacity ledger is non-canonical.");
        return values;
    }

    internal static ProductionMailboxCapacityReservation Freeze(
        ProductionMailboxCapacityReservation value)
    {
        ProductionMailboxCapacityReceipt receipt;
        try
        {
            receipt = ProductionMailboxCapacityReceiptCodec.Decode(
                value.LastCanonicalReceipt.Span);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or ArgumentException)
        {
            throw new InvalidDataException(
                "Production mailbox capacity receipt is invalid.", exception);
        }
        if (value.CohortId.Length != 32
            || value.CohortId.Span.IndexOfAnyExcept((byte)0) < 0
            || value.TargetReplicaId.Length != 32
            || value.TargetReplicaId.Span.IndexOfAnyExcept((byte)0) < 0
            || value.Revision == 0 || value.StateGeneration == 0
            || value.StateGeneration == 1
                != (value.PredecessorMarkerSha256.Span.IndexOfAnyExcept((byte)0) < 0)
            || !value.Terminal
                && receipt.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
                && (value.ReservedClosureCount == 0 || value.ReservedBytes == 0)
            || receipt.Operation == ProductionMailboxCapacityOperation.Release
                && (value.ReservedClosureCount != value.ConsumedClosureCount
                    || value.ReservedBytes != value.ConsumedBytes)
            || value.ConsumedClosureCount > value.ReservedClosureCount
            || value.ConsumedBytes > value.ReservedBytes
            || value.ExpiresAtUnixSeconds == 0
            || value.Terminal && (value.ReservedClosureCount != value.ConsumedClosureCount
                || value.ReservedBytes != value.ConsumedBytes
                || value.RetainUntilUnixSeconds <= value.ExpiresAtUnixSeconds)
            || !value.Terminal && value.RetainUntilUnixSeconds != 0
            || value.LastCommandSha256.Length != 32
            || value.LastCommandSha256.Span.IndexOfAnyExcept((byte)0) < 0
            || value.PredecessorMarkerSha256.Length != 32
            || value.LastCanonicalReceipt.Length
                != ProductionMailboxCapacityReceiptCodec.EncodedLength)
            throw new InvalidDataException("Production mailbox capacity reservation is invalid.");
        if (!receipt.CohortId.Span.SequenceEqual(value.CohortId.Span)
            || !receipt.TargetReplicaId.Span.SequenceEqual(value.TargetReplicaId.Span)
            || receipt.Revision != value.Revision
            || !receipt.CommandSha256.Span.SequenceEqual(value.LastCommandSha256.Span))
            throw new InvalidDataException("Production mailbox capacity receipt is unrelated.");
        return value with
        {
            CohortId = value.CohortId.ToArray(),
            TargetReplicaId = value.TargetReplicaId.ToArray(),
            LastCommandSha256 = value.LastCommandSha256.ToArray(),
            PredecessorMarkerSha256 = value.PredecessorMarkerSha256.ToArray(),
            LastCanonicalReceipt = value.LastCanonicalReceipt.ToArray()
        };
    }

    internal static void EncodeRecord(
        ProductionMailboxCapacityReservation value, Span<byte> output)
    {
        var frozen = Freeze(value);
        if (output.Length != RecordLength)
            throw new InvalidDataException("Production mailbox capacity record is invalid.");
        frozen.CohortId.Span.CopyTo(output);
        frozen.TargetReplicaId.Span.CopyTo(output[32..]);
        BinaryPrimitives.WriteUInt64BigEndian(output[64..], frozen.Revision);
        BinaryPrimitives.WriteUInt64BigEndian(output[72..], frozen.StateGeneration);
        output[80] = frozen.Terminal ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteUInt32BigEndian(output[84..], frozen.ReservedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output[88..], frozen.ReservedBytes);
        BinaryPrimitives.WriteUInt32BigEndian(output[96..], frozen.ConsumedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output[100..], frozen.ConsumedBytes);
        BinaryPrimitives.WriteUInt64BigEndian(output[108..], frozen.ExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt64BigEndian(output[116..], frozen.RetainUntilUnixSeconds);
        frozen.LastCommandSha256.Span.CopyTo(output[124..]);
        frozen.PredecessorMarkerSha256.Span.CopyTo(output[156..]);
        frozen.LastCanonicalReceipt.Span.CopyTo(output[188..]);
    }

    internal static ProductionMailboxCapacityReservation DecodeRecord(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != RecordLength || encoded[80] > 1
            || encoded.Slice(81, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox capacity record is invalid.");
        return Freeze(new(
            encoded[..32].ToArray(), encoded.Slice(32, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[64..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[72..]), encoded[80] == 1,
            BinaryPrimitives.ReadUInt32BigEndian(encoded[84..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[88..]),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[96..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[100..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[108..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[116..]),
            encoded.Slice(124, 32).ToArray(), encoded.Slice(156, 32).ToArray(),
            encoded.Slice(188, ProductionMailboxCapacityReceiptCodec.EncodedLength)
                .ToArray()));
    }

    private static byte[] ComputeMac(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> key)
    {
        using var hmac = new HMACSHA256(key.ToArray());
        hmac.TransformBlock(MacDomain.ToArray(), 0, MacDomain.Length, null, 0);
        hmac.TransformBlock(encoded[..8].ToArray(), 0, 8, null, 0);
        var records = encoded[HeaderLength..].ToArray();
        hmac.TransformFinalBlock(records, 0, records.Length);
        return hmac.Hash!;
    }
}

internal sealed record ProductionMailboxCapacityTransferJournal(
    bool OldScheduleExists,
    ReadOnlyMemory<byte> SelectionInputCommitment,
    ReadOnlyMemory<byte> DurableOldSelectionHash,
    ReadOnlyMemory<byte> OldScheduleSha256,
    ReadOnlyMemory<byte> NewScheduleSha256,
    ReadOnlyMemory<byte> CohortId,
    uint BeforeConsumedClosureCount,
    ulong BeforeConsumedBytes,
    uint AfterConsumedClosureCount,
    ulong AfterConsumedBytes,
    ReadOnlyMemory<byte> BeforeLedgerSha256,
    ReadOnlyMemory<byte> AfterLedgerSha256,
    ReadOnlyMemory<byte> BeforeMarkerSha256,
    ReadOnlyMemory<byte> AfterMarkerSha256,
    ulong BeforeStateGeneration,
    ulong AfterStateGeneration);

internal static class ProductionMailboxCapacityTransferJournalCodec
{
    private static ReadOnlySpan<byte> Magic => "PBT1"u8;
    private static ReadOnlySpan<byte> MacDomain =>
        "Deep/PBT1/capacity-transfer/v1"u8;
    internal const int EncodedLength = 368;

    internal static byte[] Encode(ProductionMailboxCapacityTransferJournal value,
        ReadOnlySpan<byte> hmacKey)
    {
        Validate(value);
        if (hmacKey.Length != 32)
            throw new InvalidDataException("Production mailbox capacity transfer key is invalid.");
        var output = new byte[EncodedLength];
        Magic.CopyTo(output); output[4] = 1; output[5] = value.OldScheduleExists ? (byte)1 : (byte)0;
        value.SelectionInputCommitment.Span.CopyTo(output.AsSpan(8));
        value.DurableOldSelectionHash.Span.CopyTo(output.AsSpan(40));
        value.OldScheduleSha256.Span.CopyTo(output.AsSpan(72));
        value.NewScheduleSha256.Span.CopyTo(output.AsSpan(104));
        value.CohortId.Span.CopyTo(output.AsSpan(136));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(168),
            value.BeforeConsumedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(172), value.BeforeConsumedBytes);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(180),
            value.AfterConsumedClosureCount);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(184), value.AfterConsumedBytes);
        value.BeforeLedgerSha256.Span.CopyTo(output.AsSpan(192));
        value.AfterLedgerSha256.Span.CopyTo(output.AsSpan(224));
        value.BeforeMarkerSha256.Span.CopyTo(output.AsSpan(256));
        value.AfterMarkerSha256.Span.CopyTo(output.AsSpan(288));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(320),
            value.BeforeStateGeneration);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(328),
            value.AfterStateGeneration);
        ComputeMac(output, hmacKey).CopyTo(output.AsSpan(336));
        return output;
    }

    internal static ProductionMailboxCapacityTransferJournal Decode(
        ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> hmacKey)
    {
        if (encoded.Length != EncodedLength || hmacKey.Length != 32
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 1
            || encoded[5] > 1 || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || !CryptographicOperations.FixedTimeEquals(encoded[336..],
                ComputeMac(encoded, hmacKey)))
            throw new InvalidDataException("Production mailbox capacity transfer is invalid.");
        var value = new ProductionMailboxCapacityTransferJournal(
            encoded[5] == 1, encoded.Slice(8, 32).ToArray(),
            encoded.Slice(40, 32).ToArray(), encoded.Slice(72, 32).ToArray(),
            encoded.Slice(104, 32).ToArray(), encoded.Slice(136, 32).ToArray(),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[168..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[172..]),
            BinaryPrimitives.ReadUInt32BigEndian(encoded[180..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[184..]),
            encoded.Slice(192, 32).ToArray(), encoded.Slice(224, 32).ToArray(),
            encoded.Slice(256, 32).ToArray(), encoded.Slice(288, 32).ToArray(),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[320..]),
            BinaryPrimitives.ReadUInt64BigEndian(encoded[328..]));
        Validate(value);
        if (!Encode(value, hmacKey).AsSpan().SequenceEqual(encoded))
            throw new InvalidDataException("Production mailbox capacity transfer is non-canonical.");
        return value;
    }

    private static void Validate(ProductionMailboxCapacityTransferJournal value)
    {
        if (Invalid(value.SelectionInputCommitment, false)
            || Invalid(value.DurableOldSelectionHash, false)
            || Invalid(value.OldScheduleSha256, !value.OldScheduleExists)
            || Invalid(value.NewScheduleSha256, false) || Invalid(value.CohortId, false)
            || Invalid(value.BeforeLedgerSha256, false)
            || Invalid(value.AfterLedgerSha256, false)
            || Invalid(value.BeforeMarkerSha256, false)
            || Invalid(value.AfterMarkerSha256, false)
            || value.BeforeStateGeneration == ulong.MaxValue
            || value.AfterStateGeneration != value.BeforeStateGeneration + 1
            || value.AfterConsumedClosureCount < value.BeforeConsumedClosureCount
            || value.AfterConsumedBytes < value.BeforeConsumedBytes)
            throw new InvalidDataException("Production mailbox capacity transfer fields are invalid.");
    }

    private static bool Invalid(ReadOnlyMemory<byte> value, bool requireZero) =>
        value.Length != 32 || (value.Span.IndexOfAnyExcept((byte)0) < 0) != requireZero;

    private static byte[] ComputeMac(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> key)
    {
        using var hmac = new HMACSHA256(key.ToArray());
        var payload = new byte[MacDomain.Length + 336];
        MacDomain.CopyTo(payload); encoded[..336].CopyTo(payload.AsSpan(MacDomain.Length));
        return hmac.ComputeHash(payload);
    }
}

internal static class ProductionMailboxCapacityFloorCodec
{
    private static ReadOnlySpan<byte> Magic => "PBF1"u8;
    private static ReadOnlySpan<byte> MacDomain =>
        "Deep/PBF1/capacity-floor/v1"u8;
    private const int HeaderLength = 40;
    internal const int EncodedLength = HeaderLength
        + ProductionMailboxCapacityLedgerCodec.RecordLength;

    internal static byte[] Encode(ProductionMailboxCapacityReservation value,
        ReadOnlySpan<byte> hmacKey)
    {
        if (hmacKey.Length != 32)
            throw new InvalidDataException("Production mailbox capacity floor key is invalid.");
        var output = new byte[EncodedLength];
        Magic.CopyTo(output); output[4] = 1;
        ProductionMailboxCapacityLedgerCodec.EncodeRecord(value,
            output.AsSpan(HeaderLength));
        ComputeMac(output, hmacKey).CopyTo(output.AsSpan(8));
        return output;
    }

    internal static ProductionMailboxCapacityReservation Decode(
        ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> hmacKey)
    {
        if (encoded.Length != EncodedLength || hmacKey.Length != 32
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 1
            || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0
            || !CryptographicOperations.FixedTimeEquals(encoded.Slice(8, 32),
                ComputeMac(encoded, hmacKey)))
            throw new InvalidDataException("Production mailbox capacity floor is invalid.");
        var value = ProductionMailboxCapacityLedgerCodec.DecodeRecord(
            encoded[HeaderLength..]);
        if (!Encode(value, hmacKey).AsSpan().SequenceEqual(encoded))
            throw new InvalidDataException(
                "Production mailbox capacity floor is non-canonical.");
        return value;
    }

    private static byte[] ComputeMac(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> key)
    {
        using var hmac = new HMACSHA256(key.ToArray());
        var payload = new byte[MacDomain.Length + 8
            + ProductionMailboxCapacityLedgerCodec.RecordLength];
        MacDomain.CopyTo(payload); encoded[..8].CopyTo(payload.AsSpan(MacDomain.Length));
        encoded[HeaderLength..].CopyTo(payload.AsSpan(MacDomain.Length + 8));
        return hmac.ComputeHash(payload);
    }
}
