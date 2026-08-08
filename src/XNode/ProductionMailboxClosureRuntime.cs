using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode;

public static class ProductionMailboxClosureHttpContract
{
    public const string FetchRoute = "/api/production-mailbox/closure";
    public const string PrepositionRoute = "/api/peer/production-mailbox/closure";
    public const string CapacityRoute =
        "/api/peer/production-mailbox/closure-capacity";
    public const string RequestMediaType = "application/vnd.deep.production-mailbox-closure-request";
    public const string ClosureMediaType = "application/vnd.deep.production-mailbox-closure";
    public const string PrepositionMediaType =
        "application/vnd.deep.production-mailbox-preposition-command";
    public const string CapacityCommandMediaType =
        "application/vnd.deep.production-mailbox-capacity-command";
    public const string CapacityReceiptMediaType =
        "application/vnd.deep.production-mailbox-capacity-receipt";

    public static bool IsPrepositionListener(int? localPort, int peerPort) =>
        localPort == peerPort;
}

internal static class ProductionMailboxClosureHttpEndpoint
{
    internal static async Task<IResult> HandleCapacityAsync(
        HttpContext context,
        ProductionMailboxClosureStore closures,
        int peerPort,
        CancellationToken cancellationToken)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (!ProductionMailboxClosureHttpContract.IsPrepositionListener(
                context.Connection.LocalPort, peerPort))
            return Results.NotFound();
        if (context.Request.ContentLength
                != ProductionMailboxCapacityCommandCodec.EncodedLength
            || !string.Equals(context.Request.ContentType,
                ProductionMailboxClosureHttpContract.CapacityCommandMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest();
        var command = new byte[ProductionMailboxCapacityCommandCodec.EncodedLength];
        try
        {
            await context.Request.Body.ReadExactlyAsync(command, cancellationToken);
            var receipt = await closures.ReserveCapacityAsync(
                command, cancellationToken);
            return Results.File(receipt,
                ProductionMailboxClosureHttpContract.CapacityReceiptMediaType,
                enableRangeProcessing: false);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or InvalidOperationException or IOException
            or OverflowException
            || exception is OperationCanceledException
                && context.RequestAborted.IsCancellationRequested)
        {
            return Results.BadRequest();
        }
    }

    internal static async Task<IResult> HandlePrepositionAsync(
        HttpContext context,
        ProductionMailboxClosureStore closures,
        int peerPort,
        CancellationToken cancellationToken)
    {
        context.Response.Headers.CacheControl = "no-store";
        if (!ProductionMailboxClosureHttpContract.IsPrepositionListener(
                context.Connection.LocalPort, peerPort))
            return Results.NotFound();
        if (context.Request.ContentLength is not (> 0 and var length)
            || length > ProductionMailboxPrepositionCommandCodec.MaximumCommandBytes
            || !string.Equals(context.Request.ContentType,
                ProductionMailboxClosureHttpContract.PrepositionMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest();
        var envelope = new byte[(int)length];
        try
        {
            await context.Request.Body.ReadExactlyAsync(envelope, cancellationToken);
            await closures.PrepositionAsync(envelope, cancellationToken);
            return Results.NoContent();
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or InvalidOperationException or IOException
            or OverflowException
            || exception is OperationCanceledException
                && context.RequestAborted.IsCancellationRequested)
        {
            return Results.BadRequest();
        }
    }
}

public sealed record ProductionMailboxClosureEnvelope(
    ReadOnlyMemory<byte> Authority,
    ReadOnlyMemory<byte> Revocation,
    ReadOnlyMemory<byte> Topology,
    ReadOnlyMemory<byte> Selection,
    ReadOnlyMemory<byte> Successor);

public static class ProductionMailboxClosureEnvelopeCodec
{
    private static ReadOnlySpan<byte> Magic => "PMC1"u8;
    private const int HeaderLength = 28;
    public const int MaximumEnvelopeBytes = HeaderLength
        + ProductionMailboxAuthorityConstants.MaximumArtifactBytes
        + 1_048_576
        + ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes
        + ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
        + ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes;

    public static byte[] Encode(ProductionMailboxClosureEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);
        ValidateLengths(value);
        var total = checked(HeaderLength + value.Authority.Length + value.Revocation.Length
            + value.Topology.Length + value.Selection.Length + value.Successor.Length);
        var bytes = new byte[total];
        Magic.CopyTo(bytes); bytes[4] = 1; bytes[5] = 1;
        WriteLength(bytes.AsSpan(8), value.Authority.Length);
        WriteLength(bytes.AsSpan(12), value.Revocation.Length);
        WriteLength(bytes.AsSpan(16), value.Topology.Length);
        WriteLength(bytes.AsSpan(20), value.Selection.Length);
        WriteLength(bytes.AsSpan(24), value.Successor.Length);
        var offset = HeaderLength;
        Copy(value.Authority, bytes, ref offset); Copy(value.Revocation, bytes, ref offset);
        Copy(value.Topology, bytes, ref offset); Copy(value.Selection, bytes, ref offset);
        Copy(value.Successor, bytes, ref offset);
        return bytes;
    }

    public static ProductionMailboxClosureEnvelope Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < HeaderLength or > MaximumEnvelopeBytes
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 1 || encoded[5] != 1
            || encoded[6] != 0 || encoded[7] != 0)
            throw new InvalidDataException("Production mailbox closure header is invalid.");
        var lengths = new[] { ReadLength(encoded[8..]), ReadLength(encoded[12..]),
            ReadLength(encoded[16..]), ReadLength(encoded[20..]), ReadLength(encoded[24..]) };
        var total = lengths.Aggregate(HeaderLength, static (sum, length) => checked(sum + length));
        if (total != encoded.Length)
            throw new InvalidDataException("Production mailbox closure length is invalid.");
        var offset = HeaderLength;
        var fields = new byte[lengths.Length][];
        for (var i = 0; i < lengths.Length; i++)
            fields[i] = Take(encoded, ref offset, lengths[i]);
        var value = new ProductionMailboxClosureEnvelope(fields[0], fields[1], fields[2], fields[3], fields[4]);
        ValidateLengths(value);
        return value;
    }

    private static void ValidateLengths(ProductionMailboxClosureEnvelope value)
    {
        if (value.Authority.Length is 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes
            || value.Revocation.Length is 0 or > 1_048_576
            || value.Topology.Length is 0 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes
            || value.Selection.Length is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || value.Successor.Length is 0 or > ProductionMailboxSelectionSuccessorConstants.MaximumArtifactBytes)
            throw new InvalidDataException("Production mailbox closure field is outside bounds.");
    }

    private static void WriteLength(Span<byte> target, int value) =>
        BinaryPrimitives.WriteUInt32BigEndian(target, checked((uint)value));
    private static int ReadLength(ReadOnlySpan<byte> source) =>
        checked((int)BinaryPrimitives.ReadUInt32BigEndian(source));
    private static void Copy(ReadOnlyMemory<byte> source, byte[] target, ref int offset)
    { source.Span.CopyTo(target.AsSpan(offset)); offset += source.Length; }
    private static byte[] Take(ReadOnlySpan<byte> source, ref int offset, int length)
    { var result = source.Slice(offset, length).ToArray(); offset += length; return result; }
}

public sealed record ProductionMailboxClosureRequest(
    ulong TimestampUnixSeconds,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> SelectionInputCommitment,
    ReadOnlyMemory<byte> DurableOldSelectionHash,
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> OwnerSignature);

public static class ProductionMailboxClosureRequestCodec
{
    private static ReadOnlySpan<byte> Magic => "PMQ1"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMQ1/owner-proof/v1"u8;
    public const int EncodedLength = 208;

    public static byte[] Encode(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value); Validate(value);
        var bytes = new byte[EncodedLength]; Magic.CopyTo(bytes); bytes[4] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), value.TimestampUnixSeconds);
        value.Nonce.Span.CopyTo(bytes.AsSpan(16));
        value.SelectionInputCommitment.Span.CopyTo(bytes.AsSpan(48));
        value.DurableOldSelectionHash.Span.CopyTo(bytes.AsSpan(80));
        value.MailboxOwnerEd25519PublicKey.Span.CopyTo(bytes.AsSpan(112));
        value.OwnerSignature.Span.CopyTo(bytes.AsSpan(144));
        return bytes;
    }

    public static ProductionMailboxClosureRequest Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 1 || encoded[5] != 0 || encoded[6] != 0 || encoded[7] != 0)
            throw new InvalidDataException("Production mailbox closure request is invalid.");
        var value = new ProductionMailboxClosureRequest(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]), encoded.Slice(16, 32).ToArray(),
            encoded.Slice(48, 32).ToArray(), encoded.Slice(80, 32).ToArray(),
            encoded.Slice(112, 32).ToArray(), encoded.Slice(144, 64).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value); Validate(value, allowZeroSignature: true);
        var bytes = new byte[SignatureDomain.Length + 136];
        SignatureDomain.CopyTo(bytes); var offset = SignatureDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), value.TimestampUnixSeconds); offset += 8;
        value.Nonce.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.SelectionInputCommitment.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.DurableOldSelectionHash.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.MailboxOwnerEd25519PublicKey.Span.CopyTo(bytes.AsSpan(offset));
        return bytes;
    }

    public static bool VerifyOwner(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value);
        try
        {
            return PublicKeyAuth.VerifyDetached(value.OwnerSignature.ToArray(),
                GetSigningBytes(value), value.MailboxOwnerEd25519PublicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or ArgumentException)
        { return false; }
    }

    public static bool IsFresh(ProductionMailboxClosureRequest value, ulong nowUnixSeconds,
        uint maximumSkewSeconds = 300)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.TimestampUnixSeconds > nowUnixSeconds
            ? value.TimestampUnixSeconds - nowUnixSeconds <= maximumSkewSeconds
            : nowUnixSeconds - value.TimestampUnixSeconds <= maximumSkewSeconds;
    }

    private static void Validate(ProductionMailboxClosureRequest value, bool allowZeroSignature = false)
    {
        if (value.TimestampUnixSeconds == 0 || Invalid(value.Nonce, 32)
            || Invalid(value.SelectionInputCommitment, 32)
            || Invalid(value.DurableOldSelectionHash, 32)
            || Invalid(value.MailboxOwnerEd25519PublicKey, 32)
            || value.OwnerSignature.Length != 64
            || (!allowZeroSignature && value.OwnerSignature.Span.IndexOfAnyExcept((byte)0) < 0))
            throw new InvalidDataException("Production mailbox closure request fields are invalid.");
    }
    private static bool Invalid(ReadOnlyMemory<byte> value, int length) =>
        value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0;
}

public sealed record ProductionMailboxPrepositionCommand(
    ulong TimestampUnixSeconds,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> EnvelopeSha256,
    ReadOnlyMemory<byte> TargetReplicaId,
    IReadOnlyList<ReadOnlyMemory<byte>> AuthorizedLegacyReplicaIds,
    ReadOnlyMemory<byte> PublisherSignature,
    ReadOnlyMemory<byte> CanonicalEnvelope,
    ReadOnlyMemory<byte> ReservationCohortId = default);

public static class ProductionMailboxPrepositionCommandCodec
{
    private static ReadOnlySpan<byte> Magic => "PMP1"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMP1/preposition/v1"u8;
    public const int MaximumAuthorizedLegacyReplicaIds = 2;
    public const int HeaderLength = 280;
    public const int MaximumCommandBytes = HeaderLength
        + ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes;

    public static byte[] Encode(ProductionMailboxPrepositionCommand value)
    {
        var frozen = Freeze(value);
        Validate(frozen);
        var bytes = new byte[checked(HeaderLength + frozen.CanonicalEnvelope.Length)];
        Magic.CopyTo(bytes); bytes[4] = 1;
        bytes[5] = checked((byte)frozen.AuthorizedLegacyReplicaIds.Count);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), frozen.TimestampUnixSeconds);
        frozen.Nonce.Span.CopyTo(bytes.AsSpan(16));
        frozen.EnvelopeSha256.Span.CopyTo(bytes.AsSpan(48));
        frozen.TargetReplicaId.Span.CopyTo(bytes.AsSpan(80));
        for (var index = 0; index < frozen.AuthorizedLegacyReplicaIds.Count; index++)
            frozen.AuthorizedLegacyReplicaIds[index].Span.CopyTo(
                bytes.AsSpan(112 + index * 32));
        frozen.PublisherSignature.Span.CopyTo(bytes.AsSpan(176));
        frozen.ReservationCohortId.Span.CopyTo(bytes.AsSpan(240));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(272),
            checked((uint)frozen.CanonicalEnvelope.Length));
        frozen.CanonicalEnvelope.Span.CopyTo(bytes.AsSpan(HeaderLength));
        return bytes;
    }

    public static ProductionMailboxPrepositionCommand Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < HeaderLength or > MaximumCommandBytes
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 1
            || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(276, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox preposition command header is invalid.");
        var legacyCount = encoded[5];
        if (legacyCount > MaximumAuthorizedLegacyReplicaIds
            || encoded.Slice(112 + legacyCount * 32,
                    (MaximumAuthorizedLegacyReplicaIds - legacyCount) * 32)
                .IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox preposition command legacy authorization is invalid.");
        var envelopeLengthValue = BinaryPrimitives.ReadUInt32BigEndian(encoded[272..]);
        if (envelopeLengthValue is 0
            || envelopeLengthValue > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes
            || envelopeLengthValue > int.MaxValue)
            throw new InvalidDataException("Production mailbox preposition command length is invalid.");
        var envelopeLength = (int)envelopeLengthValue;
        if (encoded.Length - HeaderLength != envelopeLength)
            throw new InvalidDataException("Production mailbox preposition command length is invalid.");
        var legacyReplicaIds = new ReadOnlyMemory<byte>[legacyCount];
        for (var index = 0; index < legacyCount; index++)
            legacyReplicaIds[index] = encoded.Slice(112 + index * 32, 32).ToArray();
        var value = new ProductionMailboxPrepositionCommand(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]), encoded.Slice(16, 32).ToArray(),
            encoded.Slice(48, 32).ToArray(), encoded.Slice(80, 32).ToArray(),
            legacyReplicaIds,
            encoded.Slice(176, 64).ToArray(), encoded[HeaderLength..].ToArray(),
            encoded.Slice(240, 32).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxPrepositionCommand value)
    {
        var frozen = Freeze(value);
        Validate(frozen, allowZeroSignature: true);
        return GetFrozenSigningBytes(frozen);
    }

    private static byte[] GetFrozenSigningBytes(ProductionMailboxPrepositionCommand frozen)
    {
        var bytes = new byte[SignatureDomain.Length + 201];
        SignatureDomain.CopyTo(bytes); var offset = SignatureDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), frozen.TimestampUnixSeconds); offset += 8;
        frozen.Nonce.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        frozen.EnvelopeSha256.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        frozen.TargetReplicaId.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        bytes[offset++] = checked((byte)frozen.AuthorizedLegacyReplicaIds.Count);
        foreach (var legacyReplicaId in frozen.AuthorizedLegacyReplicaIds)
        {
            legacyReplicaId.Span.CopyTo(bytes.AsSpan(offset));
            offset += 32;
        }
        frozen.ReservationCohortId.Span.CopyTo(
            bytes.AsSpan(SignatureDomain.Length + 169));
        return bytes;
    }

    public static bool IsFresh(ProductionMailboxPrepositionCommand value, ulong now,
        uint maximumSkewSeconds = 300) => value.TimestampUnixSeconds > now
        ? value.TimestampUnixSeconds - now <= maximumSkewSeconds
        : now - value.TimestampUnixSeconds <= maximumSkewSeconds;

    public static bool VerifyPublisher(ProductionMailboxPrepositionCommand value,
        ReadOnlySpan<byte> publisherPublicKey)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (publisherPublicKey.Length != 32) return false;
        try
        {
            var frozen = Freeze(value);
            Validate(frozen);
            return PublicKeyAuth.VerifyDetached(frozen.PublisherSignature.ToArray(),
                GetFrozenSigningBytes(frozen), publisherPublicKey.ToArray());
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or ArgumentException)
        { return false; }
    }

    private static void Validate(ProductionMailboxPrepositionCommand value,
        bool allowZeroSignature = false)
    {
        if (value.TimestampUnixSeconds == 0 || Invalid(value.Nonce, 32)
            || Invalid(value.EnvelopeSha256, 32) || Invalid(value.TargetReplicaId, 32)
            || value.AuthorizedLegacyReplicaIds is null
            || value.AuthorizedLegacyReplicaIds.Count > MaximumAuthorizedLegacyReplicaIds
            || value.AuthorizedLegacyReplicaIds.Any(static id => Invalid(id, 32))
            || !StrictlySorted(value.AuthorizedLegacyReplicaIds)
            || value.ReservationCohortId.Length != 32
            || value.PublisherSignature.Length != 64
            || (!allowZeroSignature && value.PublisherSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            || value.CanonicalEnvelope.Length is < 28
                or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
            throw new InvalidDataException("Production mailbox preposition command fields are invalid.");
    }

    private static ProductionMailboxPrepositionCommand Freeze(
        ProductionMailboxPrepositionCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Nonce.Length != 32 || value.EnvelopeSha256.Length != 32
            || value.TargetReplicaId.Length != 32 || value.PublisherSignature.Length != 64
            || value.ReservationCohortId.Length is not (0 or 32)
            || value.CanonicalEnvelope.Length is < 28
                or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes
            || value.AuthorizedLegacyReplicaIds is null)
            throw new InvalidDataException(
                "Production mailbox preposition command fields are invalid.");
        var source = value.AuthorizedLegacyReplicaIds;
        try
        {
            var count = source.Count;
            if (count > MaximumAuthorizedLegacyReplicaIds)
                throw new InvalidDataException(
                    "Production mailbox preposition command legacy authorization is invalid.");
            var legacyReplicaIds = new ReadOnlyMemory<byte>[count];
            for (var index = 0; index < count; index++)
            {
                if (source.Count != count)
                    throw new InvalidDataException(
                        "Production mailbox preposition command legacy authorization changed while being snapshotted.");
                var replicaId = source[index];
                if (replicaId.Length != 32)
                    throw new InvalidDataException(
                        "Production mailbox preposition command legacy authorization changed while being snapshotted.");
                legacyReplicaIds[index] = replicaId.ToArray();
            }
            if (source.Count != count)
                throw new InvalidDataException(
                    "Production mailbox preposition command legacy authorization changed while being snapshotted.");
            return value with
            {
                Nonce = value.Nonce.ToArray(),
                EnvelopeSha256 = value.EnvelopeSha256.ToArray(),
                TargetReplicaId = value.TargetReplicaId.ToArray(),
                AuthorizedLegacyReplicaIds = legacyReplicaIds,
                PublisherSignature = value.PublisherSignature.ToArray(),
                CanonicalEnvelope = value.CanonicalEnvelope.ToArray(),
                ReservationCohortId = value.ReservationCohortId.IsEmpty
                    ? new byte[32]
                    : value.ReservationCohortId.ToArray()
            };
        }
        catch (Exception exception) when (exception is ArgumentOutOfRangeException
            or IndexOutOfRangeException or InvalidOperationException
            or NotSupportedException)
        {
            throw new InvalidDataException(
                "Production mailbox preposition command legacy authorization could not be snapshotted.",
                exception);
        }
    }
    private static bool Invalid(ReadOnlyMemory<byte> value, int length) =>
        value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0;

    private static bool StrictlySorted(IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        for (var index = 1; index < values.Count; index++)
            if (values[index - 1].Span.SequenceCompareTo(values[index].Span) >= 0)
                return false;
        return true;
    }
}

internal static class ProductionMailboxClosureScheduleCodec
{
    private static ReadOnlySpan<byte> Magic => "PCS1"u8;
    private const int HeaderLength = 8;

    public static byte[] Encode(IReadOnlyList<byte[]> envelopes, int maximumVersions)
    {
        if (envelopes.Count is < 1 || envelopes.Count > maximumVersions)
            throw new InvalidDataException("Production mailbox closure schedule count is invalid.");
        var total = checked(HeaderLength + envelopes.Sum(static value => 4 + value.Length));
        var output = new byte[total]; Magic.CopyTo(output); output[4] = 1;
        output[5] = checked((byte)envelopes.Count);
        var offset = HeaderLength;
        foreach (var envelope in envelopes)
        {
            if (envelope.Length is < 28
                or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
                throw new InvalidDataException("Production mailbox closure schedule field is invalid.");
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset),
                checked((uint)envelope.Length));
            offset += 4; envelope.CopyTo(output.AsSpan(offset)); offset += envelope.Length;
        }
        return output;
    }

    public static IReadOnlyList<byte[]> Decode(ReadOnlySpan<byte> encoded, int maximumVersions)
    {
        if (encoded.Length < HeaderLength || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 1 || encoded[5] is 0 || encoded[5] > maximumVersions
            || encoded[6] != 0 || encoded[7] != 0)
            throw new InvalidDataException("Production mailbox closure schedule is invalid.");
        var values = new List<byte[]>(encoded[5]);
        var offset = HeaderLength;
        for (var index = 0; index < encoded[5]; index++)
        {
            if (encoded.Length - offset < 4)
                throw new InvalidDataException("Production mailbox closure schedule is truncated.");
            var lengthValue = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]);
            offset += 4;
            if (lengthValue is < 28
                or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes
                || lengthValue > int.MaxValue || encoded.Length - offset < (int)lengthValue)
                throw new InvalidDataException("Production mailbox closure schedule field is invalid.");
            values.Add(encoded.Slice(offset, (int)lengthValue).ToArray());
            offset += (int)lengthValue;
        }
        if (offset != encoded.Length || !Encode(values, maximumVersions).AsSpan().SequenceEqual(encoded))
            throw new InvalidDataException("Production mailbox closure schedule is non-canonical.");
        return values;
    }
}

public sealed class ProductionMailboxClosureStore
{
    private readonly ProductionMailboxAuthorityOptions options;
    private readonly RouterNodeOptions node;
    private readonly IClock clock;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly ProductionMailboxClosureStoreTestHooks? testHooks;
    private readonly string dataRoot;
    private readonly string processLockPath;
    private readonly string capacityLedgerPath;
    private readonly string capacityTransferPath;
    private readonly byte[] hmacKey;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly SemaphoreSlim[] lineageGates = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1)).ToArray();
    private long storedBytes;
    private int storedClosures;

    internal (int Count, long Bytes) StorageAccounting =>
        (storedClosures, storedBytes);

    public ProductionMailboxClosureStore(ProductionMailboxAuthorityOptions options, RouterNodeOptions node,
        IClock clock, IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability)
        : this(options, node, clock, security, durability, null)
    {
    }

    internal ProductionMailboxClosureStore(ProductionMailboxAuthorityOptions options,
        RouterNodeOptions node, IClock clock, IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability, ProductionMailboxClosureStoreTestHooks? testHooks)
    {
        this.options = options; this.node = node; this.clock = clock;
        this.security = security; this.durability = durability;
        this.testHooks = testHooks;
        dataRoot = Path.GetFullPath(node.DataDirectory);
        EnsureNoReparseAncestors(Path.GetDirectoryName(options.ClosureDirectory)!, dataRoot);
        EnsureNoReparseAncestors(options.ClosureStateHmacKeyPath, dataRoot);
        hmacKey = ReadKey(options.ClosureStateHmacKeyPath);
        EnsureNoReparseAncestors(options.ClosureDirectory, dataRoot);
        Directory.CreateDirectory(options.ClosureDirectory);
        EnsureNoReparseAncestors(options.ClosureDirectory, dataRoot);
        security.SecureDirectory(options.ClosureDirectory);
        EnsureNoReparseAncestors(options.ClosureDirectory, dataRoot);
        processLockPath = Path.Combine(options.ClosureDirectory, ".closure-store.lock");
        capacityLedgerPath = Path.Combine(options.ClosureDirectory,
            ".closure-capacity.pbl1");
        capacityTransferPath = Path.Combine(options.ClosureDirectory,
            ".closure-capacity-transfer.pbt1");
        using var processLock = AcquireProcessLock();
        RecoverCapacityTransfer();
        ReconcileCapacityState(
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
        PruneGloballyExpiredSchedules(
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
        PruneEmptyStoreDirectories();
        ReconcileStoreState();
        EnsureCapacityIncludingReservations(
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
    }

    public async ValueTask<byte[]> ReserveCapacityAsync(
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (canonicalCommand.Length != ProductionMailboxCapacityCommandCodec.EncodedLength)
            throw new InvalidDataException(
                "Production mailbox capacity command is outside bounds.");
        var commandBytes = canonicalCommand.ToArray();
        var command = ProductionMailboxCapacityCommandCodec.Decode(commandBytes);
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        if (!IsFresh(command.TimestampUnixSeconds, now, options.ClockSkewSeconds)
            || command.ExpiresAtUnixSeconds <= command.TimestampUnixSeconds
            || command.ExpiresAtUnixSeconds <= now
            || command.ExpiresAtUnixSeconds - command.TimestampUnixSeconds
                < options.MinimumClosureReservationLifetimeSeconds
            || command.ExpiresAtUnixSeconds - command.TimestampUnixSeconds
                > options.MaximumClosureReservationLifetimeSeconds
            || !Fixed(command.TargetReplicaId.Span, node.GetRouterId().ToBytes())
            || !ProductionMailboxCapacityCommandCodec.VerifyPublisher(
                command, options.GetClosurePublisherPublicKey()))
            throw new InvalidDataException(
                "Production mailbox capacity command authentication failed.");
        if (command.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
            && (command.ReservedClosureCount > options.MaximumStoredClosures
                || command.ReservedBytes > (ulong)options.MaximumClosureStoreBytes))
            throw new InvalidDataException(
                "Production mailbox capacity command exceeds configured bounds.");
        var commandHash = SHA256.HashData(commandBytes);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var processLock = AcquireProcessLock();
            RecoverCapacityTransfer();
            testHooks?.BeforeCapacityAdmission?.Invoke();
            var lockedNow = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            if (!IsFresh(command.TimestampUnixSeconds, lockedNow,
                    options.ClockSkewSeconds)
                || command.ExpiresAtUnixSeconds <= lockedNow)
                throw new InvalidDataException(
                    "Production mailbox capacity command expired while awaiting admission.");
            ReconcileCapacityState(lockedNow);
            ReconcileStoreState();
            var floors = ReadCapacityFloorStates();
            var reservations = floors.Select(static value => value.Reservation).ToList();
            var existingIndex = reservations.FindIndex(value =>
                Fixed(value.CohortId.Span, command.CohortId.Span));
            if (existingIndex >= 0
                && Fixed(reservations[existingIndex].LastCommandSha256.Span,
                    commandHash))
                return reservations[existingIndex].LastCanonicalReceipt.ToArray();
            var existing = existingIndex >= 0 ? reservations[existingIndex] : null;
            var existingFloor = existing is null ? null : floors.Single(value =>
                Fixed(value.Reservation.CohortId.Span, existing.CohortId.Span));
            if (command.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
                && command.Revision == ulong.MaxValue)
                throw new InvalidOperationException(
                    "Production mailbox capacity reservation cannot be terminal.");
            if (existing?.StateGeneration == ulong.MaxValue)
                throw new InvalidOperationException(
                    "Production mailbox capacity floor cannot advance beyond terminal state.");
            if (existing is null)
            {
                if (command.Operation != ProductionMailboxCapacityOperation.ReserveOrRenew
                    || command.Revision != 1
                    || reservations.Count >= options.MaximumClosureReservations)
                    throw new InvalidOperationException(
                        "Production mailbox capacity reservation cannot be created.");
            }
            else if (existing.Revision == ulong.MaxValue
                     || existing.Terminal
                     || command.Revision != existing.Revision + 1
                     || !Fixed(existing.TargetReplicaId.Span,
                         command.TargetReplicaId.Span)
                     || ProductionMailboxCapacityReceiptCodec.Decode(
                             existing.LastCanonicalReceipt.Span).Operation
                         == ProductionMailboxCapacityOperation.Release
                     || command.ExpiresAtUnixSeconds <= existing.ExpiresAtUnixSeconds)
            {
                throw new InvalidOperationException(
                    "Production mailbox capacity reservation is not a strict successor.");
            }

            var consumedCount = existing?.ConsumedClosureCount ?? 0;
            var consumedBytes = existing?.ConsumedBytes ?? 0;
            var reservedCount = command.Operation
                == ProductionMailboxCapacityOperation.Release
                ? consumedCount : command.ReservedClosureCount;
            var reservedBytes = command.Operation
                == ProductionMailboxCapacityOperation.Release
                ? consumedBytes : command.ReservedBytes;
            if (reservedCount < consumedCount || reservedBytes < consumedBytes)
                throw new InvalidOperationException(
                    "Production mailbox capacity renewal cannot revoke consumed capacity.");
            var unsignedReceipt = new ProductionMailboxCapacityReceipt(
                command.Operation, now, command.ExpiresAtUnixSeconds,
                command.CohortId.ToArray(), command.TargetReplicaId.ToArray(),
                reservedCount, reservedBytes, consumedCount, consumedBytes,
                command.Revision, commandHash, new byte[64]);
            var nodeKeyPair = PublicKeyAuth.GenerateKeyPair(
                Convert.FromHexString(node.GetEd25519PrivateKey()));
            if (!Fixed(nodeKeyPair.PublicKey, command.TargetReplicaId.Span))
                throw new InvalidOperationException(
                    "Production mailbox node signing key does not match its replica id.");
            var receipt = unsignedReceipt with
            {
                NodeSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsignedReceipt),
                    nodeKeyPair.PrivateKey)
            };
            var canonicalReceipt = ProductionMailboxCapacityReceiptCodec.Encode(receipt);
            var terminal = command.Operation == ProductionMailboxCapacityOperation.Release;
            var replacement = new ProductionMailboxCapacityReservation(
                command.CohortId.ToArray(), command.TargetReplicaId.ToArray(),
                command.Revision, existing is null ? 1 : checked(existing.StateGeneration + 1),
                terminal, reservedCount, reservedBytes, consumedCount,
                consumedBytes, command.ExpiresAtUnixSeconds,
                terminal ? checked(command.ExpiresAtUnixSeconds
                    + options.MaximumClosureReservationLifetimeSeconds) : 0,
                commandHash, existingFloor?.MarkerSha256 ?? new byte[32],
                canonicalReceipt);
            if (existingIndex < 0) reservations.Add(replacement);
            else reservations[existingIndex] = replacement;
            EnsureCapacityIncludingReservations(lockedNow, reservations);
            CommitCapacityReservationMutation(existingFloor, replacement, reservations);
            return canonicalReceipt;
        }
        finally { gate.Release(); }
    }

    public async ValueTask PrepositionAsync(ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (canonicalCommand.Length is < ProductionMailboxPrepositionCommandCodec.HeaderLength
            or > ProductionMailboxPrepositionCommandCodec.MaximumCommandBytes)
            throw new InvalidDataException("Production mailbox preposition command is outside bounds.");
        var commandBytes = canonicalCommand.ToArray();
        var command = ProductionMailboxPrepositionCommandCodec.Decode(commandBytes);
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        if (!ProductionMailboxPrepositionCommandCodec.IsFresh(command, now)
            || !Fixed(command.TargetReplicaId.Span, node.GetRouterId().ToBytes())
            || !Fixed(command.EnvelopeSha256.Span,
                SHA256.HashData(command.CanonicalEnvelope.Span))
            || !ProductionMailboxPrepositionCommandCodec.VerifyPublisher(
                command, options.GetClosurePublisherPublicKey()))
            throw new InvalidDataException("Production mailbox preposition command authentication failed.");
        var frozen = FreezeEnvelope(command.CanonicalEnvelope.Span);
        var proof = ValidateCacheClosure(frozen);
        if (!IsAuthorizedTarget(proof, command.TargetReplicaId.Span,
                command.AuthorizedLegacyReplicaIds))
            throw new InvalidDataException(
                "Production mailbox closure is unrelated to the authorized target replica.");
        if (IsExpired(proof.ExpiresAtUnixSeconds, now, options.ClockSkewSeconds))
            throw new InvalidDataException(
                "Production mailbox closure candidate is already expired.");
        var lineageGate = LineageGate(proof.SelectionInputCommitment.Span,
            proof.OldCanonicalSelectionHash.Span);
        await lineageGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var processLock = AcquireProcessLock();
                RecoverCapacityTransfer();
                now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
                if (!ProductionMailboxPrepositionCommandCodec.IsFresh(command, now)
                    || IsExpired(proof.ExpiresAtUnixSeconds, now,
                        options.ClockSkewSeconds))
                    throw new InvalidDataException(
                        "Production mailbox preposition command expired while awaiting admission.");
                ReconcileCapacityState(now);
                PruneExpiredLineages(proof.SelectionInputCommitment.Span, now);
                ReconcileStoreState();
                var path = SchedulePath(proof.SelectionInputCommitment.Span,
                    proof.OldCanonicalSelectionHash.Span);
                byte[]? existingSchedule = null;
                var versions = new List<(byte[] Bytes,
                    ProductionMailboxSelectionSuccessorProof Proof)>();
                try
                {
                    existingSchedule = ReadScheduleBounded(path);
                    versions.AddRange(ProductionMailboxClosureScheduleCodec.Decode(
                            existingSchedule, options.MaximumClosureVersionsPerSelection)
                        .Select(bytes => (bytes,
                            ValidateCacheClosure(bytes))));
                }
                catch (FileNotFoundException)
                {
                    // A missing lineage schedule is a new insertion under the process lock.
                }
                if (existingSchedule is null
                    && CountLineages(proof.SelectionInputCommitment.Span)
                        >= options.MaximumClosureLineagesPerSelection)
                    throw new InvalidOperationException(
                        "Production mailbox selection lineage capacity is exhausted.");
                var exact = versions.Any(version => version.Bytes.AsSpan().SequenceEqual(frozen));
                if (!exact && versions.Count != 0)
                    EnsureStrictlyForward(
                        versions.MaxBy(static version => Order(version.Proof)).Proof, proof);
                var retained = versions.Where(version =>
                        !IsExpired(version.Proof.ExpiresAtUnixSeconds, now,
                            options.ClockSkewSeconds)
                        || version.Bytes.AsSpan().SequenceEqual(frozen))
                    .ToList();
                if (!exact) retained.Add((frozen, proof));
                retained = retained.OrderBy(static version => Order(version.Proof)).ToList();
                if (retained.Count > options.MaximumClosureVersionsPerSelection)
                    throw new InvalidOperationException(
                        "Production mailbox route closure schedule is at its configured bound.");
                var replacement = ProductionMailboxClosureScheduleCodec.Encode(
                    retained.Select(static version => version.Bytes).ToArray(),
                    options.MaximumClosureVersionsPerSelection);
                if (existingSchedule is not null && existingSchedule.AsSpan().SequenceEqual(replacement))
                    return;
                var floors = ReadCapacityFloorStates();
                var reservations = floors.Select(static value => value.Reservation).ToList();
                var projectedClosures = checked(storedClosures - versions.Count + retained.Count);
                var projectedBytes = checked(storedBytes - AccountSchedule(existingSchedule)
                    + AccountSchedule(replacement));
                var additionalCount = Math.Max(0, retained.Count - versions.Count);
                var additionalBytes = checked((ulong)Math.Max(0,
                    AccountSchedule(replacement) - AccountSchedule(existingSchedule)));
                ProductionMailboxCapacityReservation? beforeReservation = null;
                ProductionMailboxCapacityReservation? afterReservation = null;
                CapacityFloorState? beforeFloor = null;
                var hasReservation = command.ReservationCohortId.Span
                    .IndexOfAnyExcept((byte)0) >= 0;
                if (hasReservation && (additionalCount != 0 || additionalBytes != 0))
                {
                    var index = reservations.FindIndex(value => Fixed(
                        value.CohortId.Span, command.ReservationCohortId.Span));
                    if (index < 0)
                        throw new InvalidOperationException(
                            "Production mailbox closure capacity reservation is unavailable.");
                    beforeReservation = reservations[index];
                    if (beforeReservation.StateGeneration == ulong.MaxValue)
                        throw new InvalidOperationException(
                            "Production mailbox capacity floor cannot consume after maximum state.");
                    beforeFloor = floors.Single(value => Fixed(
                        value.Reservation.CohortId.Span,
                        command.ReservationCohortId.Span));
                    if (IsExpired(beforeReservation.ExpiresAtUnixSeconds, now,
                            options.ClockSkewSeconds)
                        || beforeReservation.ReservedClosureCount
                            - beforeReservation.ConsumedClosureCount < additionalCount
                        || beforeReservation.ReservedBytes
                            - beforeReservation.ConsumedBytes < additionalBytes)
                        throw new InvalidOperationException(
                            "Production mailbox closure capacity reservation is exhausted.");
                    afterReservation = beforeReservation with
                    {
                        StateGeneration = checked(beforeReservation.StateGeneration + 1),
                        ConsumedClosureCount = checked(
                            beforeReservation.ConsumedClosureCount + (uint)additionalCount),
                        ConsumedBytes = checked(beforeReservation.ConsumedBytes + additionalBytes),
                        PredecessorMarkerSha256 = beforeFloor.MarkerSha256
                    };
                    reservations[index] = afterReservation;
                }
                if (projectedClosures > options.MaximumStoredClosures
                    || projectedBytes > options.MaximumClosureStoreBytes
                    || !FitsCapacityWithReservations(
                        projectedClosures, projectedBytes, reservations, now))
                {
                    PruneGloballyExpiredSchedules(now, path);
                    ReconcileStoreState();
                    projectedClosures = checked(storedClosures - versions.Count + retained.Count);
                    projectedBytes = checked(storedBytes - AccountSchedule(existingSchedule)
                        + AccountSchedule(replacement));
                }
                if (projectedClosures > options.MaximumStoredClosures
                    || !FitsCapacityWithReservations(
                        projectedClosures, projectedBytes, reservations, now))
                    throw new InvalidOperationException("Production mailbox closure capacity is exhausted.");
                if (projectedBytes > options.MaximumClosureStoreBytes)
                    throw new InvalidOperationException(
                        "Production mailbox closure byte capacity is exhausted.");
                EnsureLineageDirectory(proof.SelectionInputCommitment.Span,
                    proof.OldCanonicalSelectionHash.Span);
                try
                {
                    if (beforeReservation is not null && afterReservation is not null
                        && beforeFloor is not null)
                        CommitScheduleWithCapacityTransfer(path, existingSchedule,
                            replacement, proof, beforeFloor, beforeReservation, afterReservation,
                            reservations);
                    else
                        WriteAtomic(path, replacement);
                }
                catch
                {
                    ReconcileStoreState();
                    throw;
                }
                ReconcileStoreState();
            }
            finally { gate.Release(); }
        }
        finally { lineageGate.Release(); }
    }

    internal static void EnsureStrictlyForward(
        ProductionMailboxSelectionSuccessorProof existing,
        ProductionMailboxSelectionSuccessorProof candidate)
    {
        if (!Fixed(existing.NetworkId.Span, candidate.NetworkId.Span)
            || !Fixed(existing.MailboxOwnerEd25519PublicKey.Span,
                candidate.MailboxOwnerEd25519PublicKey.Span)
            || !Fixed(existing.BlindedMailboxId.Span, candidate.BlindedMailboxId.Span)
            || !Fixed(existing.BlindedPlacementId.Span, candidate.BlindedPlacementId.Span)
            || !Fixed(existing.SelectionInputCommitment.Span,
                candidate.SelectionInputCommitment.Span)
            || existing.OldEpoch != candidate.OldEpoch
            || existing.OldEpochGeneration != candidate.OldEpochGeneration
            || existing.OldTopologyGeneration != candidate.OldTopologyGeneration
            || !Fixed(existing.OldCanonicalAuthorityHash.Span,
                candidate.OldCanonicalAuthorityHash.Span)
            || !Fixed(existing.OldCanonicalTopologyHash.Span,
                candidate.OldCanonicalTopologyHash.Span)
            || !Fixed(existing.OldCanonicalSelectionHash.Span,
                candidate.OldCanonicalSelectionHash.Span))
            throw new InvalidDataException(
                "Production mailbox preposition command changes its durable route lineage.");
        var existingAuthority = ProductionMailboxAuthorityCodec.Decode(
            existing.CanonicalNewAuthority.Span);
        var candidateAuthority = ProductionMailboxAuthorityCodec.Decode(
            candidate.CanonicalNewAuthority.Span);
        if (candidateAuthority.AuthorityGeneration <= existingAuthority.AuthorityGeneration
            || candidate.NewTopologyGeneration <= existing.NewTopologyGeneration
            || candidate.NewEpoch < existing.NewEpoch
            || candidate.NewEpoch == existing.NewEpoch
                && candidate.NewEpochGeneration <= existing.NewEpochGeneration
            || candidate.IssuedAtUnixSeconds <= existing.IssuedAtUnixSeconds
            || candidate.ExpiresAtUnixSeconds <= existing.ExpiresAtUnixSeconds)
            throw new InvalidDataException(
                "Production mailbox preposition command is rollback, replay fork or non-forward.");
    }

    public async ValueTask<byte[]?> FetchAsync(ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        if (canonicalRequest.Length != ProductionMailboxClosureRequestCodec.EncodedLength)
            return null;
        ProductionMailboxClosureRequest request;
        try { request = ProductionMailboxClosureRequestCodec.Decode(canonicalRequest.Span); }
        catch (InvalidDataException) { return null; }
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        if (!ProductionMailboxClosureRequestCodec.IsFresh(request, now)
            || !ProductionMailboxClosureRequestCodec.VerifyOwner(request))
            return null;
        var lineageGate = LineageGate(request.SelectionInputCommitment.Span,
            request.DurableOldSelectionHash.Span);
        await lineageGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ValidateLineageDirectory(request.SelectionInputCommitment.Span,
                request.DurableOldSelectionHash.Span);
            var live = new List<(byte[] Bytes, ProductionMailboxSelectionSuccessorProof Proof)>();
            var schedule = ReadScheduleBounded(SchedulePath(
                request.SelectionInputCommitment.Span,
                request.DurableOldSelectionHash.Span));
            foreach (var bytes in ProductionMailboxClosureScheduleCodec.Decode(
                         schedule, options.MaximumClosureVersionsPerSelection))
            {
                var proof = ValidateCacheClosure(bytes);
                if (Fixed(proof.SelectionInputCommitment.Span,
                        request.SelectionInputCommitment.Span)
                    && Fixed(proof.OldCanonicalSelectionHash.Span,
                        request.DurableOldSelectionHash.Span)
                    && Fixed(proof.MailboxOwnerEd25519PublicKey.Span,
                        request.MailboxOwnerEd25519PublicKey.Span)
                    && IsLiveWindow(proof.IssuedAtUnixSeconds,
                        proof.ExpiresAtUnixSeconds, now, options.ClockSkewSeconds))
                    live.Add((bytes, proof));
            }
            return live.Count == 0
                ? null
                : live.MaxBy(static version => Order(version.Proof)).Bytes;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException
            or CryptographicException)
        { return null; }
        finally { lineageGate.Release(); }
    }

    private IReadOnlyList<ProductionMailboxCapacityReservation>
        ReadCapacityReservations()
    {
        try
        {
            var bytes = ReadProtectedBounded(capacityLedgerPath, 40,
                checked(40 + options.MaximumClosureReservations
                    * ProductionMailboxCapacityLedgerCodec.RecordLength));
            return ProductionMailboxCapacityLedgerCodec.Decode(
                bytes, hmacKey, options.MaximumClosureReservations);
        }
        catch (FileNotFoundException)
        {
            return [];
        }
    }

    private byte[] CanonicalCapacityLedger(
        IReadOnlyList<ProductionMailboxCapacityReservation> reservations) =>
        ProductionMailboxCapacityLedgerCodec.Encode(
            reservations, hmacKey, options.MaximumClosureReservations);

    private void WriteCapacityReservations(
        IReadOnlyList<ProductionMailboxCapacityReservation> reservations) =>
        WriteAtomic(capacityLedgerPath, CanonicalCapacityLedger(reservations));

    private sealed record CapacityFloorState(
        ProductionMailboxCapacityReservation Reservation,
        byte[] CanonicalMarker,
        byte[] MarkerSha256,
        string Path);

    private IReadOnlyList<CapacityFloorState> ReadCapacityFloorStates()
    {
        ValidateStoreDirectory();
        var paths = Directory.EnumerateFiles(options.ClosureDirectory,
                ".capacity-*.pbf1", SearchOption.TopDirectoryOnly)
            .Take(checked(options.MaximumClosureReservations * 4 + 1)).ToArray();
        if (paths.Length > options.MaximumClosureReservations * 4)
            throw new InvalidOperationException(
                "Production mailbox capacity floor count exceeds its bound.");
        var values = paths.Select(path =>
        {
            var marker = ReadProtectedBounded(path,
                ProductionMailboxCapacityFloorCodec.EncodedLength,
                ProductionMailboxCapacityFloorCodec.EncodedLength);
            var reservation = ProductionMailboxCapacityFloorCodec.Decode(marker, hmacKey);
            var markerHash = SHA256.HashData(marker);
            var expected = CapacityFloorPath(reservation.CohortId.Span,
                reservation.StateGeneration, markerHash);
            if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(expected),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production mailbox capacity floor filename is not canonical.");
            return new CapacityFloorState(reservation, marker, markerHash, path);
        }).ToArray();
        var authoritative = new List<CapacityFloorState>();
        foreach (var group in values.GroupBy(value =>
                     Convert.ToHexString(value.Reservation.CohortId.Span),
                     StringComparer.Ordinal))
        {
            var ordered = group.OrderBy(value => value.Reservation.StateGeneration).ToArray();
            for (var index = 1; index < ordered.Length; index++)
            {
                if (ordered[index].Reservation.StateGeneration
                        != checked(ordered[index - 1].Reservation.StateGeneration + 1)
                    || !Fixed(ordered[index].Reservation.PredecessorMarkerSha256.Span,
                        ordered[index - 1].MarkerSha256))
                    throw new InvalidDataException(
                        "Production mailbox capacity floor contains a fork or broken chain.");
            }
            authoritative.Add(ordered[^1]);
        }
        if (authoritative.Count > options.MaximumClosureReservations)
            throw new InvalidOperationException(
                "Production mailbox capacity reservation count exceeds its bound.");
        return authoritative;
    }

    private void ReconcileCapacityState(ulong now)
    {
        var floors = ReadCapacityFloorStates().ToList();
        var changed = false;
        foreach (var floor in floors.ToArray())
        {
            var value = floor.Reservation;
            if (!value.Terminal
                && IsExpired(value.ExpiresAtUnixSeconds, now, options.ClockSkewSeconds))
            {
                if (value.StateGeneration == ulong.MaxValue)
                    throw new InvalidOperationException(
                        "Production mailbox capacity floor cannot terminate after maximum state.");
                var terminal = value with
                {
                    StateGeneration = checked(value.StateGeneration + 1),
                    Terminal = true,
                    ReservedClosureCount = value.ConsumedClosureCount,
                    ReservedBytes = value.ConsumedBytes,
                    RetainUntilUnixSeconds = checked(value.ExpiresAtUnixSeconds
                        + options.MaximumClosureReservationLifetimeSeconds),
                    PredecessorMarkerSha256 = floor.MarkerSha256
                };
                var successor = WriteCapacityFloor(terminal);
                floors[floors.IndexOf(floor)] = successor;
                changed = true;
            }
        }
        foreach (var floor in floors.ToArray())
        {
            if (floor.Reservation.Terminal
                && IsExpired(floor.Reservation.RetainUntilUnixSeconds, now,
                    options.ClockSkewSeconds))
            {
                DeleteProtectedFile(floor.Path);
                floors.Remove(floor);
                changed = true;
            }
        }
        var canonical = CanonicalCapacityLedger(
            floors.Select(static value => value.Reservation).ToArray());
        byte[]? existingLedger = null;
        try
        {
            existingLedger = ReadProtectedBounded(capacityLedgerPath, 40,
                checked(40 + options.MaximumClosureReservations
                    * ProductionMailboxCapacityLedgerCodec.RecordLength));
        }
        catch (FileNotFoundException) { }
        if (floors.Count == 0 && existingLedger is not null)
        {
            DeleteProtectedFile(capacityLedgerPath);
            changed = true;
        }
        else if (floors.Count != 0
                 && (existingLedger is null
                     || !existingLedger.AsSpan().SequenceEqual(canonical)))
        {
            WriteAtomic(capacityLedgerPath, canonical);
            changed = true;
        }
        var authoritativePaths = floors.Select(value => Path.GetFullPath(value.Path))
            .ToHashSet(OperatingSystem.IsWindows()
                ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(options.ClosureDirectory,
                     ".capacity-*.pbf1", SearchOption.TopDirectoryOnly))
            if (!authoritativePaths.Contains(Path.GetFullPath(path)))
            {
                DeleteProtectedFile(path);
                changed = true;
            }
        if (changed)
        {
            var verified = ReadCapacityFloorStates();
            if (verified.Count == 0)
            {
                if (File.Exists(capacityLedgerPath))
                    throw new InvalidOperationException(
                        "Production mailbox empty capacity ledger was resurrected.");
                return;
            }
            var expected = CanonicalCapacityLedger(
                verified.Select(static value => value.Reservation).ToArray());
            var actual = ReadProtectedBounded(capacityLedgerPath, 40,
                checked(40 + options.MaximumClosureReservations
                    * ProductionMailboxCapacityLedgerCodec.RecordLength));
            if (!actual.AsSpan().SequenceEqual(expected))
                throw new InvalidOperationException(
                    "Production mailbox capacity state reconciliation is ambiguous.");
        }
    }

    private void CommitCapacityReservationMutation(
        CapacityFloorState? existingFloor,
        ProductionMailboxCapacityReservation replacement,
        IReadOnlyList<ProductionMailboxCapacityReservation> reservations)
    {
        var floor = WriteCapacityFloor(replacement);
        testHooks?.AfterCapacityReservationFloor?.Invoke();
        WriteCapacityReservations(reservations);
        testHooks?.AfterCapacityReservationLedger?.Invoke();
        if (existingFloor is not null)
            DeleteProtectedFile(existingFloor.Path);
        testHooks?.AfterCapacityReservationDelete?.Invoke();
        var authoritative = ReadCapacityFloorStates();
        if (!authoritative.Any(value => Fixed(
                value.MarkerSha256, floor.MarkerSha256)))
            throw new InvalidOperationException(
                "Production mailbox capacity floor mutation is ambiguous.");
    }

    private CapacityFloorState WriteCapacityFloor(
        ProductionMailboxCapacityReservation reservation)
    {
        var marker = ProductionMailboxCapacityFloorCodec.Encode(reservation, hmacKey);
        var markerHash = SHA256.HashData(marker);
        var path = CapacityFloorPath(
            reservation.CohortId.Span, reservation.StateGeneration, markerHash);
        try
        {
            var existing = ReadProtectedBounded(path,
                ProductionMailboxCapacityFloorCodec.EncodedLength,
                ProductionMailboxCapacityFloorCodec.EncodedLength);
            if (!existing.AsSpan().SequenceEqual(marker))
                throw new InvalidDataException(
                    "Production mailbox capacity floor content conflicts.");
        }
        catch (FileNotFoundException)
        {
            WriteAtomic(path, marker);
        }
        return new(reservation, marker, markerHash, path);
    }

    private string CapacityFloorPath(ReadOnlySpan<byte> cohortId,
        ulong stateGeneration, ReadOnlySpan<byte> markerSha256)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey);
        hmac.AppendData("Deep/XNode/production-mailbox-capacity-floor/v1"u8);
        hmac.AppendData(cohortId);
        var cohortKey = Convert.ToHexStringLower(hmac.GetHashAndReset());
        return Path.Combine(options.ClosureDirectory,
            $".capacity-{cohortKey[..2]}-{cohortKey}-{stateGeneration:D20}-"
            + $"{Convert.ToHexStringLower(markerSha256)}.pbf1");
    }

    private void EnsureCapacityIncludingReservations(ulong now,
        IReadOnlyList<ProductionMailboxCapacityReservation>? reservations = null)
    {
        var values = reservations ?? ReadCapacityReservations();
        if (!FitsCapacityWithReservations(storedClosures, storedBytes, values, now))
            throw new InvalidOperationException(
                "Production mailbox closure reservations exceed configured capacity.");
    }

    private bool FitsCapacityWithReservations(int actualCount, long actualBytes,
        IReadOnlyList<ProductionMailboxCapacityReservation> reservations, ulong now)
    {
        ulong unusedCount = 0;
        ulong unusedBytes = 0;
        foreach (var value in reservations)
        {
            if (IsExpired(value.ExpiresAtUnixSeconds, now, options.ClockSkewSeconds))
                continue;
            unusedCount = checked(unusedCount + value.ReservedClosureCount
                - value.ConsumedClosureCount);
            unusedBytes = checked(unusedBytes + value.ReservedBytes
                - value.ConsumedBytes);
        }
        return actualCount >= 0 && actualBytes >= 0
            && checked((ulong)actualCount + unusedCount)
                <= (ulong)options.MaximumStoredClosures
            && checked((ulong)actualBytes + unusedBytes)
                <= (ulong)options.MaximumClosureStoreBytes;
    }

    private int AccountSchedule(byte[]? schedule) => schedule is null
        ? 0
        : checked(schedule.Length + options.ClosureScheduleAccountingOverheadBytes);

    private void CommitScheduleWithCapacityTransfer(
        string path,
        byte[]? existingSchedule,
        byte[] replacement,
        ProductionMailboxSelectionSuccessorProof proof,
        CapacityFloorState beforeFloor,
        ProductionMailboxCapacityReservation beforeReservation,
        ProductionMailboxCapacityReservation afterReservation,
        IReadOnlyList<ProductionMailboxCapacityReservation> afterReservations)
    {
        var beforeReservations = afterReservations.Select(value =>
                Fixed(value.CohortId.Span, beforeReservation.CohortId.Span)
                    ? beforeReservation : value)
            .ToArray();
        var beforeLedger = CanonicalCapacityLedger(beforeReservations);
        var currentLedger = ReadProtectedBounded(capacityLedgerPath, 40,
            checked(40 + options.MaximumClosureReservations
                * ProductionMailboxCapacityLedgerCodec.RecordLength));
        if (!currentLedger.AsSpan().SequenceEqual(beforeLedger))
            throw new InvalidOperationException(
                "Production mailbox capacity ledger changed before transfer.");
        var afterLedger = CanonicalCapacityLedger(afterReservations);
        var afterMarker = ProductionMailboxCapacityFloorCodec.Encode(
            afterReservation, hmacKey);
        var afterMarkerHash = SHA256.HashData(afterMarker);
        var journal = ProductionMailboxCapacityTransferJournalCodec.Encode(new(
            existingSchedule is not null,
            proof.SelectionInputCommitment.ToArray(),
            proof.OldCanonicalSelectionHash.ToArray(),
            existingSchedule is null ? new byte[32] : SHA256.HashData(existingSchedule),
            SHA256.HashData(replacement), beforeReservation.CohortId.ToArray(),
            beforeReservation.ConsumedClosureCount, beforeReservation.ConsumedBytes,
            afterReservation.ConsumedClosureCount, afterReservation.ConsumedBytes,
            SHA256.HashData(beforeLedger), SHA256.HashData(afterLedger),
            beforeFloor.MarkerSha256, afterMarkerHash,
            beforeReservation.StateGeneration, afterReservation.StateGeneration), hmacKey);
        try
        {
            WriteAtomic(capacityTransferPath, journal);
            testHooks?.AfterCapacityTransferJournal?.Invoke();
            WriteAtomic(path, replacement);
            testHooks?.AfterCapacityTransferSchedule?.Invoke();
            var writtenFloor = WriteCapacityFloor(afterReservation);
            if (!Fixed(writtenFloor.MarkerSha256, afterMarkerHash))
                throw new InvalidOperationException(
                    "Production mailbox capacity transfer floor is inconsistent.");
            testHooks?.AfterCapacityTransferFloor?.Invoke();
            WriteAtomic(capacityLedgerPath, afterLedger);
            testHooks?.AfterCapacityTransferLedger?.Invoke();
            DeleteProtectedFile(beforeFloor.Path);
            DeleteProtectedFile(capacityTransferPath);
        }
        catch
        {
            if (testHooks?.SimulateCapacityTransferProcessTermination != true)
                RecoverCapacityTransfer();
            throw;
        }
    }

    private void RecoverCapacityTransfer()
    {
        byte[] encoded;
        try
        {
            encoded = ReadProtectedBounded(capacityTransferPath,
                ProductionMailboxCapacityTransferJournalCodec.EncodedLength,
                ProductionMailboxCapacityTransferJournalCodec.EncodedLength);
        }
        catch (FileNotFoundException)
        {
            return;
        }
        var journal = ProductionMailboxCapacityTransferJournalCodec.Decode(encoded, hmacKey);
        var schedulePath = SchedulePath(journal.SelectionInputCommitment.Span,
            journal.DurableOldSelectionHash.Span);
        byte[]? schedule = null;
        try { schedule = ReadScheduleBounded(schedulePath); }
        catch (FileNotFoundException) { }
        var scheduleHash = schedule is null ? new byte[32] : SHA256.HashData(schedule);
        var isOldSchedule = schedule is null
            ? !journal.OldScheduleExists
            : journal.OldScheduleExists
                && Fixed(scheduleHash, journal.OldScheduleSha256.Span);
        var isNewSchedule = schedule is not null
            && Fixed(scheduleHash, journal.NewScheduleSha256.Span);
        var ledger = ReadProtectedBounded(capacityLedgerPath, 40,
            checked(40 + options.MaximumClosureReservations
                * ProductionMailboxCapacityLedgerCodec.RecordLength));
        var ledgerHash = SHA256.HashData(ledger);
        if (isOldSchedule)
        {
            if (!Fixed(ledgerHash, journal.BeforeLedgerSha256.Span))
                throw new InvalidOperationException(
                    "Production mailbox capacity transfer has inconsistent old state.");
        }
        else if (isNewSchedule)
        {
            var afterFloor = FindCapacityFloorByHash(journal.AfterMarkerSha256.Span);
            if (afterFloor is null)
            {
                var beforeFloor = FindCapacityFloorByHash(
                    journal.BeforeMarkerSha256.Span)
                    ?? throw new InvalidOperationException(
                        "Production mailbox capacity transfer lost its predecessor floor.");
                var before = beforeFloor.Reservation;
                if (!Fixed(before.CohortId.Span, journal.CohortId.Span)
                    || before.StateGeneration != journal.BeforeStateGeneration
                    || before.ConsumedClosureCount
                        != journal.BeforeConsumedClosureCount
                    || before.ConsumedBytes != journal.BeforeConsumedBytes)
                    throw new InvalidOperationException(
                        "Production mailbox capacity transfer cannot recover its reservation.");
                var after = before with
                {
                    StateGeneration = journal.AfterStateGeneration,
                    ConsumedClosureCount = journal.AfterConsumedClosureCount,
                    ConsumedBytes = journal.AfterConsumedBytes,
                    PredecessorMarkerSha256 = journal.BeforeMarkerSha256.ToArray()
                };
                afterFloor = WriteCapacityFloor(after);
                if (!Fixed(afterFloor.MarkerSha256,
                        journal.AfterMarkerSha256.Span))
                    throw new InvalidOperationException(
                        "Production mailbox capacity transfer floor recovery hash is invalid.");
            }
            else if (afterFloor.Reservation.StateGeneration
                         != journal.AfterStateGeneration
                     || !Fixed(afterFloor.Reservation.CohortId.Span,
                         journal.CohortId.Span))
                throw new InvalidOperationException(
                    "Production mailbox capacity transfer has inconsistent floor state.");
            ReconcileCapacityState(
                checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
            ledger = ReadProtectedBounded(capacityLedgerPath, 40,
                checked(40 + options.MaximumClosureReservations
                    * ProductionMailboxCapacityLedgerCodec.RecordLength));
            if (!Fixed(SHA256.HashData(ledger), journal.AfterLedgerSha256.Span))
                throw new InvalidOperationException(
                    "Production mailbox capacity transfer has inconsistent new ledger.");
        }
        else
        {
            throw new InvalidOperationException(
                "Production mailbox capacity transfer schedule is ambiguous.");
        }
        DeleteProtectedFile(capacityTransferPath);
    }

    private CapacityFloorState? FindCapacityFloorByHash(ReadOnlySpan<byte> markerHash)
    {
        foreach (var path in Directory.EnumerateFiles(options.ClosureDirectory,
                     ".capacity-*.pbf1", SearchOption.TopDirectoryOnly)
                 .Take(checked(options.MaximumClosureReservations * 4 + 1)))
        {
            var marker = ReadProtectedBounded(path,
                ProductionMailboxCapacityFloorCodec.EncodedLength,
                ProductionMailboxCapacityFloorCodec.EncodedLength);
            var hash = SHA256.HashData(marker);
            if (!Fixed(hash, markerHash)) continue;
            var reservation = ProductionMailboxCapacityFloorCodec.Decode(marker, hmacKey);
            var expected = CapacityFloorPath(
                reservation.CohortId.Span, reservation.StateGeneration, hash);
            if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(expected),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production mailbox capacity floor filename is not canonical.");
            return new(reservation, marker, hash, path);
        }
        return null;
    }

    private byte[] ReadProtectedBounded(string path, int minimum, int maximum)
    {
        using var stream = ProductionMailboxAuthorityNativeFile.OpenStableRead(
            path, () => ValidateRegularFilePath(path));
        if (stream.Length < minimum || stream.Length > maximum)
            throw new InvalidDataException(
                "Production mailbox protected state is outside bounds.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private void DeleteProtectedFile(string path)
    {
        ValidateRegularFilePath(path);
        durability.DeleteFile(path);
        durability.FlushParentDirectory(path);
        if (File.Exists(path))
            throw new IOException("Production mailbox protected state deletion is ambiguous.");
    }

    private ProductionMailboxSelectionSuccessorProof ValidateCacheClosure(byte[] frozen)
    {
        var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(frozen);
        var authority = ProductionMailboxAuthorityCodec.Decode(envelope.Authority.Span);
        var revocation = ProductionMailboxRevocationSnapshotCodec.Decode(envelope.Revocation.Span);
        var topology = ProductionMailboxTopologyCodec.Decode(envelope.Topology.Span);
        var selection = ProductionMailboxTopologyCodec.DecodeSelection(envelope.Selection.Span);
        var successor = ProductionMailboxSelectionSuccessorCodec.Decode(envelope.Successor.Span);
        RequireHash(envelope.Authority.Span, successor.NewCanonicalAuthorityHash.Span);
        RequireHash(envelope.Revocation.Span, authority.Revocation.SnapshotHash.Span);
        RequireHash(envelope.Topology.Span, successor.NewCanonicalTopologyHash.Span);
        RequireHash(envelope.Selection.Span, successor.NewCanonicalSelectionHash.Span);
        if (!envelope.Authority.Span.SequenceEqual(successor.CanonicalNewAuthority.Span)
            || !envelope.Selection.Span.SequenceEqual(successor.NewCanonicalSelection.Span)
            || !Fixed(authority.NetworkId.Span, options.GetExpectedNetworkId())
            || !Fixed(authority.NetworkId.Span, successor.NetworkId.Span)
            || !Fixed(revocation.NetworkId.Span, authority.NetworkId.Span)
            || revocation.AuthorityGeneration != authority.AuthorityGeneration
            || !Fixed(revocation.AuthorityBindingHash.Span,
                ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(authority))
            || revocation.RevocationGeneration != authority.Revocation.Generation
            || !Fixed(revocation.RevocationHeadHash.Span, authority.Revocation.HeadHash.Span)
            || !Fixed(revocation.PreviousRevocationHeadHash.Span,
                authority.Revocation.PreviousHeadHash.Span)
            || revocation.IssuedAtUnixSeconds != authority.Revocation.IssuedAtUnixSeconds
            || revocation.ExpiresAtUnixSeconds != authority.Revocation.ExpiresAtUnixSeconds
            || !Fixed(topology.NetworkId.Span, authority.NetworkId.Span)
            || topology.AuthorityGeneration != authority.AuthorityGeneration
            || !Fixed(topology.CanonicalAuthorityHash.Span,
                successor.NewCanonicalAuthorityHash.Span)
            || topology.TopologyGeneration != successor.NewTopologyGeneration
            || !Fixed(selection.NetworkId.Span, authority.NetworkId.Span)
            || selection.AuthorityGeneration != authority.AuthorityGeneration
            || !Fixed(selection.CanonicalAuthorityHash.Span,
                successor.NewCanonicalAuthorityHash.Span)
            || selection.TopologyGeneration != topology.TopologyGeneration
            || !Fixed(selection.CanonicalTopologyHash.Span,
                successor.NewCanonicalTopologyHash.Span)
            || selection.Epoch != successor.NewEpoch
            || selection.Generation != successor.NewEpochGeneration
            || !Fixed(selection.SelectionInputCommitment.Span, successor.SelectionInputCommitment.Span)
            || !Fixed(SHA256.HashData(authority.MrXApprovalEd25519PublicKey.Span),
                options.GetPinnedMrXKeyHash())
            || !Fixed(authority.MrXApproval.AuthorityPayloadHash.Span,
                ProductionMailboxAuthorityCodec.ComputePayloadHash(authority))
            || !new SodiumProductionMailboxAuthoritySignatureVerifier().Verify(
                authority.MrXApprovalEd25519PublicKey.Span,
                ProductionMailboxAuthorityCodec.GetSigningBytes(authority), authority.Signature.Span)
            || !new SodiumProductionMailboxRevocationSnapshotSignatureVerifier().Verify(
                authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(revocation),
                revocation.IssuerSignature.Span)
            || !new SodiumProductionMailboxTopologySignatureVerifier().Verify(
                authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxTopologyCodec.GetSigningBytes(topology), topology.IssuerSignature.Span)
            || !new SodiumProductionMailboxTopologySignatureVerifier().Verify(
                authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxTopologyCodec.GetSelectionSigningBytes(selection),
                selection.IssuerSignature.Span)
            || !new SodiumProductionMailboxSelectionSuccessorSignatureVerifier().Verify(
                authority.MailboxIssuerEd25519PublicKey.Span,
                ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(successor),
                successor.NewIssuerSignature.Span)
            || successor.IssuedAtUnixSeconds < authority.MrXApproval.RolloutNotBeforeUnixSeconds
            || successor.ExpiresAtUnixSeconds > authority.MrXApproval.RolloutNotAfterUnixSeconds
            || !successor.NewCanonicalSelectionHash.Span.SequenceEqual(SHA256.HashData(
                successor.NewCanonicalSelection.Span)))
            throw new InvalidDataException("Production mailbox closure authentication failed.");
        return successor;
    }

    private static bool IsAuthorizedTarget(
        ProductionMailboxSelectionSuccessorProof successor,
        ReadOnlySpan<byte> targetReplicaId,
        IReadOnlyList<ReadOnlyMemory<byte>> authorizedLegacyReplicaIds)
    {
        var oldSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            successor.OldCanonicalSelection.Span);
        var newSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            successor.NewCanonicalSelection.Span);
        var frozenTargetReplicaId = targetReplicaId.ToArray();
        var ordinaryReplicaIds = oldSelection.Replicas.Concat(newSelection.Replicas)
            .Select(static replica => replica.ReplicaId)
            .ToArray();
        if (authorizedLegacyReplicaIds.Any(legacyReplicaId =>
                ordinaryReplicaIds.Any(ordinaryReplicaId =>
                    Fixed(legacyReplicaId.Span, ordinaryReplicaId.Span))))
            throw new InvalidDataException(
                "Production mailbox legacy authorization redundantly names an ordinary replica.");
        if (ordinaryReplicaIds.Any(replicaId =>
                Fixed(replicaId.Span, frozenTargetReplicaId)))
            return true;
        return authorizedLegacyReplicaIds.Any(
            replicaId => Fixed(replicaId.Span, frozenTargetReplicaId));
    }

    private static byte[] FreezeEnvelope(ReadOnlySpan<byte> value)
    {
        if (value.Length is < 28 or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
            throw new InvalidDataException("Production mailbox closure is outside bounds.");
        var frozen = value.ToArray();
        if (!ProductionMailboxClosureEnvelopeCodec.Encode(
                ProductionMailboxClosureEnvelopeCodec.Decode(frozen)).AsSpan().SequenceEqual(frozen))
            throw new InvalidDataException("Production mailbox closure is non-canonical.");
        return frozen;
    }

    private string SelectionKey(ReadOnlySpan<byte> selection)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey);
        hmac.AppendData("Deep/XNode/production-mailbox-closure-state/v1"u8);
        hmac.AppendData(selection);
        return Convert.ToHexStringLower(hmac.GetHashAndReset());
    }

    private string RouteKey(ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey);
        hmac.AppendData("Deep/XNode/production-mailbox-closure-lineage/v1"u8);
        hmac.AppendData(selection);
        hmac.AppendData(oldSelectionHash);
        return Convert.ToHexStringLower(hmac.GetHashAndReset());
    }

    private string SelectionDirectory(ReadOnlySpan<byte> selection)
    {
        var key = SelectionKey(selection);
        return Path.Combine(options.ClosureDirectory, key[..2], key);
    }

    private string LineageDirectory(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash) =>
        Path.Combine(SelectionDirectory(selection), RouteKey(selection, oldSelectionHash));

    private SemaphoreSlim LineageGate(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash)
    {
        var key = RouteKey(selection, oldSelectionHash);
        return lineageGates[Convert.ToByte(key[..2], 16) & (lineageGates.Length - 1)];
    }

    private string SchedulePath(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash) =>
        Path.Combine(LineageDirectory(selection, oldSelectionHash), "schedule.pmcs1");

    private void EnsureLineageDirectory(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash)
    {
        var lineage = LineageDirectory(selection, oldSelectionHash);
        var selectionDirectory = Path.GetDirectoryName(lineage)!;
        var shard = Path.GetDirectoryName(selectionDirectory)!;
        foreach (var directory in new[] { shard, selectionDirectory, lineage })
        {
            EnsureNoReparseAncestors(directory, dataRoot);
            Directory.CreateDirectory(directory);
            EnsureNoReparseAncestors(directory, dataRoot);
            security.SecureDirectory(directory);
        }
    }

    private void ValidateLineageDirectory(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash)
    {
        var directory = LineageDirectory(selection, oldSelectionHash);
        if (Directory.Exists(directory)) EnsureNoReparseAncestors(directory, dataRoot);
    }

    private int CountLineages(ReadOnlySpan<byte> selection)
    {
        var directory = SelectionDirectory(selection);
        if (!Directory.Exists(directory)) return 0;
        EnsureNoReparseAncestors(directory, dataRoot);
        var count = 0;
        foreach (var lineage in Directory.EnumerateDirectories(
                     directory, "*", SearchOption.TopDirectoryOnly))
        {
            EnsureNoReparseAncestors(lineage, dataRoot);
            if (!File.Exists(Path.Combine(lineage, "schedule.pmcs1"))) continue;
            count++;
            if (count > options.MaximumClosureLineagesPerSelection)
                throw new InvalidOperationException(
                    "Production mailbox selection lineage capacity is exhausted.");
        }
        return count;
    }

    private void PruneExpiredLineages(ReadOnlySpan<byte> selection, ulong now)
    {
        var selectionDirectory = SelectionDirectory(selection);
        if (!Directory.Exists(selectionDirectory)) return;
        EnsureNoReparseAncestors(selectionDirectory, dataRoot);
        foreach (var schedulePath in Directory.EnumerateFiles(
                     selectionDirectory, "*.pmcs1", SearchOption.AllDirectories).ToArray())
            PruneScheduleIfGloballyExpired(schedulePath, now);
    }

    private void PruneGloballyExpiredSchedules(ulong now, string? excludedPath = null)
    {
        ValidateStoreDirectory();
        testHooks?.BeforeGlobalExpiredGc?.Invoke();
        foreach (var schedulePath in Directory.EnumerateFiles(
                     options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories)
                 .ToArray())
        {
            if (excludedPath is not null && string.Equals(
                    Path.GetFullPath(schedulePath), Path.GetFullPath(excludedPath),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
                continue;
            PruneScheduleIfGloballyExpired(schedulePath, now);
        }
    }

    private void PruneScheduleIfGloballyExpired(string schedulePath, ulong now)
    {
        var schedule = ReadScheduleBounded(schedulePath);
        var proofs = ProductionMailboxClosureScheduleCodec.Decode(schedule, 16)
            .Select(ValidateCacheClosure).ToArray();
        if (proofs.Any(proof => !IsExpired(
                proof.ExpiresAtUnixSeconds, now, options.ClockSkewSeconds)))
            return;
        ValidateRegularFilePath(schedulePath);
        Exception? ambiguousFailure = null;
        try
        {
            durability.DeleteFile(schedulePath);
            durability.FlushParentDirectory(schedulePath);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException)
        {
            ambiguousFailure = exception;
        }
        if (File.Exists(schedulePath))
            throw ambiguousFailure ?? new IOException(
                "Production mailbox expired closure schedule could not be deleted.");
        RemoveEmptyScheduleAncestors(Path.GetDirectoryName(schedulePath)!);
        if (ambiguousFailure is not null) throw ambiguousFailure;
    }

    private void RemoveEmptyScheduleAncestors(string lineageDirectory)
    {
        var stop = Path.GetFullPath(options.ClosureDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = Path.GetFullPath(lineageDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        while (!string.Equals(current, stop, comparison))
        {
            EnsureNoReparseAncestors(current, dataRoot);
            if (Directory.EnumerateFileSystemEntries(current).Any()) return;
            DeleteEmptyDirectoryDurably(current);
            var parent = Path.GetDirectoryName(current);
            if (parent is null) return;
            current = Path.GetFullPath(parent)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
    }

    private void PruneEmptyStoreDirectories()
    {
        ValidateStoreDirectory();
        var maximumDirectories = checked((long)options.MaximumStoredClosures * 3 + 256);
        var directories = Directory.EnumerateDirectories(
                options.ClosureDirectory, "*", SearchOption.AllDirectories)
            .Take(checked((int)Math.Min(maximumDirectories + 1, int.MaxValue)))
            .ToArray();
        if (directories.LongLength > maximumDirectories)
            throw new InvalidOperationException(
                "Production mailbox closure directory metadata exceeds its configured bound.");
        foreach (var directory in directories.OrderByDescending(static path => path.Length))
        {
            if (!Directory.Exists(directory)) continue;
            EnsureNoReparseAncestors(directory, dataRoot);
            if (!Directory.EnumerateFileSystemEntries(directory).Any())
                DeleteEmptyDirectoryDurably(directory);
        }
    }

    private void DeleteEmptyDirectoryDurably(string path)
    {
        Exception? ambiguousFailure = null;
        try
        {
            durability.DeleteDirectory(path);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException)
        {
            ambiguousFailure = exception;
        }
        if (Directory.Exists(path))
            throw ambiguousFailure ?? new IOException(
                "Production mailbox empty closure directory could not be deleted.");
        if (ambiguousFailure is not null) throw ambiguousFailure;
    }

    private byte[] ReadBounded(string path)
    {
        using var stream = ProductionMailboxAuthorityNativeFile.OpenStableRead(
            path,
            () => ValidateRegularFilePath(path),
            () => testHooks?.AfterClosureActualOpen?.Invoke(path));
        if (stream.Length is < 28 or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
            throw new InvalidDataException("Production mailbox closure file is outside bounds.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return bytes;
    }

    private byte[] ReadScheduleBounded(string path)
    {
        using var stream = ProductionMailboxAuthorityNativeFile.OpenStableRead(
            path,
            () => ValidateRegularFilePath(path),
            () => testHooks?.AfterClosureActualOpen?.Invoke(path));
        var maximum = checked(8L + options.MaximumClosureVersionsPerSelection
            * (4L + ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes));
        if (stream.Length is < 8 || stream.Length > maximum)
            throw new InvalidDataException("Production mailbox closure schedule file is outside bounds.");
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private void WriteAtomic(string path, byte[] bytes)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            ValidateStoreDirectory();
            EnsureNoReparseAncestors(Path.GetDirectoryName(path)!, dataRoot);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                       FileShare.None, 4096, FileOptions.WriteThrough))
            { stream.Write(bytes); stream.Flush(flushToDisk: true); }
            using (ProductionMailboxAuthorityNativeFile.OpenStableRead(
                       temporary,
                       () => ValidateRegularFilePath(temporary),
                       () => security.SecureFile(temporary)))
            {
            }
            ValidateStoreDirectory();
            durability.ReplaceFile(temporary, path);
            using (ProductionMailboxAuthorityNativeFile.OpenStableRead(
                       path,
                       () => ValidateRegularFilePath(path),
                       () => security.SecureFile(path)))
            {
            }
            durability.FlushParentDirectory(path);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                ValidateRegularFilePath(temporary);
                durability.DeleteFile(temporary);
            }
        }
    }

    private byte[] ReadKey(string path)
    {
        using var stream = ProductionMailboxAuthorityNativeFile.OpenStableRead(
            path, () => ValidateRegularFilePath(path));
        if (stream.Length != 32)
            throw new InvalidOperationException("Production mailbox closure HMAC key is invalid.");
        var bytes = new byte[32];
        stream.ReadExactly(bytes);
        if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException("Production mailbox closure HMAC key is invalid.");
        return bytes;
    }

    private IDisposable AcquireProcessLock() =>
        ProductionMailboxAuthorityNativeFile.AcquireLock(
            processLockPath,
            () => ValidateRegularFilePath(processLockPath),
            durability);

    private void ReconcileStoreState()
    {
        ValidateStoreDirectory();
        if (Directory.EnumerateFiles(options.ClosureDirectory, "*.tmp",
                SearchOption.AllDirectories).Any())
            throw new InvalidOperationException(
                "Production mailbox closure store contains an incomplete atomic write.");

        long bytes = 0;
        var count = 0;
        var lineagesBySelection = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(options.ClosureDirectory, "*.pmcs1",
                     SearchOption.AllDirectories))
        {
            var canonicalSchedule = ReadScheduleBounded(path);
            var canonicalEnvelopes = ProductionMailboxClosureScheduleCodec.Decode(
                canonicalSchedule, options.MaximumClosureVersionsPerSelection);
            var schedule = canonicalEnvelopes
                .Select(envelope => ValidateCacheClosure(envelope)).OrderBy(Order).ToArray();
            var first = schedule[0];
            var expectedPath = SchedulePath(first.SelectionInputCommitment.Span,
                first.OldCanonicalSelectionHash.Span);
            if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(expectedPath),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production mailbox closure filename is not bound to its authenticated route and content.");
            for (var index = 1; index < schedule.Length; index++)
                EnsureStrictlyForward(schedule[index - 1], schedule[index]);
            if (schedule.Any(proof =>
                    !Fixed(proof.SelectionInputCommitment.Span,
                        first.SelectionInputCommitment.Span)
                    || !Fixed(proof.OldCanonicalSelectionHash.Span,
                        first.OldCanonicalSelectionHash.Span)))
                throw new InvalidDataException(
                    "Production mailbox closure schedule mixes authenticated lineages.");
            var routeKey = RouteKey(first.SelectionInputCommitment.Span,
                first.OldCanonicalSelectionHash.Span);
            var selectionKey = SelectionKey(first.SelectionInputCommitment.Span);
            if (!lineagesBySelection.TryGetValue(selectionKey, out var lineages))
                lineagesBySelection[selectionKey] = lineages = new(StringComparer.Ordinal);
            lineages.Add(routeKey);
            if (lineages.Count > options.MaximumClosureLineagesPerSelection)
                throw new InvalidOperationException(
                    "Production mailbox closure store exceeds its per-selection lineage bound.");
            bytes = checked(bytes + AccountSchedule(canonicalSchedule));
            count = checked(count + schedule.Length);
            if (bytes > options.MaximumClosureStoreBytes
                || count > options.MaximumStoredClosures)
                throw new InvalidOperationException(
                    "Production mailbox closure store exceeds configured capacity.");
        }
        storedBytes = bytes;
        storedClosures = count;
    }

    private void ValidateStoreDirectory() =>
        EnsureNoReparseAncestors(options.ClosureDirectory, dataRoot);

    private void ValidateRegularFilePath(string path)
    {
        EnsureNoReparseAncestors(path, dataRoot);
        if (!File.Exists(path))
            throw new FileNotFoundException(
                "Production mailbox protected file is missing.", path);
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidDataException(
                "Production mailbox closure state contains a reparse point.");
    }
    private static void EnsureNoReparseAncestors(string path, string root)
    {
        var canonicalRoot = Path.GetFullPath(root).TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = Path.GetFullPath(path);
        while (current.Length >= canonicalRoot.Length)
        {
            if (File.Exists(current) || Directory.Exists(current))
            {
                var attributes = File.GetAttributes(current);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidOperationException(
                        "Production mailbox closure state cannot traverse a reparse point.");
            }
            if (string.Equals(current, canonicalRoot,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                return;
            current = Path.GetDirectoryName(current)
                ?? throw new InvalidOperationException(
                    "Production mailbox closure state escaped its data root.");
        }
        throw new InvalidOperationException(
            "Production mailbox closure state escaped its data root.");
    }
    private static void RequireHash(ReadOnlySpan<byte> value, ReadOnlySpan<byte> expected)
    { if (!Fixed(SHA256.HashData(value), expected)) throw new InvalidDataException("Production mailbox closure hash mismatch."); }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool IsLiveWindow(ulong issuedAt, ulong expiresAt, ulong now, uint skew) =>
        (now >= issuedAt || issuedAt - now <= skew)
        && (now <= expiresAt || now - expiresAt <= skew);
    private static bool IsExpired(ulong expiresAt, ulong now, uint skew) =>
        now > expiresAt && now - expiresAt > skew;
    private static bool IsFresh(ulong timestamp, ulong now, uint skew) =>
        timestamp >= now ? timestamp - now <= skew : now - timestamp <= skew;
    private static (ulong Authority, ulong Topology, ulong Epoch, ulong Generation) Order(
        ProductionMailboxSelectionSuccessorProof proof)
    {
        var authority = ProductionMailboxAuthorityCodec.Decode(
            proof.CanonicalNewAuthority.Span);
        return (authority.AuthorityGeneration, proof.NewTopologyGeneration,
            proof.NewEpoch, proof.NewEpochGeneration);
    }
}

internal sealed record ProductionMailboxClosureStoreTestHooks(
    Action<string>? AfterClosureActualOpen = null,
    Action? BeforeGlobalExpiredGc = null,
    Action? BeforeCapacityAdmission = null,
    Action? AfterCapacityTransferJournal = null,
    Action? AfterCapacityTransferSchedule = null,
    Action? AfterCapacityTransferFloor = null,
    Action? AfterCapacityTransferLedger = null,
    Action? AfterCapacityReservationFloor = null,
    Action? AfterCapacityReservationLedger = null,
    Action? AfterCapacityReservationDelete = null,
    bool SimulateCapacityTransferProcessTermination = false);
