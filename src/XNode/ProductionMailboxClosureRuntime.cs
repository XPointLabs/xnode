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
    public const string CapacityReconciliationRoute =
        "/api/peer/production-mailbox/closure-capacity-reconciliation";
    public const string RequestMediaType = "application/vnd.deep.production-mailbox-closure-request";
    public const string ClosureMediaType = "application/vnd.deep.production-mailbox-closure";
    public const string PrepositionMediaType =
        "application/vnd.deep.production-mailbox-preposition-command";
    public const string CapacityCommandMediaType =
        "application/vnd.deep.production-mailbox-capacity-command";
    public const string CapacityReceiptMediaType =
        "application/vnd.deep.production-mailbox-capacity-receipt";
    public const string CapacityReconciliationCommandMediaType =
        "application/vnd.deep.production-mailbox-capacity-reconciliation-command";
    public const string CapacityReconciliationReceiptMediaType =
        "application/vnd.deep.production-mailbox-capacity-reconciliation-receipt";

    public static bool IsPrepositionListener(int? localPort, int peerPort) =>
        localPort == peerPort;
}

internal static class ProductionMailboxClosureHttpEndpoint
{
    internal static async Task<IResult> HandleCapacityReconciliationAsync(
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
                != ProductionMailboxCapacityReconciliationCommandCodec.EncodedLength
            || !string.Equals(context.Request.ContentType,
                ProductionMailboxClosureHttpContract.CapacityReconciliationCommandMediaType,
                StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest();
        var command = new byte[
            ProductionMailboxCapacityReconciliationCommandCodec.EncodedLength];
        try
        {
            await context.Request.Body.ReadExactlyAsync(command, cancellationToken);
            var receipt = await closures.ReconcileAbsentCapacityAsync(
                command, cancellationToken);
            return Results.File(receipt,
                ProductionMailboxClosureHttpContract.CapacityReconciliationReceiptMediaType,
                enableRangeProcessing: false);
        }
        catch (Exception exception) when (exception is InvalidDataException
            or CryptographicException or InvalidOperationException or IOException
            or OverflowException
            || exception is OperationCanceledException
                && context.RequestAborted.IsCancellationRequested)
        { return Results.BadRequest(); }
    }

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
    ProductionMailboxRouteAuthorizationKind AuthorizationKind,
    ReadOnlyMemory<byte> CacheSalt,
    ReadOnlyMemory<byte> LineageCommitment,
    ReadOnlyMemory<byte> Authority,
    ReadOnlyMemory<byte> Revocations,
    ReadOnlyMemory<byte> Topology,
    ReadOnlyMemory<byte> CurrentSelection,
    ReadOnlyMemory<byte> NextSelection,
    ReadOnlyMemory<byte> SelectionSuccessorV2,
    ReadOnlyMemory<byte> RouteCertificate,
    ReadOnlyMemory<byte> TransitionContext,
    ReadOnlyMemory<byte> RouteAuthorization,
    ReadOnlyMemory<byte> RevocationCheckpoint);

public static class ProductionMailboxClosureEnvelopeCodec
{
    private static ReadOnlySpan<byte> Magic => "PMC2"u8;
    private static ReadOnlySpan<byte> CommitmentDomain =>
        "Deep/XNode/production-mailbox-route-lineage-commitment/v2"u8;
    public const int HeaderLength = 112;
    public const int MaximumEnvelopeBytes = HeaderLength
        + ProductionMailboxNodeCacheVerifier.MaximumAggregateBytes;

    public static byte[] Encode(ProductionMailboxClosureEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);
        Validate(value);
        var fields = Fields(value);
        var total = fields.Aggregate(HeaderLength,
            static (sum, field) => checked(sum + field.Length));
        var bytes = new byte[total];
        Magic.CopyTo(bytes); bytes[4] = 2;
        bytes[5] = checked((byte)value.AuthorizationKind);
        value.CacheSalt.Span.CopyTo(bytes.AsSpan(8));
        value.LineageCommitment.Span.CopyTo(bytes.AsSpan(40));
        for (var index = 0; index < fields.Length; index++)
            WriteLength(bytes.AsSpan(72 + index * 4), fields[index].Length);
        var offset = HeaderLength;
        foreach (var field in fields)
            Copy(field, bytes, ref offset);
        return bytes;
    }

    public static ProductionMailboxClosureEnvelope Decode(ReadOnlySpan<byte> encoded)
    {
        try { return DecodeCore(encoded); }
        catch (Exception exception) when (exception is FormatException
            or ProductionMailboxAuthorityException
            or ProductionMailboxRevocationSnapshotException
            or ProductionMailboxTopologyException
            or ProductionMailboxSelectionSuccessorException
            or ProductionMailboxRouteAdvertisementException
            or ProductionMailboxRouteAuthorizationException
            or ProductionMailboxRouteContinuityException)
        {
            throw new InvalidDataException(
                "Production mailbox closure protocol framing is invalid.", exception);
        }
    }

    private static ProductionMailboxClosureEnvelope DecodeCore(ReadOnlySpan<byte> encoded)
    {
        Preflight(encoded);
        var authorizationKind = (ProductionMailboxRouteAuthorizationKind)encoded[5];
        Span<int> lengths = stackalloc int[10];
        for (var index = 0; index < lengths.Length; index++)
            lengths[index] = ReadLength(encoded[(72 + index * 4)..]);
        var offset = HeaderLength;
        var fields = new byte[lengths.Length][];
        for (var i = 0; i < lengths.Length; i++)
            fields[i] = Take(encoded, ref offset, lengths[i]);
        var value = new ProductionMailboxClosureEnvelope(authorizationKind,
            encoded.Slice(8, 32).ToArray(), encoded.Slice(40, 32).ToArray(),
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
            fields[6], fields[7], fields[9], fields[8]);
        Validate(value);
        if (!Encode(value).AsSpan().SequenceEqual(encoded))
            throw new InvalidDataException("Production mailbox closure is non-canonical.");
        return value;
    }

    internal static void Preflight(ReadOnlySpan<byte> encoded)
    {
        try { PreflightCore(encoded); }
        catch (OverflowException exception)
        {
            throw new InvalidDataException(
                "Production mailbox closure length framing overflowed.", exception);
        }
    }

    private static void PreflightCore(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < HeaderLength or > MaximumEnvelopeBytes
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 2
            || encoded[6] != 0 || encoded[7] != 0)
            throw new InvalidDataException("Production mailbox closure header is invalid.");
        var authorizationKind = (ProductionMailboxRouteAuthorizationKind)encoded[5];
        Span<int> lengths = stackalloc int[10];
        var total = HeaderLength;
        for (var index = 0; index < lengths.Length; index++)
        {
            lengths[index] = ReadLength(encoded[(72 + index * 4)..]);
            total = checked(total + lengths[index]);
        }
        ValidateShape(authorizationKind, encoded.Slice(8, 32),
            encoded.Slice(40, 32), lengths, total, encoded.Length);
        if (total != encoded.Length)
            throw new InvalidDataException("Production mailbox closure length is invalid.");
        PreflightArtifacts(encoded, lengths, authorizationKind);
    }

    public static byte[] ComputeLineageCommitment(ProductionMailboxClosureEnvelope value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var fields = Fields(value);
        var total = fields.Aggregate(HeaderLength,
            static (sum, field) => checked(sum + field.Length));
        Span<int> lengths = stackalloc int[10];
        for (var index = 0; index < fields.Length; index++) lengths[index] = fields[index].Length;
        ValidateShape(value.AuthorizationKind, value.CacheSalt.Span,
            new byte[32], lengths, total, total, allowZeroCommitment: true);
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            value.SelectionSuccessorV2.Span);
        var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
            value.TransitionContext.Span);
        if (pss.Selection.Mode != rtc.Mode || pss.NewAuthorizationKind != value.AuthorizationKind)
            throw new InvalidDataException("Production mailbox closure transition tags differ.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(CommitmentDomain);
        hash.AppendData(pss.Selection.NetworkId.Span);
        hash.AppendData(pss.Selection.MailboxOwnerEd25519PublicKey.Span);
        hash.AppendData(pss.Selection.SelectionInputCommitment.Span);
        hash.AppendData(pss.Selection.OldCanonicalSelectionHash.Span);
        hash.AppendData(rtc.SealedOldRouteOriginLkgHash.Span);
        hash.AppendData(stackalloc byte[] { (byte)rtc.Mode, (byte)value.AuthorizationKind });
        hash.AppendData(SHA256.HashData(value.TransitionContext.Span));
        hash.AppendData(SHA256.HashData(value.SelectionSuccessorV2.Span));
        hash.AppendData(value.CacheSalt.Span);
        return hash.GetHashAndReset();
    }

    private static void Validate(ProductionMailboxClosureEnvelope value)
    {
        var fields = Fields(value);
        var total = fields.Aggregate(HeaderLength,
            static (sum, field) => checked(sum + field.Length));
        Span<int> lengths = stackalloc int[10];
        for (var index = 0; index < fields.Length; index++) lengths[index] = fields[index].Length;
        ValidateShape(value.AuthorizationKind, value.CacheSalt.Span,
            value.LineageCommitment.Span, lengths, total, total);
        if (!CryptographicOperations.FixedTimeEquals(
                ComputeLineageCommitment(value), value.LineageCommitment.Span))
            throw new InvalidDataException("Production mailbox closure commitment is invalid.");
    }

    private static void ValidateShape(ProductionMailboxRouteAuthorizationKind kind,
        ReadOnlySpan<byte> salt, ReadOnlySpan<byte> commitment, ReadOnlySpan<int> lengths,
        int total, int encodedLength, bool allowZeroCommitment = false)
    {
        var tagged = kind switch
        {
            ProductionMailboxRouteAuthorizationKind.OwnerPRA2 =>
                lengths[8] == 0 && lengths[9] ==
                    ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length,
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1 =>
                lengths[8] == ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength
                && lengths[9] == ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength,
            _ => false
        };
        if (salt.Length != 32 || salt.IndexOfAnyExcept((byte)0) < 0
            || commitment.Length != 32
            || (!allowZeroCommitment && commitment.IndexOfAnyExcept((byte)0) < 0)
            || lengths.Length != 10 || total != encodedLength
            || total > MaximumEnvelopeBytes
            || lengths[0] is < 1 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes
            || lengths[1] is < 1 or > ProductionMailboxRevocationSnapshotConstants.MaximumArtifactBytes
            || lengths[2] is < 1 or > ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes
            || lengths[3] is < 1 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || lengths[4] is < 1 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || lengths[5] is < 1 or > ProductionMailboxSelectionSuccessorV2Constants.MaximumArtifactBytes
            || lengths[6] != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength
            || lengths[7] != ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength
            || !tagged)
            throw new InvalidDataException("Production mailbox closure shape is invalid.");
    }

    private static ReadOnlyMemory<byte>[] Fields(ProductionMailboxClosureEnvelope value) =>
    [
        value.Authority, value.Revocations, value.Topology, value.CurrentSelection,
        value.NextSelection, value.SelectionSuccessorV2, value.RouteCertificate,
        value.TransitionContext, value.RevocationCheckpoint, value.RouteAuthorization
    ];

    private static void WriteLength(Span<byte> target, int value) =>
        BinaryPrimitives.WriteUInt32BigEndian(target, checked((uint)value));
    private static int ReadLength(ReadOnlySpan<byte> source) =>
        checked((int)BinaryPrimitives.ReadUInt32BigEndian(source));
    private static void Copy(ReadOnlyMemory<byte> source, byte[] target, ref int offset)
    { source.Span.CopyTo(target.AsSpan(offset)); offset += source.Length; }
    private static byte[] Take(ReadOnlySpan<byte> source, ref int offset, int length)
    { var result = source.Slice(offset, length).ToArray(); offset += length; return result; }

    private static void PreflightArtifacts(ReadOnlySpan<byte> encoded,
        ReadOnlySpan<int> lengths, ProductionMailboxRouteAuthorizationKind kind)
    {
        var offset = HeaderLength + lengths[0];
        PreflightPmr(encoded.Slice(offset, lengths[1])); offset += lengths[1];
        PreflightPmt(encoded.Slice(offset, lengths[2])); offset += lengths[2];
        PreflightPms(encoded.Slice(offset, lengths[3])); offset += lengths[3];
        PreflightPms(encoded.Slice(offset, lengths[4])); offset += lengths[4];
        PreflightPss(encoded.Slice(offset, lengths[5]), kind);
    }

    private static void PreflightPmr(ReadOnlySpan<byte> encoded)
    {
        const int countOffset = 152;
        if (encoded.Length < ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials
            || !encoded[..4].SequenceEqual("PMR1"u8)
            || encoded[4] != ProductionMailboxRevocationSnapshotConstants.Version
            || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox PMR1 framing is invalid.");
        var count = BinaryPrimitives.ReadUInt16LittleEndian(encoded.Slice(countOffset, 2));
        var expected = checked(
            ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials
            + count * ProductionMailboxRevocationSnapshotConstants.RevokedGrantSerialBytes);
        if (count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials
            || encoded.Length != expected)
            throw new InvalidDataException("Production mailbox PMR1 count framing is invalid.");
    }

    private static void PreflightPmt(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < 780 || !encoded[..4].SequenceEqual("PMT1"u8)
            || encoded[4] != 1 || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox PMT1 framing is invalid.");
        var offset = 120;
        ParsePmtEpoch(encoded, ref offset);
        ParsePmtEpoch(encoded, ref offset);
        if (offset != encoded.Length - 64)
            throw new InvalidDataException("Production mailbox PMT1 trailing framing is invalid.");
    }

    private static void ParsePmtEpoch(ReadOnlySpan<byte> encoded, ref int offset)
    {
        const int fixedBeforeNodes = 100;
        if (offset > encoded.Length - fixedBeforeNodes - 64)
            throw new InvalidDataException("Production mailbox PMT1 epoch framing is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 96, 2));
        if (encoded.Slice(offset + 98, 2).IndexOfAnyExcept((byte)0) >= 0
            || count is < 2 or > ProductionMailboxTopologyConstants.MaximumNodesPerEpoch)
            throw new InvalidDataException("Production mailbox PMT1 epoch count is invalid.");
        offset += fixedBeforeNodes;
        for (var index = 0; index < count; index++)
        {
            const int nodeFixed = 98;
            if (offset > encoded.Length - nodeFixed - 64)
                throw new InvalidDataException("Production mailbox PMT1 node framing is invalid.");
            var endpointLength = BinaryPrimitives.ReadUInt16BigEndian(
                encoded.Slice(offset + 32, 2));
            if (endpointLength is 0 or > ProductionMailboxTopologyConstants.MaximumEndpointBytes
                || offset > encoded.Length - nodeFixed - endpointLength - 64)
                throw new InvalidDataException("Production mailbox PMT1 endpoint framing is invalid.");
            offset += nodeFixed + endpointLength;
        }
    }

    private static void PreflightPms(ReadOnlySpan<byte> encoded)
    {
        const int headerLength = 272;
        if (encoded.Length < headerLength + 2 * 36 + 64
            || !encoded[..4].SequenceEqual("PMS1"u8) || encoded[4] != 1
            || encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0
            || encoded[268] != ProductionMailboxTopologyConstants.ReplicaCount
            || encoded.Slice(269, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox PMS1 framing is invalid.");
        var offset = headerLength;
        for (var index = 0; index < ProductionMailboxTopologyConstants.ReplicaCount; index++)
        {
            if (offset > encoded.Length - 36 - 64)
                throw new InvalidDataException("Production mailbox PMS1 replica framing is invalid.");
            var proofLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 32, 2));
            if (encoded.Slice(offset + 34, 2).IndexOfAnyExcept((byte)0) >= 0
                || proofLength == 0 || offset > encoded.Length - 36 - proofLength - 64)
                throw new InvalidDataException("Production mailbox PMS1 proof framing is invalid.");
            offset += 36 + proofLength;
        }
        if (offset != encoded.Length - 64)
            throw new InvalidDataException("Production mailbox PMS1 trailing framing is invalid.");
    }

    private static void PreflightPss(ReadOnlySpan<byte> encoded,
        ProductionMailboxRouteAuthorizationKind kind)
    {
        const int lengthsOffset = 408;
        if (encoded.Length < ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength
                + ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes
            || !encoded[..4].SequenceEqual("PSS2"u8)
            || encoded[4] != ProductionMailboxSelectionSuccessorV2Constants.Version
            || encoded[5] is not (byte)ProductionMailboxSelectionSuccessorMode.DirectPromotion
                and not (byte)ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint
            || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(414, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(450, 6).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox PSS2 header framing is invalid.");
        var authorityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(lengthsOffset, 2));
        var oldLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(lengthsOffset + 2, 2));
        var currentLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(lengthsOffset + 4, 2));
        var expected = checked(ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength
            + authorityLength + oldLength + currentLength
            + ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes);
        if (authorityLength is 0 or > ProductionMailboxAuthorityConstants.MaximumArtifactBytes
            || oldLength is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || currentLength is 0 or > ProductionMailboxTopologyConstants.MaximumSelectionArtifactBytes
            || encoded.Length != expected || encoded[449] != (byte)kind)
            throw new InvalidDataException("Production mailbox PSS2 count framing is invalid.");
    }
}

public sealed record ProductionMailboxClosureRequest(
    ulong TimestampUnixSeconds,
    ReadOnlyMemory<byte> Nonce,
    ReadOnlyMemory<byte> SelectionInputCommitment,
    ReadOnlyMemory<byte> DurableOldSelectionHash,
    ReadOnlyMemory<byte> LineageCommitment,
    ReadOnlyMemory<byte> TargetReplicaId,
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> OwnerSignature);

public static class ProductionMailboxClosureRequestCodec
{
    private static ReadOnlySpan<byte> Magic => "PMQ2"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMQ2/retrieve/v2"u8;
    public const int EncodedLength = 272;

    public static byte[] Encode(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value); Validate(value);
        var bytes = new byte[EncodedLength]; Magic.CopyTo(bytes); bytes[4] = 2;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), value.TimestampUnixSeconds);
        value.Nonce.Span.CopyTo(bytes.AsSpan(16));
        value.SelectionInputCommitment.Span.CopyTo(bytes.AsSpan(48));
        value.DurableOldSelectionHash.Span.CopyTo(bytes.AsSpan(80));
        value.LineageCommitment.Span.CopyTo(bytes.AsSpan(112));
        value.TargetReplicaId.Span.CopyTo(bytes.AsSpan(144));
        value.MailboxOwnerEd25519PublicKey.Span.CopyTo(bytes.AsSpan(176));
        value.OwnerSignature.Span.CopyTo(bytes.AsSpan(208));
        return bytes;
    }

    public static ProductionMailboxClosureRequest Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength || !encoded[..4].SequenceEqual(Magic)
            || encoded[4] != 2 || encoded[5] != 0 || encoded[6] != 0 || encoded[7] != 0)
            throw new InvalidDataException("Production mailbox closure request is invalid.");
        var value = new ProductionMailboxClosureRequest(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]), encoded.Slice(16, 32).ToArray(),
            encoded.Slice(48, 32).ToArray(), encoded.Slice(80, 32).ToArray(),
            encoded.Slice(112, 32).ToArray(), encoded.Slice(144, 32).ToArray(),
            encoded.Slice(176, 32).ToArray(), encoded.Slice(208, 64).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value); Validate(value, allowZeroSignature: true);
        var bytes = new byte[SignatureDomain.Length + 200];
        SignatureDomain.CopyTo(bytes); var offset = SignatureDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), value.TimestampUnixSeconds); offset += 8;
        value.Nonce.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.SelectionInputCommitment.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.DurableOldSelectionHash.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.LineageCommitment.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.TargetReplicaId.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
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
            || Invalid(value.LineageCommitment, 32)
            || Invalid(value.TargetReplicaId, 32)
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
    ReadOnlyMemory<byte> PublisherSignature,
    ReadOnlyMemory<byte> CanonicalEnvelope,
    ReadOnlyMemory<byte> ReservationCohortId = default);

public static class ProductionMailboxPrepositionCommandCodec
{
    private static ReadOnlySpan<byte> Magic => "PMP2"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMP2/preposition/v2"u8;
    public const int HeaderLength = 280;
    public const int MaximumCommandBytes = HeaderLength
        + ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes;

    public static byte[] Encode(ProductionMailboxPrepositionCommand value)
    {
        var frozen = Freeze(value);
        Validate(frozen);
        var bytes = new byte[checked(HeaderLength + frozen.CanonicalEnvelope.Length)];
        Magic.CopyTo(bytes); bytes[4] = 2;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), frozen.TimestampUnixSeconds);
        frozen.Nonce.Span.CopyTo(bytes.AsSpan(16));
        frozen.EnvelopeSha256.Span.CopyTo(bytes.AsSpan(48));
        frozen.TargetReplicaId.Span.CopyTo(bytes.AsSpan(80));
        frozen.PublisherSignature.Span.CopyTo(bytes.AsSpan(176));
        frozen.ReservationCohortId.Span.CopyTo(bytes.AsSpan(240));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(272),
            checked((uint)frozen.CanonicalEnvelope.Length));
        frozen.CanonicalEnvelope.Span.CopyTo(bytes.AsSpan(HeaderLength));
        return bytes;
    }

    public static ProductionMailboxPrepositionCommand Decode(ReadOnlySpan<byte> encoded)
    {
        Preflight(encoded);
        var envelopeLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded[272..]));
        _ = ProductionMailboxClosureEnvelopeCodec.Decode(encoded.Slice(HeaderLength, envelopeLength));
        var value = new ProductionMailboxPrepositionCommand(
            BinaryPrimitives.ReadUInt64BigEndian(encoded[8..]), encoded.Slice(16, 32).ToArray(),
            encoded.Slice(48, 32).ToArray(), encoded.Slice(80, 32).ToArray(),
            encoded.Slice(176, 64).ToArray(), encoded[HeaderLength..].ToArray(),
            encoded.Slice(240, 32).ToArray());
        Validate(value); return value;
    }

    internal static void Preflight(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < HeaderLength or > MaximumCommandBytes
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 2
            || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(276, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox preposition command header is invalid.");
        if (encoded[5] != 0 || encoded.Slice(112, 64).IndexOfAnyExcept((byte)0) >= 0)
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
        ProductionMailboxClosureEnvelopeCodec.Preflight(
            encoded.Slice(HeaderLength, envelopeLength));
    }

    public static byte[] GetSigningBytes(ProductionMailboxPrepositionCommand value)
    {
        var frozen = Freeze(value);
        Validate(frozen, allowZeroSignature: true);
        return GetFrozenSigningBytes(frozen);
    }

    private static byte[] GetFrozenSigningBytes(ProductionMailboxPrepositionCommand frozen)
    {
        var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(frozen.CanonicalEnvelope.Span);
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            envelope.SelectionSuccessorV2.Span);
        var bytes = new byte[SignatureDomain.Length + 234];
        SignatureDomain.CopyTo(bytes); var offset = SignatureDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), frozen.TimestampUnixSeconds); offset += 8;
        frozen.Nonce.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        frozen.EnvelopeSha256.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        frozen.TargetReplicaId.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        offset += 65; // Fixed zero legacy-count byte followed by two fixed zero slots.
        frozen.ReservationCohortId.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        bytes[offset++] = (byte)pss.Selection.Mode;
        envelope.LineageCommitment.Span.CopyTo(bytes.AsSpan(offset));
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
            || value.ReservationCohortId.Length != 32
            || value.PublisherSignature.Length != 64
            || (!allowZeroSignature && value.PublisherSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            || value.CanonicalEnvelope.Length is < ProductionMailboxClosureEnvelopeCodec.HeaderLength
                or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
            throw new InvalidDataException("Production mailbox preposition command fields are invalid.");
        _ = ProductionMailboxClosureEnvelopeCodec.Decode(value.CanonicalEnvelope.Span);
    }

    private static ProductionMailboxPrepositionCommand Freeze(
        ProductionMailboxPrepositionCommand value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Nonce.Length != 32 || value.EnvelopeSha256.Length != 32
            || value.TargetReplicaId.Length != 32 || value.PublisherSignature.Length != 64
            || value.ReservationCohortId.Length is not (0 or 32)
            || value.CanonicalEnvelope.Length is < ProductionMailboxClosureEnvelopeCodec.HeaderLength
                or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
            throw new InvalidDataException(
                "Production mailbox preposition command fields are invalid.");
        _ = ProductionMailboxClosureEnvelopeCodec.Decode(value.CanonicalEnvelope.Span);
        return value with
        {
            Nonce = value.Nonce.ToArray(),
            EnvelopeSha256 = value.EnvelopeSha256.ToArray(),
            TargetReplicaId = value.TargetReplicaId.ToArray(),
            PublisherSignature = value.PublisherSignature.ToArray(),
            CanonicalEnvelope = value.CanonicalEnvelope.ToArray(),
            ReservationCohortId = value.ReservationCohortId.IsEmpty
                ? new byte[32]
                : value.ReservationCohortId.ToArray()
        };
    }
    private static bool Invalid(ReadOnlyMemory<byte> value, int length) =>
        value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0;

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
            ".closure-capacity-transfer.pbt2");
        using var processLock = AcquireProcessLock();
        RecoverCapacityTransfer();
        ReconcileCapacityState(
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
        PruneEmptyStoreDirectories();
        ValidateBoundedStoreDirectoryInventory();
        PruneGloballyExpiredClosures(
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
        if (!Fixed(command.TargetReplicaId.Span, node.GetRouterId().ToBytes())
            || !ProductionMailboxCapacityCommandCodec.VerifyPublisher(
                command, options.GetClosurePublisherPublicKey()))
            throw new InvalidDataException(
                "Production mailbox capacity command authentication failed.");
        var commandHash = SHA256.HashData(commandBytes);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var processLock = AcquireProcessLock();
            var floors = ReadCapacityFloorStates();
            var reservations = floors.Select(static value => value.Reservation).ToList();
            var existingIndex = reservations.FindIndex(value =>
                Fixed(value.CohortId.Span, command.CohortId.Span));
            if (existingIndex >= 0
                && Fixed(reservations[existingIndex].LastCommandSha256.Span,
                    commandHash))
                return reservations[existingIndex].LastCanonicalReceipt.ToArray();
            RecoverCapacityTransfer();
            testHooks?.BeforeCapacityAdmission?.Invoke();
            var lockedNow = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            if (!IsFresh(command.TimestampUnixSeconds, lockedNow,
                    options.ClockSkewSeconds)
                || command.ExpiresAtUnixSeconds <= lockedNow)
                throw new InvalidDataException(
                    "Production mailbox capacity command expired while awaiting admission.");
            if (command.ExpiresAtUnixSeconds - command.TimestampUnixSeconds
                    < options.MinimumClosureReservationLifetimeSeconds
                || command.ExpiresAtUnixSeconds - command.TimestampUnixSeconds
                    > options.MaximumClosureReservationLifetimeSeconds)
                throw new InvalidDataException(
                    "Production mailbox capacity command lifetime is outside policy.");
            if (command.Operation == ProductionMailboxCapacityOperation.ReserveOrRenew
                && (command.ReservedClosureCount > options.MaximumStoredClosures
                    || command.ReservedBytes > (ulong)options.MaximumClosureStoreBytes))
                throw new InvalidDataException(
                    "Production mailbox capacity command exceeds configured bounds.");
            ReconcileCapacityState(lockedNow);
            ReconcileStoreState();
            floors = ReadCapacityFloorStates();
            reservations = floors.Select(static value => value.Reservation).ToList();
            existingIndex = reservations.FindIndex(value =>
                Fixed(value.CohortId.Span, command.CohortId.Span));
            var existing = existingIndex >= 0 ? reservations[existingIndex] : null;
            var existingFloor = existing is null ? null : floors.Single(value =>
                Fixed(value.Reservation.CohortId.Span, existing.CohortId.Span));
            var existingReceiptOperation = existing is null
                ? (ProductionMailboxCapacityOperation?)null
                : ProductionMailboxCapacityReceiptCodec.Decode(
                    existing.LastCanonicalReceipt.Span).Operation;
            var isExpiredTerminalRelease = existing is not null
                && existing.Terminal
                && existingReceiptOperation
                    == ProductionMailboxCapacityOperation.ReserveOrRenew
                && command.Operation == ProductionMailboxCapacityOperation.Release;
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
                     || existing.Terminal && !isExpiredTerminalRelease
                     || command.Revision != existing.Revision + 1
                     || !Fixed(existing.TargetReplicaId.Span,
                         command.TargetReplicaId.Span)
                     || existingReceiptOperation
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
                command.Operation, lockedNow, command.ExpiresAtUnixSeconds,
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

    public async ValueTask<byte[]> ReconcileAbsentCapacityAsync(
        ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (canonicalCommand.Length
            != ProductionMailboxCapacityReconciliationCommandCodec.EncodedLength)
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation command is outside bounds.");
        var commandBytes = canonicalCommand.ToArray();
        var command = ProductionMailboxCapacityReconciliationCommandCodec.Decode(commandBytes);
        var target = node.GetRouterId().ToBytes();
        var priorReceipt = ProductionMailboxCapacityReceiptCodec.Decode(
            command.LastCanonicalReceipt.Span);
        if (!Fixed(command.TargetReplicaId.Span, target)
            || !ProductionMailboxCapacityReconciliationCommandCodec.VerifyPublisher(
                command, options.GetClosurePublisherPublicKey())
            || !ProductionMailboxCapacityReceiptCodec.VerifyNode(priorReceipt, target))
            throw new InvalidDataException(
                "Production mailbox capacity reconciliation authentication failed.");

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var processLock = AcquireProcessLock();
            var lockedNow = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            if (!IsFresh(command.TimestampUnixSeconds, lockedNow, options.ClockSkewSeconds)
                || command.ExpiresAtUnixSeconds <= lockedNow
                || command.ExpiresAtUnixSeconds - command.TimestampUnixSeconds
                    > 300)
                throw new InvalidDataException(
                    "Production mailbox capacity reconciliation command is not fresh.");

            try
            {
                _ = ReadProtectedBounded(capacityTransferPath,
                    ProductionMailboxCapacityTransferJournalCodec.EncodedLength,
                    ProductionMailboxCapacityTransferJournalCodec.EncodedLength);
                throw new InvalidOperationException(
                    "Production mailbox capacity transfer is pending.");
            }
            catch (FileNotFoundException) { }

            var floors = ReadCapacityFloorStates();
            if (floors.Any(value => Fixed(value.Reservation.CohortId.Span,
                    command.CohortId.Span)))
                throw new InvalidOperationException(
                    "Production mailbox capacity cohort is not absent.");
            var canonicalLedger = CanonicalCapacityLedger(
                floors.Select(static value => value.Reservation).ToArray());
            byte[]? storedLedger = null;
            try
            {
                storedLedger = ReadProtectedBounded(capacityLedgerPath, 40,
                    checked(40 + options.MaximumClosureReservations
                        * ProductionMailboxCapacityLedgerCodec.RecordLength));
            }
            catch (FileNotFoundException) { }
            if (floors.Count == 0 ? storedLedger is not null
                : storedLedger is null || !storedLedger.AsSpan().SequenceEqual(canonicalLedger))
                throw new InvalidOperationException(
                    "Production mailbox capacity accounting is not authoritative.");

            var accounting = ScanStoreState();
            if (accounting.Count != storedClosures || accounting.Bytes != storedBytes)
                throw new InvalidOperationException(
                    "Production mailbox closure accounting is stale.");
            var stateTranscript = new byte[32 + canonicalLedger.Length + 12];
            "Deep/PMB4/authoritative-state/v1"u8.CopyTo(stateTranscript);
            canonicalLedger.CopyTo(stateTranscript.AsSpan(32));
            BinaryPrimitives.WriteUInt32BigEndian(
                stateTranscript.AsSpan(32 + canonicalLedger.Length),
                checked((uint)accounting.Count));
            BinaryPrimitives.WriteUInt64BigEndian(
                stateTranscript.AsSpan(36 + canonicalLedger.Length),
                checked((ulong)accounting.Bytes));
            var unsigned = new ProductionMailboxCapacityReconciliationReceipt(
                ProductionMailboxCapacityReconciliationStatus.AbsentTerminal,
                lockedNow, command.ExpiresAtUnixSeconds, command.CohortId.ToArray(),
                command.TargetReplicaId.ToArray(), command.LastKnownRevision,
                command.LastReceiptSha256.ToArray(), command.LastCommandSha256.ToArray(),
                checked((uint)accounting.Count), checked((ulong)accounting.Bytes),
                SHA256.HashData(stateTranscript), new byte[64]);
            var keyPair = PublicKeyAuth.GenerateKeyPair(
                Convert.FromHexString(node.GetEd25519PrivateKey()));
            if (!Fixed(keyPair.PublicKey, target))
                throw new InvalidOperationException(
                    "Production mailbox node signing key does not match its replica id.");
            return ProductionMailboxCapacityReconciliationReceiptCodec.Encode(unsigned with
            {
                NodeSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReconciliationReceiptCodec.GetSigningBytes(unsigned),
                    keyPair.PrivateKey)
            });
        }
        finally { gate.Release(); }
    }

    public async ValueTask PrepositionAsync(ReadOnlyMemory<byte> canonicalCommand,
        CancellationToken cancellationToken)
    {
        if (canonicalCommand.Length is < ProductionMailboxPrepositionCommandCodec.HeaderLength
            or > ProductionMailboxPrepositionCommandCodec.MaximumCommandBytes)
            throw new InvalidDataException("Production mailbox preposition command is outside bounds.");
        ProductionMailboxPrepositionCommandCodec.Preflight(canonicalCommand.Span);
        testHooks?.AfterPrepositionStructuralPreflight?.Invoke();
        var commandBytes = canonicalCommand.ToArray();
        var command = ProductionMailboxPrepositionCommandCodec.Decode(commandBytes);
        var frozen = FreezeEnvelope(command.CanonicalEnvelope.Span);
        var verifiedCache = ValidateCacheClosure(frozen);
        var proof = verifiedCache.Selection;
        var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(frozen);
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        if (!ProductionMailboxPrepositionCommandCodec.IsFresh(
                command, now, options.ClockSkewSeconds)
            || !Fixed(command.TargetReplicaId.Span, node.GetRouterId().ToBytes())
            || !Fixed(command.EnvelopeSha256.Span,
                SHA256.HashData(command.CanonicalEnvelope.Span))
            || !ProductionMailboxPrepositionCommandCodec.VerifyPublisher(
                command, options.GetClosurePublisherPublicKey()))
            throw new InvalidDataException("Production mailbox preposition command authentication failed.");
        if (!IsAuthorizedTarget(proof, command.TargetReplicaId.Span))
            throw new InvalidDataException(
                "Production mailbox closure is unrelated to the authorized target replica.");
        if (!IsLiveWindow(proof.IssuedAtUnixSeconds,
                verifiedCache.CacheExpiresAtUnixSeconds,
                now, options.ClockSkewSeconds))
            throw new InvalidDataException(
                "Production mailbox closure candidate is not currently live.");
        var lineageGate = LineageGate(proof.SelectionInputCommitment.Span,
            proof.OldCanonicalSelectionHash.Span, envelope.LineageCommitment.Span);
        await lineageGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var processLock = AcquireProcessLock();
                RecoverCapacityTransfer();
                now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
                if (!ProductionMailboxPrepositionCommandCodec.IsFresh(
                        command, now, options.ClockSkewSeconds)
                    || !IsLiveWindow(proof.IssuedAtUnixSeconds,
                        verifiedCache.CacheExpiresAtUnixSeconds,
                        now, options.ClockSkewSeconds))
                    throw new InvalidDataException(
                        "Production mailbox preposition command expired while awaiting admission.");
                ReconcileCapacityState(now);
                PruneExpiredLineages(proof.SelectionInputCommitment.Span, now);
                ReconcileStoreState();
                var path = ClosurePath(proof.SelectionInputCommitment.Span,
                    proof.OldCanonicalSelectionHash.Span,
                    envelope.LineageCommitment.Span);
                byte[]? existingClosure = null;
                try
                {
                    existingClosure = ReadBounded(path);
                    _ = ValidateCacheClosure(existingClosure);
                }
                catch (FileNotFoundException)
                {
                    // A missing exact lineage is a new cardinality-one insertion.
                }
                if (existingClosure is not null)
                {
                    if (existingClosure.AsSpan().SequenceEqual(frozen)) return;
                    throw new InvalidDataException(
                        "Production mailbox route lineage conflicts with its committed bytes.");
                }
                if (CountLineages(proof.SelectionInputCommitment.Span)
                        >= options.MaximumClosureLineagesPerSelection)
                    throw new InvalidOperationException(
                        "Production mailbox selection lineage capacity is exhausted.");
                var replacement = frozen;
                var floors = ReadCapacityFloorStates();
                var reservations = floors.Select(static value => value.Reservation).ToList();
                var projectedClosures = checked(storedClosures + 1);
                var projectedBytes = checked(storedBytes + AccountClosure(replacement));
                const int additionalCount = 1;
                var additionalBytes = checked((ulong)AccountClosure(replacement));
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
                    PruneGloballyExpiredClosures(now, path);
                    ReconcileStoreState();
                    projectedClosures = checked(storedClosures + 1);
                    projectedBytes = checked(storedBytes + AccountClosure(replacement));
                }
                if (projectedClosures > options.MaximumStoredClosures
                    || !FitsCapacityWithReservations(
                        projectedClosures, projectedBytes, reservations, now))
                    throw new InvalidOperationException("Production mailbox closure capacity is exhausted.");
                if (projectedBytes > options.MaximumClosureStoreBytes)
                    throw new InvalidOperationException(
                        "Production mailbox closure byte capacity is exhausted.");
                EnsureLineageDirectory(proof.SelectionInputCommitment.Span,
                    proof.OldCanonicalSelectionHash.Span,
                    envelope.LineageCommitment.Span);
                try
                {
                    if (beforeReservation is not null && afterReservation is not null
                        && beforeFloor is not null)
                        CommitClosureWithCapacityTransfer(path, null,
                            replacement, proof, envelope.LineageCommitment.Span, beforeFloor,
                            beforeReservation, afterReservation, reservations);
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
        if (!ProductionMailboxClosureRequestCodec.IsFresh(
                request, now, options.ClockSkewSeconds)
            || !Fixed(request.TargetReplicaId.Span, node.GetRouterId().ToBytes())
            || !ProductionMailboxClosureRequestCodec.VerifyOwner(request))
            return null;
        var lineageGate = LineageGate(request.SelectionInputCommitment.Span,
            request.DurableOldSelectionHash.Span, request.LineageCommitment.Span);
        await lineageGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] bytes;
            ulong lockedNow;
            using (var processLock = await AcquireProcessLockForFetchAsync(
                       cancellationToken).ConfigureAwait(false))
            {
                RecoverCapacityTransfer();
                lockedNow = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
                if (!ProductionMailboxClosureRequestCodec.IsFresh(
                        request, lockedNow, options.ClockSkewSeconds))
                    return null;
                ValidateLineageDirectory(request.SelectionInputCommitment.Span,
                    request.DurableOldSelectionHash.Span,
                    request.LineageCommitment.Span);
                bytes = ReadBounded(ClosurePath(
                    request.SelectionInputCommitment.Span,
                    request.DurableOldSelectionHash.Span,
                    request.LineageCommitment.Span));
            }
            testHooks?.BeforeCacheClosureVerification?.Invoke();
            var verifiedCache = ValidateCacheClosure(bytes);
            var proof = verifiedCache.Selection;
            var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(bytes);
            var finalNow = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            return ProductionMailboxClosureRequestCodec.IsFresh(
                       request, finalNow, options.ClockSkewSeconds)
                   && Fixed(proof.SelectionInputCommitment.Span,
                       request.SelectionInputCommitment.Span)
                   && Fixed(proof.OldCanonicalSelectionHash.Span,
                       request.DurableOldSelectionHash.Span)
                   && Fixed(envelope.LineageCommitment.Span,
                       request.LineageCommitment.Span)
                   && Fixed(proof.MailboxOwnerEd25519PublicKey.Span,
                       request.MailboxOwnerEd25519PublicKey.Span)
                   && IsLiveWindow(proof.IssuedAtUnixSeconds,
                       verifiedCache.CacheExpiresAtUnixSeconds,
                       lockedNow, options.ClockSkewSeconds)
                   && IsLiveWindow(proof.IssuedAtUnixSeconds,
                       verifiedCache.CacheExpiresAtUnixSeconds,
                       finalNow, options.ClockSkewSeconds)
                ? bytes
                : null;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException
            or CryptographicException or InvalidOperationException)
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

    private int AccountClosure(byte[]? closure) => closure is null
        ? 0
        : checked(closure.Length + options.ClosureAccountingOverheadBytes);

    private void CommitClosureWithCapacityTransfer(
        string path,
        byte[]? existingClosure,
        byte[] replacement,
        ProductionMailboxSelectionSuccessorProof proof,
        ReadOnlySpan<byte> lineageCommitment,
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
            existingClosure is not null,
            proof.SelectionInputCommitment.ToArray(),
            proof.OldCanonicalSelectionHash.ToArray(),
            lineageCommitment.ToArray(),
            existingClosure is null ? new byte[32] : SHA256.HashData(existingClosure),
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
            testHooks?.AfterCapacityTransferClosure?.Invoke();
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
        var closurePath = ClosurePath(journal.SelectionInputCommitment.Span,
            journal.DurableOldSelectionHash.Span, journal.LineageCommitment.Span);
        byte[]? closure = null;
        try { closure = ReadBounded(closurePath); }
        catch (FileNotFoundException) { }
        var closureHash = closure is null ? new byte[32] : SHA256.HashData(closure);
        var isOldClosure = closure is null
            ? !journal.OldClosureExists
            : journal.OldClosureExists
                && Fixed(closureHash, journal.OldClosureSha256.Span);
        var isNewClosure = closure is not null
            && Fixed(closureHash, journal.NewClosureSha256.Span);
        var ledger = ReadProtectedBounded(capacityLedgerPath, 40,
            checked(40 + options.MaximumClosureReservations
                * ProductionMailboxCapacityLedgerCodec.RecordLength));
        var ledgerHash = SHA256.HashData(ledger);
        if (isOldClosure)
        {
            if (!Fixed(ledgerHash, journal.BeforeLedgerSha256.Span))
                throw new InvalidOperationException(
                    "Production mailbox capacity transfer has inconsistent old state.");
        }
        else if (isNewClosure)
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
            var recoveryNow = afterFloor.Reservation.ExpiresAtUnixSeconds == 0
                ? 0 : afterFloor.Reservation.ExpiresAtUnixSeconds - 1;
            ReconcileCapacityState(recoveryNow);
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
                "Production mailbox capacity transfer closure is ambiguous.");
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

    private ProductionMailboxVerifiedCacheDescriptor ValidateCacheClosure(byte[] frozen)
    {
        try { return ValidateCacheClosureCore(frozen); }
        catch (Exception exception) when (exception is FormatException
            or ProductionMailboxAuthorityException
            or ProductionMailboxRevocationSnapshotException
            or ProductionMailboxTopologyException
            or ProductionMailboxSelectionSuccessorException
            or ProductionMailboxRouteAdvertisementException
            or ProductionMailboxRouteAuthorizationException
            or ProductionMailboxRouteContinuityException)
        {
            throw new InvalidDataException(
                "Production mailbox cache closure protocol validation failed.", exception);
        }
    }

    private ProductionMailboxVerifiedCacheDescriptor ValidateCacheClosureCore(byte[] frozen)
    {
        var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(frozen);
        var authority = ProductionMailboxAuthorityCodec.Decode(envelope.Authority.Span);
        var successor = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            envelope.SelectionSuccessorV2.Span);
        var routeCertificate = ProductionMailboxRouteAdvertisementCodec.DecodeCertificate(
            envelope.RouteCertificate.Span);
        var oldSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            successor.Selection.OldCanonicalSelection.Span);
        var verified = ProductionMailboxNodeCacheVerifier.Verify(
            new ProductionMailboxNodeCacheArtifacts
            {
                AuthorizationKind = envelope.AuthorizationKind,
                CanonicalAuthority = envelope.Authority,
                CanonicalRevocations = envelope.Revocations,
                CanonicalTopology = envelope.Topology,
                CanonicalCurrentSelection = envelope.CurrentSelection,
                CanonicalNextSelection = envelope.NextSelection,
                CanonicalSelectionSuccessorV2 = envelope.SelectionSuccessorV2,
                CanonicalRouteCertificate = envelope.RouteCertificate,
                CanonicalTransitionContext = envelope.TransitionContext,
                CanonicalRouteAuthorization = envelope.RouteAuthorization,
                CanonicalRevocationCheckpoint = envelope.RevocationCheckpoint
            },
            new ProductionMailboxNodeCacheVerificationContext
            {
                ExpectedRouteDomainHash =
                    ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
                        routeCertificate),
                ControlPlane = new ProductionMailboxNodeCacheControlPlaneContext
                {
                    ExpectedNetworkId = successor.Selection.NetworkId,
                    ExpectedMailboxOwnerEd25519PublicKey =
                        successor.Selection.MailboxOwnerEd25519PublicKey,
                    ExpectedBlindedMailboxId = successor.Selection.BlindedMailboxId,
                    ExpectedBlindedPlacementId = successor.Selection.BlindedPlacementId,
                    ExpectedSelectionInputCommitment =
                        successor.Selection.SelectionInputCommitment,
                    PinnedMrXPublicKeySha256 = options.GetPinnedMrXKeyHash(),
                    ExpectedOldAuthorityGeneration = oldSelection.AuthorityGeneration,
                    ExpectedOldCanonicalAuthorityHash =
                        successor.Selection.OldCanonicalAuthorityHash,
                    ExpectedOldRevocationGeneration = authority.Revocation.Generation,
                    ExpectedOldRevocationHeadHash = authority.Revocation.HeadHash,
                    ExpectedOldRevocationSnapshotHash = authority.Revocation.SnapshotHash,
                    ExpectedOldTopologyGeneration = successor.Selection.OldTopologyGeneration,
                    ExpectedOldCanonicalTopologyHash =
                        successor.Selection.OldCanonicalTopologyHash,
                    ExpectedOldCanonicalSelectionHash =
                        successor.Selection.OldCanonicalSelectionHash,
                    VerifiedAtUnixSeconds = successor.Selection.IssuedAtUnixSeconds,
                    ClockSkewSeconds = options.ClockSkewSeconds
                }
            });
        return new(successor.Selection, verified.CacheExpiresAtUnixSeconds);
    }

    private static bool IsAuthorizedTarget(
        ProductionMailboxSelectionSuccessorProof successor,
        ReadOnlySpan<byte> targetReplicaId)
    {
        var oldSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            successor.OldCanonicalSelection.Span);
        var newSelection = ProductionMailboxTopologyCodec.DecodeSelection(
            successor.NewCanonicalSelection.Span);
        var frozenTargetReplicaId = targetReplicaId.ToArray();
        var ordinaryReplicaIds = oldSelection.Replicas.Concat(newSelection.Replicas)
            .Select(static replica => replica.ReplicaId)
            .ToArray();
        return ordinaryReplicaIds.Any(replicaId =>
            Fixed(replicaId.Span, frozenTargetReplicaId));
    }

    private static byte[] FreezeEnvelope(ReadOnlySpan<byte> value)
    {
        if (value.Length is < ProductionMailboxClosureEnvelopeCodec.HeaderLength
            or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
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

    private string RouteKey(ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> lineageCommitment)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey);
        hmac.AppendData("Deep/XNode/production-mailbox-closure-lineage/v2"u8);
        hmac.AppendData(selection);
        hmac.AppendData(oldSelectionHash);
        hmac.AppendData(lineageCommitment);
        return Convert.ToHexStringLower(hmac.GetHashAndReset());
    }

    private string SelectionDirectory(ReadOnlySpan<byte> selection)
    {
        var key = SelectionKey(selection);
        return Path.Combine(options.ClosureDirectory, key[..2], key);
    }

    private string LineageDirectory(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> lineageCommitment) =>
        Path.Combine(SelectionDirectory(selection),
            RouteKey(selection, oldSelectionHash, lineageCommitment));

    private SemaphoreSlim LineageGate(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> lineageCommitment)
    {
        var key = RouteKey(selection, oldSelectionHash, lineageCommitment);
        return lineageGates[Convert.ToByte(key[..2], 16) & (lineageGates.Length - 1)];
    }

    private string ClosurePath(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> lineageCommitment) =>
        Path.Combine(LineageDirectory(selection, oldSelectionHash, lineageCommitment),
            "closure.pmcs2");

    private void EnsureLineageDirectory(
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> lineageCommitment)
    {
        var lineage = LineageDirectory(selection, oldSelectionHash, lineageCommitment);
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
        ReadOnlySpan<byte> selection, ReadOnlySpan<byte> oldSelectionHash,
        ReadOnlySpan<byte> lineageCommitment)
    {
        var directory = LineageDirectory(selection, oldSelectionHash, lineageCommitment);
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
            if (!File.Exists(Path.Combine(lineage, "closure.pmcs2"))) continue;
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
        var closurePaths = Directory.EnumerateFiles(
                selectionDirectory, "*.pmcs2", SearchOption.AllDirectories)
            .Take(checked(options.MaximumClosureLineagesPerSelection + 1))
            .ToArray();
        if (closurePaths.Length > options.MaximumClosureLineagesPerSelection)
            throw new InvalidOperationException(
                "Production mailbox selection exceeds its lineage metadata bound.");
        foreach (var closurePath in closurePaths)
            PruneClosureIfGloballyExpired(closurePath, now);
    }

    private void PruneGloballyExpiredClosures(ulong now, string? excludedPath = null)
    {
        ValidateStoreDirectory();
        testHooks?.BeforeGlobalExpiredGc?.Invoke();
        var closurePaths = Directory.EnumerateFiles(
                options.ClosureDirectory, "*.pmcs2", SearchOption.AllDirectories)
            .Take(checked(options.MaximumStoredClosures + 1))
            .ToArray();
        if (closurePaths.Length > options.MaximumStoredClosures)
            throw new InvalidOperationException(
                "Production mailbox closure metadata exceeds its global count bound.");
        foreach (var closurePath in closurePaths)
        {
            if (excludedPath is not null && string.Equals(
                    Path.GetFullPath(closurePath), Path.GetFullPath(excludedPath),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
                continue;
            PruneClosureIfGloballyExpired(closurePath, now);
        }
    }

    private void PruneClosureIfGloballyExpired(string closurePath, ulong now)
    {
        var closure = ReadBounded(closurePath);
        var verifiedCache = ValidateCacheClosure(closure);
        if (!IsExpired(verifiedCache.CacheExpiresAtUnixSeconds,
                now, options.ClockSkewSeconds))
            return;
        ValidateRegularFilePath(closurePath);
        Exception? ambiguousFailure = null;
        try
        {
            durability.DeleteFile(closurePath);
            durability.FlushParentDirectory(closurePath);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException)
        {
            ambiguousFailure = exception;
        }
        if (File.Exists(closurePath))
            throw ambiguousFailure ?? new IOException(
                "Production mailbox expired closure could not be deleted.");
        RemoveEmptyClosureAncestors(Path.GetDirectoryName(closurePath)!);
        if (ambiguousFailure is not null) throw ambiguousFailure;
    }

    private void RemoveEmptyClosureAncestors(string lineageDirectory)
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

    private void ValidateBoundedStoreDirectoryInventory()
    {
        var maximumDirectories = checked((long)options.MaximumStoredClosures * 3 + 256);
        var directories = Directory.EnumerateDirectories(
                options.ClosureDirectory, "*", SearchOption.AllDirectories)
            .Take(checked((int)Math.Min(maximumDirectories + 1, int.MaxValue)))
            .ToArray();
        if (directories.LongLength > maximumDirectories)
            throw new InvalidOperationException(
                "Production mailbox closure directory metadata exceeds its configured bound.");
        foreach (var directory in directories)
        {
            EnsureNoReparseAncestors(directory, dataRoot);
            var segments = Path.GetRelativePath(options.ClosureDirectory, directory)
                .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
            var valid = segments.Length switch
            {
                1 => IsLowerHex(segments[0], 2),
                2 => IsLowerHex(segments[0], 2) && IsLowerHex(segments[1], 64)
                    && segments[1].StartsWith(segments[0], StringComparison.Ordinal),
                3 => IsLowerHex(segments[0], 2) && IsLowerHex(segments[1], 64)
                    && segments[1].StartsWith(segments[0], StringComparison.Ordinal)
                    && IsLowerHex(segments[2], 64),
                _ => false
            };
            if (!valid)
                throw new InvalidDataException(
                    "Production mailbox closure directory layout is non-canonical.");
        }
    }

    private static bool IsLowerHex(string value, int length) =>
        value.Length == length && value.All(static character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

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
        if (stream.Length is < ProductionMailboxClosureEnvelopeCodec.HeaderLength
            or > ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes)
            throw new InvalidDataException("Production mailbox closure file is outside bounds.");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return bytes;
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

    private async ValueTask<IDisposable> AcquireProcessLockForFetchAsync(
        CancellationToken cancellationToken)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        IOException? lastFailure = null;
        while (System.Diagnostics.Stopwatch.GetElapsedTime(started) < TimeSpan.FromSeconds(5))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return ProductionMailboxAuthorityNativeFile.AcquireLockOnce(
                    processLockPath,
                    () => ValidateRegularFilePath(processLockPath),
                    durability,
                    afterCreateBeforeSecure: null);
            }
            catch (IOException exception) { lastFailure = exception; }
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
        }
        throw lastFailure ?? new IOException(
            "Production mailbox closure store lock could not be acquired.");
    }

    private void ReconcileStoreState()
    {
        var accounting = ScanStoreState();
        storedBytes = accounting.Bytes;
        storedClosures = accounting.Count;
    }

    private (int Count, long Bytes) ScanStoreState()
    {
        ValidateStoreDirectory();
        if (Directory.EnumerateFiles(options.ClosureDirectory, "*.tmp",
                SearchOption.AllDirectories).Any())
            throw new InvalidOperationException(
                "Production mailbox closure store contains an incomplete atomic write.");
        if (Directory.EnumerateFiles(options.ClosureDirectory, "*.pmcs1",
                SearchOption.AllDirectories).Any())
            throw new InvalidDataException(
                "Production mailbox closure store contains unsupported PMC1 state.");

        long bytes = 0;
        var count = 0;
        var lineagesBySelection = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(options.ClosureDirectory, "*.pmcs2",
                     SearchOption.AllDirectories))
        {
            var canonicalClosure = ReadBounded(path);
            var proof = ValidateCacheClosure(canonicalClosure).Selection;
            var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(canonicalClosure);
            var expectedPath = ClosurePath(proof.SelectionInputCommitment.Span,
                proof.OldCanonicalSelectionHash.Span,
                envelope.LineageCommitment.Span);
            if (!string.Equals(Path.GetFullPath(path), Path.GetFullPath(expectedPath),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
                throw new InvalidDataException(
                    "Production mailbox closure filename is not bound to its authenticated route and content.");
            var routeKey = RouteKey(proof.SelectionInputCommitment.Span,
                proof.OldCanonicalSelectionHash.Span, envelope.LineageCommitment.Span);
            var selectionKey = SelectionKey(proof.SelectionInputCommitment.Span);
            if (!lineagesBySelection.TryGetValue(selectionKey, out var lineages))
                lineagesBySelection[selectionKey] = lineages = new(StringComparer.Ordinal);
            lineages.Add(routeKey);
            if (lineages.Count > options.MaximumClosureLineagesPerSelection)
                throw new InvalidOperationException(
                    "Production mailbox closure store exceeds its per-selection lineage bound.");
            bytes = checked(bytes + AccountClosure(canonicalClosure));
            count = checked(count + 1);
            if (bytes > options.MaximumClosureStoreBytes
                || count > options.MaximumStoredClosures)
                throw new InvalidOperationException(
                    "Production mailbox closure store exceeds configured capacity.");
        }
        return (count, bytes);
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
    Action? BeforeCacheClosureVerification = null,
    Action? AfterPrepositionStructuralPreflight = null,
    Action? BeforeGlobalExpiredGc = null,
    Action? BeforeCapacityAdmission = null,
    Action? AfterCapacityTransferJournal = null,
    Action? AfterCapacityTransferClosure = null,
    Action? AfterCapacityTransferFloor = null,
    Action? AfterCapacityTransferLedger = null,
    Action? AfterCapacityReservationFloor = null,
    Action? AfterCapacityReservationLedger = null,
    Action? AfterCapacityReservationDelete = null,
    bool SimulateCapacityTransferProcessTermination = false);

internal readonly record struct ProductionMailboxVerifiedCacheDescriptor(
    ProductionMailboxSelectionSuccessorProof Selection,
    ulong CacheExpiresAtUnixSeconds);
