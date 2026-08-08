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
    public const string RequestMediaType = "application/vnd.deep.production-mailbox-closure-request";
    public const string ClosureMediaType = "application/vnd.deep.production-mailbox-closure";
    public const string PrepositionMediaType =
        "application/vnd.deep.production-mailbox-preposition-command";

    public static bool IsPrepositionListener(int? localPort, int peerPort) =>
        localPort == peerPort;
}

internal static class ProductionMailboxClosureHttpEndpoint
{
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
    ReadOnlyMemory<byte> MailboxOwnerEd25519PublicKey,
    ReadOnlyMemory<byte> OwnerSignature);

public static class ProductionMailboxClosureRequestCodec
{
    private static ReadOnlySpan<byte> Magic => "PMQ1"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMQ1/owner-proof/v1"u8;
    public const int EncodedLength = 176;

    public static byte[] Encode(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value); Validate(value);
        var bytes = new byte[EncodedLength]; Magic.CopyTo(bytes); bytes[4] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), value.TimestampUnixSeconds);
        value.Nonce.Span.CopyTo(bytes.AsSpan(16));
        value.SelectionInputCommitment.Span.CopyTo(bytes.AsSpan(48));
        value.MailboxOwnerEd25519PublicKey.Span.CopyTo(bytes.AsSpan(80));
        value.OwnerSignature.Span.CopyTo(bytes.AsSpan(112));
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
            encoded.Slice(112, 64).ToArray());
        Validate(value); return value;
    }

    public static byte[] GetSigningBytes(ProductionMailboxClosureRequest value)
    {
        ArgumentNullException.ThrowIfNull(value); Validate(value, allowZeroSignature: true);
        var bytes = new byte[SignatureDomain.Length + 104];
        SignatureDomain.CopyTo(bytes); var offset = SignatureDomain.Length;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), value.TimestampUnixSeconds); offset += 8;
        value.Nonce.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
        value.SelectionInputCommitment.Span.CopyTo(bytes.AsSpan(offset)); offset += 32;
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
            or CryptographicException or ArgumentException) { return false; }
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
    ReadOnlyMemory<byte> CanonicalEnvelope);

public static class ProductionMailboxPrepositionCommandCodec
{
    private static ReadOnlySpan<byte> Magic => "PMP1"u8;
    private static ReadOnlySpan<byte> SignatureDomain => "Deep/PMP1/preposition/v1"u8;
    public const int MaximumAuthorizedLegacyReplicaIds = 2;
    public const int HeaderLength = 248;
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
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(240),
            checked((uint)frozen.CanonicalEnvelope.Length));
        frozen.CanonicalEnvelope.Span.CopyTo(bytes.AsSpan(HeaderLength));
        return bytes;
    }

    public static ProductionMailboxPrepositionCommand Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is < HeaderLength or > MaximumCommandBytes
            || !encoded[..4].SequenceEqual(Magic) || encoded[4] != 1
            || encoded.Slice(6, 2).IndexOfAnyExcept((byte)0) >= 0
            || encoded.Slice(244, 4).IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException("Production mailbox preposition command header is invalid.");
        var legacyCount = encoded[5];
        if (legacyCount > MaximumAuthorizedLegacyReplicaIds
            || encoded.Slice(112 + legacyCount * 32,
                    (MaximumAuthorizedLegacyReplicaIds - legacyCount) * 32)
                .IndexOfAnyExcept((byte)0) >= 0)
            throw new InvalidDataException(
                "Production mailbox preposition command legacy authorization is invalid.");
        var envelopeLengthValue = BinaryPrimitives.ReadUInt32BigEndian(encoded[240..]);
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
            encoded.Slice(176, 64).ToArray(), encoded[HeaderLength..].ToArray());
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
        var bytes = new byte[SignatureDomain.Length + 169];
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
            or CryptographicException or ArgumentException) { return false; }
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
                CanonicalEnvelope = value.CanonicalEnvelope.ToArray()
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
    private readonly byte[] hmacKey;
    private readonly SemaphoreSlim gate = new(1, 1);
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
        using var processLock = AcquireProcessLock();
        ReconcileStoreState();
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
        var path = PathFor(proof.SelectionInputCommitment.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var processLock = AcquireProcessLock();
            ReconcileStoreState();
            byte[]? existing = null;
            try
            {
                existing = ReadBounded(path);
            }
            catch (FileNotFoundException)
            {
                // A missing route is a new insertion under the cross-process store lock.
            }
            if (existing is not null)
            {
                if (existing.AsSpan().SequenceEqual(frozen)) return;
                var existingProof = ValidateCacheClosure(existing);
                EnsureStrictlyForward(existingProof, proof);
            }
            var existingLength = existing?.Length ?? 0;
            if (existingLength == 0 && storedClosures >= options.MaximumStoredClosures)
                throw new InvalidOperationException("Production mailbox closure capacity is exhausted.");
            var projectedBytes = checked(storedBytes - existingLength + frozen.Length);
            if (projectedBytes > options.MaximumClosureStoreBytes)
                throw new InvalidOperationException(
                    "Production mailbox closure byte capacity is exhausted.");
            try
            {
                WriteAtomic(path, frozen);
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
                && candidate.NewEpochGeneration <= existing.NewEpochGeneration)
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
        var path = PathFor(request.SelectionInputCommitment.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var bytes = ReadBounded(path);
            var proof = ValidateCacheClosure(bytes);
            if (!Fixed(proof.SelectionInputCommitment.Span, request.SelectionInputCommitment.Span)
                || !Fixed(proof.MailboxOwnerEd25519PublicKey.Span,
                    request.MailboxOwnerEd25519PublicKey.Span)
                || !IsLiveWindow(proof.IssuedAtUnixSeconds,
                    proof.ExpiresAtUnixSeconds, now, options.ClockSkewSeconds))
                return null;
            return bytes;
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException
            or CryptographicException) { return null; }
        finally { gate.Release(); }
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

    private string PathFor(ReadOnlySpan<byte> selection)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey);
        hmac.AppendData("Deep/XNode/production-mailbox-closure-state/v1"u8);
        hmac.AppendData(selection);
        return Path.Combine(options.ClosureDirectory,
            Convert.ToHexStringLower(hmac.GetHashAndReset()) + ".pmc1");
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

    private void WriteAtomic(string path, byte[] bytes)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            ValidateStoreDirectory();
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
                SearchOption.TopDirectoryOnly).Any())
            throw new InvalidOperationException(
                "Production mailbox closure store contains an incomplete atomic write.");

        long bytes = 0;
        var count = 0;
        foreach (var path in Directory.EnumerateFiles(options.ClosureDirectory, "*.pmc1",
                     SearchOption.TopDirectoryOnly))
        {
            var canonical = ReadBounded(path);
            bytes = checked(bytes + canonical.Length);
            count = checked(count + 1);
        }
        if (bytes > options.MaximumClosureStoreBytes
            || count > options.MaximumStoredClosures)
            throw new InvalidOperationException(
                "Production mailbox closure store exceeds configured capacity.");
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
}

internal sealed record ProductionMailboxClosureStoreTestHooks(
    Action<string>? AfterClosureActualOpen = null);
