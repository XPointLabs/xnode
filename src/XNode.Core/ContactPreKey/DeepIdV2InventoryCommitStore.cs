using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV2;
using Sodium;
using XNode.Core.Mailbox;

namespace XNode.Core.ContactPreKey;

/// <summary>
/// Local, service-capability-keyed DID2 inventory CAS. The caller must first
/// verify current DID2/device authority, the complete XPP1 inventory and the
/// current selected placement. One signed receipt is not claim authority:
/// clients and claims still require both selected replicas' final XIC1.
/// </summary>
internal sealed class DeepIdV2InventoryCommitStore : IDisposable
{
    private const string StateHashDomain = "Deep/XNode/V2/prekey-active-snapshot";
    private const string ServicePathDomain = "Deep/XNode/V2/prekey-service-path";
    // Internal local-state discriminator, not a four-ASCII-byte wire magic.
    private static ReadOnlySpan<byte> StatePrefix => [0x00, 0xd2, 0x50, 0x4b];
    private const int HeaderLength = 87;
    private const int SlotLength = 32 + DeepIdV2PreKeyManifestCodec.CanonicalLength +
        DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength;
    private readonly string directory;
    private readonly byte[] networkId;
    private readonly byte[] serviceCapability;
    private readonly byte[] localReplicaId;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lease;
    private bool disposed;

    internal DeepIdV2InventoryCommitStore(string dataDirectory,
        ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> serviceCapability,
        ReadOnlySpan<byte> localReplicaId,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        if (networkId.Length != 16 || serviceCapability.Length != 32 ||
            localReplicaId.Length != 32 || IsZero(networkId) ||
            IsZero(serviceCapability) || IsZero(localReplicaId))
            throw new ArgumentException("The DID2 inventory custody scope is invalid.");
        this.networkId = networkId.ToArray();
        this.serviceCapability = serviceCapability.ToArray();
        this.localReplicaId = localReplicaId.ToArray();
        this.security = security ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();
        var root = Path.GetFullPath(Path.Combine(dataDirectory,
            "did2-prekey-commits"));
        var networkRoot = Path.Combine(root, Convert.ToHexString(networkId));
        directory = Path.Combine(networkRoot, Convert.ToHexString(
            HashDomain(ServicePathDomain,
                serviceCapability)));
        foreach (var path in new[] { root, networkRoot, directory })
        {
            RejectExistingLinks(path);
            this.security.SecureDirectory(path);
            RejectExistingLinks(path);
        }
        var lockPath = Path.Combine(directory, "inventory.lock");
        RejectExistingLinks(lockPath);
        lease = new FileStream(lockPath, new FileStreamOptions
        {
            Mode = FileMode.OpenOrCreate,
            Access = FileAccess.ReadWrite,
            Share = FileShare.None,
            BufferSize = 1,
            Options = FileOptions.WriteThrough
        });
        try
        {
            this.security.SecureFile(lockPath);
            if (File.Exists(PathFor("fault.marker")) ||
                File.Exists(PathFor("fork.marker")))
                throw new InvalidDataException(
                    "DID2 inventory custody is quarantined or fork-latched.");
            var state = ReadState();
            if (state.Length != 0 && !File.Exists(PathFor("activated.marker")))
                WriteFile("activated.marker", [1]);
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    internal ParsedXpi1V2? ReadCurrentManifest()
    {
        EnsureAvailable();
        return ReadState().LastOrDefault()?.Manifest;
    }

    internal ParsedXic1V2 CommitAuthorized(ParsedXpp1V2 verifiedPublication,
        ulong committedAtUnixSeconds, Func<byte[], byte[]> signReceipt)
    {
        EnsureAvailable();
        ArgumentNullException.ThrowIfNull(verifiedPublication);
        ArgumentNullException.ThrowIfNull(signReceipt);
        var manifest = verifiedPublication.Manifest;
        if (!Fixed(verifiedPublication.NetworkId.Span, networkId) ||
            !Fixed(manifest.Field(1).Span, networkId) ||
            !Fixed(manifest.Field(2).Span, serviceCapability))
            throw new UnauthorizedAccessException(
                "The verified DID2 publication belongs to another service.");
        var aggregateHash = DeepIdV2BoundedPreKeyPublicationCodec
            .ComputeAggregateHash(verifiedPublication.CanonicalBytes.Span);
        var state = ReadState();
        var epoch = U64(manifest.Field(7).Span);
        foreach (var slot in state)
        {
            var storedEpoch = U64(slot.Manifest.Field(7).Span);
            if (Fixed(slot.Receipt.Field(2).Span,
                    verifiedPublication.PublicationOperationId.Span) ||
                storedEpoch == epoch)
            {
                if (storedEpoch == epoch &&
                    Fixed(slot.AggregateHash, aggregateHash) &&
                    Fixed(slot.Manifest.CanonicalBytes.Span,
                        manifest.CanonicalBytes.Span) &&
                    Fixed(slot.Receipt.Field(2).Span,
                        verifiedPublication.PublicationOperationId.Span) &&
                    Fixed(slot.Receipt.Field(4).Span,
                        verifiedPublication.PlacementHash.Span))
                    return slot.Receipt;
                WriteFile("fork.marker", [1]);
                throw new InvalidDataException(
                    "DID2 inventory operation or epoch has conflicting bytes.");
            }
        }

        DeepIdV2PreKeyLineageVerifier.VerifySuccessor(manifest,
            state.LastOrDefault()?.Manifest);
        if (committedAtUnixSeconds < U64(manifest.Field(14).Span) ||
            committedAtUnixSeconds >= U64(manifest.Field(15).Span))
            throw new InvalidOperationException(
                "DID2 inventory commit time is outside its signed validity.");
        ReadOnlyMemory<byte>[] fields =
        [
            networkId, verifiedPublication.PublicationOperationId,
            manifest.ExactHash, verifiedPublication.PlacementHash,
            localReplicaId, U64Bytes(committedAtUnixSeconds)
        ];
        var signatureInput = DeepIdV2PreKeyCommitReceiptCodec
            .CreateSignatureInput(fields);
        var signature = signReceipt(signatureInput);
        if (signature is null || signature.Length != 64 ||
            !PublicKeyAuth.VerifyDetached(signature, signatureInput,
                localReplicaId))
            throw new CryptographicException(
                "The DID2 inventory receipt signer differs from this replica.");
        var receipt = DeepIdV2PreKeyCommitReceiptCodec.Decode(
            DeepIdV2PreKeyCommitReceiptCodec.Encode(fields, signature));
        var next = state.Length == 0
            ? new[] { new Slot(aggregateHash, manifest, receipt) }
            : new[] { state[^1], new Slot(aggregateHash, manifest, receipt) };
        WriteFile("active.state", EncodeState(next));
        if (!File.Exists(PathFor("activated.marker")))
            WriteFile("activated.marker", [1]);
        return ReadState()[^1].Receipt;
    }

    private Slot[] ReadState()
    {
        var path = PathFor("active.state");
        if (!File.Exists(path))
        {
            if (File.Exists(PathFor("activated.marker")))
                Fault("DID2 inventory custody lost its activated state.");
            return [];
        }
        try
        {
            security.ValidateSecureFile(path);
            var info = new FileInfo(path);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0 ||
                info.Length is not (HeaderLength + SlotLength + 32) and not
                    (HeaderLength + 2 * SlotLength + 32))
                throw new InvalidDataException(
                    "DID2 inventory active snapshot has an invalid size or link.");
            var bytes = File.ReadAllBytes(path);
            if (!bytes.AsSpan(0, 4).SequenceEqual(StatePrefix) ||
                BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(4, 2)) != 1 ||
                !Fixed(bytes.AsSpan(6, 16), networkId) ||
                !Fixed(bytes.AsSpan(22, 32), serviceCapability) ||
                !Fixed(bytes.AsSpan(54, 32), localReplicaId) ||
                bytes[86] is < 1 or > 2 ||
                bytes.Length != HeaderLength + bytes[86] * SlotLength + 32 ||
                !Fixed(HashDomain(StateHashDomain,
                        bytes.AsSpan(0, bytes.Length - 32)), bytes.AsSpan(^32)))
                throw new InvalidDataException(
                    "DID2 inventory active snapshot has a wrong scope or checksum.");
            var state = new Slot[bytes[86]];
            var offset = HeaderLength;
            for (var index = 0; index < state.Length; index++)
            {
                var aggregateHash = bytes.AsSpan(offset, 32).ToArray();
                offset += 32;
                var manifest = DeepIdV2PreKeyManifestCodec.Decode(bytes.AsSpan(
                    offset, DeepIdV2PreKeyManifestCodec.CanonicalLength));
                offset += DeepIdV2PreKeyManifestCodec.CanonicalLength;
                var receipt = DeepIdV2PreKeyCommitReceiptCodec.Decode(bytes.AsSpan(
                    offset, DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength));
                offset += DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength;
                ValidateSlot(aggregateHash, manifest, receipt);
                state[index] = new Slot(aggregateHash, manifest, receipt);
            }
            if (state.Length == 1 && U64(state[0].Manifest.Field(7).Span) != 1)
                throw new InvalidDataException(
                    "DID2 inventory history lost its first epoch.");
            if (state.Length == 2)
                DeepIdV2PreKeyLineageVerifier.VerifySuccessor(
                    state[1].Manifest, state[0].Manifest);
            return state;
        }
        catch (Exception exception) when (exception is FormatException or
            InvalidDataException or IOException or UnauthorizedAccessException)
        {
            Fault("DID2 inventory active snapshot is corrupt.", exception);
            throw;
        }
    }

    private void ValidateSlot(ReadOnlySpan<byte> aggregateHash,
        ParsedXpi1V2 manifest, ParsedXic1V2 receipt)
    {
        var committedAt = U64(receipt.Field(6).Span);
        if (IsZero(aggregateHash) ||
            !Fixed(manifest.Field(1).Span, networkId) ||
            !Fixed(manifest.Field(2).Span, serviceCapability) ||
            !Fixed(receipt.Field(1).Span, networkId) ||
            !Fixed(receipt.Field(3).Span, manifest.ExactHash.Span) ||
            !Fixed(receipt.Field(5).Span, localReplicaId) ||
            committedAt < U64(manifest.Field(14).Span) ||
            committedAt >= U64(manifest.Field(15).Span) ||
            !PublicKeyAuth.VerifyDetached(receipt.Field(7).ToArray(),
                receipt.SignatureInput.ToArray(), localReplicaId))
            throw new InvalidDataException(
                "DID2 inventory active slot is not this replica's signed manifest.");
    }

    private byte[] EncodeState(IReadOnlyList<Slot> slots)
    {
        if (slots.Count is < 1 or > 2)
            throw new ArgumentException("DID2 active history has an invalid size.",
                nameof(slots));
        var bytes = new byte[HeaderLength + slots.Count * SlotLength + 32];
        StatePrefix.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), 1);
        networkId.CopyTo(bytes, 6);
        serviceCapability.CopyTo(bytes, 22);
        localReplicaId.CopyTo(bytes, 54);
        bytes[86] = checked((byte)slots.Count);
        var offset = HeaderLength;
        foreach (var slot in slots)
        {
            slot.AggregateHash.CopyTo(bytes, offset);
            offset += 32;
            slot.Manifest.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset));
            offset += DeepIdV2PreKeyManifestCodec.CanonicalLength;
            slot.Receipt.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset));
            offset += DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength;
        }
        HashDomain(StateHashDomain,
            bytes.AsSpan(0, bytes.Length - 32)).CopyTo(bytes, offset);
        return bytes;
    }

    private void WriteFile(string name, ReadOnlySpan<byte> bytes)
    {
        var destination = PathFor(name);
        var temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew,
                       FileAccess.Write, FileShare.None, 4096,
                       FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            durability.FlushFileAndParentDirectory(temporary);
            durability.ReplaceFile(temporary, destination);
            durability.FlushFileAndParentDirectory(destination);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private void Fault(string message, Exception? cause = null)
    {
        // Persist the latch before moving the suspect state: if quarantine
        // fails, the original still rejects on the next open; if it succeeds,
        // a missing snapshot cannot be mistaken for a fresh epoch-one store.
        if (!File.Exists(PathFor("fault.marker")))
            WriteFile("fault.marker", [1]);
        var state = PathFor("active.state");
        if (File.Exists(state))
        {
            var quarantine = state + ".quarantine." + Guid.NewGuid().ToString("N");
            durability.ReplaceFile(state, quarantine);
            durability.FlushFileAndParentDirectory(quarantine);
        }
        throw new InvalidDataException(message, cause);
    }

    private void EnsureAvailable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (File.Exists(PathFor("fault.marker")) ||
            File.Exists(PathFor("fork.marker")))
            throw new InvalidDataException(
                "DID2 inventory custody is quarantined or fork-latched.");
    }

    private string PathFor(string name) => Path.Combine(directory, name);

    private static byte[] U64Bytes(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);

    private static bool IsZero(ReadOnlySpan<byte> value) =>
        value.IndexOfAnyExcept((byte)0) < 0;

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] HashDomain(string label, ReadOnlySpan<byte> value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes(label));
        hash.AppendData([0]);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)value.Length));
        hash.AppendData(length);
        hash.AppendData(value);
        return hash.GetHashAndReset();
    }

    private static void RejectExistingLinks(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ??
            throw new InvalidDataException("DID2 inventory path has no root.");
        var current = root;
        foreach (var part in Path.GetRelativePath(root, full).Split(
                     [Path.DirectorySeparatorChar,
                      Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException(
                    "DID2 inventory custody path contains a link.");
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        lease.Dispose();
    }

    private sealed record Slot(byte[] AggregateHash, ParsedXpi1V2 Manifest,
        ParsedXic1V2 Receipt);
}
