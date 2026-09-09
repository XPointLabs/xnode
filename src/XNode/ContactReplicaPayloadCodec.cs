using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;

namespace XNode;

internal static class ContactReplicaPayloadCodec
{
    internal static byte[] EncodeBoundedPreKeyPublication(Xpp1BoundedRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var exact = request.CanonicalBytes.ToArray();
        if (exact.Length > Xpp1BoundedCodec.MaximumCanonicalRequestBytes)
        {
            throw new InvalidDataException("The exact bounded XPP1 request exceeds its closed RPC bound.");
        }
        _ = Xpp1BoundedCodec.Decode(exact);
        return exact;
    }

    internal static Xpp1BoundedRequest DecodeBoundedPreKeyPublication(ReadOnlySpan<byte> payload) =>
        Xpp1BoundedCodec.Decode(payload);

    internal static byte[] EncodeBoundedPreKeyReceipt(Xic1BoundedReceipt receipt)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        var exact = receipt.CanonicalBytes.ToArray();
        _ = Xic1BoundedCodec.Decode(exact);
        return exact;
    }

    internal static Xic1BoundedReceipt DecodeBoundedPreKeyReceipt(ReadOnlySpan<byte> payload) =>
        Xic1BoundedCodec.Decode(payload);

    internal static byte[] EncodeAuthorizedPublish(ReadOnlySpan<byte> exactXpu1)
    {
        if (exactXpu1.Length is < 1 or > 69_649)
        {
            throw new ArgumentOutOfRangeException(nameof(exactXpu1));
        }
        _ = Xpu1Codec.Decode(exactXpu1);
        var writer = new PayloadWriter();
        writer.Lp32(exactXpu1);
        return writer.ToArray();
    }

    internal static Xpu1Request DecodeAuthorizedPublish(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var exact = reader.Lp32(69_649).ToArray();
        reader.End();
        return Xpu1Codec.Decode(exact);
    }

    internal static byte[] Encode(OpaqueDcrResolveRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var writer = new PayloadWriter();
        writer.Bytes(request.LocatorHash);
        writer.Bytes(request.OperationId);
        writer.Bytes(request.RequestHash);
        writer.U64(request.ResponseUnixSeconds);
        writer.Lp32(request.CanonicalRouteClosure);
        return writer.ToArray();
    }

    internal static OpaqueDcrResolveRequest DecodeDcrResolveRequest(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var locator = reader.Bytes(32).ToArray();
        var operation = reader.Bytes(32).ToArray();
        var requestHash = reader.Bytes(32).ToArray();
        var responseTime = reader.U64();
        var closure = reader.Lp32(23_295).ToArray();
        reader.End();
        return new OpaqueDcrResolveRequest(
            locator,
            operation,
            requestHash,
            closure,
            responseTime);
    }

    internal static byte[] Encode(OpaqueXurWriteRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var writer = new PayloadWriter();
        writer.Bytes(request.ServiceCapability);
        writer.Bytes(request.OperationId);
        writer.Bytes(request.RequestHash);
        writer.Bytes(request.ExactXur1Hash);
        writer.U64(request.EventGeneration);
        writer.Bytes(request.PredecessorEventHash);
        writer.Bytes(request.EventHash);
        writer.Bytes(request.EventCiphertextHash);
        writer.U64(request.EffectiveExpiresAtUnixSeconds);
        writer.Lp32(request.Ciphertext);
        return writer.ToArray();
    }

    internal static OpaqueXurWriteRequest DecodeXurWrite(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var capability = reader.Bytes(32).ToArray();
        var operation = reader.Bytes(32).ToArray();
        var requestHash = reader.Bytes(32).ToArray();
        var xur = reader.Bytes(32).ToArray();
        var generation = reader.U64();
        var predecessor = reader.Bytes(32).ToArray();
        var eventHash = reader.Bytes(32).ToArray();
        var ciphertextHash = reader.Bytes(32).ToArray();
        var expiry = reader.U64();
        var ciphertext = reader.Lp32(32_768).ToArray();
        reader.End();
        return new OpaqueXurWriteRequest(
            capability,
            operation,
            requestHash,
            xur,
            generation,
            predecessor,
            eventHash,
            ciphertextHash,
            ciphertext,
            expiry);
    }

    internal static byte[] Encode(OpaquePreKeyClaimRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var writer = new PayloadWriter();
        writer.Bytes(request.NetworkId);
        writer.Bytes(request.ServiceCapability);
        writer.Bytes(request.ResponderDeviceId);
        writer.U16(request.RequestedSuite);
        writer.Bytes(request.OperationId);
        writer.Bytes(request.RequestHash);
        writer.Bytes(request.ExactDcb1Hash);
        writer.Bytes(request.ExactXps1Hash);
        writer.U64(request.RequestExpiresAtUnixSeconds);
        return writer.ToArray();
    }

    internal static OpaquePreKeyClaimRequest DecodePreKeyClaimRequest(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var result = new OpaquePreKeyClaimRequest(
            reader.Bytes(16),
            reader.Bytes(32),
            reader.Bytes(32),
            reader.U16(),
            reader.Bytes(32),
            reader.Bytes(32),
            reader.Bytes(32),
            reader.Bytes(32),
            reader.U64());
        reader.End();
        return result;
    }

    internal static byte[] EncodeFixed32(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32)
        {
            throw new ArgumentException("An exact 32-byte value is required.", nameof(value));
        }
        return value.ToArray();
    }

    internal static byte[] EncodeReadXur(
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents)
    {
        if (serviceCapability32.Length != 32
            || exactXur1Hash32.Length != 32
            || maximumEvents is < 1 or > 64)
        {
            throw new ArgumentException("The XUR replica read request is invalid.");
        }
        var writer = new PayloadWriter();
        writer.Bytes(serviceCapability32);
        writer.Bytes(exactXur1Hash32);
        writer.U64(afterGeneration);
        writer.U16(checked((ushort)maximumEvents));
        return writer.ToArray();
    }

    internal static (byte[] Capability, byte[] XurHash, ulong After, int Maximum)
        DecodeReadXur(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var result = (
            reader.Bytes(32).ToArray(),
            reader.Bytes(32).ToArray(),
            reader.U64(),
            checked((int)reader.U16()));
        reader.End();
        if (result.Item4 is < 1 or > 64)
        {
            throw new InvalidDataException("The XUR replica read limit is invalid.");
        }
        return result;
    }

    internal static byte[] Encode(ContactResolverMutationResult result)
    {
        var writer = new PayloadWriter();
        writer.U16((ushort)result.Disposition);
        writer.U64(result.Generation);
        writer.Lp32(result.ObjectHash);
        return writer.ToArray();
    }

    internal static ContactResolverMutationResult DecodeMutation(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var disposition = (ContactResolverMutationDisposition)reader.U16();
        var generation = reader.U64();
        var hash = reader.Lp32(32).ToArray();
        reader.End();
        if (!Enum.IsDefined(disposition) || hash.Length is not (0 or 32))
        {
            throw new InvalidDataException("The contact mutation result is invalid.");
        }
        return new ContactResolverMutationResult(disposition, generation, hash);
    }

    internal static byte[] Encode(ContactResolverDcrReadResult result)
    {
        var writer = new PayloadWriter();
        writer.U16((ushort)result.Disposition);
        WritePublication(writer, result.Publication);
        return writer.ToArray();
    }

    internal static ContactResolverDcrReadResult DecodeDcrRead(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var disposition = (ContactResolverReadDisposition)reader.U16();
        var publication = ReadPublication(ref reader);
        reader.End();
        if (!Enum.IsDefined(disposition))
        {
            throw new InvalidDataException("The DCR read disposition is invalid.");
        }
        return new ContactResolverDcrReadResult(disposition, publication);
    }

    internal static byte[] Encode(ContactResolverDcrResolveResult result)
    {
        var writer = new PayloadWriter();
        writer.U16((ushort)result.Disposition);
        WritePublication(writer, result.Publication);
        writer.U64(result.ClaimCommitGeneration);
        writer.U64(result.ResponseUnixSeconds);
        writer.Lp32(result.CanonicalRouteClosure);
        return writer.ToArray();
    }

    internal static ContactResolverDcrResolveResult DecodeDcrResolve(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var disposition = (ContactResolverResolveDisposition)reader.U16();
        var publication = ReadPublication(ref reader);
        var commitGeneration = reader.U64();
        var responseTime = reader.U64();
        var closure = reader.Lp32(23_295).ToArray();
        reader.End();
        if (!Enum.IsDefined(disposition))
        {
            throw new InvalidDataException("The DCR resolve disposition is invalid.");
        }
        return new ContactResolverDcrResolveResult(
            disposition,
            publication,
            commitGeneration,
            closure,
            responseTime);
    }

    internal static byte[] Encode(ContactResolverXurReadResult result)
    {
        var writer = new PayloadWriter();
        writer.U16((ushort)result.Disposition);
        writer.U64(result.CurrentGeneration);
        writer.Lp32(result.CurrentEventHash);
        writer.U16(checked((ushort)result.Events.Count));
        foreach (var item in result.Events)
        {
            writer.U64(item.Generation);
            writer.Bytes(item.PredecessorEventHash);
            writer.Bytes(item.EventHash);
            writer.Bytes(item.EventCiphertextHash);
            writer.U64(item.EffectiveExpiresAtUnixSeconds);
            writer.Lp32(item.Ciphertext);
        }
        return writer.ToArray();
    }

    internal static ContactResolverXurReadResult DecodeXurRead(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var disposition = (ContactResolverReadDisposition)reader.U16();
        var currentGeneration = reader.U64();
        var currentHash = reader.Lp32(32).ToArray();
        var count = reader.U16();
        if (!Enum.IsDefined(disposition) || count > 64 || currentHash.Length is not (0 or 32))
        {
            throw new InvalidDataException("The XUR read result header is invalid.");
        }
        var events = new List<OpaqueXurEvent>(count);
        for (var index = 0; index < count; index++)
        {
            var generation = reader.U64();
            var predecessor = reader.Bytes(32).ToArray();
            var eventHash = reader.Bytes(32).ToArray();
            var ciphertextHash = reader.Bytes(32).ToArray();
            var expiry = reader.U64();
            var ciphertext = reader.Lp32(32_768).ToArray();
            events.Add(new OpaqueXurEvent(
                generation,
                predecessor,
                eventHash,
                ciphertextHash,
                ciphertext,
                expiry));
        }
        reader.End();
        return new ContactResolverXurReadResult(
            disposition,
            events,
            currentGeneration,
            currentHash);
    }

    internal static byte[] Encode(ContactPreKeyClaimResult result)
    {
        var writer = new PayloadWriter();
        writer.U16((ushort)result.Disposition);
        writer.Lp32(result.RequestHash);
        writer.Lp32(result.ExactDpk2);
        writer.Lp32(result.OneTimePreKeyId);
        writer.Lp32(result.ExactDpk2Hash);
        writer.Lp32(result.ExactCurrentDmd1Hash);
        writer.Lp32(result.ExactCurrentDrs1Ref);
        writer.U64(result.ServiceGeneration);
        writer.U64(result.PreKeyExpiresAt);
        writer.U16(result.LastResortUseCounter);
        writer.U64(result.ClaimCommitGeneration);
        writer.U64(result.ClaimedAtUnixSeconds);
        writer.Lp32(result.ExactXpi1);
        writer.Lp32(result.Xpi1Hash);
        writer.U64(result.InventoryEpoch);
        writer.U16(result.InventoryIndex);
        writer.Lp32(result.InclusionProof);
        writer.U16(checked((ushort)result.ReplicaNodeIds.Count));
        foreach (var replicaNodeId in result.ReplicaNodeIds)
        {
            writer.Lp32(replicaNodeId.Span);
        }
        writer.Lp32(result.RequiredDcb1Hash);
        writer.Lp32(result.RequiredXps1Hash);
        writer.Lp32(result.RequiredXpi1Hash);
        return writer.ToArray();
    }

    internal static ContactPreKeyClaimResult DecodePreKeyClaim(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var disposition = (ContactPreKeyClaimDisposition)reader.U16();
        var requestHash = reader.Lp32(32).ToArray();
        var dpk2 = reader.Lp32(2_037).ToArray();
        var preKeyId = reader.Lp32(32).ToArray();
        var dpk2Hash = reader.Lp32(32).ToArray();
        var dmd = reader.Lp32(32).ToArray();
        var drs = reader.Lp32(38).ToArray();
        var generation = reader.U64();
        var expiry = reader.U64();
        var counter = reader.U16();
        var commit = reader.U64();
        var claimedAt = reader.U64();
        var exactXpi1 = reader.Lp32(560).ToArray();
        var xpi1Hash = reader.Lp32(32).ToArray();
        var inventoryEpoch = reader.U64();
        var inventoryIndex = reader.U16();
        var inclusionProof = reader.Lp32(384).ToArray();
        var replicaCount = reader.U16();
        if (replicaCount is not (0 or 2))
        {
            throw new InvalidDataException("The pre-key result XIC1 replica count is invalid.");
        }
        var replicaNodeIds = new ReadOnlyMemory<byte>[replicaCount];
        for (var index = 0; index < replicaNodeIds.Length; index++)
        {
            replicaNodeIds[index] = reader.Lp32(32).ToArray();
        }
        var requiredDcb = reader.Lp32(32).ToArray();
        var requiredXps = reader.Lp32(32).ToArray();
        var requiredXpi = reader.Lp32(32).ToArray();
        reader.End();
        if (!Enum.IsDefined(disposition))
        {
            throw new InvalidDataException("The pre-key result disposition is invalid.");
        }
        return new ContactPreKeyClaimResult(
            disposition,
            requestHash,
            dpk2,
            preKeyId,
            dpk2Hash,
            dmd,
            drs,
            generation,
            expiry,
            counter,
            commit,
            claimedAt,
            exactXpi1,
            xpi1Hash,
            inventoryEpoch,
            inventoryIndex,
            inclusionProof,
            replicaNodeIds,
            requiredDcb,
            requiredXps,
            requiredXpi);
    }

    internal static byte[] EncodeReceiptRequest(
        ContactServiceReplicaReceiptRequest request,
        ContactReplicaRpcOperation evidenceOperation,
        ReadOnlySpan<byte> evidencePayload)
    {
        var writer = new PayloadWriter();
        writer.U16((ushort)request.Kind);
        writer.Lp32(request.CanonicalTuple.Span);
        writer.U16((ushort)evidenceOperation);
        writer.Lp32(evidencePayload);
        return writer.ToArray();
    }

    internal static (ContactServiceReplicaReceiptRequest Request,
        ContactReplicaRpcOperation EvidenceOperation, byte[] EvidencePayload)
        DecodeReceiptRequest(ReadOnlySpan<byte> payload)
    {
        var reader = new PayloadReader(payload);
        var kind = (ContactServiceReceiptKind)reader.U16();
        var tuple = reader.Lp32(160).ToArray();
        var operation = (ContactReplicaRpcOperation)reader.U16();
        var evidence = reader.Lp32(ContactReplicaWireCodec.MaximumRequestBytes).ToArray();
        reader.End();
        if (!Enum.IsDefined(kind) || !Enum.IsDefined(operation))
        {
            throw new InvalidDataException("The receipt evidence header is invalid.");
        }
        return (new ContactServiceReplicaReceiptRequest(kind, tuple), operation, evidence);
    }

    internal static byte[] Encode(ContactServiceReplicaReceipt receipt)
    {
        var writer = new PayloadWriter();
        writer.Bytes(receipt.ReplicaId.Span);
        writer.Bytes(receipt.Signature.Span);
        return writer.ToArray();
    }

    internal static ContactServiceReplicaReceipt DecodeReceipt(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 96)
        {
            throw new InvalidDataException("The contact replica receipt response is invalid.");
        }
        return new ContactServiceReplicaReceipt(
            payload[..32].ToArray(),
            payload[32..].ToArray());
    }

    private static void WritePublication(PayloadWriter writer, OpaqueDcrPublication? value)
    {
        writer.U16(value is null ? (ushort)0 : (ushort)1);
        if (value is null)
        {
            return;
        }
        writer.U64(value.Generation);
        writer.Bytes(value.ObjectCiphertextHash);
        writer.U32(value.UsageLimit);
        writer.U64(value.EffectiveExpiresAtUnixSeconds);
        writer.Lp32(value.Ciphertext);
    }

    private static OpaqueDcrPublication? ReadPublication(ref PayloadReader reader)
    {
        var present = reader.U16();
        if (present == 0)
        {
            return null;
        }
        if (present != 1)
        {
            throw new InvalidDataException("The DCR publication marker is invalid.");
        }
        var generation = reader.U64();
        var hash = reader.Bytes(32).ToArray();
        var usage = reader.U32();
        var expiry = reader.U64();
        var ciphertext = reader.Lp32(1_048_576).ToArray();
        return new OpaqueDcrPublication(generation, hash, ciphertext, usage, expiry);
    }

    private sealed class PayloadWriter
    {
        private readonly MemoryStream stream = new();

        internal void Bytes(ReadOnlySpan<byte> value) => stream.Write(value);
        internal void U16(ushort value)
        {
            Span<byte> buffer = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
            stream.Write(buffer);
        }
        internal void U32(uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            stream.Write(buffer);
        }
        internal void U64(ulong value)
        {
            Span<byte> buffer = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
            stream.Write(buffer);
        }
        internal void Lp32(ReadOnlySpan<byte> value)
        {
            U32(checked((uint)value.Length));
            Bytes(value);
        }
        internal byte[] ToArray() => stream.ToArray();
    }

    private ref struct PayloadReader
    {
        private readonly ReadOnlySpan<byte> payload;
        private int offset;
        internal PayloadReader(ReadOnlySpan<byte> payload)
        {
            this.payload = payload;
            offset = 0;
        }

        internal ReadOnlySpan<byte> Bytes(int length)
        {
            if (length < 0 || offset > payload.Length - length)
            {
                throw new InvalidDataException("The contact replica payload is truncated.");
            }
            var value = payload.Slice(offset, length);
            offset += length;
            return value;
        }
        internal ushort U16() => BinaryPrimitives.ReadUInt16BigEndian(Bytes(2));
        internal uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Bytes(4));
        internal ulong U64() => BinaryPrimitives.ReadUInt64BigEndian(Bytes(8));
        internal ReadOnlySpan<byte> Lp32(int maximum)
        {
            var length = U32();
            if (length > maximum)
            {
                throw new InvalidDataException("The contact replica LP32 value exceeds its bound.");
            }
            return Bytes(checked((int)length));
        }
        internal void End()
        {
            if (offset != payload.Length)
            {
                throw new InvalidDataException("The contact replica payload has trailing bytes.");
            }
        }
    }
}
