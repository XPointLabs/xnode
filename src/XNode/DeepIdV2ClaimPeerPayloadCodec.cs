using System.Buffers.Binary;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using XNode.Core.ContactPreKey;

namespace XNode;

internal sealed record DeepIdV2ClaimPreparePayload(DeepIdV2ClaimProposal Proposal,
    ParsedXic1V2 FirstPublicationReceipt, ParsedXic1V2 SecondPublicationReceipt,
    ReadOnlyMemory<byte> CoordinatorSignature);

internal sealed record DeepIdV2ClaimCompletePayload(ParsedXpk1V2 Request,
    ParsedXpc1V2 Result, ParsedXic1V2 FirstPublicationReceipt, ParsedXic1V2 SecondPublicationReceipt);

/// <summary>Closed internal peer payloads; all authority is independently re-minted by the receiver.</summary>
internal static class DeepIdV2ClaimPeerPayloadCodec
{
    private const int ReceiptPairLength = 2 * DeepIdV2PreKeyCommitReceiptCodec.CanonicalLength;
    private const int PrepareOverhead = DeepIdV2PreKeyClaimRequestCodec.CanonicalLength +
        DeepIdV2PreKeyManifestCodec.CanonicalLength + 8 + 2 + 4 + ReceiptPairLength + 64;

    internal static byte[] EncodePrepare(DeepIdV2ClaimProposal proposal,
        ParsedXic1V2 first, ParsedXic1V2 second, ReadOnlySpan<byte> coordinatorSignature)
    {
        if (coordinatorSignature.Length != 64) throw new InvalidDataException("Invalid DID2 claim proposal signature size.");
        using var stream = new MemoryStream();
        stream.Write(proposal.Request.CanonicalBytes.Span);
        stream.Write(proposal.Manifest.CanonicalBytes.Span);
        stream.Write(U64(proposal.Generation));
        stream.Write(U16(proposal.Counter));
        var offering = proposal.Offering.CanonicalBytes;
        stream.Write(U32((uint)offering.Length));
        stream.Write(offering.Span);
        stream.Write(first.CanonicalBytes.Span);
        stream.Write(second.CanonicalBytes.Span);
        stream.Write(coordinatorSignature);
        var bytes = stream.ToArray();
        _ = DecodePrepare(bytes);
        return bytes;
    }

    internal static DeepIdV2ClaimPreparePayload DecodePrepare(ReadOnlySpan<byte> exact)
    {
        if (exact.Length is not (PrepareOverhead + Dpk2Codec.OneTimeTotalBytes or
                PrepareOverhead + Dpk2Codec.LastResortTotalBytes))
            throw new InvalidDataException("DID2 claim proposal exceeds its exact peer bounds.");
        var offset = 0;
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exact[..438]); offset += 438;
        var manifest = DeepIdV2PreKeyManifestCodec.Decode(exact.Slice(offset, 560)); offset += 560;
        var generation = BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(offset, 8)); offset += 8;
        var counter = BinaryPrimitives.ReadUInt16BigEndian(exact.Slice(offset, 2)); offset += 2;
        var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(offset, 4)); offset += 4;
        if (length != exact.Length - PrepareOverhead)
            throw new InvalidDataException("DID2 claim proposal offering length is noncanonical.");
        var offering = DeepIdV2Dpk2Codec.Decode(exact.Slice(offset, (int)length)); offset += (int)length;
        var first = DeepIdV2PreKeyCommitReceiptCodec.Decode(exact.Slice(offset, 284)); offset += 284;
        var second = DeepIdV2PreKeyCommitReceiptCodec.Decode(exact.Slice(offset, 284)); offset += 284;
        _ = DeepIdV2PreKeyClaimCommitment.CreateTuple(request.CanonicalBytes.Span,
            offering.CanonicalBytes.Span, manifest.CanonicalBytes.Span, generation, counter);
        return new(new(request, offering, manifest, generation, counter), first, second, exact[offset..].ToArray());
    }

    internal static byte[] EncodeComplete(ParsedXpk1V2 request, ParsedXpc1V2 result,
        ParsedXic1V2 first, ParsedXic1V2 second)
    {
        using var stream = new MemoryStream();
        stream.Write(request.CanonicalBytes.Span);
        var wire = result.WireBytes;
        stream.Write(U32((uint)wire.Length)); stream.Write(wire.Span);
        stream.Write(first.CanonicalBytes.Span); stream.Write(second.CanonicalBytes.Span);
        var bytes = stream.ToArray(); _ = DecodeComplete(bytes); return bytes;
    }

    internal static DeepIdV2ClaimCompletePayload DecodeComplete(ReadOnlySpan<byte> exact)
    {
        const int overhead = DeepIdV2PreKeyClaimRequestCodec.CanonicalLength + 4 + ReceiptPairLength;
        if (exact.Length is not (overhead + 4096 or overhead + 16384))
            throw new InvalidDataException("DID2 claim completion exceeds its exact peer bounds.");
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(exact[..438]);
        var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(438, 4));
        if (length != exact.Length - overhead)
            throw new InvalidDataException("DID2 claim completion length is noncanonical.");
        var result = DeepIdV2PreKeyClaimResultCodec.Decode(exact.Slice(442, (int)length), request.CanonicalBytes.Span);
        if (result.Status is not (Xpc1V2Status.Claimed or Xpc1V2Status.Replay))
            throw new InvalidDataException("Only successful exact DID2 results can complete a claim.");
        var first = DeepIdV2PreKeyCommitReceiptCodec.Decode(exact.Slice(442 + (int)length, 284));
        var second = DeepIdV2PreKeyCommitReceiptCodec.Decode(exact.Slice(726 + (int)length, 284));
        return new(request, result, first, second);
    }

    internal static byte[] U16(ushort value)
    { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    internal static byte[] U32(uint value)
    { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    internal static byte[] U64(ulong value)
    { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
}
