using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using XNode.Core.ContactResolver;

namespace XNode.Tests.Core;

/// <summary>
/// Test-assembly-only capability seam. Production code can obtain this sealed
/// capability only from Xpa1PublicationAuthorizationVerifier. Deep.Protocol owns
/// threshold-verifier hostile coverage; these tests exercise XNode consumption.
/// </summary>
internal sealed class Xpa1AuthorizationTestFixture : IContactPublicationAuthorizationVerifier
{
    public ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(CreateCapability(request));
    }

    internal byte[] CreateEncodedRequest(
        uint usageLimit = 0,
        byte operationMarker = 2,
        byte authorizationMarker = 8,
        byte ciphertextMarker = 7)
    {
        var network = Enumerable.Range(1, 16)
            .Select(static value => checked((byte)value)).ToArray();
        var operation = Bytes(32, operationMarker);
        var view = Bytes(32, 3);
        var placement = Bytes(32, 4);
        var locator = Bytes(32, 5);
        var xir = Bytes(32, 6);
        var ciphertext = Bytes(40, ciphertextMarker);
        var routeClosure = CreateRouteClosure(network);
        var bodyHash = Xpu1Codec.ComputeAuthorizedBodyHash(
            network, operation, view, placement, 195, 240,
            locator, xir, 0, new byte[32], ciphertext, usageLimit, 250,
            routeClosure);
        var witnessReceipts = new byte[192];
        Bytes(32, 1).CopyTo(witnessReceipts, 0);
        Bytes(64, 3).CopyTo(witnessReceipts, 32);
        Bytes(32, 2).CopyTo(witnessReceipts, 96);
        Bytes(64, 4).CopyTo(witnessReceipts, 128);
        var xpa = Record("XPA1",
        [
            (1, network), (2, Bytes(32, authorizationMarker)), (3, operation), (4, locator),
            (5, new byte[] { usageLimit == 0 ? (byte)1 : (byte)2 }),
            (6, Bytes(32, 9)), (7, Bytes(32, 10)), (8, xir),
            (9, U64(0)), (10, new byte[32]), (11, SHA256.HashData(ciphertext)),
            (12, U32(usageLimit)), (13, U64(250)), (14, Bytes(32, 11)),
            (15, U64(190)), (16, U64(194)), (17, U64(250)),
            (18, Bytes(32, 12)), (19, bodyHash),
            (20, new byte[] { 2 }), (21, witnessReceipts)
        ]);
        return Xpu1Codec.Encode(
            network, operation, view, placement, 195, 240,
            locator, xir, 0, new byte[32], ciphertext, usageLimit, 250,
            routeClosure, xpa);
    }

    private static byte[] CreateRouteClosure(byte[] network)
    {
        var pmt = Author("PMT2",
        [
            network, U64(0), new byte[32], Reference("PMA2", 2), Reference("XNV1", 3),
            U64(1), new byte[] { 2 }, U16(2), Rows(136, 2, 4), U64(1), U64(1),
            U64(2), new byte[32], Reference("ADH1", 5), new byte[] { 2 }, Rows(96, 2, 6)
        ]);
        var xra = Author("XRA1",
        [
            network, Bytes(32, 2), U64(0), new byte[32],
            ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes, Bytes(32, 3),
            U16(1), U32(1), Bytes(32, 4), Bytes(32, 5), Bytes(32, 6), U64(1),
            U64(2), Bytes(32, 7), Reference("DPD1", 8), Bytes(64, 9)
        ]);
        var ranked = RankedNodes(network, pmt, xra.Field(6));
        ReadOnlyMemory<byte>[] pmsFields =
        [
            network, ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
            xra.Field(6), pmt.Field(6), new byte[] { 2 }, ranked.AsMemory(0, 64),
            new byte[32], U64(1), U64(2), new byte[] { 2 }, Rows(96, 2, 10)
        ];
        var provisional = Write("PMS2", pmsFields);
        pmsFields[6] = HashDomain("Deep/XPoint/V1/PMS2/selection", Project(provisional, 6));
        var pms = Author("PMS2", pmsFields);
        var replicas = ReplicaEntries(pms);
        var xrc = Author("XRC1",
        [
            network, Bytes(32, 10), U64(0), new byte[32],
            ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
            ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
            pms.ArtifactHash, pmt.Field(5), Reference("XNH1", 12), Bytes(32, 13),
            xra.Field(10), xra.Field(11), U64(1), new byte[] { 2 }, replicas,
            U64(1), U64(1), U64(2), pmt.Field(14), new byte[] { 2 }, Rows(96, 2, 18)
        ]);
        var xss = Author("XSS1",
        [
            network, xrc.Field(2), U64(1), xrc.CoreHash,
            ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
            ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
            ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
            xrc.Field(8), pms.ArtifactHash, U64(1), U64(2), Reference("ADH1", 23),
            new byte[] { 2 }, Rows(96, 2, 24)
        ]);
        var xrr = Author("XRR1",
        [
            network, Bytes(32, 25), U64(0), new byte[32],
            ContactCodec.ArtifactReference("XRA1", xra).CanonicalBytes,
            ContactCodec.ArtifactReference("XRC1", xrc).CanonicalBytes,
            ContactCodec.ArtifactReference("XSS1", xss).CanonicalBytes,
            ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes,
            pms.ArtifactHash, Bytes(32, 26), Bytes(32, 27), new byte[] { 1 },
            U32(1), U16(1), U64(1), U64(1), U64(2), xra.Field(15),
            Bytes(64, 29), new byte[2]
        ]);
        var records = new[] { xrr, xra, xrc, xss, pmt, pms };
        var output = new byte[1 + records.Sum(record => 4 + record.CanonicalBytes.Length)];
        output[0] = 6;
        var offset = 1;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                output.AsSpan(offset), checked((uint)record.CanonicalBytes.Length));
            offset += 4;
            record.CanonicalBytes.Span.CopyTo(output.AsSpan(offset));
            offset += record.CanonicalBytes.Length;
        }
        _ = ContactRouteClosureCodec.Decode(output);
        return output;
    }

    private static ContactRecord Author(
        string magic,
        IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
        ContactCodec.Decode(magic, Write(magic, fields));

    private static byte[] Write(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var output = new byte[12 + fields.Sum(field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(
                output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(
                output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            fields[index].Span.CopyTo(output.AsSpan(offset + 8));
            offset += 8 + fields[index].Length;
        }
        return output;
    }

    private static byte[] Project(byte[] record, int fieldCount) =>
        Write(Encoding.ASCII.GetString(record, 0, 4), ReadFields(record).Take(fieldCount).ToArray());

    private static IEnumerable<ReadOnlyMemory<byte>> ReadFields(byte[] record)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(8));
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                record.AsSpan(offset + 4)));
            yield return record.AsMemory(offset + 8, length);
            offset += 8 + length;
        }
    }

    private static byte[] RankedNodes(
        byte[] network,
        ContactRecord pmt,
        ReadOnlyMemory<byte> placement)
    {
        var reference = ContactCodec.ArtifactReference("PMT2", pmt).CanonicalBytes.ToArray();
        return pmt.Field(9).ToArray().Chunk(136).Select(row => row[..32]).Select(node => new
            {
                Node = node,
                Score = SHA256.HashData(Join(
                    Encoding.ASCII.GetBytes("Deep/XPoint/V1/PMS2/rendezvous-sha256/v2"),
                    [0], network, reference, pmt.Field(6).ToArray(), placement.ToArray(), node))
            })
            .OrderBy(value => value.Score, ByteArrayComparer.Instance)
            .ThenBy(value => value.Node, ByteArrayComparer.Instance)
            .SelectMany(value => value.Node).ToArray();
    }

    private static byte[] ReplicaEntries(ContactRecord pms)
    {
        var ranked = pms.Field(6).ToArray();
        var output = new byte[ranked.Length * 2];
        for (var index = 0; index < ranked.Length / 32; index++)
        {
            ranked.AsSpan(index * 32, 32).CopyTo(output.AsSpan(index * 64));
            Bytes(32, checked((byte)(0x80 + index))).CopyTo(output, index * 64 + 32);
        }
        return output;
    }

    private static byte[] Rows(int width, int count, byte seed)
    {
        var output = new byte[width * count];
        for (var index = 0; index < count; index++)
        {
            Bytes(32, checked((byte)(seed + index))).CopyTo(output, index * width);
            Bytes(width - 32, checked((byte)(seed + 32 + index)))
                .CopyTo(output, index * width + 32);
        }
        return output;
    }

    private static byte[] Reference(string magic, byte seed)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        Bytes(32, seed).CopyTo(output, 6);
        return output;
    }

    private static byte[] HashDomain(string domain, ReadOnlySpan<byte> payload)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + payload.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            input.AsSpan(label.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(input.AsSpan(label.Length + 5));
        return SHA256.HashData(input);
    }

    private static byte[] Join(params byte[][] values) =>
        values.SelectMany(static value => value).ToArray();

    internal static VerifiedXpa1PublicationAuthorization CreateCapability(Xpu1Request request)
    {
        var capability = (VerifiedXpa1PublicationAuthorization)
            RuntimeHelpers.GetUninitializedObject(typeof(VerifiedXpa1PublicationAuthorization));
        var xpa = request.ExactXpa1.Span;
        ExactXpa1(capability) = xpa.ToArray();
        NetworkId(capability) = request.NetworkId.ToArray();
        AuthorizationId(capability) = Field(xpa, 2).ToArray();
        OperationId(capability) = request.OperationId.ToArray();
        LocatorHash(capability) = request.LocatorHash.ToArray();
        Dcr1Hash(capability) = Field(xpa, 6).ToArray();
        Dcb1Hash(capability) = Field(xpa, 7).ToArray();
        Xir1Hash(capability) = request.Xir1Hash.ToArray();
        PredecessorObjectHash(capability) = request.PredecessorObjectHash.ToArray();
        ObjectCiphertextHash(capability) = request.ObjectCiphertextHash.ToArray();
        PolicyHash(capability) = Field(xpa, 14).ToArray();
        DirectoryHeadHash(capability) = Field(xpa, 18).ToArray();
        AuthorizedBodyHash(capability) = request.AuthorizedBodyHash.ToArray();
        RequestHash(capability) = request.RequestHash.ToArray();
        ViewHash(capability) = request.ViewHash.ToArray();
        PlacementHash(capability) = request.PlacementHash.ToArray();
        AuthorityCoreReference(capability) = Bytes(38, 31);
        WitnessPolicyHash(capability) = Bytes(32, 32);
        BootId(capability) = Bytes(16, 33);
        PublicationKind(capability) = request.UsageLimit == 0
            ? Xpa1PublicationKind.PermanentAddress
            : Xpa1PublicationKind.OneTimeInvite;
        Generation(capability) = request.Generation;
        UsageLimit(capability) = request.UsageLimit;
        EffectiveExpiresAt(capability) = request.EffectiveExpiresAtUnixSeconds;
        AuthorizationExpiresAt(capability) = BinaryPrimitives.ReadUInt64BigEndian(Field(xpa, 17));
        return capability;
    }

    private static ReadOnlySpan<byte> Field(ReadOnlySpan<byte> bytes, ushort wanted)
    {
        var count = BinaryPrimitives.ReadUInt16BigEndian(bytes[8..10]);
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(offset, 2));
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset + 4, 4)));
            offset += 8;
            if (tag == wanted) return bytes.Slice(offset, length);
            offset += length;
        }
        throw new InvalidOperationException("Required synthetic XPA1 field is absent.");
    }

    private static byte[] Record(string magic, IReadOnlyList<(ushort Tag, byte[] Value)> fields)
    {
        var result = new byte[12 + fields.Sum(static item => 8 + item.Value.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        foreach (var field in fields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset), field.Tag);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(offset + 4), checked((uint)field.Value.Length));
            offset += 8;
            field.Value.CopyTo(result, offset);
            offset += field.Value.Length;
        }
        return result;
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var output = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(output, value); return output; }
    private static byte[] U32(uint value) { var output = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(output, value); return output; }
    private static byte[] U64(ulong value) { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output, value); return output; }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_exactXpa1")]
    private static extern ref byte[] ExactXpa1(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_networkId")]
    private static extern ref byte[] NetworkId(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_authorizationId")]
    private static extern ref byte[] AuthorizationId(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_operationId")]
    private static extern ref byte[] OperationId(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_locatorHash")]
    private static extern ref byte[] LocatorHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_dcr1Hash")]
    private static extern ref byte[] Dcr1Hash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_dcb1Hash")]
    private static extern ref byte[] Dcb1Hash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_xir1Hash")]
    private static extern ref byte[] Xir1Hash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_predecessorObjectHash")]
    private static extern ref byte[] PredecessorObjectHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_objectCiphertextHash")]
    private static extern ref byte[] ObjectCiphertextHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_policyHash")]
    private static extern ref byte[] PolicyHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_directoryHeadHash")]
    private static extern ref byte[] DirectoryHeadHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_authorizedBodyHash")]
    private static extern ref byte[] AuthorizedBodyHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_requestHash")]
    private static extern ref byte[] RequestHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_viewHash")]
    private static extern ref byte[] ViewHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_placementHash")]
    private static extern ref byte[] PlacementHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_authorityCoreReference")]
    private static extern ref byte[] AuthorityCoreReference(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_witnessPolicyHash")]
    private static extern ref byte[] WitnessPolicyHash(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_bootId")]
    private static extern ref byte[] BootId(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<PublicationKind>k__BackingField")]
    private static extern ref Xpa1PublicationKind PublicationKind(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Generation>k__BackingField")]
    private static extern ref ulong Generation(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<UsageLimit>k__BackingField")]
    private static extern ref uint UsageLimit(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<EffectiveExpiresAtUnixSeconds>k__BackingField")]
    private static extern ref ulong EffectiveExpiresAt(VerifiedXpa1PublicationAuthorization value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<AuthorizationExpiresAtUnixSeconds>k__BackingField")]
    private static extern ref ulong AuthorizationExpiresAt(VerifiedXpa1PublicationAuthorization value);
}
