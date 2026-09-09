using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using XNode.Core.ContactPreKey;

namespace XNode.Tests.Core;

/// <summary>
/// Test-assembly-only capability seam. Production code accepts only the sealed
/// Protocol verifier result and exposes no raw inventory constructor.
/// </summary>
internal static class PreKeyInventoryTestCapability
{
    internal static VerifiedOpaquePreKeyInventory Create(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> serviceCapability,
        ReadOnlySpan<byte> responderDeviceId,
        ReadOnlySpan<byte> responderDpd1Reference,
        ulong serviceGeneration,
        ReadOnlySpan<byte> exactXps1Hash,
        ReadOnlySpan<byte> exactCurrentDmd1Hash,
        ReadOnlySpan<byte> exactCurrentDrs1Reference,
        ulong issuedAt,
        ulong expiresAt,
        IReadOnlyList<ReadOnlyMemory<byte>> oneTimeDpk2,
        ReadOnlySpan<byte> lastResortDpk2,
        IReadOnlyList<ReadOnlyMemory<byte>> replicaNodeIds,
        ulong inventoryEpoch = 1,
        ReadOnlySpan<byte> predecessorXpi1Hash = default,
        ReadOnlySpan<byte> publicationOperationId = default)
    {
        var predecessor = predecessorXpi1Hash.IsEmpty ? new byte[32] : predecessorXpi1Hash.ToArray();
        var operation = publicationOperationId.IsEmpty ? Bytes(32, 0x91) : publicationOperationId.ToArray();
        if (exactXps1Hash.Length != 32)
        {
            throw new ArgumentException("The test XPS1 hash must be 32 bytes.", nameof(exactXps1Hash));
        }
        var exactHashes = oneTimeDpk2.Select(static exact => ExactDpk2Hash(exact.Span)).ToArray();
        var root = ComputeRoot(exactHashes);
        var lastHash = ExactDpk2Hash(lastResortDpk2);
        var xps1Reference = Reference("XPS1", exactXps1Hash);
        var fields = new Xpi1UnsignedFields(
            networkId, serviceCapability, responderDeviceId, responderDpd1Reference,
            serviceGeneration, xps1Reference, inventoryEpoch, predecessor,
            checked((ushort)oneTimeDpk2.Count), root, lastHash, exactCurrentDmd1Hash,
            exactCurrentDrs1Reference, issuedAt, expiresAt);
        var exactXpi1 = Xpi1Codec.Encode(fields, Bytes(64, 0x93));
        var publication = (VerifiedPreKeyInventoryPublication)
            RuntimeHelpers.GetUninitializedObject(typeof(VerifiedPreKeyInventoryPublication));
        NetworkId(publication) = networkId.ToArray();
        ServiceCapability(publication) = serviceCapability.ToArray();
        PublicationOperationId(publication) = operation;
        Xpi1Hash(publication) = Xpi1Codec.ComputeHash(exactXpi1);
        ExactXpi1(publication) = exactXpi1;
        PredecessorXpi1Hash(publication) = predecessor;
        ReplicaNodeIds(publication) = replicaNodeIds
            .Select(static value => value.ToArray())
            .OrderBy(static value => value, ByteArrayComparer.Instance).ToArray();
        OneTimeMembers(publication) = oneTimeDpk2.Select(static exact => Member(exact.Span)).ToArray();
        LastResortMember(publication) = Member(lastResortDpk2);
        InventoryEpoch(publication) = inventoryEpoch;
        OneTimeDpk2Count(publication) = checked((ushort)oneTimeDpk2.Count);
        IssuedAt(publication) = issuedAt;
        ExpiresAt(publication) = expiresAt;
        return VerifiedOpaquePreKeyInventory.FromVerifiedPublication(publication);
    }

    private static VerifiedPreKeyInventoryMember Member(ReadOnlySpan<byte> exactDpk2)
    {
        var dpk2 = Dpk2Codec.Decode(exactDpk2);
        var member = (VerifiedPreKeyInventoryMember)
            RuntimeHelpers.GetUninitializedObject(typeof(VerifiedPreKeyInventoryMember));
        MemberExactDpk2(member) = exactDpk2.ToArray();
        MemberExactDpk2Hash(member) = ExactDpk2Hash(exactDpk2);
        MemberClaimPreKeyId(member) = dpk2.MlKemKind == Dpk2PrekeyKind.OneTime
            ? dpk2.OneTimeX25519PrekeyId.ToArray()
            : new byte[32];
        MemberMlKemPreKeyId(member) = dpk2.MlKemPrekeyId.ToArray();
        MemberKind(member) = dpk2.MlKemKind;
        MemberExpiresAt(member) = dpk2.ExpiresAt;
        MemberReuseLimit(member) = dpk2.ReuseLimit;
        return member;
    }

    private static byte[] ComputeRoot(IReadOnlyList<byte[]> hashes)
    {
        var width = 1;
        while (width < hashes.Count) width <<= 1;
        var level = new byte[width][];
        for (var index = 0; index < width; index++)
        {
            var position = U16(checked((ushort)index));
            level[index] = index < hashes.Count
                ? Sha256Domain("Deep/ContactResolver/V1/prekey-inventory-leaf", Join(position, hashes[index]))
                : Sha256Domain("Deep/ContactResolver/V1/prekey-inventory-empty", position);
        }
        while (level.Length > 1)
        {
            var next = new byte[level.Length / 2][];
            for (var index = 0; index < next.Length; index++)
            {
                next[index] = Sha256Domain(
                    "Deep/ContactResolver/V1/prekey-inventory-node",
                    Join(level[index * 2], level[(index * 2) + 1]));
            }
            level = next;
        }
        return level[0];
    }

    private static byte[] ExactDpk2Hash(ReadOnlySpan<byte> exact) =>
        MessagingWireCryptographicInputs.ComputeExactDpk2Hash(Dpk2Codec.Decode(exact));

    private static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var preimage = new byte[label.Length + 5 + value.Length];
        label.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(label.Length + 1), checked((uint)value.Length));
        value.CopyTo(preimage.AsSpan(label.Length + 5));
        return SHA256.HashData(preimage);
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Record(string magic, IReadOnlyList<byte[]> fields)
    {
        var output = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), ContactPreKeyStoreOptions.SupportedSuite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_networkId")]
    private static extern ref byte[] NetworkId(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_serviceCapability")]
    private static extern ref byte[] ServiceCapability(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_publicationOperationId")]
    private static extern ref byte[] PublicationOperationId(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_xpi1Hash")]
    private static extern ref byte[] Xpi1Hash(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_exactXpi1")]
    private static extern ref byte[] ExactXpi1(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_predecessorXpi1Hash")]
    private static extern ref byte[] PredecessorXpi1Hash(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_replicaNodeIds")]
    private static extern ref byte[][] ReplicaNodeIds(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_oneTimeMembers")]
    private static extern ref VerifiedPreKeyInventoryMember[] OneTimeMembers(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<LastResortMember>k__BackingField")]
    private static extern ref VerifiedPreKeyInventoryMember LastResortMember(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<InventoryEpoch>k__BackingField")]
    private static extern ref ulong InventoryEpoch(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<OneTimeDpk2Count>k__BackingField")]
    private static extern ref ushort OneTimeDpk2Count(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<IssuedAtUnixSeconds>k__BackingField")]
    private static extern ref ulong IssuedAt(VerifiedPreKeyInventoryPublication value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<ExpiresAtUnixSeconds>k__BackingField")]
    private static extern ref ulong ExpiresAt(VerifiedPreKeyInventoryPublication value);

    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_exactDpk2")]
    private static extern ref byte[] MemberExactDpk2(VerifiedPreKeyInventoryMember value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_exactDpk2Hash")]
    private static extern ref byte[] MemberExactDpk2Hash(VerifiedPreKeyInventoryMember value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_claimPreKeyId")]
    private static extern ref byte[] MemberClaimPreKeyId(VerifiedPreKeyInventoryMember value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_mlKemPreKeyId")]
    private static extern ref byte[] MemberMlKemPreKeyId(VerifiedPreKeyInventoryMember value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<Kind>k__BackingField")]
    private static extern ref Dpk2PrekeyKind MemberKind(VerifiedPreKeyInventoryMember value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<ExpiresAtUnixSeconds>k__BackingField")]
    private static extern ref ulong MemberExpiresAt(VerifiedPreKeyInventoryMember value);
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "<ReuseLimit>k__BackingField")]
    private static extern ref ushort MemberReuseLimit(VerifiedPreKeyInventoryMember value);

}
