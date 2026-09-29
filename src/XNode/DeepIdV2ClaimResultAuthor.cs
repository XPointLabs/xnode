using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV2;
using Deep.Protocol.MessagingWire;
using XNode.Core.ContactPreKey;

namespace XNode;

internal static class DeepIdV2ClaimResultAuthor
{
    internal static ParsedXpc1V2 Create(DeepIdV2ClaimProposal proposal, ParsedXpp1V2 publication,
        ContactServicePlacementCapability placement, ReadOnlyMemory<byte> localId,
        ReadOnlyMemory<byte> localSignature, ReadOnlyMemory<byte> remoteSignature, ulong serverTime)
    {
        if (localSignature.Length != 64 || remoteSignature.Length != 64)
            throw new InvalidDataException("DID2 claim requires two exact signatures.");
        var remoteId = placement.OtherReplica(localId.Span);
        var rows = new byte[193]; rows[0] = 2;
        var localFirst = localId.Span.SequenceCompareTo(remoteId) < 0;
        localId.Span.CopyTo(rows.AsSpan(localFirst ? 1 : 97));
        localSignature.Span.CopyTo(rows.AsSpan(localFirst ? 33 : 129));
        remoteId.CopyTo(rows, localFirst ? 97 : 1);
        remoteSignature.Span.CopyTo(rows.AsSpan(localFirst ? 129 : 33));
        var member = proposal.Offering;
        var manifest = proposal.Manifest;
        var index = ushort.MaxValue;
        byte[] proof = [];
        if (member.Kind == Dpk2PrekeyKind.OneTime)
        {
            var members = publication.OneTimeMembers;
            var found = Enumerable.Range(0, members.Count).Single(i =>
                members[i].CanonicalBytes.Span.SequenceEqual(member.CanonicalBytes.Span));
            index = checked((ushort)found);
            proof = InclusionProof(members, found);
        }
        ReadOnlyMemory<byte>[] payload = [member.CanonicalBytes,
            member.Kind == Dpk2PrekeyKind.OneTime ? member.OneTimePrekeyId : new byte[32],
            DeepIdV2PreKeyClaimCommitment.ComputeReceiptHash(proposal.Request.CanonicalBytes.Span,
                member.CanonicalBytes.Span, manifest.CanonicalBytes.Span, proposal.Generation, proposal.Counter),
            manifest.Field(12), manifest.Field(13), manifest.Field(5), manifest.Field(15),
            DeepIdV2ClaimPeerPayloadCodec.U16(proposal.Counter),
            DeepIdV2ClaimPeerPayloadCodec.U64(proposal.Generation), rows, manifest.CanonicalBytes,
            DeepIdV2ClaimPeerPayloadCodec.U16(index), proof];
        var wire = DeepIdV2PreKeyClaimResultCodec.Encode(proposal.Request.CanonicalBytes.Span,
            Xpc1V2Status.Claimed, Xpc1V2MutationOutcome.DurablyCommitted, serverTime, 0, payload);
        return DeepIdV2PreKeyClaimResultCodec.Decode(wire, proposal.Request.CanonicalBytes.Span);
    }

    // Exact reviewed XPI1 padded-tree algorithm. The Protocol result reader
    // independently verifies this path/root before the result can leave here.
    private static byte[] InclusionProof(IReadOnlyList<ParsedDpk2V2> members, int index)
    {
        var width = 1; while (width < members.Count) width <<= 1;
        var level = new byte[width][];
        for (var i = 0; i < width; i++)
        {
            var position = DeepIdV2ClaimPeerPayloadCodec.U16((ushort)i);
            level[i] = i < members.Count
                ? Hash("Deep/ContactResolver/V2/prekey-inventory-leaf", position.Concat(members[i].ExactHash.ToArray()).ToArray())
                : Hash("Deep/ContactResolver/V2/prekey-inventory-empty", position);
        }
        var proof = new List<byte>();
        while (level.Length > 1)
        {
            proof.AddRange(level[index ^ 1]); index >>= 1;
            level = Enumerable.Range(0, level.Length / 2).Select(i => Hash(
                "Deep/ContactResolver/V2/prekey-inventory-node", level[i * 2].Concat(level[i * 2 + 1]).ToArray())).ToArray();
        }
        return proof.ToArray();
    }

    private static byte[] Hash(string domain, byte[] bytes)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes(domain)); hash.AppendData([0]);
        Span<byte> length = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(length, (uint)bytes.Length);
        hash.AppendData(length); hash.AppendData(bytes); return hash.GetHashAndReset();
    }
}
