using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using XNode.Core.ContactResolver;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class RetainedMailboxRouteStoreTests
{
    [Theory]
    [InlineData("unknown")]
    [InlineData("zero-horizon")]
    [InlineData("over-ceiling")]
    [InlineData("failed-with-route")]
    [InlineData("trailing")]
    [InlineData("oversize")]
    [InlineData("truncated")]
    [InlineData("bad-length")]
    public async Task RetainedPeerFactsRejectUnknownHostileOrUnboundedResults(string defect)
    {
        using var f = ProtectedFiles(); var store = f.Enroll(); _ = store.PublishDcr(await Publication());
        var facts = await store.ResolveProtectedRetainedMailboxRouteAsync(await Request());
        var exact = ContactReplicaPayloadCodec.Encode(facts);
        if (defect == "unknown") BinaryPrimitives.WriteUInt16BigEndian(exact, 0xffff);
        if (defect == "zero-horizon") BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(2), 0);
        if (defect == "over-ceiling") BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(2),
            ContactResolverOpaqueStore.LastPossibleRouteAdmission(ContactRouteClosureCodec.Decode(facts.ExactRouteClosure.Span))
            + ContactResolverOpaqueStore.MailboxObjectHorizonSeconds + 1);
        if (defect == "failed-with-route") BinaryPrimitives.WriteUInt16BigEndian(exact, (ushort)RetainedMailboxRouteDisposition.NotFound);
        if (defect == "trailing") exact = [.. exact, 0];
        if (defect == "oversize") exact = new byte[15 + ContactRouteClosureCodec.MaximumEncodedBytes];
        if (defect == "truncated") exact = exact[..13];
        if (defect == "bad-length") BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(10), uint.MaxValue);
        Assert.Throws<InvalidDataException>(() => ContactReplicaPayloadCodec.DecodeRetainedMailboxGrantResult(exact));
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void RetainedFailureCodecNeverExportsRouteOrHorizon(int code)
    {
        var disposition = (RetainedMailboxRouteDisposition)code;
        var exact = ContactReplicaPayloadCodec.Encode(new RetainedMailboxRouteLookup(disposition, [], 0));
        Assert.Equal(14, exact.Length);
        var decoded = ContactReplicaPayloadCodec.DecodeRetainedMailboxGrantResult(exact);
        Assert.Equal(disposition, decoded.Disposition); Assert.Empty(decoded.ExactRouteClosure.ToArray());
        Assert.Equal(0UL, decoded.ReadUntilUnixSeconds);
        Assert.Throws<InvalidDataException>(() => ContactReplicaPayloadCodec.Encode(new RetainedMailboxRouteLookup(disposition, [], 1)));
    }
}
