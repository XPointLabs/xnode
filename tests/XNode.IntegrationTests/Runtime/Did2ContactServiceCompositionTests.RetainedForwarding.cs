using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class Did2ContactServiceCompositionTests
{
    [Theory]
    [InlineData("unknown-kind")]
    [InlineData("zero-kind")]
    [InlineData("zero-horizon")]
    [InlineData("current-with-horizon")]
    [InlineData("retained-with-current-expiry")]
    [InlineData("retained-failure")]
    [InlineData("retained-disposition")]
    [InlineData("wrong-role")]
    [InlineData("changed-deadline")]
    [InlineData("invalid-holder-proof")]
    public async Task RetainedForwardingRejectsUnknownOrCrossFedPrivateFieldsBeforeIo(string defect)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true,
            distinctNodeIdentities: true);
        using var holder = new GrantSigner(0x52);
        var authored = defect == "wrong-role"
            ? await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(fixture.ContactRoute,
                fixture.ContactPublication.LocatorHash, holder)
            : await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(fixture.ContactRoute,
                fixture.ContactPublication.LocatorHash, fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var placement = ContactServicePlacementFactory.Create(fixture.NetworkContext, ContactServiceRequestKind.ResolveInvite,
            authored.Record.Field(3));
        var id = placement.RankedReplicaNodeIds[0];
        var options = new RouterNodeOptions { RouterId = Convert.ToHexStringLower(id.Span),
            Ed25519PrivateKey = Convert.ToHexStringLower(fixture.Node(id.Span).Seed) };
        var request = new MailboxGrantAuthorityRequest(placement, authored.ExactXmg2, MailboxGrantAcquisitionResultCode.Success,
            fixture.ContactRoute.ExactRouteClosure, 1, 0, BinaryPrimitives.ReadUInt64BigEndian(authored.Record.Field(10).Span),
            [new(id, new byte[64]), new(placement.RankedReplicaNodeIds[1], new byte[64])],
            MailboxGrantAuthorityEvidenceKind.RetainedRead, 1_000_000);
        request = defect switch {
            "unknown-kind" => request with { EvidenceKind = (MailboxGrantAuthorityEvidenceKind)99 },
            "zero-kind" => request with { EvidenceKind = 0 },
            "zero-horizon" => request with { ReadUntilUnixSeconds = 0 },
            "current-with-horizon" => request with { EvidenceKind = MailboxGrantAuthorityEvidenceKind.CurrentRoute },
            "retained-with-current-expiry" => request with { RouteEffectiveExpiresAtUnixSeconds = 1_200 },
            "retained-failure" => request with { ResultCode = MailboxGrantAcquisitionResultCode.Unavailable },
            "retained-disposition" => request with { RouteDisposition = 2 },
            "changed-deadline" => request with { ResultExpiresAtUnixSeconds = request.ResultExpiresAtUnixSeconds + 1 },
            _ => request
        };
        if (defect == "invalid-holder-proof") {
            var bytes = request.ExactXmg2.ToArray(); bytes[^1] ^= 1; request = request with { ExactXmg2 = bytes };
        }
        using var handler = new RejectGrantIoHandler(); using var http = new HttpClient(handler);
        var client = new HttpsMailboxGrantAuthorityClient(http, options, new("https://issuer.example/"), new SystemClock());
        await Assert.ThrowsAsync<ContactServiceUnavailableException>(() => client.AuthorizeAsync(request, default).AsTask());
        Assert.Equal(0, handler.Calls);
    }
}
