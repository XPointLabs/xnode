using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.ContactResolver;

namespace XNode.IntegrationTests.Runtime;

/// <summary>
/// Class-scoped, signed DID2 test inputs. No uninitialized capabilities, raw-key
/// authority constructors, frozen V1 routes or production secrets. Native crypto
/// and the public author/verifier are real; this is not transport/device evidence.
/// </summary>
public sealed class CurrentContactPublicationFixture : IAsyncLifetime
{
    private DeepIdV2PublicationAuthorityFixture ceremony = null!;
    private readonly bool oneTime;
    public CurrentContactPublicationFixture() { }
    internal CurrentContactPublicationFixture(bool oneTime) { this.oneTime = oneTime; }
    internal Xpu1Request Request => ceremony.ContactPublication;
    internal Xpu1Request AlternateRequest => ceremony.AlternateContactPublication;
    internal ContactServicePlacementCapability Placement { get; private set; } = null!;
    internal ContactServicePlacementCapability ClaimPlacement { get; private set; } = null!;
    internal IContactPublicationAuthorizationVerifier Verifier { get; private set; } = null!;
    internal VerifiedOnionNetworkContext Network => ceremony.NetworkContext;
    internal VerifiedDeepIdV2ContactRouteClosure Route => ceremony.ContactRoute;
    internal ValueTask<VerifiedMailboxHostAuthorityV2> VerifyMailboxHostAsync(
        IOnionMonotonicClock? clock = null) => MailboxGrantRevocationStoreTests.Host(ceremony, clock);

    public async Task InitializeAsync()
    {
        ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true,
            authorOneTimeObject: oneTime, distinctNodeIdentities: true);
        try
        {
            Placement = Mint(ContactServiceRequestKind.PublishInvite, Request.LocatorHash);
            ClaimPlacement = Mint(ContactServiceRequestKind.ClaimPreKey,
                Enumerable.Repeat((byte)15, 32).ToArray());
            Verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
            var authorization = await Verifier.VerifyAsync(Request, default);
            await authorization.EnsureCurrentAsync();
        }
        catch
        {
            ceremony.Dispose();
            throw;
        }
    }

    private ContactServicePlacementCapability Mint(ContactServiceRequestKind kind,
        ReadOnlyMemory<byte> shard) => ContactServicePlacementCapability.FromNetcodec(
            ContactServicePlacementFactory.Create(ceremony.NetworkContext, kind, shard),
            kind, shard, ceremony.Freshness.TrustedUpperUnixSeconds);

    internal LocalContactServiceReplicaReceiptAuthority[] CreateReceiptAuthorities() =>
        Placement.ReplicaIds.OrderBy(static id => Convert.ToHexString(id.Span), StringComparer.Ordinal)
            .Select(id => new LocalContactServiceReplicaReceiptAuthority(id.Span, ceremony.Node(id.Span).Seed))
            .ToArray();

    internal async Task VerifyCommittedAsync(Xpo1Result result)
    {
        if (oneTime)
            _ = await DeepIdV2PublicationCommitVerifier.VerifyOneTimeCommittedAsync(
                ceremony.ContactRoute, ceremony.OneTimeContactObject!, ceremony.ContactOwnedRequest,
                Request.CanonicalBytes, result.WireBytes);
        else
            _ = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(
                ceremony.ContactRoute, ceremony.ContactObject, ceremony.ContactOwnedRequest,
                Request.CanonicalBytes, result.WireBytes);
    }

    public Task DisposeAsync()
    {
        ceremony?.Dispose();
        return Task.CompletedTask;
    }
}
