using Deep.Protocol.ContactV1;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ContactAuthorizedPublicationReplicaTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "xnode-contact-authorized-replica-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ExactXpaReservationAndCommitSurviveReplicaRestart()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var request = ceremony.ContactPublication;

        using (var first = Open(verifier))
        {
            var committed = await first.Service.PublishAsync(request, default);
            Assert.Equal(ContactResolverMutationDisposition.Committed, committed.Disposition);
        }

        using var restarted = Open(verifier);
        var replay = await restarted.Service.PublishAsync(request, default);
        Assert.Equal(ContactResolverMutationDisposition.ExactReplay, replay.Disposition);
    }

    [Fact]
    public async Task SameAuthorizationWithDifferentValidWitnessSetLatchesExactRequestConflict()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var firstRequest = ceremony.ContactPublication;
        var changedRequest = ceremony.AlternateContactPublication;
        var originalAuthorization = await verifier.VerifyAsync(firstRequest, default);
        var alternateAuthorization = await verifier.VerifyAsync(changedRequest, default);
        Assert.Equal(originalAuthorization.AuthorizationId.ToArray(), alternateAuthorization.AuthorizationId.ToArray());
        Assert.Equal(firstRequest.AuthorizedBodyHash.ToArray(), changedRequest.AuthorizedBodyHash.ToArray());
        Assert.NotEqual(firstRequest.RequestHash.ToArray(), changedRequest.RequestHash.ToArray());
        using var runtime = Open(verifier);

        _ = await runtime.Service.PublishAsync(firstRequest, default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await runtime.Service.PublishAsync(changedRequest, default));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await runtime.Service.PublishAsync(firstRequest, default));

        var stored = await runtime.Replica.ResolveCurrentDcrAsync(
            firstRequest.LocatorHash,
            default);
        Assert.Equal(ContactResolverReadDisposition.Current, stored.Disposition);
        Assert.Equal(
            firstRequest.ObjectCiphertextHash.ToArray(),
            stored.Publication!.ObjectCiphertextHash);
    }

    [Fact]
    public async Task ForgedWitnessCannotReserveAuthorizationOrPreventValidPublication()
    {
        using var ceremony = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var verifier = new VerifiedContactPublicationAuthorizationVerifier(ceremony);
        var request = ceremony.ContactPublication;
        var forgedXpa = request.ExactXpa1.ToArray();
        forgedXpa[^1] ^= 1;
        var forged = Xpu1Codec.Decode(Xpu1Codec.Encode(request.NetworkId.Span,
            request.OperationId.Span, request.ViewHash.Span, request.PlacementHash.Span,
            request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds, request.LocatorHash.Span,
            request.Xir1Hash.Span, request.Generation, request.PredecessorObjectHash.Span,
            request.ObjectCiphertext.Span, request.UsageLimit, request.EffectiveExpiresAtUnixSeconds,
            request.ExactRouteClosure.Span, forgedXpa, request.OwnerRetrieveCapability.Span));
        using var runtime = Open(verifier);
        await Assert.ThrowsAsync<Xpa1PublicationAuthorizationException>(async () =>
            await runtime.Service.PublishAsync(forged, default));
        var absent = await runtime.Replica.ResolveCurrentDcrAsync(request.LocatorHash, default);
        Assert.Equal(ContactResolverReadDisposition.NotFound, absent.Disposition);
        var accepted = await runtime.Service.PublishAsync(request, default);
        Assert.Equal(ContactResolverMutationDisposition.Committed, accepted.Disposition);
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private Runtime Open(IContactPublicationAuthorizationVerifier verifier)
    {
        Directory.CreateDirectory(root);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1100));
        var store = new ContactResolverOpaqueStore(
            Path.Combine(root, "resolver.state"),
            clock: clock);
        var replica = new ContactResolverStoreReplica(
            Enumerable.Repeat((byte)0x51, 32).ToArray(),
            store);
        var saga = new ContactPublicationAuthorizationSaga(
            Path.Combine(root, "xpa1-saga.state"),
            Path.Combine(root, "xpa1-saga.key"));
        return new Runtime(
            store,
            saga,
            replica,
            new ContactAuthorizedPublicationReplica(replica, verifier, saga, clock));
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed record Runtime(
        ContactResolverOpaqueStore Store,
        ContactPublicationAuthorizationSaga Saga,
        ContactResolverStoreReplica Replica,
        ContactAuthorizedPublicationReplica Service) : IDisposable
    {
        public void Dispose()
        {
            Saga.Dispose();
            Store.Dispose();
        }
    }
}
