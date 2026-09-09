using Deep.Protocol.ContactV1;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ContactAuthorizedPublicationReplicaTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "xnode-contact-authorized-replica-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task ExactXpaReservationAndCommitSurviveReplicaRestart()
    {
        var verifier = new Xpa1AuthorizationTestFixture();
        var exact = verifier.CreateEncodedRequest();
        var request = Xpu1Codec.Decode(exact);

        var first = Open(verifier);
        var committed = await first.Service.PublishAsync(request, default);
        Assert.Equal(ContactResolverMutationDisposition.Committed, committed.Disposition);
        first.Dispose();

        using var restarted = Open(verifier);
        var replay = await restarted.Service.PublishAsync(request, default);
        Assert.Equal(ContactResolverMutationDisposition.ExactReplay, replay.Disposition);
    }

    [Fact]
    public async Task SameAuthorizationWithChangedAuthorizedBodyFailsBeforeSecondMutation()
    {
        var verifier = new Xpa1AuthorizationTestFixture();
        var firstRequest = Xpu1Codec.Decode(verifier.CreateEncodedRequest());
        var changedRequest = Xpu1Codec.Decode(verifier.CreateEncodedRequest(ciphertextMarker: 12));
        using var runtime = Open(verifier);

        _ = await runtime.Service.PublishAsync(firstRequest, default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await runtime.Service.PublishAsync(changedRequest, default));

        var stored = await runtime.Replica.ResolveCurrentDcrAsync(
            firstRequest.LocatorHash,
            default);
        Assert.Equal(ContactResolverReadDisposition.Current, stored.Disposition);
        Assert.Equal(
            firstRequest.ObjectCiphertextHash.ToArray(),
            stored.Publication!.ObjectCiphertextHash);
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
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(200));
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
