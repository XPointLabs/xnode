using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.DependencyInjection;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class Did2ContactServiceCompositionTests
{
    [Theory]
    [InlineData(null)]
    [InlineData(18)]
    [InlineData(9)]
    public async Task PublicRetrieveUsesActualTwoProtectedStoresAndSameWinnerAfterColdLostPeerReply(int? lostOperation)
    {
        await using var scope = await RetainedPeerScope.CreateAsync();
        await scope.PublishAsync(); await scope.ReopenAsync();
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var dispatcher = scope.Providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>();
        if (lostOperation is { } operation)
        {
            scope.State.LoseNextOperation = (ContactReplicaRpcOperation)operation;
            await Assert.ThrowsAsync<IOException>(() => dispatcher.DispatchAsync(
                ContactServiceOperation.AcquireMailboxGrant, request.ExactXmg2, default).AsTask());
            Assert.Equal(0, scope.State.GrantCalls); Assert.Equal(0, scope.State.GrantSignatures);
        }
        scope.State.LoseNextGrant = true;
        await Assert.ThrowsAsync<IOException>(() => dispatcher.DispatchAsync(
            ContactServiceOperation.AcquireMailboxGrant, request.ExactXmg2, default).AsTask());
        Assert.Equal(1, scope.State.GrantCalls); Assert.Equal(1, scope.State.GrantSignatures);
        await scope.ReopenAsync();
        dispatcher = scope.Providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>();
        var exact = await dispatcher.DispatchAsync(ContactServiceOperation.AcquireMailboxGrant, request.ExactXmg2, default);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(scope.Fixture.NetworkContext,
            scope.Fixture.Authority, scope.Fixture.MailboxAuthority, new(scope.Fixture));
        var verified = await host.VerifyRetainedReadSuccessAsync(scope.Fixture.ContactRoute.ExactRouteClosure,
            request.ExactXmg2, exact);
        await verified.EnsureCurrentAsync();
        Assert.Equal(2, scope.State.GrantCalls); Assert.Equal(1, scope.State.GrantSignatures);
        Assert.Equal(scope.State.GrantWinners.Values.Single(), exact.ToArray());
        // Native read/signatures and peer TLS are real. The role issuer/journal
        // in this fixture remain in-process, not actual Registry SQL/device E2E.
    }

    [Fact]
    public async Task PublicRetrieveWithWrongActualPeerPinNeverCallsIssuer()
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        scope.State.WrongPin = true;
        await scope.ReopenAsync(); // Capture the hostile actual peer pin in its new HTTP client.
        var before = scope.State.Requests;
        await Assert.ThrowsAsync<IOException>(() => scope.Providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>()
            .DispatchAsync(ContactServiceOperation.AcquireMailboxGrant, request.ExactXmg2, default).AsTask());
        Assert.Equal(0, scope.State.GrantCalls); Assert.Equal(0, scope.State.GrantSignatures);
        Assert.Equal(before, scope.State.Requests);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("document")]
    [InlineData("cancel")]
    public async Task PublicRetrieveCannotReleaseIssuerWinnerAfterLocalProtectedOwnerLoss(string defect)
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        using var holder = new GrantSigner(0x52); using var cancel = new CancellationTokenSource();
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        scope.State.BeforeGrantReturn = () => {
            if (defect == "source") scope.Fixture.RejectProof = true;
            if (defect == "document") File.AppendAllText(Path.Combine(scope.Nodes[0].DataDirectory,
                "contact-service-v1", "resolver.state"), " ");
            if (defect == "cancel") cancel.Cancel();
        };
        var dispatcher = scope.Providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>();
        Task Execute() => dispatcher.DispatchAsync(ContactServiceOperation.AcquireMailboxGrant,
            request.ExactXmg2, cancel.Token).AsTask();
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(Execute);
        else await Assert.ThrowsAsync<IOException>(Execute);
        Assert.Equal(1, scope.State.GrantCalls); Assert.Equal(1, scope.State.GrantSignatures);
        if (defect == "document") return; // Never import/bless split native data.
        scope.State.BeforeGrantReturn = null; scope.Fixture.RejectProof = false;
        var recovered = await dispatcher.DispatchAsync(ContactServiceOperation.AcquireMailboxGrant, request.ExactXmg2, default);
        Assert.Equal(scope.State.GrantWinners.Values.Single(), recovered.ToArray());
        Assert.Equal(2, scope.State.GrantCalls); Assert.Equal(1, scope.State.GrantSignatures);
    }
}
