using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.ContactResolver;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class Did2ContactServiceCompositionTests
{
    [Theory]
    [InlineData(null)]
    [InlineData(18)]
    [InlineData(9)]
    public async Task RetainedReadUsesTwoIndependentNativeStoresAndActualPinnedPeerAfterColdReopen(int? lostOperation)
    {
        await using var scope = await RetainedPeerScope.CreateAsync();
        await scope.PublishAsync(); await scope.ReopenAsync();
        using var holder = new GrantSigner(0x52);
        var authored = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var placement = await scope.PlacementAsync();
        var local = scope.Providers[0].GetRequiredService<ProtectedRetainedMailboxReadAuthority>();
        var remote = scope.Remote(placement, authored.ExactXmg2);
        var first = await local.ReadAsync(placement, authored.ExactXmg2, default);
        if (lostOperation == 18)
        {
            scope.State.LoseNextOperation = ContactReplicaRpcOperation.ReadRetainedMailboxGrantRoute;
            await Assert.ThrowsAsync<IOException>(() => remote.ReadRetainedMailboxGrantRouteAsync(default).AsTask());
            Assert.True(scope.State.LostAfterExecution);
        }
        var second = await remote.ReadRetainedMailboxGrantRouteAsync(default);
        Assert.Equal(RetainedMailboxRouteDisposition.Found, first.Disposition);
        Assert.Equal(first.ExactRouteClosure.ToArray(), second.ExactRouteClosure.ToArray());
        Assert.Equal(first.ReadUntilUnixSeconds, second.ReadUntilUnixSeconds);
        var receiptRequest = RetainedReceipt(authored.ExactXmg2, first);
        var a = await local.IssueAsync(placement, authored.ExactXmg2, receiptRequest, default);
        if (lostOperation == 9)
        {
            scope.State.LoseNextOperation = ContactReplicaRpcOperation.IssueReceipt;
            await Assert.ThrowsAsync<IOException>(() => remote.IssueAsync(receiptRequest, default).AsTask());
            Assert.True(scope.State.LostAfterExecution);
        }
        var b = await remote.IssueAsync(receiptRequest, default);
        Assert.NotEqual(a.ReplicaId.ToArray(), b.ReplicaId.ToArray());
        var snapshot = await scope.Fixture.ReadPublicationAuthorityAsync(default);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(snapshot.Network, snapshot.Authority,
            snapshot.MailboxAuthority.ExactPma2, snapshot.TrustedTime);
        var issuance = await host.VerifyRetainedReadIssuanceAsync(authored.ExactXmg2,
            first.ExactRouteClosure, first.ReadUntilUnixSeconds,
            [new(a.ReplicaId.Span, a.Signature.Span), new(b.ReplicaId.Span, b.Signature.Span)]);
        using var issuer = new GrantSigner(0x32);
        var result = await issuance.AuthorSuccessAsync(issuer);
        await issuance.VerifySuccessAsync(result);
        Assert.Equal(510, result.Length);
        Assert.True(scope.State.Requests >= 2);
        Assert.Equal(200, scope.State.LastPeerStatus);
        // Real native two-store producer and TLS/H2 only: neither an actual
        // Registry database exchange nor elapsed-history/device qualification.
    }

    [Fact]
    public async Task NewlySelectedStoreWithoutOriginalNativeAdmissionCannotAttestCopiedFacts()
    {
        await using var scope = await RetainedPeerScope.CreateAsync();
        var fixture = scope.Fixture;
        var authorization = await new VerifiedContactPublicationAuthorizationVerifier(fixture)
            .VerifyAsync(fixture.ContactPublication, default);
        var publication = await OpaqueDcrPublishRequest.FromAuthorizedPublicationAsync(authorization,
            fixture.ContactPublication, default);
        var firstStore = scope.Providers[0].GetRequiredService<ContactServiceLocalReplicaRuntime>();
        Assert.Equal(ContactResolverMutationDisposition.Committed,
            (await firstStore.Binding.ResolverReplica.PublishDcrAsync(publication, default)).Disposition);
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(fixture.ContactRoute,
            fixture.ContactPublication.LocatorHash, fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var placement = await scope.PlacementAsync();
        var local = scope.Providers[0].GetRequiredService<ProtectedRetainedMailboxReadAuthority>();
        var first = await local.ReadAsync(placement, request.ExactXmg2, default);
        var remote = scope.Remote(placement, request.ExactXmg2);
        var missing = await remote.ReadRetainedMailboxGrantRouteAsync(default);
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound, missing.Disposition);
        Assert.Empty(missing.ExactRouteClosure.ToArray()); Assert.Equal(0UL, missing.ReadUntilUnixSeconds);
        var receipt = RetainedReceipt(request.ExactXmg2, first);
        _ = await local.IssueAsync(placement, request.ExactXmg2, receipt, default);
        await Assert.ThrowsAsync<IOException>(() => remote.IssueAsync(receipt, default).AsTask());
        Assert.Equal(503, scope.State.LastPeerStatus);
        var after = await remote.ReadRetainedMailboxGrantRouteAsync(default);
        Assert.Equal(RetainedMailboxRouteDisposition.NotFound, after.Disposition);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(96)]
    [InlineData(135)]
    public async Task RetainedSignerRejectsAnyTupleFieldDifferentFromActualNativeReadBack(int offset)
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var placement = await scope.PlacementAsync();
        var local = scope.Providers[0].GetRequiredService<ProtectedRetainedMailboxReadAuthority>();
        var facts = await local.ReadAsync(placement, request.ExactXmg2, default);
        var good = RetainedReceipt(request.ExactXmg2, facts);
        var tuple = good.CanonicalTuple.ToArray(); tuple[offset] ^= 1;
        var hostile = new ContactServiceReplicaReceiptRequest(ContactServiceReceiptKind.MailboxRetainedRead, tuple);
        await Assert.ThrowsAsync<ContactServiceReceiptAuthorityException>(() =>
            local.IssueAsync(placement, request.ExactXmg2, hostile, default).AsTask());
        var remote = scope.Remote(placement, request.ExactXmg2);
        _ = await remote.ReadRetainedMailboxGrantRouteAsync(default);
        await Assert.ThrowsAsync<IOException>(() => remote.IssueAsync(hostile, default).AsTask());
        Assert.Equal(503, scope.State.LastPeerStatus);
        _ = await remote.IssueAsync(good, default);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("time")]
    [InlineData("cancel")]
    [InlineData("document")]
    public async Task ActualSourceRecheckRejectsLossDuringRetainedSigning(string defect)
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var placement = await scope.PlacementAsync();
        var local = scope.Providers[0].GetRequiredService<ProtectedRetainedMailboxReadAuthority>();
        var receipt = RetainedReceipt(request.ExactXmg2, await local.ReadAsync(placement, request.ExactXmg2, default));
        using var cancel = new CancellationTokenSource();
        // Third source read is after actual key-backed signing, before return.
        scope.Source.Arm(3, () =>
        {
            if (defect == "source") scope.Fixture.RejectProof = true;
            if (defect == "time") scope.Fixture.Sample = 500;
            if (defect == "cancel") cancel.Cancel();
            if (defect == "document") File.AppendAllText(Path.Combine(scope.Nodes[0].DataDirectory,
                "contact-service-v1", "resolver.state"), " ");
        });
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            local.IssueAsync(placement, request.ExactXmg2, receipt, cancel.Token).AsTask());
        else if (defect == "document") await Assert.ThrowsAsync<InvalidDataException>(() =>
            local.IssueAsync(placement, request.ExactXmg2, receipt, default).AsTask());
        else await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            local.IssueAsync(placement, request.ExactXmg2, receipt, default).AsTask());
        Assert.True(scope.Source.Reached);
    }

    private static ContactServiceReplicaReceiptRequest RetainedReceipt(ReadOnlyMemory<byte> exact,
        RetainedMailboxRouteLookup facts)
    {
        var request = ContactCodec.Decode("XMG2", exact.Span);
        return new(ContactServiceReceiptKind.MailboxRetainedRead,
            MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(exact.Span), request.Field(3).Span,
                XNode.Core.ContactResolver.MailboxGrantCapabilityDigest.Compute(request.Field(4).Span, ContactMailboxGrantRole.Retrieve),
                SHA256.HashData(facts.ExactRouteClosure.Span), facts.ReadUntilUnixSeconds));
    }

    [Fact]
    public async Task RetainedPeerRejectsWrongTlsPinBeforeAnyRemoteReadOrSignature()
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        scope.State.WrongPin = true; await scope.ReopenAsync();
        using var holder = new GrantSigner(0x52);
        var request = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, holder);
        var remote = scope.Remote(await scope.PlacementAsync(), request.ExactXmg2);
        var before = scope.State.Requests;
        await Assert.ThrowsAsync<IOException>(() => remote.ReadRetainedMailboxGrantRouteAsync(default).AsTask());
        Assert.Equal(before, scope.State.Requests);
    }

    [Fact]
    public async Task RetainedBoundaryRejectsDepositAndCurrentReceiptCrossFeed()
    {
        await using var scope = await RetainedPeerScope.CreateAsync(); await scope.PublishAsync();
        var placement = await scope.PlacementAsync();
        using var holder = new GrantSigner(0x51);
        var deposit = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, holder);
        var before = scope.State.Requests;
        await Assert.ThrowsAsync<InvalidDataException>(() => scope.Remote(placement, deposit.ExactXmg2)
            .ReadRetainedMailboxGrantRouteAsync(default).AsTask());
        Assert.Equal(before, scope.State.Requests);
        using var ownerHolder = new GrantSigner(0x52);
        var retrieve = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(scope.Fixture.ContactRoute,
            scope.Fixture.ContactPublication.LocatorHash, scope.Fixture.ContactOwnedRequest.OwnerRetrieveCapability, ownerHolder);
        var local = scope.Providers[0].GetRequiredService<ProtectedRetainedMailboxReadAuthority>();
        var current = new ContactServiceReplicaReceiptRequest(ContactServiceReceiptKind.MailboxGrantRoute, new byte[139]);
        await Assert.ThrowsAsync<ContactServiceReceiptAuthorityException>(() =>
            local.IssueAsync(placement, retrieve.ExactXmg2, current, default).AsTask());
        Assert.Throws<ArgumentException>(() => new ContactServiceReplicaReceiptRequest(
            ContactServiceReceiptKind.MailboxRetainedRead, current.CanonicalTuple.Span));
        var facts = await local.ReadAsync(placement, retrieve.ExactXmg2, default);
        var wrongEvidence = ContactReplicaPayloadCodec.EncodeReceiptRequest(RetainedReceipt(retrieve.ExactXmg2, facts),
            ContactReplicaRpcOperation.ReadMailboxGrantRoute, retrieve.ExactXmg2.Span);
        var client = scope.Providers[0].GetRequiredService<IContactReplicaPeerClient>();
        await Assert.ThrowsAsync<IOException>(() => client.SendAsync(new(placement,
            ContactReplicaRpcOperation.IssueReceipt, RandomNumberGenerator.GetBytes(32), wrongEvidence), default).AsTask());
        Assert.Equal(503, scope.State.LastPeerStatus);
    }

    private sealed class RetainedPublicationSource(DeepIdV2PublicationAuthorityFixture fixture)
        : IDeepIdV2ContactStoreAuthoritySource
    {
        private int calls, at; private Action? action; internal bool Reached;
        internal void Arm(int count, Action callback) { calls = 0; at = count; action = callback; }
        public ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken ct)
        {
            if (++calls == at) { Reached = true; action?.Invoke(); }
            return fixture.ReadPublicationAuthorityAsync(ct);
        }
    }

    private sealed class RetainedPeerScope : IAsyncDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "did2-retained-peer-" + Guid.NewGuid().ToString("N"));
        internal DeepIdV2PublicationAuthorityFixture Fixture = null!;
        internal RetainedPublicationSource Source = null!;
        internal RouterNodeOptions[] Nodes = [];
        internal ServiceProvider[] Providers = [];
        internal readonly PeerState State = new();
        private readonly Dictionary<RouterId, ServiceProvider> peers = [];
        private readonly List<ContactPeerHost> hosts = [];
        private readonly ContactServicePersistenceOptions options = new() { RuntimeActivation = true, MapReplicaEndpoint = true };
        internal static async Task<RetainedPeerScope> CreateAsync()
        {
            var scope = new RetainedPeerScope();
            try
            {
                scope.Fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true, distinctNodeIdentities: true);
                scope.Source = new(scope.Fixture);
                var placement = await scope.PlacementAsync();
                scope.Nodes = placement.ReplicaIds.Select((id, index) => new RouterNodeOptions {
                    RouterId = Convert.ToHexStringLower(id.Span),
                    Ed25519PrivateKey = Convert.ToHexStringLower(scope.Fixture.Node(id.Span).Seed),
                    DataDirectory = Path.Combine(scope.root, index.ToString()) }).ToArray();
                foreach (var node in scope.Nodes)
                {
                    var host = await ContactPeerHost.CreateAsync(node.GetRouterId(), scope.peers, scope.State);
                    scope.hosts.Add(host); scope.State.Hosts.Add(node.GetRouterId(), host);
                }
                scope.Open(); return scope;
            }
            catch { await scope.DisposeAsync(); throw; }
        }
        internal ValueTask<ContactServicePlacementCapability> PlacementAsync() =>
            new VerifiedContactServicePlacementAuthoritySource(Fixture, Fixture).MintAsync(
                ContactServiceRequestKind.ResolveInvite, Fixture.ContactPublication.LocatorHash, default);
        private void Open()
        {
            foreach (var node in Nodes)
            {
                var provider = Compose(node, Nodes, Fixture, options, peers, State, false, Source);
                Providers = [.. Providers, provider]; peers.Add(node.GetRouterId(), provider);
            }
        }
        internal async Task ReopenAsync()
        {
            foreach (var provider in Providers) await provider.DisposeAsync();
            Providers = []; peers.Clear(); Open();
        }
        internal async Task PublishAsync()
        {
            var result = await Providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>().DispatchAsync(
                ContactServiceOperation.PublishDcr, Fixture.ContactPublication.CanonicalBytes, default);
            _ = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(Fixture.ContactRoute, Fixture.ContactObject,
                Fixture.ContactOwnedRequest, Fixture.ContactPublication.CanonicalBytes, result);
        }
        internal AuthenticatedRemoteContactServiceReplica Remote(ContactServicePlacementCapability placement, ReadOnlyMemory<byte> request) =>
            new(placement, Nodes[0].GetRouterId().ToBytes(), Providers[0].GetRequiredService<IContactReplicaPeerClient>(), request);
        public async ValueTask DisposeAsync()
        {
            foreach (var provider in Providers) await provider.DisposeAsync();
            foreach (var host in hosts) await host.DisposeAsync(); Fixture?.Dispose();
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true); // Exact test-owned scope only.
        }
    }
}
