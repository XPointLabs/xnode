using System.Net;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Configuration;
using System.Runtime.InteropServices;
using Sodium;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

// Real public DID2/NET authorization, opaque journals and production authenticated
// binary peer HTTP code through an in-process handler. No socket/TLS/device claim.
public sealed class Did2ContactServiceCompositionTests
{
    [Fact]
    public async Task PendingGenesisExposesOnlyDefensiveSignedArtifacts()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var pending = fixture.PendingOperational;
        var type = typeof(PendingXPointNetworkOperationalGenesis);
        Assert.Empty(type.GetConstructors());
        Assert.Equal(new[] { "ExactPma2", "ExactXnd1", "ExactXnh1", "ExactXnv1", "ExactXvp1" },
            type.GetProperties().Select(property => property.Name).Order().ToArray());
        Func<ReadOnlyMemory<byte>>[] artifacts = [() => pending.ExactXvp1, () => pending.ExactXnv1,
            () => pending.ExactXnh1, () => pending.ExactPma2, () => pending.ExactXnd1[0],
            () => fixture.CompletedOperational.ExactXvp1, () => fixture.CompletedOperational.ExactXnv1,
            () => fixture.CompletedOperational.ExactXnh1, () => fixture.CompletedOperational.ExactXnd1[0],
            () => fixture.CompletedOperational.ExactAdh1, () => fixture.CompletedOperational.ExactDtt1,
            () => fixture.CompletedOperational.ExactAdp1, () => fixture.CompletedOperational.ExactPma2,
            () => fixture.CompletedOperational.ExactPmt2];
        foreach (var read in artifacts)
        {
            var original = read().ToArray();
            Assert.True(MemoryMarshal.TryGetArray(read(), out var copy));
            copy.Array![copy.Offset] ^= 0xff;
            Assert.Equal(original, read().ToArray());
        }
        Assert.Equal(3, fixture.TopologySignatureCalls);
    }

    [Fact]
    public async Task Did2GenesisRejectsForeignViewClockAndCancellationBeforeTopologySigning()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var otherView = await DeepIdV2PublicationAuthorityFixture.CreateAsync(networkCommitmentMarker: 1);
        using var otherRoot = await DeepIdV2PublicationAuthorityFixture.CreateAsync(rootMarker: 0x21);
        Assert.NotEqual(fixture.View.ToArray(), otherView.View.ToArray());
        var calls = fixture.TopologySignatureCalls;
        await Assert.ThrowsAsync<CryptographicException>(() => XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(
            fixture.PendingOperational, otherView.Freshness, new(fixture)).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(
            fixture.PendingOperational, otherRoot.Freshness, new(fixture)).AsTask());
        foreach (var reading in new[] {
            new OnionMonotonicReading(Enumerable.Repeat((byte)0x42, 16).ToArray(), 100),
            new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Boot, 99),
            new OnionMonotonicReading(DeepIdV2PublicationAuthorityFixture.Boot, 500) })
        {
            fixture.ClockReadings.Enqueue(reading);
            await Assert.ThrowsAsync<CryptographicException>(() => XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(
                fixture.PendingOperational, fixture.Freshness, new(fixture)).AsTask());
        }
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => XPointNetworkOperationalGenesisAuthor.CompleteDid2Async(
            fixture.PendingOperational, fixture.Freshness, new(fixture), cancelled.Token).AsTask());
        Assert.Equal(calls, fixture.TopologySignatureCalls);
    }

    [Theory]
    [InlineData("ContactAuthority", "false")]
    [InlineData("ContactAuthority:Enabled", "false")]
    [InlineData("ContactAuthority:Unknown", "unused")]
    [InlineData("GroupControlAuthority", "disabled")]
    [InlineData("GroupControlAuthority:Enabled", "false")]
    public void RetiredConfigurationRejectsEvenDisabledAndUnknownFields(string key, string value)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { [key] = value }).Build();
        Assert.Throws<InvalidOperationException>(() => RetiredAuthorityConfiguration.RequireAbsent(configuration));
    }

    [Fact]
    public void CurrentConfigurationRejectsRemovedRecipientEvidenceSettings()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["DeepIdV2ContactResolver:Enabled"] = "false", ["ContactService:RuntimeActivation"] = "false" }).Build();
        RetiredAuthorityConfiguration.RequireAbsent(configuration);
        Assert.False(configuration.GetSection("ContactService").Get<ContactServicePersistenceOptions>(
            options => options.ErrorOnUnknownConfiguration = true)!.RuntimeActivation);
        foreach (var field in new[] { "RecipientEvidenceMaximumProtectedStateBytes", "RecipientEvidenceMaximumEntries" })
        {
            var old = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["ContactService:" + field] = "4096" }).Build();
            Assert.Throws<InvalidOperationException>(() => old.GetSection("ContactService").Get<ContactServicePersistenceOptions>(
                options => options.ErrorOnUnknownConfiguration = true));
        }
    }

    [Fact]
    public async Task CurrentContactHostActivationRequiresIndependentDid2SourceAndClock()
    {
        var options = new ContactServicePersistenceOptions { RuntimeActivation = true, MapReplicaEndpoint = true };
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddDid2ContactServiceBoundary(options));
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var services = new ServiceCollection();
        services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(fixture);
        Assert.Throws<InvalidOperationException>(() => services.AddDid2ContactServiceBoundary(options));
        services.AddSingleton<IOnionMonotonicClock>(fixture);
        var plan = services.AddDid2ContactServiceBoundary(options);
        Assert.True(plan.RuntimeActivation); Assert.True(plan.MapReplicaEndpoint);
        Assert.Null(plan.Authorities); // Resolver, not a V1 snapshot, owns the subsequent composition.
        Assert.DoesNotContain(services, descriptor => descriptor.ServiceType == typeof(IContactServiceOpaqueDispatcher));
        services.AddDid2ContactResolver(new() { Enabled = true });
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(Did2ContactResolverDispatcher));
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IContactReplicaCommandReceiver));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CandidateMapsExactlyOneReplicaEndpointOnlyWhenEnabled(bool enabled)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Services.AddContactServiceBoundary(new());
        builder.Services.AddSingleton(new RouterNodeOptions());
        builder.Services.AddSingleton<IClock, SystemClock>();
        builder.Services.AddSingleton<IContactReplicaCommandReceiver, RejectUninvokedReceiver>();
        await using var app = builder.Build();
        app.MapDeepIdV2ContactReplicaEndpoint(enabled, 4443);
        var endpoints = ((IEndpointRouteBuilder)app).DataSources.SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>().ToArray();
        if (enabled) Assert.Equal(ContactReplicaHttpContract.Route, Assert.Single(endpoints).RoutePattern.RawText);
        else Assert.Empty(endpoints);
    }

    [Fact]
    public async Task TwoSelectedStoresPublishResolveAndResumeExactAfterLostPeerResponse()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(authorContactPublication: true);
        var placementSource = new VerifiedContactServicePlacementAuthoritySource(fixture, fixture);
        var publication = fixture.ContactPublication;
        var placement = await placementSource.MintAsync(ContactServiceRequestKind.PublishInvite, publication.LocatorHash, default);
        var root = Path.Combine(Path.GetTempPath(), "did2-active-contact-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var nodes = placement.ReplicaIds.Select((id, index) => new RouterNodeOptions {
                RouterId = Convert.ToHexStringLower(id.Span),
                Ed25519PrivateKey = Convert.ToHexStringLower(fixture.Node(id.Span).Seed),
                DataDirectory = Path.Combine(root, index.ToString()) }).ToArray();
            var options = new ContactServicePersistenceOptions { RuntimeActivation = true, MapReplicaEndpoint = true };
            var peers = new Dictionary<RouterId, ServiceProvider>();
            var state = new PeerState();
            var providers = nodes.Select(node => Compose(node, nodes, fixture, options, peers, state)).ToArray();
            try
            {
                for (var i = 0; i < nodes.Length; i++) peers.Add(nodes[i].GetRouterId(), providers[i]);
                Assert.Single(providers[0].GetServices<IContactReplicaCommandReceiver>());
                Assert.IsType<Did2ContactReplicaCommandDispatcher>(providers[0].GetRequiredService<IContactReplicaCommandReceiver>());
                var dispatcher = providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>();
                Assert.IsType<DeepIdV2ContactOnionDispatcher>(dispatcher);
                state.LoseNextPublish = true;
                var uncertain = Xpo1Codec.Decode((await dispatcher.DispatchAsync(ContactServiceOperation.PublishDcr,
                    publication.CanonicalBytes, default)).Span, publication.CanonicalBytes.Span);
                Assert.Equal(Xpo1Status.OutcomeUnknown, uncertain.Status);
                Assert.True(state.LostAfterExecution);
                // Recreate both service owners against their actual persisted
                // directories, not just retry with an in-memory saga/receipt.
                foreach (var provider in providers) await provider.DisposeAsync();
                peers.Clear();
                providers = nodes.Select(node => Compose(node, nodes, fixture, options, peers, state)).ToArray();
                for (var i = 0; i < nodes.Length; i++) peers.Add(nodes[i].GetRouterId(), providers[i]);
                dispatcher = providers[0].GetRequiredService<IContactServiceOpaqueDispatcher>();
                var exact = await dispatcher.DispatchAsync(ContactServiceOperation.PublishDcr, publication.CanonicalBytes, default);
                var commit = await DeepIdV2PublicationCommitVerifier.VerifyCommittedAsync(fixture.ContactRoute,
                    fixture.ContactObject, fixture.ContactOwnedRequest, publication.CanonicalBytes, exact);
                Assert.Equal(exact.ToArray(), commit.ExactXpo1.ToArray());
                var query = await DeepIdV2PermanentContactResolveRequestAuthor.AuthorAsync(fixture.ContactAddress,
                    fixture.ContactRoute.Recipient, fixture.NetworkContext, fixture.Authority, new(fixture));
                var result = await dispatcher.DispatchAsync(ContactServiceOperation.ResolveDcr, query.CanonicalBytes, default);
                var candidate = DeepIdV2PermanentContactResolveVerifier.OpenCandidate(fixture.ContactAddress, query.CanonicalBytes, result);
                var contact = await DeepIdV2PermanentContactResolveVerifier.VerifyAsync(candidate, fixture.Freshness,
                    fixture.NetworkContext, fixture.Authority, new(fixture));
                Assert.Equal(fixture.ContactObject.Closure.CanonicalBytes.ToArray(), contact.Contact.CanonicalBytes.ToArray());
                using var holder = new GrantSigner(0x51);
                var deposit = await DeepIdV2MailboxGrantRequestAuthor.AuthorDepositAsync(fixture.ContactRoute,
                    publication.LocatorHash, holder);
                state.LoseNextGrant = true;
                await Assert.ThrowsAsync<IOException>(() => dispatcher.DispatchAsync(ContactServiceOperation.AcquireMailboxGrant,
                    deposit.ExactXmg1, default).AsTask());
                fixture.Sample++;
                var depositResult = await dispatcher.DispatchAsync(ContactServiceOperation.AcquireMailboxGrant, deposit.ExactXmg1, default);
                var granted = await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(fixture.ContactRoute,
                    deposit, depositResult, fixture.MailboxAuthority);
                Assert.Equal(MailboxCapabilityDomain.Deposit, granted.Domain);
                Assert.Equal(1, state.GrantSignatures);
                using var ownerHolder = new GrantSigner(0x52);
                var retrieve = await DeepIdV2MailboxGrantRequestAuthor.AuthorRetrieveAsync(fixture.ContactRoute,
                    publication.LocatorHash, fixture.ContactOwnedRequest.OwnerRetrieveCapability, ownerHolder);
                var retrieveResult = await dispatcher.DispatchAsync(ContactServiceOperation.AcquireMailboxGrant, retrieve.ExactXmg1, default);
                Assert.Equal(MailboxCapabilityDomain.Retrieve, (await DeepIdV2MailboxGrantResultVerifier.VerifySuccessAsync(
                    fixture.ContactRoute, retrieve, retrieveResult, fixture.MailboxAuthority)).Domain);
                Assert.Equal(2, state.GrantSignatures);
                Assert.Equal(3, state.GrantCalls);
                Assert.True(state.Requests >= 4);
                Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(checked((long)fixture.Freshness.TrustedUpperUnixSeconds + 1)),
                    providers[0].GetRequiredService<Did2AuthenticatedContactClock>().UtcNow);
                Assert.True(DateTimeOffset.UtcNow.ToUnixTimeSeconds() > 1_000_000); // OS epoch is deliberately unrelated.
                var before = state.Requests;
                await Assert.ThrowsAsync<ContactServiceUnavailableException>(() => dispatcher.DispatchAsync(
                    ContactServiceOperation.WriteContactUpdate, new byte[1], default).AsTask());
                var receiver = providers[0].GetRequiredService<IContactReplicaCommandReceiver>();
                await Assert.ThrowsAsync<InvalidDataException>(() => receiver.ReceiveAsync(new(placement,
                    ContactReplicaRpcOperation.ClaimPreKey, new byte[32], new byte[1]), nodes[1].GetRouterId(), default).AsTask());
                Assert.Equal(before, state.Requests);
                fixture.Sample = 500;
                await Assert.ThrowsAsync<ContactServiceUnavailableException>(() => dispatcher.DispatchAsync(
                    ContactServiceOperation.PublishDcr, publication.CanonicalBytes, default).AsTask());
                Assert.Equal(before, state.Requests);
            }
            finally { foreach (var provider in providers) await provider.DisposeAsync(); }
        }
        finally { Directory.Delete(root, recursive: true); } // Exact test-created root only.
    }

    [Fact]
    public async Task AuthenticatedServiceClockRejectsMissingExpiredForeignBootAndRollbackProof()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var clock = new Did2AuthenticatedContactClock(fixture, fixture);
        var first = await clock.ReadAsync(default);
        fixture.Sample++;
        var next = await clock.ReadAsync(default);
        Assert.Equal(first.Lower + 1, next.Lower);
        Assert.Equal(first.Upper + 1, next.Upper);
        fixture.Sample--;
        await Assert.ThrowsAsync<CryptographicException>(() => clock.ReadAsync(default).AsTask());
        fixture.Sample++;
        fixture.RejectProof = true;
        await Assert.ThrowsAsync<CryptographicException>(() => clock.ReadAsync(default).AsTask());
        fixture.RejectProof = false;
        fixture.ClockReadings.Enqueue(new(Enumerable.Repeat((byte)0x42, 16).ToArray(), fixture.Sample));
        await Assert.ThrowsAsync<CryptographicException>(() => clock.ReadAsync(default).AsTask());
        fixture.Sample = 500;
        await Assert.ThrowsAsync<CryptographicException>(() => clock.ReadAsync(default).AsTask());
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => clock.ReadAsync(cancelled.Token).AsTask());
    }

    [Fact]
    public void ActivationRequiresClosedDid2DependenciesAndRejectsRetiredRuntime()
    {
        Assert.False(new DeepIdV2ContactResolverOptions().Validate(false, false, false));
        var options = new DeepIdV2ContactResolverOptions { Enabled = true };
        Assert.True(options.Validate(true, true, true));
        foreach (var inputs in new[] { (false, true, true), (true, false, true),
            (true, true, false) })
            Assert.Throws<InvalidOperationException>(() => options.Validate(inputs.Item1, inputs.Item2, inputs.Item3));
        options.MailboxGrantEnabled = true;
        foreach (var origin in new[] { "", "http://issuer.example/", "https://issuer.example/path", "https://u:p@issuer.example/", "https://issuer.example/?q=1" })
        {
            options.MailboxGrantAuthorityOrigin = origin;
            Assert.Throws<InvalidOperationException>(() => options.Validate(true, true, true));
        }
        options.MailboxGrantAuthorityOrigin = "https://issuer.example/";
        Assert.True(options.Validate(true, true, true));
    }

    private static ServiceProvider Compose(RouterNodeOptions node, RouterNodeOptions[] nodes,
        DeepIdV2PublicationAuthorityFixture fixture, ContactServicePersistenceOptions options,
        Dictionary<RouterId, ServiceProvider> providers, PeerState state)
    {
        var services = new ServiceCollection(); services.AddLogging();
        services.AddSingleton(node); services.AddSingleton<IOnionMonotonicClock>(fixture);
        services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(fixture);
        services.AddSingleton<IDeepIdV2PreKeyPlacementSource>(fixture);
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddSingleton<DeepIdV2ReplicaStageReceiver>();
        services.AddDid2ContactServiceBoundary(options);
        services.AddSingleton<IContactReplicaPeerClient>(_ => new HttpContactReplicaPeerClient(node,
            Privacy(nodes), options, new SystemClock(), peer => new Handler(peer, providers, state)));
        services.AddDid2ContactResolver(new() { Enabled = true, MailboxGrantEnabled = true, MailboxGrantAuthorityOrigin = "https://issuer.example/" });
        services.RemoveAll<IMailboxGrantAuthorityClient>();
        services.AddSingleton<IMailboxGrantAuthorityClient>(new VerifiedGrantIssuer(fixture, state));
        services.AddSingleton<IContactServiceOpaqueDispatcher, DeepIdV2ContactOnionDispatcher>();
        return services.BuildServiceProvider();
    }

    private static PrivacyRoutingConfiguration Privacy(RouterNodeOptions[] nodes) => new(true,
        Enumerable.Repeat((byte)0x81, 32).ToArray(),
        Sodium.ScalarMult.Base(Enumerable.Repeat((byte)0x81, 32).ToArray()), new("https://peer.example/"), nodes.ToDictionary(node => node.GetRouterId(),
            node => new PrivacyPeer(node.GetRouterId(), new("https://peer.example/"), new byte[32], [], false)),
        8, 1_000, TimeSpan.FromSeconds(5), 1024, 1_000, TimeSpan.FromSeconds(300));

    private sealed class PeerState
    {
        internal int Requests, GrantCalls, GrantSignatures;
        internal bool LoseNextPublish, LostAfterExecution, LoseNextGrant;
        internal Dictionary<string, byte[]> GrantWinners { get; } = new(StringComparer.Ordinal);
    }

    // Private hop/journal are in-process fixture state, not production DB/TLS evidence.
    private sealed class VerifiedGrantIssuer(DeepIdV2PublicationAuthorityFixture fixture, PeerState state) : IMailboxGrantAuthorityClient
    {
        public async ValueTask<ReadOnlyMemory<byte>> AuthorizeAsync(MailboxGrantAuthorityRequest request, CancellationToken ct)
        {
            state.GrantCalls++;
            if (request.ResultCode != MailboxGrantAcquisitionResultCode.Success) throw new ContactServiceUnavailableException("No current route.");
            var xmg = ContactCodec.Decode("XMG1", request.ExactXmg1.Span);
            Assert.Equal(BinaryPrimitives.ReadUInt64BigEndian(xmg.Field(10).Span), request.ResultExpiresAtUnixSeconds);
            var current = await DeepIdV2MailboxGrantIssuanceVerifier.VerifyAsync(fixture.NetworkContext, fixture.Authority,
                fixture.MailboxAuthority, request.ExactXmg1, request.ExactRouteClosure, request.RouteEffectiveExpiresAtUnixSeconds,
                request.ReplicaEvidence.Select(item => new DeepIdV2MailboxGrantReplicaEvidence(item.ReplicaId.Span, item.Signature.Span)).ToArray(),
                new(fixture), ct);
            var key = Convert.ToHexString(xmg.Field(2).Span);
            if (!state.GrantWinners.TryGetValue(key, out var exact))
            {
                using var issuer = new GrantSigner(xmg.Field(6).Span[0] == 1 ? (byte)0x31 : (byte)0x32);
                exact = (await current.AuthorSuccessAsync(issuer, ct)).ToArray();
                state.GrantSignatures++; state.GrantWinners.Add(key, exact);
            }
            await current.VerifySuccessAsync(exact, ct);
            if (state.LoseNextGrant) { state.LoseNextGrant = false; throw new IOException("Injected lost grant response."); }
            return exact.ToArray();
        }
    }
    private sealed class GrantSigner : IDisposable, IReachabilityMailboxHolderSigner, IMailboxGrantIssuerSigner
    {
        private readonly KeyPair key;
        internal GrantSigner(byte marker) => key = PublicKeyAuth.GenerateKeyPair(Enumerable.Repeat(marker, 32).ToArray());
        public ReadOnlyMemory<byte> Ed25519PublicKey => key.PublicKey.ToArray();
        public ValueTask<int> SignMailboxGrantRequestAsync(ReadOnlyMemory<byte> bytes, Memory<byte> signature, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); PublicKeyAuth.SignDetached(bytes.ToArray(), key.PrivateKey).CopyTo(signature); return ValueTask.FromResult(64); }
        public ValueTask<ReadOnlyMemory<byte>> SignAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct)
        { ct.ThrowIfCancellationRequested(); return ValueTask.FromResult<ReadOnlyMemory<byte>>(PublicKeyAuth.SignDetached(bytes.ToArray(), key.PrivateKey)); }
        public void Dispose() => CryptographicOperations.ZeroMemory(key.PrivateKey);
    }
    private sealed class RejectUninvokedReceiver : IContactReplicaCommandReceiver
    {
        public ValueTask<ContactReplicaRpcResponse> ReceiveAsync(ContactReplicaRpcCommand command,
            RouterId authenticatedSender, CancellationToken ct) => throw new InvalidOperationException("Mapping test performs no peer dispatch.");
    }
    private sealed class Handler(PrivacyPeer peer, Dictionary<RouterId, ServiceProvider> providers,
        PeerState state) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage message, CancellationToken ct)
        {
            var provider = providers[peer.RouterId];
            var body = await message.Content!.ReadAsByteArrayAsync(ct);
            var command = ContactReplicaWireCodec.DecodeRequest(body);
            var context = new DefaultHttpContext(); context.RequestServices = provider;
            context.Connection.LocalPort = 4443; context.Request.Scheme = "https";
            context.Request.Protocol = "HTTP/2"; context.Request.Method = "POST";
            context.Request.ContentType = ContactReplicaHttpContract.MediaType;
            context.Request.ContentLength = body.Length; context.Request.Body = new MemoryStream(body);
            context.Response.Body = new MemoryStream();
            foreach (var header in message.Headers) context.Request.Headers[header.Key] = header.Value.ToArray();
            state.Requests++;
            var result = await ContactReplicaHttpEndpoint.HandleCoreAsync(context, true,
                provider.GetRequiredService<ContactServicePersistenceOptions>(), provider.GetRequiredService<ContactReplicaReplayGuard>(),
                provider.GetRequiredService<IContactReplicaCommandReceiver>(), provider.GetRequiredService<RouterNodeOptions>(),
                new SystemClock(), 4443, ct);
            await result.ExecuteAsync(context);
            if (state.LoseNextPublish && command.Operation == ContactReplicaRpcOperation.PublishDcr && context.Response.StatusCode == 200)
            {
                state.LoseNextPublish = false; state.LostAfterExecution = true;
                return new(HttpStatusCode.GatewayTimeout) { Version = HttpVersion.Version20, Content = new ByteArrayContent([]) };
            }
            var response = new HttpResponseMessage((HttpStatusCode)context.Response.StatusCode) {
                Version = HttpVersion.Version20, Content = new ByteArrayContent(((MemoryStream)context.Response.Body).ToArray()) };
            foreach (var header in context.Response.Headers)
                if (!response.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                    response.Content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
            return response;
        }
    }
}
