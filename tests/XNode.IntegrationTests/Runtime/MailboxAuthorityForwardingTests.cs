using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using XNode;
using XNode.Core;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxAuthorityForwardingTests
{
    [Fact]
    public void Configuration_SeparatesExitForwardingFromAuthoritativeIngress()
    {
        var exit = Identity(1);
        var authority = Identity(2);
        using var exitPrivacy = Privacy(exit.Id, authority.Id);
        var forwarding = new MailboxAuthorityForwardingOptions
        {
            Enabled = true,
            AuthorityRouterId = authority.Id.Value
        }.Validate(Plan(routesMapped: false), exitPrivacy, exit.Options);
        Assert.True(forwarding.ForwardingEnabled);
        Assert.False(forwarding.AuthorityIngressEnabled);
        Assert.Equal(authority.Id, forwarding.AuthorityRouterId);

        using var authorityPrivacy = Privacy(authority.Id, exit.Id);
        var ingress = new MailboxAuthorityForwardingOptions
        {
            AllowedExitRouterIds = [exit.Id.Value]
        }.Validate(Plan(routesMapped: true), authorityPrivacy, authority.Options);
        Assert.False(ingress.ForwardingEnabled);
        Assert.True(ingress.AuthorityIngressEnabled);
        Assert.Contains(exit.Id, ingress.AllowedExitRouterIds);
    }

    [Fact]
    public void Configuration_RejectsSecondAdapterAndUnpinnedAuthority()
    {
        var exit = Identity(3);
        var authority = Identity(4);
        using var privacy = Privacy(exit.Id, authority.Id);
        var options = new MailboxAuthorityForwardingOptions
        {
            Enabled = true,
            AuthorityRouterId = authority.Id.Value
        };
        Assert.Throws<InvalidOperationException>(() =>
            options.Validate(Plan(routesMapped: true), privacy, exit.Options));

        var unpinned = Identity(5);
        options.AuthorityRouterId = unpinned.Id.Value;
        Assert.Throws<InvalidOperationException>(() =>
            options.Validate(Plan(routesMapped: false), privacy, exit.Options));
    }

    [Fact]
    public void ProductionForwarding_UsesVerifiedPma1ResolverInsteadOfDevPeerInventory()
    {
        var exit = Identity(10);
        var authority = Identity(11);
        var unrelated = Identity(12);
        using var privacy = Privacy(exit.Id, unrelated.Id);
        var options = new MailboxAuthorityForwardingOptions
        {
            Enabled = true,
            AuthorityRouterId = authority.Id.Value
        };

        var configuration = options.Validate(
            Plan(routesMapped: false),
            privacy,
            exit.Options,
            useProductionAuthority: true);

        Assert.True(configuration.ForwardingEnabled);
        Assert.True(configuration.UseProductionAuthority);
        Assert.Null(configuration.DevelopmentAuthority);
        Assert.Equal(authority.Id, configuration.AuthorityRouterId);
    }

    [Fact]
    public void ExitRouter_ExposesOnlyVerifiedOnionRequestBoundary()
    {
        var local = new RecordingLocalDispatcher();
        var forwarding = new RecordingForwardingClient(
            new NativeMailboxDispatchResult(200, "MQR3"u8.ToArray()));
        var configuration = new MailboxAuthorityForwardingConfiguration(
            new PrivacyPeer(
                Identity(7).Id,
                new Uri("http://127.0.0.1:8083/api/peer/privacy/v1/frame"),
                [],
                [],
                true),
            new HashSet<RouterId>());
        var routed = new RoutedNativeMailboxExitDispatcher(
            configuration,
            local,
            forwarding);
        INativeMailboxExitDispatcher boundary = routed;
        Func<VerifiedCanonicalOnionRequest, CancellationToken,
            Task<NativeMailboxDispatchResult>> dispatch = boundary.DispatchAsync;

        Assert.NotNull(dispatch);
        Assert.Equal(0, local.Calls);
        Assert.Equal(0, forwarding.Calls);
    }

    [Fact]
    public async Task AuthorityIngress_AuthenticatesExitAndRejectsTransportReplay()
    {
        var exit = Identity(8);
        var authority = Identity(9);
        using var privacy = Privacy(authority.Id, exit.Id);
        var configuration = new MailboxAuthorityForwardingOptions
        {
            AllowedExitRouterIds = [exit.Id.Value]
        }.Validate(Plan(routesMapped: true), privacy, authority.Options);
        var replay = new MailboxAuthorityForwardingReplayGuard(privacy);
        var limiter = new MailboxAuthorityForwardingIngressLimiter(privacy);
        var local = new RecordingLocalDispatcher
        {
            Result = new NativeMailboxDispatchResult(200, "MQR3"u8.ToArray())
        };
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        var clock = new FixedClock(now);
        var body = Enumerable.Repeat(
            (byte)0x31,
            MailboxAuthorityForwardingHttpContract.Contract(
                OnionOperation.Store).MinimumRequestBytes).ToArray();
        var authentication = MailboxAuthorityForwardingAuthenticator.Sign(
            exit.Id,
            authority.Id,
            exit.SeedHex,
            OnionOperation.Store,
            body,
            now);
        Assert.False(MailboxAuthorityForwardingAuthenticator.Verify(
            authentication,
            authority.Id,
            OnionOperation.Retrieve,
            body,
            now,
            out _,
            out _));

        var first = Context(body, authentication);
        var firstResult = await MailboxAuthorityForwardingHttpEndpoint.HandleAsync(
            first,
            configuration,
            limiter,
            replay,
            local,
            authority.Options,
            clock,
            8083,
            CancellationToken.None);
        await firstResult.ExecuteAsync(first);
        Assert.Equal(StatusCodes.Status200OK, first.Response.StatusCode);
        Assert.Equal(1, local.Calls);
        Assert.Equal(body, local.LastBody);

        var repeated = Context(body, authentication);
        var replayResult = await MailboxAuthorityForwardingHttpEndpoint.HandleAsync(
            repeated,
            configuration,
            limiter,
            replay,
            local,
            authority.Options,
            clock,
            8083,
            CancellationToken.None);
        await replayResult.ExecuteAsync(repeated);
        Assert.Equal(StatusCodes.Status504GatewayTimeout, repeated.Response.StatusCode);
        Assert.Equal(1, local.Calls);
    }

    [Fact]
    public async Task AuthorityIngress_RejectsAtAdmissionBeforeReadingAnotherBody()
    {
        var exit = Identity(13);
        var authority = Identity(14);
        using var privacy = Privacy(authority.Id, exit.Id, requestsPerMinute: 1);
        var configuration = new MailboxAuthorityForwardingOptions
        {
            AllowedExitRouterIds = [exit.Id.Value]
        }.Validate(Plan(routesMapped: true), privacy, authority.Options);
        var limiter = new MailboxAuthorityForwardingIngressLimiter(privacy);
        var replay = new MailboxAuthorityForwardingReplayGuard(privacy);
        var local = new RecordingLocalDispatcher
        {
            Result = new NativeMailboxDispatchResult(200, "MQR3"u8.ToArray())
        };
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_100);
        var clock = new FixedClock(now);
        var body = Enumerable.Repeat(
            (byte)0x32,
            MailboxAuthorityForwardingHttpContract.Contract(
                OnionOperation.Store).MinimumRequestBytes).ToArray();

        async Task<DefaultHttpContext> InvokeAsync()
        {
            var authentication = MailboxAuthorityForwardingAuthenticator.Sign(
                exit.Id,
                authority.Id,
                exit.SeedHex,
                OnionOperation.Store,
                body,
                now);
            var context = Context(body, authentication);
            var result = await MailboxAuthorityForwardingHttpEndpoint.HandleAsync(
                context,
                configuration,
                limiter,
                replay,
                local,
                authority.Options,
                clock,
                8083,
                CancellationToken.None);
            await result.ExecuteAsync(context);
            return context;
        }

        var accepted = await InvokeAsync();
        Assert.Equal(StatusCodes.Status200OK, accepted.Response.StatusCode);
        var rejected = await InvokeAsync();
        Assert.Equal(StatusCodes.Status429TooManyRequests, rejected.Response.StatusCode);
        Assert.Equal(1, local.Calls);
    }

    private static DefaultHttpContext Context(
        byte[] body,
        MailboxAuthorityForwardingAuthenticationHeaders authentication)
    {
        var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Connection.LocalPort = 8083;
        context.Request.Protocol = "HTTP/2";
        context.Request.Method = HttpMethods.Post;
        context.Request.Path = MailboxAuthorityForwardingHttpContract.StoreRoute;
        context.Request.ContentType =
            MailboxAuthorityForwardingHttpContract.Contract(
                OnionOperation.Store).RequestContentType;
        context.Request.Headers.Accept =
            MailboxAuthorityForwardingHttpContract.Contract(
                OnionOperation.Store).ResponseContentType;
        context.Request.ContentLength = body.Length;
        context.Request.Body = new MemoryStream(body);
        context.Response.Body = new MemoryStream();
        context.Request.Headers[MailboxAuthorityForwardingAuthenticator.SenderHeader] =
            authentication.SenderRouterId;
        context.Request.Headers[MailboxAuthorityForwardingAuthenticator.RecipientHeader] =
            authentication.RecipientRouterId;
        context.Request.Headers[MailboxAuthorityForwardingAuthenticator.TimestampHeader] =
            authentication.TimestampUnixMilliseconds.ToString(
                System.Globalization.CultureInfo.InvariantCulture);
        context.Request.Headers[MailboxAuthorityForwardingAuthenticator.NonceHeader] =
            authentication.Nonce;
        context.Request.Headers[MailboxAuthorityForwardingAuthenticator.SignatureHeader] =
            authentication.Signature;
        return context;
    }

    private static MailboxClientActivationPlan Plan(bool routesMapped) => new(
        new MailboxClientActivationOptions { Enabled = routesMapped },
        new MailboxClientAdapterOptions { Enabled = routesMapped },
        routesMapped,
        DevelopmentFixture: routesMapped,
        ProductionTopology: false);

    private static PrivacyRoutingConfiguration Privacy(
        RouterId local,
        RouterId peer,
        int requestsPerMinute = 600) => new(
        true,
        Enumerable.Repeat((byte)0x41, 32).ToArray(),
        Enumerable.Repeat((byte)0x42, 32).ToArray(),
        new Uri("http://127.0.0.1:8083/api/peer/privacy/v1/frame"),
        new Dictionary<RouterId, PrivacyPeer>
        {
            [peer] = new PrivacyPeer(
                peer,
                new Uri("http://127.0.0.1:8083/api/peer/privacy/v1/frame"),
                [],
                [],
                true)
        },
        64,
        requestsPerMinute,
        TimeSpan.FromSeconds(30),
        1024,
        1000,
        TimeSpan.FromMinutes(5));

    private static IdentityFixture Identity(byte fill)
    {
        var seed = Enumerable.Repeat(fill, 32).ToArray();
        var signer = new Rebex.Security.Cryptography.Ed25519();
        signer.FromSeed(seed);
        var id = RouterId.FromBytes(signer.GetPublicKey());
        return new IdentityFixture(
            id,
            Convert.ToHexStringLower(seed),
            new RouterNodeOptions
            {
                RouterId = id.Value,
                Ed25519PrivateKey = Convert.ToHexStringLower(seed)
            });
    }

    private sealed record IdentityFixture(
        RouterId Id,
        string SeedHex,
        RouterNodeOptions Options);

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class RecordingLocalDispatcher : ILocalNativeMailboxExitDispatcher
    {
        public int Calls { get; private set; }
        public byte[] LastBody { get; private set; } = [];
        public NativeMailboxDispatchResult Result { get; init; } =
            new(503, ReadOnlyMemory<byte>.Empty);

        public Task<NativeMailboxDispatchResult> DispatchAsync(
            OnionOperation privacyOperation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastBody = canonicalMau2.ToArray();
            return Task.FromResult(Result);
        }
    }

    private sealed class RecordingForwardingClient(
        NativeMailboxDispatchResult result) : IMailboxAuthorityForwardingClient
    {
        public int Calls { get; private set; }
        public byte[] LastBody { get; private set; } = [];

        public Task<NativeMailboxDispatchResult> ForwardAsync(
            OnionOperation operation,
            ReadOnlyMemory<byte> canonicalMau2,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastBody = canonicalMau2.ToArray();
            return Task.FromResult(result);
        }
    }
}
