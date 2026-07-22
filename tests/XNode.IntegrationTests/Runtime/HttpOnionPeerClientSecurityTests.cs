using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using XNode;
using XNode.Core;
using XNode.Core.Onion;
using XNode.Core.Runtime;
using XNode.Core.Session;

namespace XNode.IntegrationTests.Runtime;

public sealed class HttpOnionPeerClientSecurityTests
{
    [Fact]
    public void TypedHttpClient_HasExactlyOneApplicablePublicConstructor()
    {
        var constructors = typeof(HttpOnionPeerClient)
            .GetConstructors()
            .Where(constructor => constructor.GetParameters().Any(parameter => parameter.ParameterType == typeof(HttpClient)))
            .ToArray();

        Assert.Single(constructors);
    }

    [Fact]
    public async Task ForwardAsync_RejectsPrivatePeerEndpointBeforeSending()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));
        using var client = new HttpClient(handler);
        var peer = CreatePeer(client);

        var response = await peer.ForwardAsync(
            Id(2),
            "http://169.254.169.254/latest/meta-data",
            Request(),
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal("blocked-onion-peer-endpoint", response.Error);
        Assert.Equal(0, handler.Requests);
    }

    [Fact]
    public async Task ForwardAsync_AllowsRfc1918PeerOnlyWithExplicitRuntimeOptIn()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = JsonContent.Create(SessionRpcResponse.Ok("onion-forward", new { accepted = true }))
        });
        using var client = new HttpClient(handler);
        var peer = CreatePeer(client, new RouterRuntimeOptions { AllowPrivatePeerEndpoints = true });

        var response = await peer.ForwardAsync(
            Id(2),
            "http://10.1.2.3:8081/api/peer/onion",
            Request(),
            CancellationToken.None);

        Assert.True(response.Success);
        Assert.Equal(1, handler.Requests);
    }

    [Fact]
    public async Task ForwardAsync_RejectsRedirectsWithoutFollowingThem()
    {
        var handler = new CountingHandler(_ => new HttpResponseMessage(HttpStatusCode.Found)
        {
            Headers = { Location = new Uri("http://127.0.0.1:8081/api/peer/onion") }
        });
        using var client = new HttpClient(handler);
        var peer = CreatePeer(client);

        var response = await peer.ForwardAsync(
            Id(2),
            "https://8.8.8.8/api/peer/onion",
            Request(),
            CancellationToken.None);

        Assert.False(response.Success);
        Assert.Equal("onion-peer-redirect-blocked:302", response.Error);
        Assert.Equal(1, handler.Requests);
    }

    private static HttpOnionPeerClient CreatePeer(
        HttpClient client,
        RouterRuntimeOptions? runtimeOptions = null)
    {
        const string seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        return new HttpOnionPeerClient(
            client,
            new RouterNodeOptions
            {
                RouterId = RelayContactSigner.DeriveRouterId(seed).Value,
                Ed25519PrivateKey = seed
            },
            runtimeOptions ?? new RouterRuntimeOptions(),
            new FixedClock(new DateTimeOffset(2026, 5, 28, 12, 0, 0, TimeSpan.Zero)));
    }

    private static OnionRequest Request() => new(new OnionEnvelope(
        "xpoint-onion-v1",
        Convert.ToBase64String(new byte[32]),
        Convert.ToBase64String(new byte[24]),
        Convert.ToBase64String(new byte[16])));

    private static RouterId Id(byte value)
    {
        var bytes = new byte[RouterId.ByteLength];
        bytes[^1] = value;
        return RouterId.FromBytes(bytes);
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _response;

        public CountingHandler(Func<HttpRequestMessage, HttpResponseMessage> response)
        {
            _response = response;
        }

        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(_response(request));
        }
    }

    private sealed class FixedClock : IClock
    {
        public FixedClock(DateTimeOffset now)
        {
            UtcNow = now;
        }

        public DateTimeOffset UtcNow { get; }
    }
}
