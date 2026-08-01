using XNode.Core;
using XNode.Core.Runtime;
using XNode.Transport.Vless;

namespace XNode.IntegrationTests.Runtime;

public sealed class LocalRelayContactProviderTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 22, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DisabledVless_WithValidPeerRpc_AdvertisesReachableSessionContactOnly()
    {
        var node = NodeOptions("http://xnode-1:8081/api/peer/onion");
        var provider = new LocalRelayContactProvider(
            node,
            new VlessTransportOptions { Enabled = false },
            new FixedClock(Now));

        var contact = provider.Create();

        Assert.True(contact.IsReachable);
        Assert.Equal("xnode-1", contact.PublicHost);
        Assert.Equal(8080, contact.PublicPort);
        Assert.Equal("http://xnode-1:8081/api/peer/onion", contact.RpcEndpoint);
        Assert.Contains("onion-v1", contact.Capabilities, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("session-rpc", contact.Capabilities, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("vless-ingress", contact.Capabilities, StringComparer.OrdinalIgnoreCase);
        Assert.True(RelayContactSigner.VerifyFresh(contact, Now));
    }

    [Fact]
    public void DisabledVless_WithInvalidPeerRpc_FailsClosed()
    {
        var provider = new LocalRelayContactProvider(
            NodeOptions("ftp://xnode-1:8081/api/peer/onion"),
            new VlessTransportOptions { Enabled = false },
            new FixedClock(Now));

        var error = Assert.Throws<InvalidOperationException>(provider.Create);

        Assert.Equal(
            "Node:PublicPeerRpcEndpoint must be an absolute http(s) URL with exact path '/api/peer/onion'.",
            error.Message);
    }

    [Fact]
    public void EnabledVless_PreservesVlessIngressAdvertisement()
    {
        var provider = new LocalRelayContactProvider(
            NodeOptions("https://xnode-1:8081/api/peer/onion"),
            new VlessTransportOptions
            {
                Enabled = true,
                PublicHost = "edge.example.org",
                PublicPort = 443
            },
            new FixedClock(Now));

        var contact = provider.Create();

        Assert.True(contact.IsReachable);
        Assert.Equal("edge.example.org", contact.PublicHost);
        Assert.Equal(443, contact.PublicPort);
        Assert.Contains("vless-ingress", contact.Capabilities, StringComparer.OrdinalIgnoreCase);
    }

    private static RouterNodeOptions NodeOptions(string peerEndpoint)
    {
        const string seed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        return new RouterNodeOptions
        {
            RouterId = RelayContactSigner.DeriveRouterId(seed).Value,
            Ed25519PrivateKey = seed,
            PublicHost = "xnode-1",
            PublicPort = 8080,
            PublicPeerRpcEndpoint = peerEndpoint
        };
    }

    private sealed class FixedClock(DateTimeOffset utcNow) : IClock
    {
        public DateTimeOffset UtcNow { get; } = utcNow;
    }
}
