using System.Net;
using XNode.Core;
using XNode.Core.Runtime;

namespace XNode.Tests.Core;

public sealed class PeerEndpointPolicyTests
{
    [Theory]
    [InlineData("http://127.0.0.1:8081/api/peer/onion")]
    [InlineData("http://10.1.2.3:8081/api/peer/onion")]
    [InlineData("http://172.16.1.2:8081/api/peer/onion")]
    [InlineData("http://192.168.1.2:8081/api/peer/onion")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("http://[fe80::1]/api/peer/onion")]
    public void TryValidateUri_RejectsNonPublicPeerEndpoints(string endpoint)
    {
        var allowed = PeerEndpointPolicy.TryValidateUri(new Uri(endpoint), allowLoopback: false, out var error);

        Assert.False(allowed);
        Assert.Equal("blocked-onion-peer-endpoint", error);
    }

    [Fact]
    public void TryValidateUri_AllowsLoopbackOnlyWhenExplicitlyEnabled()
    {
        var endpoint = new Uri("http://127.0.0.1:8081/api/peer/onion");

        Assert.False(PeerEndpointPolicy.TryValidateUri(endpoint, allowLoopback: false, out _));
        Assert.True(PeerEndpointPolicy.TryValidateUri(endpoint, allowLoopback: true, out _));
    }

    [Fact]
    public void TryValidateUri_AllowsPubliclyRoutableAddress()
    {
        Assert.True(PeerEndpointPolicy.TryValidateUri(
            new Uri("https://8.8.8.8/api/peer/onion"),
            allowLoopback: false,
            out _));
    }

    [Fact]
    public void ExactPrivateTuple_IsAllowedForItsBoundRouterOnly()
    {
        var recipient = Id(2);
        var policy = CreateUatPolicy(recipient, "10.20.30.40", 8081);
        var endpoint = new Uri("http://10.20.30.40:8081/api/peer/onion");

        Assert.True(policy.TryValidatePeerEndpoint(recipient, endpoint, out _));
        Assert.True(policy.IsResolvedAddressAllowed(recipient, endpoint, IPAddress.Parse("10.20.30.40")));
        Assert.False(policy.TryValidatePeerEndpoint(Id(3), endpoint, out var wrongRouterError));
        Assert.Equal("blocked-onion-peer-endpoint", wrongRouterError);
    }

    [Theory]
    [InlineData("http://10.20.30.41:8081/api/peer/onion")]
    [InlineData("http://10.20.30.40:8082/api/peer/onion")]
    [InlineData("http://10.20.30.40:8081/api/peer/onion/")]
    [InlineData("http://10.20.30.40:8081/api/peer/onion?next=1")]
    public void ExactPrivateTuple_RejectsNeighborPortPathAndQueryMismatches(string endpoint)
    {
        var recipient = Id(2);
        var policy = CreateUatPolicy(recipient, "10.20.30.40", 8081);

        Assert.False(policy.TryValidatePeerEndpoint(recipient, new Uri(endpoint), out _));
    }

    [Fact]
    public void HostnameResolvingPrivate_CannotClaimLiteralPrivateException()
    {
        var recipient = Id(2);
        var policy = CreateUatPolicy(recipient, "10.20.30.40", 8081);
        var endpoint = new Uri("http://peer.internal:8081/api/peer/onion");

        Assert.True(policy.TryValidatePeerEndpoint(recipient, endpoint, out _));
        Assert.False(policy.IsResolvedAddressAllowed(recipient, endpoint, IPAddress.Parse("10.20.30.40")));
    }

    [Fact]
    public void PublicHostnameRebindingToPrivate_IsBlockedAtConnectDecision()
    {
        var recipient = Id(2);
        var policy = CreateUatPolicy(recipient, "10.20.30.40", 8081);
        var endpoint = new Uri("https://peer.example.test:8081/api/peer/onion");

        Assert.True(policy.TryValidatePeerEndpoint(recipient, endpoint, out _));
        Assert.True(policy.IsResolvedAddressAllowed(recipient, endpoint, IPAddress.Parse("8.8.8.8")));
        Assert.False(policy.IsResolvedAddressAllowed(recipient, endpoint, IPAddress.Parse("10.20.30.40")));
    }

    [Fact]
    public void CloudMetadataAddress_RemainsBlockedAndCannotBeAllowlisted()
    {
        var recipient = Id(2);
        var policy = CreateUatPolicy(recipient, "10.20.30.40", 8081);

        Assert.False(policy.TryValidatePeerEndpoint(
            recipient,
            new Uri("http://169.254.169.254:80/api/peer/onion"),
            out var error));
        Assert.Equal("blocked-onion-peer-endpoint", error);

        var options = UatOptions(recipient, "169.254.169.254", 80);
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "uat" },
            "Staging"));
    }

    [Theory]
    [InlineData("Production", "uat", "uat")]
    [InlineData("Development", "mainnet", "mainnet")]
    [InlineData("Development", "testnet", "uat")]
    public void PrivateExceptions_FailClosedOutsideMatchingNonProductionTestIdentity(
        string environment,
        string nodeNetwork,
        string configuredNetwork)
    {
        var recipient = Id(2);
        var options = UatOptions(recipient, "10.20.30.40", 8081);
        options.PrivatePeerNetworkIdentity = configuredNetwork;

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = nodeNetwork },
            environment));
    }

    [Fact]
    public void DisabledPolicy_RejectsDormantAllowlistConfiguration()
    {
        var options = UatOptions(Id(2), "10.20.30.40", 8081);
        options.EnablePrivatePeerEndpoints = false;

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "uat" },
            "Staging"));
    }

    [Fact]
    public void RuntimePolicy_RejectsLegacyLoopbackException()
    {
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            new RouterRuntimeOptions { AllowLoopbackPeerEndpoints = true },
            new RouterNodeOptions { Network = "development" },
            "Development"));
    }

    private static PeerEndpointPolicy CreateUatPolicy(RouterId recipient, string ipAddress, int port) =>
        PeerEndpointPolicy.Create(
            UatOptions(recipient, ipAddress, port),
            new RouterNodeOptions { Network = "uat" },
            "UAT");

    private static RouterRuntimeOptions UatOptions(RouterId recipient, string ipAddress, int port) =>
        new()
        {
            EnablePrivatePeerEndpoints = true,
            PrivatePeerNetworkIdentity = "uat",
            PrivatePeerEndpointAllowlist =
            [
                new PrivatePeerEndpointAllowlistEntry
                {
                    RouterId = recipient.Value,
                    IpAddress = ipAddress,
                    Port = port,
                    Path = PeerEndpointPolicy.OnionPeerPath
                }
            ]
        };

    private static RouterId Id(byte value)
    {
        var bytes = new byte[RouterId.ByteLength];
        bytes[^1] = value;
        return RouterId.FromBytes(bytes);
    }
}
