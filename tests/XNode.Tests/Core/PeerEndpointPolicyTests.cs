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
    [InlineData("http://169.254.169.254/api/peer/onion")]
    [InlineData("http://[fe80::1]/api/peer/onion")]
    public void PublicPolicy_RejectsNonPublicPeerEndpoints(string endpoint)
    {
        var allowed = PeerEndpointPolicy.PublicOnly().TryValidatePeerEndpoint(
            Id(1),
            new Uri(endpoint),
            out var error);

        Assert.False(allowed);
        Assert.Equal("blocked-onion-peer-endpoint", error);
    }

    [Fact]
    public void PublicPolicy_AlwaysRejectsLoopback()
    {
        var endpoint = new Uri("http://127.0.0.1:8081/api/peer/onion");

        Assert.False(PeerEndpointPolicy.PublicOnly().TryValidatePeerEndpoint(Id(1), endpoint, out _));
    }

    [Fact]
    public void PublicPolicy_AllowsPubliclyRoutableAddress()
    {
        Assert.True(PeerEndpointPolicy.PublicOnly().TryValidatePeerEndpoint(
            Id(1),
            new Uri("https://8.8.8.8/api/peer/onion"),
            out _));
    }

    [Theory]
    [InlineData("64:ff9b::a00:1")]
    [InlineData("64:ff9b:1::a00:1")]
    [InlineData("2001::1")]
    [InlineData("2001:2::1")]
    [InlineData("2001:10::1")]
    [InlineData("2001:20::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2002:a00:1::1")]
    [InlineData("3fff::1")]
    public void PublicPolicy_RejectsIpv6SpecialPurposeAndTransitionRanges(string address)
    {
        var endpoint = new Uri($"https://[{address}]/api/peer/onion");

        Assert.False(PeerEndpointPolicy.PublicOnly().TryValidatePeerEndpoint(Id(1), endpoint, out _));
        Assert.False(PeerEndpointPolicy.PublicOnly().IsResolvedAddressAllowed(
            Id(1),
            endpoint,
            IPAddress.Parse(address)));
    }

    [Fact]
    public void PublicPolicy_AllowsAssignedGlobalUnicastIpv6()
    {
        var endpoint = new Uri("https://[2606:4700:4700::1111]/api/peer/onion");

        Assert.True(PeerEndpointPolicy.PublicOnly().TryValidatePeerEndpoint(Id(1), endpoint, out _));
    }

    [Fact]
    public void ProductionPublicEndpoint_RequiresHttpsAllowedPortAndOwnershipProof()
    {
        var options = new RouterRuntimeOptions();
        var node = new RouterNodeOptions { Network = "mainnet" };
        var denied = PeerEndpointPolicy.Create(
            options,
            node,
            "Production",
            DenyAllPublicPeerEndpointAuthorizer.Instance);
        var allowed = PeerEndpointPolicy.Create(
            options,
            node,
            "Production",
            TestProductionPublicPeerEndpointAuthorizer.Instance);
        var router = Id(9);

        Assert.False(denied.TryValidatePeerEndpoint(
            router,
            new Uri("https://8.8.8.8/api/peer/onion"),
            out var proofError));
        Assert.Equal("unverified-onion-peer-endpoint", proofError);
        Assert.Equal(PublicPeerAuthorizationMode.DenyAll, denied.PublicAuthorizationMode);
        Assert.False(denied.PrivateAllowlistActsAsMembership);
        Assert.Empty(denied.PrivateMembershipRouterIds);
        Assert.False(denied.IsProductionPublicRoutingReady);
        Assert.False(denied.IsResolvedAddressAllowed(
            router,
            new Uri("https://peer.example/api/peer/onion"),
            IPAddress.Parse("8.8.8.8")));
        Assert.True(allowed.TryValidatePeerEndpoint(
            router,
            new Uri("https://8.8.8.8/api/peer/onion"),
            out _));
        Assert.Equal(PublicPeerAuthorizationMode.VerifiedTickets, allowed.PublicAuthorizationMode);
        Assert.True(allowed.IsProductionPublicRoutingReady);
        Assert.True(allowed.IsResolvedAddressAllowed(
            router,
            new Uri("https://peer.example/api/peer/onion"),
            IPAddress.Parse("8.8.8.8")));
        Assert.False(allowed.TryValidatePeerEndpoint(
            router,
            new Uri("http://8.8.8.8/api/peer/onion"),
            out _));
        Assert.False(allowed.TryValidatePeerEndpoint(
            router,
            new Uri("https://8.8.8.8:8443/api/peer/onion"),
            out _));
    }

    [Fact]
    public void ProductionPublicEndpoint_RejectsGenericAllowAllAuthorizer()
    {
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            new RouterRuntimeOptions(),
            new RouterNodeOptions { Network = "mainnet" },
            "Production",
            AllowAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Fact]
    public void ProductionPublicEndpoint_UsesExplicitAllowedPortSet()
    {
        var options = new RouterRuntimeOptions { ProductionPublicPeerPorts = [443, 8443] };
        var policy = PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "mainnet" },
            "Production",
            TestProductionPublicPeerEndpointAuthorizer.Instance);

        Assert.True(policy.TryValidatePeerEndpoint(
            Id(9),
            new Uri("https://8.8.8.8:8443/api/peer/onion"),
            out _));
    }

    [Fact]
    public void ProductionPublicEndpoint_RejectsInvalidAllowedPortConfiguration()
    {
        var options = new RouterRuntimeOptions { ProductionPublicPeerPorts = [443, 443] };

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "mainnet" },
            "Production",
            TestProductionPublicPeerEndpointAuthorizer.Instance));
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

    [Fact]
    public void PrivateOnlyUatPolicy_AllowsExactTupleAndRejectsPublicPeers()
    {
        var recipient = Id(2);
        var policy = PeerEndpointPolicy.Create(
            UatOptions(recipient, "10.20.30.40", 8081),
            new RouterNodeOptions { Network = "uat" },
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance);

        Assert.True(policy.TryValidatePeerEndpoint(
            recipient,
            new Uri("http://10.20.30.40:8081/api/peer/onion"),
            out _));
        Assert.False(policy.TryValidatePeerEndpoint(
            Id(3),
            new Uri("https://8.8.8.8/api/peer/onion"),
            out var publicError));
        Assert.Equal("unverified-onion-peer-endpoint", publicError);
        Assert.Equal(PublicPeerAuthorizationMode.DenyAll, policy.PublicAuthorizationMode);
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
            "Staging",
            AllowAllPublicPeerEndpointAuthorizer.Instance));
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
            environment,
            AllowAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Fact]
    public void DisabledPolicy_RejectsDormantAllowlistConfiguration()
    {
        var options = UatOptions(Id(2), "10.20.30.40", 8081);
        options.EnablePrivatePeerEndpoints = false;

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "uat" },
            "Staging",
            AllowAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Fact]
    public void RuntimePolicy_RejectsLegacyLoopbackException()
    {
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            new RouterRuntimeOptions { AllowLoopbackPeerEndpoints = true },
            new RouterNodeOptions { Network = "development" },
            "Development",
            AllowAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Fact]
    public void PrivateMembership_RequiresPrivateOnlySignedDenyAllComposition()
    {
        var recipient = Id(2);
        var node = new RouterNodeOptions { Network = "uat", RouterId = recipient.Value };

        var privateDisabled = PrivateMembershipOptions(recipient);
        privateDisabled.EnablePrivatePeerEndpoints = false;
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            privateDisabled,
            node,
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        var publicEnabled = PrivateMembershipOptions(recipient);
        publicEnabled.AllowPublicPeerEndpoints = true;
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            publicEnabled,
            node,
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        var unsigned = PrivateMembershipOptions(recipient);
        unsigned.RequireSignedRelayContacts = false;
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            unsigned,
            node,
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            PrivateMembershipOptions(recipient),
            node,
            "UAT",
            AllowAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Fact]
    public void PrivateMembership_RequiresMatchingNonProductionIdentityAndLocalTuple()
    {
        var local = Id(2);
        var options = PrivateMembershipOptions(local);

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "uat", RouterId = local.Value },
            "Production",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        var wrongNetwork = PrivateMembershipOptions(local);
        wrongNetwork.PrivatePeerNetworkIdentity = "testnet";
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            wrongNetwork,
            new RouterNodeOptions { Network = "uat", RouterId = local.Value },
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            PrivateMembershipOptions(Id(3)),
            new RouterNodeOptions { Network = "uat", RouterId = local.Value },
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Fact]
    public void PrivateMembership_RequiresOneUniqueEndpointPerRouter()
    {
        var local = Id(2);
        var duplicateRouter = PrivateMembershipOptions(local);
        duplicateRouter.PrivatePeerEndpointAllowlist[1].RouterId = local.Value;
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            duplicateRouter,
            new RouterNodeOptions { Network = "uat", RouterId = local.Value },
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        var duplicateEndpoint = PrivateMembershipOptions(local);
        duplicateEndpoint.PrivatePeerEndpointAllowlist[1].IpAddress =
            duplicateEndpoint.PrivatePeerEndpointAllowlist[0].IpAddress;
        duplicateEndpoint.PrivatePeerEndpointAllowlist[1].Port =
            duplicateEndpoint.PrivatePeerEndpointAllowlist[0].Port;
        Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            duplicateEndpoint,
            new RouterNodeOptions { Network = "uat", RouterId = local.Value },
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public void PrivateMembership_RequiresExactlyThreeRouters(int routerCount)
    {
        var local = Id(2);
        var options = PrivateMembershipOptions(local);
        if (routerCount < RouterRuntimeOptions.PrivateAllowlistMembershipRelayCount)
        {
            options.PrivatePeerEndpointAllowlist.RemoveRange(
                routerCount,
                options.PrivatePeerEndpointAllowlist.Count - routerCount);
        }
        else
        {
            options.PrivatePeerEndpointAllowlist.Add(new PrivatePeerEndpointAllowlistEntry
            {
                RouterId = Id(252).Value,
                IpAddress = "10.20.30.43",
                Port = 8084,
                Path = PeerEndpointPolicy.OnionPeerPath
            });
        }

        var error = Assert.Throws<InvalidOperationException>(() => PeerEndpointPolicy.Create(
            options,
            new RouterNodeOptions { Network = "uat", RouterId = local.Value },
            "UAT",
            DenyAllPublicPeerEndpointAuthorizer.Instance));

        Assert.Contains("requires exactly 3 routers", error.Message);
    }

    private static PeerEndpointPolicy CreateUatPolicy(RouterId recipient, string ipAddress, int port) =>
        PeerEndpointPolicy.Create(
            UatOptions(recipient, ipAddress, port),
            new RouterNodeOptions { Network = "uat" },
            "UAT",
            AllowAllPublicPeerEndpointAuthorizer.Instance);

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

    private static RouterRuntimeOptions PrivateMembershipOptions(RouterId local) =>
        new()
        {
            EnablePrivatePeerEndpoints = true,
            EnablePrivateAllowlistMembership = true,
            PrivatePeerNetworkIdentity = "uat",
            AllowPublicPeerEndpoints = false,
            RequireSignedRelayContacts = true,
            PrivatePeerEndpointAllowlist =
            [
                new PrivatePeerEndpointAllowlistEntry
                {
                    RouterId = local.Value,
                    IpAddress = "10.20.30.40",
                    Port = 8081,
                    Path = PeerEndpointPolicy.OnionPeerPath
                },
                new PrivatePeerEndpointAllowlistEntry
                {
                    RouterId = Id(250).Value,
                    IpAddress = "10.20.30.41",
                    Port = 8082,
                    Path = PeerEndpointPolicy.OnionPeerPath
                },
                new PrivatePeerEndpointAllowlistEntry
                {
                    RouterId = Id(251).Value,
                    IpAddress = "10.20.30.42",
                    Port = 8083,
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

    private sealed class TestProductionPublicPeerEndpointAuthorizer
        : IProductionPublicPeerEndpointAuthorizer
    {
        public static TestProductionPublicPeerEndpointAuthorizer Instance { get; } = new();

        public PublicPeerAuthorizationMode Mode =>
            PublicPeerAuthorizationMode.VerifiedTickets;

        public bool IsAuthorized(RouterId routerId, Uri endpoint) => true;

        public bool IsResolvedAddressAuthorized(
            RouterId routerId,
            Uri endpoint,
            IPAddress resolvedAddress) => true;
    }
}
