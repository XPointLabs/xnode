using System.Net;
using XNode.Core;

namespace XNode.Tests;

public sealed class QuorumCoordinatorAccessTests
{
    [Theory]
    [InlineData("111.235.151.150", "111.235.151.150/32")]
    [InlineData("172.20.0.12", "172.16.0.0/12,192.168.1.44")]
    [InlineData("::ffff:111.235.151.150", "111.235.151.150")]
    public void AllowsConfiguredCoordinator(string remote, string networks)
    {
        Assert.True(QuorumCoordinatorAccess.IsAllowed(IPAddress.Parse(remote), networks));
    }

    [Theory]
    [InlineData("111.235.151.151", "111.235.151.150/32")]
    [InlineData("10.0.0.2", "172.16.0.0/12")]
    [InlineData("127.0.0.1", "")]
    public void RejectsOtherSources(string remote, string networks)
    {
        Assert.False(QuorumCoordinatorAccess.IsAllowed(IPAddress.Parse(remote), networks));
    }

    [Fact]
    public void SigningEndpointRequiresPeerRpcListenerAndConfiguredCoordinator()
    {
        var coordinator = IPAddress.Parse("172.20.0.12");
        const string networks = "172.16.0.0/12";

        Assert.True(QuorumCoordinatorAccess.IsAllowed(
            localPort: 8081,
            peerRpcPort: 8081,
            coordinator,
            networks));
        Assert.False(QuorumCoordinatorAccess.IsAllowed(
            localPort: 8080,
            peerRpcPort: 8081,
            coordinator,
            networks));
        Assert.False(QuorumCoordinatorAccess.IsAllowed(
            localPort: 8081,
            peerRpcPort: 8081,
            IPAddress.Parse("203.0.113.9"),
            networks));
    }
}
