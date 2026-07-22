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
        var allowed = PeerEndpointPolicy.TryValidateUri(
            new Uri(endpoint),
            allowLoopback: false,
            allowPrivate: false,
            out var error);

        Assert.False(allowed);
        Assert.Equal("blocked-onion-peer-endpoint", error);
    }

    [Fact]
    public void TryValidateUri_AllowsLoopbackOnlyWhenExplicitlyEnabled()
    {
        var endpoint = new Uri("http://127.0.0.1:8081/api/peer/onion");

        Assert.False(PeerEndpointPolicy.TryValidateUri(endpoint, allowLoopback: false, allowPrivate: false, out _));
        Assert.True(PeerEndpointPolicy.TryValidateUri(endpoint, allowLoopback: true, allowPrivate: false, out _));
    }

    [Theory]
    [InlineData("http://10.1.2.3:8081/api/peer/onion")]
    [InlineData("http://172.16.1.2:8081/api/peer/onion")]
    [InlineData("http://192.168.1.2:8081/api/peer/onion")]
    public void TryValidateUri_AllowsRfc1918OnlyWhenExplicitlyEnabled(string endpoint)
    {
        var uri = new Uri(endpoint);

        Assert.False(PeerEndpointPolicy.TryValidateUri(uri, allowLoopback: false, allowPrivate: false, out _));
        Assert.True(PeerEndpointPolicy.TryValidateUri(uri, allowLoopback: false, allowPrivate: true, out _));
    }

    [Theory]
    [InlineData("http://0.0.0.0:8081/api/peer/onion")]
    [InlineData("http://169.254.1.2:8081/api/peer/onion")]
    [InlineData("http://224.0.0.1:8081/api/peer/onion")]
    [InlineData("http://[fe80::1]:8081/api/peer/onion")]
    [InlineData("http://[ff02::1]:8081/api/peer/onion")]
    public void TryValidateUri_PrivateOptInStillRejectsUnsafeSpecialRanges(string endpoint)
    {
        Assert.False(PeerEndpointPolicy.TryValidateUri(
            new Uri(endpoint),
            allowLoopback: true,
            allowPrivate: true,
            out var error));
        Assert.Equal("blocked-onion-peer-endpoint", error);
    }

    [Fact]
    public void TryValidateUri_AllowsPubliclyRoutableAddress()
    {
        Assert.True(PeerEndpointPolicy.TryValidateUri(
            new Uri("https://8.8.8.8/api/peer/onion"),
            allowLoopback: false,
            allowPrivate: false,
            out _));
    }
}
