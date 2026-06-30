using XNode.Core;
using XNode.Registry;
using XNode.Registry.Bootstrap;
using XNode.Tests.Transport;

namespace XNode.Tests.Registry;

public sealed class ClientBootstrapTests
{
    [Fact]
    public void ClientBootstrap_IncludesAllTransportParameters()
    {
        var transport = XrayConfigGenerationTests.Options();
        var factory = new RegistryPayloadFactory(
            new RouterNodeOptions
            {
                RouterId = TestData.Id(1).Value,
                PublicHost = transport.PublicHost,
                PublicPort = transport.PublicPort
            },
            transport);

        var bootstrap = new ClientBootstrapService(factory, transport).Create();

        Assert.Equal("node.example.org", bootstrap.PublicHost);
        Assert.Equal(443, bootstrap.PublicPort);
        Assert.Contains("security=reality", bootstrap.VlessUri);
        Assert.Contains("sni=cloudflare-dns.com", bootstrap.VlessUri);
        Assert.Contains("pbk=pub", bootstrap.VlessUri);
        Assert.Equal("node.example.org", bootstrap.XrayOutbound["settings"]!["vnext"]![0]!["address"]!.GetValue<string>());
    }

    [Fact]
    public void ClientBootstrap_UsesConfiguredPublicPort()
    {
        var transport = XrayConfigGenerationTests.Options();
        transport.PublicPort = 8443;
        var factory = new RegistryPayloadFactory(
            new RouterNodeOptions
            {
                RouterId = TestData.Id(1).Value,
                PublicHost = transport.PublicHost,
                PublicPort = transport.PublicPort
            },
            transport);

        var bootstrap = new ClientBootstrapService(factory, transport).Create();

        Assert.Equal(8443, bootstrap.PublicPort);
        Assert.Contains("@node.example.org:8443?", bootstrap.VlessUri);
        Assert.Equal(8443, bootstrap.XrayOutbound["settings"]!["vnext"]![0]!["port"]!.GetValue<int>());
    }
}
