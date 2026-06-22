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
        Assert.Contains("sni=www.microsoft.com", bootstrap.VlessUri);
        Assert.Contains("pbk=pub", bootstrap.VlessUri);
        Assert.Equal("node.example.org", bootstrap.XrayOutbound["settings"]!["vnext"]![0]!["address"]!.GetValue<string>());
    }
}
