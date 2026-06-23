using System.Text.Json.Nodes;
using XNode.Transport.Vless;

namespace XNode.Tests.Transport;

public sealed class XrayConfigGenerationTests
{
    [Fact]
    public void XrayConfigGenerator_RendersVlessRealitySidecarConfig()
    {
        var options = Options();
        var json = new XrayConfigGenerator().Generate(options);
        var root = JsonNode.Parse(json)!.AsObject();

        var inbound = root["inbounds"]![0]!.AsObject();
        Assert.Equal("vless", inbound["protocol"]!.GetValue<string>());
        Assert.Equal(options.InboundListenPort, inbound["port"]!.GetValue<int>());
        Assert.Equal("reality", inbound["streamSettings"]!["security"]!.GetValue<string>());
        Assert.Equal(options.ClientId, inbound["settings"]!["clients"]![0]!["id"]!.GetValue<string>());

        var outbound = root["outbounds"]![0]!.AsObject();
        Assert.Equal("freedom", outbound["protocol"]!.GetValue<string>());
        Assert.Equal("127.0.0.1:8080", outbound["settings"]!["redirect"]!.GetValue<string>());
    }

    public static VlessTransportOptions Options()
    {
        return new VlessTransportOptions
        {
            PublicHost = "node.example.org",
            PublicPort = 443,
            InboundListenPort = 443,
            ApiIngressHost = "127.0.0.1",
            ApiIngressPort = 8080,
            ClientId = "11111111-1111-1111-1111-111111111111",
            MaskDomain = "www.microsoft.com",
            TransportMode = VlessTransportMode.Reality,
            Reality = new RealityMetadata
            {
                ServerName = "www.microsoft.com",
                PublicKey = "pub",
                PrivateKey = "priv",
                ShortId = "abcd",
                Fingerprint = "chrome",
                SpiderX = "/"
            }
        };
    }
}
