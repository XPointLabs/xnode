using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

public sealed class ManagedIngressH2ListenerTests
{
    [Fact]
    public void DefaultConfiguration_KeepsDedicatedListenerDisabled()
    {
        var node = new RouterNodeOptions();

        var plan = NodeListenerConfiguration.Create(node);

        Assert.Equal("", node.ManagedIngressH2ListenUrl);
        Assert.Null(plan.ManagedIngress);
        Assert.Equal(HttpProtocols.Http1AndHttp2, plan.Api.Protocols);
        Assert.Equal(HttpProtocols.Http1AndHttp2, plan.Peer.Protocols);
        Assert.Equal(new Uri(node.ApiListenUrl).Port, plan.ManagedIngressPort);
    }

    [Fact]
    public async Task SeparateH2cListener_AcceptsExactHttp2WhileApiAndPeerAcceptHttp1()
    {
        var apiPort = ReservePort();
        var peerPort = ReservePort(apiPort);
        var managedIngressPort = ReservePort(apiPort, peerPort);
        var node = new RouterNodeOptions
        {
            ApiListenUrl = $"http://127.0.0.1:{apiPort}",
            PeerRpcListenUrl = $"http://127.0.0.1:{peerPort}",
            ManagedIngressH2ListenUrl = $"http://127.0.0.1:{managedIngressPort}"
        };
        var plan = NodeListenerConfiguration.Create(node);

        Assert.NotNull(plan.ManagedIngress);
        Assert.Equal(HttpProtocols.Http2, plan.ManagedIngress.Protocols);
        Assert.Equal(NodeListenerBindKind.Address, plan.ManagedIngress.BindKind);
        Assert.Equal(IPAddress.Loopback, plan.ManagedIngress.Address);
        Assert.Equal(apiPort, plan.Api.Url.Port);
        Assert.Equal(managedIngressPort, plan.ManagedIngressPort);
        Assert.NotEqual(plan.Api.Url.Port, plan.ManagedIngressPort);

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(plan.Configure);
        await using var app = builder.Build();
        app.MapGet("/protocol", (HttpContext context) => context.Request.Protocol);
        await app.StartAsync();

        try
        {
            using var client = new HttpClient(new SocketsHttpHandler());
            Assert.Equal(
                "HTTP/1.1",
                await client.GetStringAsync($"http://127.0.0.1:{apiPort}/protocol"));
            Assert.Equal(
                "HTTP/1.1",
                await client.GetStringAsync($"http://127.0.0.1:{peerPort}/protocol"));

            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"http://127.0.0.1:{managedIngressPort}/protocol")
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            using var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();
            Assert.Equal(HttpVersion.Version20, response.Version);
            Assert.Equal("HTTP/2", await response.Content.ReadAsStringAsync());
        }
        finally
        {
            await app.StopAsync();
        }
    }

    [Fact]
    public void HostWiring_KeepsVlessOnApiAndManagedIngressOnDedicatedPort()
    {
        var source = File.ReadAllText(Path.Combine(
            FindRepositoryRoot(),
            "src",
            "XNode",
            "Program.cs"));

        Assert.Contains("vlessOptions.ApiIngressPort = apiListenUri.Port;", source);
        Assert.DoesNotContain(
            "vlessOptions.ApiIngressPort = listenerPlan.ManagedIngressPort;",
            source);
        Assert.Equal(
            2,
            source.Split("listenerPlan.ManagedIngressPort", StringSplitOptions.None).Length - 1);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("http://127.0.0.1:8081")]
    public void DedicatedListener_RejectsApiOrPeerPortCollision(string value)
    {
        var node = new RouterNodeOptions
        {
            ManagedIngressH2ListenUrl = value
        };

        var error = Assert.Throws<InvalidOperationException>(() =>
            NodeListenerConfiguration.Create(node));

        Assert.Contains("must use different ports", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("localhost:8082")]
    [InlineData("ftp://127.0.0.1:8082/")]
    [InlineData("http://user@127.0.0.1:8082/")]
    [InlineData("http://127.0.0.1:8082/ingress")]
    [InlineData("http://127.0.0.1:8082/?query=1")]
    [InlineData("http://127.0.0.1:8082/#fragment")]
    [InlineData(" http://127.0.0.1:8082/")]
    [InlineData("http://127.0.0.1:8082/ ")]
    public void DedicatedListener_RejectsMalformedOrNonCanonicalUrl(string value)
    {
        var node = new RouterNodeOptions
        {
            ManagedIngressH2ListenUrl = value
        };

        var error = Assert.Throws<InvalidOperationException>(() =>
            NodeListenerConfiguration.Create(node));

        Assert.Contains(
            "must be an absolute canonical HTTP(S) origin URL",
            error.Message,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://localhost:8082/", "Localhost")]
    [InlineData("http://10.0.0.8:8082/", "Address")]
    [InlineData("http://xnode-internal:8082/", "AnyIp")]
    public void DedicatedListener_PreservesUseUrlsBindHostSemantics(
        string value,
        string expected)
    {
        var plan = NodeListenerConfiguration.Create(new RouterNodeOptions
        {
            ManagedIngressH2ListenUrl = value
        });

        Assert.Equal(expected, plan.ManagedIngress?.BindKind.ToString());
    }

    private static int ReservePort(params int[] excluded)
    {
        while (true)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            if (!excluded.Contains(port))
            {
                return port;
            }
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate the XNode repository root.");
    }
}
