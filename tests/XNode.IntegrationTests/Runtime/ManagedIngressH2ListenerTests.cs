using System.Net;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Primitives;
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
        Assert.Empty(node.ManagedIngressTrustedProxyAddresses);
        Assert.Null(plan.ManagedIngress);
        Assert.Empty(plan.ManagedIngressTrustedProxyAddresses);
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
            ManagedIngressH2ListenUrl = $"http://127.0.0.1:{managedIngressPort}",
            ManagedIngressTrustedProxyAddresses = ["127.0.0.1"]
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
        app.UseManagedIngressProxyTrustBoundary(plan);
        app.MapGet("/protocol", (HttpContext context) => string.Join(
            '|',
            context.Request.Protocol,
            context.Request.Scheme,
            context.Request.Headers["X-Forwarded-Proto"].Count));
        await app.StartAsync();

        try
        {
            using var client = new HttpClient(new SocketsHttpHandler());
            Assert.Equal(
                "HTTP/1.1|http|0",
                await client.GetStringAsync($"http://127.0.0.1:{apiPort}/protocol"));
            Assert.Equal(
                "HTTP/1.1|http|0",
                await client.GetStringAsync($"http://127.0.0.1:{peerPort}/protocol"));

            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"http://127.0.0.1:{managedIngressPort}/protocol")
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact
            };
            request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            using var response = await client.SendAsync(request);

            response.EnsureSuccessStatusCode();
            Assert.Equal(HttpVersion.Version20, response.Version);
            Assert.Equal("HTTP/2|https|0", await response.Content.ReadAsStringAsync());
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

    [Fact]
    public void DedicatedListener_RejectsEmptyTrustedProxyList()
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            NodeListenerConfiguration.Create(new RouterNodeOptions
            {
                ManagedIngressH2ListenUrl = "http://127.0.0.1:8082/"
            }));

        Assert.Contains(
            "must contain at least one exact IP address",
            error.Message,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("haproxy")]
    [InlineData("1")]
    [InlineData("0172.30.82.7")]
    [InlineData("172.30.82.0/24")]
    [InlineData(" 172.30.82.7")]
    [InlineData("172.30.82.7 ")]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("fe80::1%12")]
    public void DedicatedListener_RejectsMalformedOrNonLiteralTrustedProxy(
        string value)
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            NodeListenerConfiguration.Create(new RouterNodeOptions
            {
                ManagedIngressH2ListenUrl = "http://127.0.0.1:8082/",
                ManagedIngressTrustedProxyAddresses = [value]
            }));

        Assert.Contains(
            "IPv4 or IPv6 literals",
            error.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void DedicatedListener_RejectsDuplicateTrustedProxyAddresses()
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            NodeListenerConfiguration.Create(new RouterNodeOptions
            {
                ManagedIngressH2ListenUrl = "http://127.0.0.1:8082/",
                ManagedIngressTrustedProxyAddresses =
                [
                    "2001:db8::7",
                    "2001:0db8:0:0:0:0:0:7"
                ]
            }));

        Assert.Contains("must not contain duplicate", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DedicatedListener_AcceptsExactHaproxyAndChaosAddresses()
    {
        var plan = NodeListenerConfiguration.Create(new RouterNodeOptions
        {
            ManagedIngressH2ListenUrl = "http://127.0.0.1:8082/",
            ManagedIngressTrustedProxyAddresses = ["172.30.82.7", "172.30.82.8"]
        });

        Assert.Equal(2, plan.ManagedIngressTrustedProxyAddresses.Count);
        Assert.Contains(IPAddress.Parse("172.30.82.7"), plan.ManagedIngressTrustedProxyAddresses);
        Assert.Contains(IPAddress.Parse("172.30.82.8"), plan.ManagedIngressTrustedProxyAddresses);
    }

    [Fact]
    public async Task TrustBoundary_RejectsUnknownProxyAsNotFoundWithoutDispatch()
    {
        var plan = CreateTrustBoundaryPlan();
        var context = CreateContext(plan, "172.30.82.9", "https");
        var dispatched = false;

        await ManagedIngressProxyTrustBoundary.InvokeAsync(
            context,
            _ =>
            {
                dispatched = true;
                return Task.CompletedTask;
            },
            plan);

        Assert.False(dispatched);
        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("http")]
    [InlineData("HTTPS")]
    [InlineData("https,http")]
    [InlineData(" https")]
    public async Task TrustBoundary_RejectsMissingOrNonExactForwardedProto(
        string? forwardedProto)
    {
        var plan = CreateTrustBoundaryPlan();
        var context = CreateContext(plan, "172.30.82.7", forwardedProto);
        var dispatched = false;

        await ManagedIngressProxyTrustBoundary.InvokeAsync(
            context,
            _ =>
            {
                dispatched = true;
                return Task.CompletedTask;
            },
            plan);

        Assert.False(dispatched);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    [Fact]
    public async Task TrustBoundary_RejectsDuplicateForwardedProtoValues()
    {
        var plan = CreateTrustBoundaryPlan();
        var context = CreateContext(plan, "172.30.82.7", null);
        context.Request.Headers["X-Forwarded-Proto"] = new StringValues(["https", "https"]);
        var dispatched = false;

        await ManagedIngressProxyTrustBoundary.InvokeAsync(
            context,
            _ =>
            {
                dispatched = true;
                return Task.CompletedTask;
            },
            plan);

        Assert.False(dispatched);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    [Fact]
    public async Task TrustBoundary_TrustsExactProxySetsHttpsAndConsumesHeader()
    {
        var plan = CreateTrustBoundaryPlan();
        var context = CreateContext(plan, "172.30.82.8", "https");
        var dispatched = false;

        await ManagedIngressProxyTrustBoundary.InvokeAsync(
            context,
            nextContext =>
            {
                dispatched = true;
                Assert.Equal("https", nextContext.Request.Scheme);
                Assert.False(nextContext.Request.Headers.ContainsKey("X-Forwarded-Proto"));
                return Task.CompletedTask;
            },
            plan);

        Assert.True(dispatched);
    }

    [Theory]
    [InlineData(8080)]
    [InlineData(8081)]
    public async Task TrustBoundary_DoesNotTrustOrChangeHeadersOnApiOrPeer(int localPort)
    {
        var plan = CreateTrustBoundaryPlan();
        var context = CreateContext(plan, "203.0.113.10", null);
        context.Connection.LocalPort = localPort;
        context.Request.Headers["X-Forwarded-Proto"] = new StringValues(["http", "https"]);
        var dispatched = false;

        await ManagedIngressProxyTrustBoundary.InvokeAsync(
            context,
            nextContext =>
            {
                dispatched = true;
                Assert.Equal("http", nextContext.Request.Scheme);
                Assert.Equal(2, nextContext.Request.Headers["X-Forwarded-Proto"].Count);
                return Task.CompletedTask;
            },
            plan);

        Assert.True(dispatched);
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
            ManagedIngressH2ListenUrl = value,
            ManagedIngressTrustedProxyAddresses = ["127.0.0.1"]
        });

        Assert.Equal(expected, plan.ManagedIngress?.BindKind.ToString());
    }

    private static NodeListenerPlan CreateTrustBoundaryPlan() =>
        NodeListenerConfiguration.Create(new RouterNodeOptions
        {
            ManagedIngressH2ListenUrl = "http://127.0.0.1:8082/",
            ManagedIngressTrustedProxyAddresses = ["172.30.82.7", "172.30.82.8"]
        });

    private static DefaultHttpContext CreateContext(
        NodeListenerPlan plan,
        string remoteAddress,
        string? forwardedProto)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = plan.ManagedIngressPort;
        context.Connection.RemoteIpAddress = IPAddress.Parse(remoteAddress);
        context.Request.Scheme = Uri.UriSchemeHttp;
        if (forwardedProto is not null)
        {
            context.Request.Headers["X-Forwarded-Proto"] = forwardedProto;
        }

        return context;
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
