using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;

namespace XNode.IntegrationTests.Runtime;

// Resource tests only: fake handlers never stand in for authenticated routing
// or release E2E. ForwardAsync still requires the real Protocol capabilities.
public sealed class PrivacyPeerHttpPoolTests
{
    [Fact]
    public async Task RealTlsH2RequestsReuseOneConnectionAndOnePinnedHandshake()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using var issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
        var pfx = issued.Export(X509ContentType.Pfx);
        X509Certificate2 certificate;
        try { certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.DefaultKeySet); }
        finally { CryptographicOperations.ZeroMemory(pfx); }
        using var certificateOwner = certificate;
        var pin = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());
        var builder = WebApplication.CreateBuilder(); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
            endpoint => { endpoint.Protocols = HttpProtocols.Http2; endpoint.UseHttps(certificate); }));
        await using var app = builder.Build();
        app.Run(context => context.Response.WriteAsync(context.Connection.Id));
        await app.StartAsync();
        using var pool = new PrivacyPeerHttpPool(); var network = new object(); var handshakes = 0;
        HttpClient Create(Action<DateTime, DateTime> validity)
        {
            var handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false, UseCookies = false };
            handler.SslOptions.AllowTlsResume = false;
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, errors) =>
            {
                if (!HttpPrivacyPeerClient.ValidatePinnedCertificate(cert, errors, pin)) return false;
                Interlocked.Increment(ref handshakes); validity(((X509Certificate2)cert!).NotBefore, ((X509Certificate2)cert).NotAfter); return true;
            };
            return new(handler) { BaseAddress = new Uri(app.Urls.Single()) };
        }
        async Task<string> Send()
        {
            using var lease = pool.Borrow(network, "exact-test-view-hop", Create);
            using var message = new HttpRequestMessage(HttpMethod.Get, "/")
            { Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
            using var response = await lease.Client.SendAsync(message);
            response.EnsureSuccessStatusCode(); Assert.Equal(HttpVersion.Version20, response.Version);
            Assert.True(lease.CertificateCurrent); return await response.Content.ReadAsStringAsync();
        }
        Assert.Equal(await Send(), await Send()); Assert.Equal(1, handshakes);
        await app.StopAsync();
    }
    [Fact]
    public void ExactNetworkAndBindingReuseButDifferentViewOrHopDoNot()
    {
        using var pool = new PrivacyPeerHttpPool();
        var network = new object(); var created = 0;
        HttpClient Create(Action<DateTime, DateTime> _) { created++; return new(new TrackingHandler()); }
        using var first = pool.Borrow(network, "exact-hop", Create);
        using var same = pool.Borrow(network, "exact-hop", Create);
        using var newView = pool.Borrow(new object(), "exact-hop", Create);
        using var newHop = pool.Borrow(network, "changed-pin-or-address", Create);
        Assert.Same(first.Client, same.Client);
        Assert.NotSame(first.Client, newView.Client); Assert.NotSame(first.Client, newHop.Client);
        Assert.Equal(3, created);
    }

    [Fact]
    public void ExpiredPoolDrainsActiveRequestInsteadOfCancellingIt()
    {
        var clock = new Clock(); using var pool = new PrivacyPeerHttpPool(clock);
        var network = new object(); var handlers = new List<TrackingHandler>();
        HttpClient Create(Action<DateTime, DateTime> _) { var h = new TrackingHandler(); handlers.Add(h); return new(h); }
        using var first = pool.Borrow(network, "hop", Create);
        clock.Advance(PrivacyPeerHttpPool.Lifetime);
        using var second = pool.Borrow(network, "hop", Create);
        Assert.NotSame(first.Client, second.Client); Assert.False(handlers[0].Disposed);
        first.Dispose(); Assert.True(handlers[0].Disposed); Assert.False(handlers[1].Disposed);
        pool.Dispose(); Assert.False(handlers[1].Disposed);
        second.Dispose(); Assert.True(handlers[1].Disposed);
        Assert.Throws<ObjectDisposedException>(() => pool.Borrow(network, "hop", Create));
    }

    [Fact]
    public void CapacityUsesOneShotWithoutEvictingActiveDispatch()
    {
        using var pool = new PrivacyPeerHttpPool(capacity: 1); var network = new object();
        var handlers = new List<TrackingHandler>();
        HttpClient Create(Action<DateTime, DateTime> _) { var h = new TrackingHandler(); handlers.Add(h); return new(h); }
        using var first = pool.Borrow(network, "first", Create);
        using var full = pool.Borrow(network, "second", Create);
        using var same = pool.Borrow(network, "first", Create);
        Assert.Same(first.Client, same.Client); Assert.False(handlers[0].Disposed);
        full.Dispose(); Assert.True(handlers[1].Disposed);
        using var next = pool.Borrow(network, "second", Create);
        Assert.NotSame(full.Client, next.Client); Assert.Equal(3, handlers.Count);
    }

    [Fact]
    public void CertificateExpiryIsCheckedOnReuseAndCannotBeExtendedByAnotherHandshake()
    {
        var clock = new Clock(); using var pool = new PrivacyPeerHttpPool(clock); var network = new object();
        Action<DateTime, DateTime>? record = null;
        HttpClient Create(Action<DateTime, DateTime> callback) { record = callback; return new(new TrackingHandler()); }
        using var first = pool.Borrow(network, "hop", Create);
        Assert.False(first.CertificateCurrent); // no successful handshake yet
        record!(clock.GetUtcNow().AddMinutes(-1).UtcDateTime, clock.GetUtcNow().AddSeconds(10).UtcDateTime); Assert.True(first.CertificateCurrent);
        record(clock.GetUtcNow().AddMinutes(-2).UtcDateTime, clock.GetUtcNow().AddHours(1).UtcDateTime);
        clock.Advance(TimeSpan.FromSeconds(10)); Assert.False(first.CertificateCurrent);
        using var second = pool.Borrow(network, "hop", Create);
        Assert.NotSame(first.Client, second.Client); Assert.False(second.CertificateCurrent);
    }

    [Fact]
    public void ClockBeforeAuthenticatedCertificateStartCannotReuseItsValidity()
    {
        var clock = new Clock(); using var pool = new PrivacyPeerHttpPool(clock); var network = new object();
        using var lease = pool.Borrow(network, "hop", record =>
        {
            record(clock.GetUtcNow().AddSeconds(-1).UtcDateTime, clock.GetUtcNow().AddHours(1).UtcDateTime);
            return new(new TrackingHandler());
        });
        Assert.True(lease.CertificateCurrent);
        clock.Advance(TimeSpan.FromSeconds(-2)); Assert.False(lease.CertificateCurrent);
    }

    [Fact]
    public void FailedCreationDoesNotPoisonTheNextBorrow()
    {
        using var pool = new PrivacyPeerHttpPool(); var network = new object();
        Assert.Throws<IOException>(() => pool.Borrow(network, "hop", _ => throw new IOException()));
        using var next = pool.Borrow(network, "hop", _ => new(new TrackingHandler()));
        Assert.NotNull(next.Client);
    }

    private sealed class Clock : TimeProvider
    {
        private readonly DateTimeOffset origin = DateTimeOffset.UtcNow;
        private long elapsed;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => elapsed;
        public override DateTimeOffset GetUtcNow() => origin.AddMilliseconds(elapsed);
        internal void Advance(TimeSpan span) => elapsed += checked((long)span.TotalMilliseconds);
    }

    private sealed class TrackingHandler : HttpMessageHandler
    {
        internal bool Disposed;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
