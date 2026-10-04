using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Sodium;
using XNode.Core;

namespace XNode.IntegrationTests.Runtime;

// HTTP-handler boundary, actual independent Rebex/Sodium signatures. No witness,
// socket TLS, ONION, publication or physical delivery authority is claimed.
public sealed class ContactCoordinationBackendClientTests
{
    private static readonly byte[] Network = B(16, 0x11);
    private static readonly byte[] Seed = B(32, 0x73);

    [Fact]
    public async Task ExactRetryOwnsBytesAndRenewsOnlyTransportNonce()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var body = Request(); var original = body.ToArray();
        var held = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observed = new List<byte[]>(); var nonces = new List<string>();
        var count = 0;
        var client = Client(() => new Handler(async (message, ct) =>
        {
            Assert.Equal("https://authority.example/api/v2/contact-route-authority", message.RequestUri!.AbsoluteUri);
            Assert.Equal(ContactRouteAuthorityWireCodec.RequestMediaType, message.Content!.Headers.ContentType!.ToString());
            if (Interlocked.Increment(ref count) == 1) { entered.SetResult(); await held.Task; }
            var exact = await message.Content.ReadAsByteArrayAsync(ct);
            var headers = Headers(message);
            Assert.True(ContactCoordinationPeerAuthentication.Verify(headers, Network, ContactCoordinationTarget.Route, exact, DateTimeOffset.UtcNow));
            Assert.NotEqual(FixtureNode(fixture).RouterId, headers.NodePublicKeyHex);
            observed.Add(exact); nonces.Add(headers.NonceHex);
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        }), fixture);
        var pending = client.SendAsync(ContactCoordinationTarget.Route, body, fixture.NetworkContext, default).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); body[^1] ^= 1; held.SetResult();
        await Assert.ThrowsAsync<IOException>(() => pending);
        await Assert.ThrowsAsync<IOException>(() => client.SendAsync(ContactCoordinationTarget.Route, original, fixture.NetworkContext, default).AsTask());
        Assert.Equal(2, count);
        Assert.All(observed, exact => Assert.Equal(original, exact));
        Assert.NotEqual(nonces[0], nonces[1]);
    }

    [Fact]
    public async Task CancellationBoundsIgnoredHandlerAndDisposesLateResponse()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var late = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var content = new TrackedContent();
        var client = Client(() => new Handler((_, _) => { entered.SetResult(); return late.Task; }), fixture);
        using var cancel = new CancellationTokenSource();
        var pending = client.SendAsync(ContactCoordinationTarget.Route, Request(), fixture.NetworkContext, cancel.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(5)));
        late.SetResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        await content.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Theory]
    [InlineData("redirect")]
    [InlineData("missing-length")]
    [InlineData("size")]
    [InlineData("encoding")]
    [InlineData("media")]
    [InlineData("unpaired")]
    public async Task NoncanonicalResponseNeverReturnsAuthority(string mutation)
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var count = 0;
        var client = Client(() => new Handler((_, _) =>
        {
            count++;
            var content = new ByteArrayContent(new byte[ContactRouteAuthorityWireCodec.MinimumResponseBytes]);
            content.Headers.ContentType = MediaTypeHeaderValue.Parse(ContactRouteAuthorityWireCodec.ResponseMediaType);
            if (mutation == "missing-length") content.Headers.ContentLength = null;
            if (mutation == "size") content.Headers.ContentLength = ContactRouteAuthorityWireCodec.MaximumResponseBytes + 1;
            if (mutation == "encoding") content.Headers.ContentEncoding.Add("gzip");
            if (mutation == "media") content.Headers.ContentType = new("application/octet-stream");
            var response = new HttpResponseMessage(mutation == "redirect" ? HttpStatusCode.TemporaryRedirect : HttpStatusCode.OK) { Content = content };
            response.Headers.Location = new Uri("https://other.example/");
            return Task.FromResult(response);
        }), fixture);
        await Assert.ThrowsAsync<IOException>(() => client.SendAsync(ContactCoordinationTarget.Route, Request(), fixture.NetworkContext, default).AsTask());
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task UnknownTargetWrongNetworkHostileBodyAndWrongNodeRejectBeforeIo()
    {
        using var fixture = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var count = 0;
        var client = Client(() => { count++; return new Handler((_, _) => throw new InvalidOperationException()); }, fixture);
        await Assert.ThrowsAsync<ArgumentException>(() => client.SendAsync((ContactCoordinationTarget)3, Request(), fixture.NetworkContext, default).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => client.SendAsync(ContactCoordinationTarget.Route, new byte[1_000_000], fixture.NetworkContext, default).AsTask());
        await Assert.ThrowsAsync<ArgumentException>(() => client.SendAsync(ContactCoordinationTarget.Route, Request(B(16, 0x12)), fixture.NetworkContext, default).AsTask());
        foreach (var mode in new[] { "wrong-key", "node-id-as-seed", "public-key-as-node", "unknown-node" })
        {
            var node = FixtureNode(fixture);
            if (mode == "wrong-key") node.Ed25519PrivateKey = Convert.ToHexStringLower(Seed);
            if (mode == "node-id-as-seed") node.Ed25519PrivateKey = node.RouterId;
            if (mode == "public-key-as-node") node.RouterId = Convert.ToHexStringLower(
                fixture.NetworkContext.ResolveNodeIdentityPublicKey(node.GetRouterId().ToBytes()).Span);
            if (mode == "unknown-node") node.RouterId = new string('f', 64);
            var wrong = new HttpContactCoordinationBackendClient(new("https://authority.example/"), Network, node, new SystemClock(), () =>
                { count++; return new Handler((_, _) => throw new InvalidOperationException()); });
            if (mode is "public-key-as-node" or "unknown-node")
                await Assert.ThrowsAsync<Deep.Protocol.DeepExtension.PrivacyRouting.OnionBoundaryException>(() =>
                    wrong.SendAsync(ContactCoordinationTarget.Route, Request(), fixture.NetworkContext, default).AsTask());
            else await Assert.ThrowsAsync<CryptographicException>(() =>
                wrong.SendAsync(ContactCoordinationTarget.Route, Request(), fixture.NetworkContext, default).AsTask());
        }
        Assert.Equal(0, count);
    }

    [Theory]
    [InlineData("http://authority.example/")]
    [InlineData("https://authority.example/path")]
    [InlineData("https://authority.example/?x=1")]
    [InlineData("https://authority.example/#x")]
    [InlineData("https://user:pass@authority.example/")]
    public void OriginHasNoCallerChosenTargetOrCredential(string origin) => Assert.Throws<ArgumentException>(() =>
        new HttpContactCoordinationBackendClient(new(origin), Network, Node(), new SystemClock()));

    [Fact]
    public void ShippingHandlerKeepsPlatformTlsAndNeverFollowsRedirects()
    {
        using var handler = HttpContactCoordinationBackendClient.CreateHandler();
        Assert.False(handler.AllowAutoRedirect); Assert.False(handler.UseCookies); Assert.False(handler.UseProxy);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
    }

    private static HttpContactCoordinationBackendClient Client(Func<HttpMessageHandler> factory, DeepIdV2PublicationAuthorityFixture fixture) =>
        new(new("https://authority.example/"), Network, FixtureNode(fixture), new SystemClock(), factory);
    private static RouterNodeOptions FixtureNode(DeepIdV2PublicationAuthorityFixture fixture)
    {
        var id = fixture.Placement.ReplicaIds[0];
        return new() { RouterId = Convert.ToHexStringLower(id.Span),
            Ed25519PrivateKey = Convert.ToHexStringLower(fixture.Node(id.Span).Seed) };
    }
    private static RouterNodeOptions Node()
    {
        var key = PublicKeyAuth.GenerateKeyPair(Seed);
        try { return new() { RouterId = Convert.ToHexStringLower(key.PublicKey), Ed25519PrivateKey = Convert.ToHexStringLower(Seed) }; }
        finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
    }
    private static ContactCoordinationPeerHeaders Headers(HttpRequestMessage message) => new(
        message.Headers.GetValues(ContactCoordinationPeerAuthentication.NodeHeader).Single(),
        message.Headers.GetValues(ContactCoordinationPeerAuthentication.TimestampHeader).Single(),
        message.Headers.GetValues(ContactCoordinationPeerAuthentication.NonceHeader).Single(),
        message.Headers.GetValues(ContactCoordinationPeerAuthentication.SignatureHeader).Single());

    private static byte[] Request(byte[]? network = null)
    {
        network ??= Network;
        // Closed canonical transport fixture only; these fake route/signature fields
        // are never promoted to verified network or publisher authority.
        var fields = new byte[][] { network, B(32, 1), U64(0), new byte[32], Reference("PMT2"), B(32, 2),
            [0, 1], [0, 0, 0, 10], B(32, 3), B(32, 4), B(32, 5), U64(20), U64(90), B(32, 6), Reference("DPD1"), B(64, 7) };
        var xra = new byte[550]; Encoding.ASCII.GetBytes("XRA1").CopyTo(xra, 0);
        BinaryPrimitives.WriteUInt16BigEndian(xra.AsSpan(4), 1); // Identity-neutral frozen XRA1 header.
        BinaryPrimitives.WriteUInt16BigEndian(xra.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(xra.AsSpan(8), 16); var offset = 12;
        for (var i = 0; i < fields.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(xra.AsSpan(offset), checked((ushort)(i + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(xra.AsSpan(offset + 4), checked((uint)fields[i].Length));
            fields[i].CopyTo(xra, offset + 8); offset += 8 + fields[i].Length;
        }
        _ = ContactCodec.Decode("XRA1", xra);
        var dca = DeepIdV2ContactAuthorizationCodec.Author(network, B(32, 8), ApplicationCoreCodec.CreateArtifactReference(1, 644, B(32, 9)),
            1, B(32, 10), B(32, 11), fields[13], 3, 5, 20, 90, B(64, 12), B(32, 13),
            ApplicationCoreCodec.CreateArtifactReference(DeepIdV2Codec.Dab2ArtifactType, DeepIdV2Codec.Dab2Length, B(32, 14)));
        return ContactRouteAuthorityWireCodec.EncodeRequest(new(network, B(32, 15), B(32, 16), 0, B(32, 17), dca.CanonicalBytes.Span, xra));
    }
    private static byte[] Reference(string magic)
    { var value = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(value, 0); BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1); B(32, 21).CopyTo(value, 6); return value; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => send(request, ct); }
    private sealed class TrackedContent() : ByteArrayContent([])
    {
        internal TaskCompletionSource Disposed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override void Dispose(bool disposing) { base.Dispose(disposing); if (disposing) Disposed.TrySetResult(); }
    }
}
