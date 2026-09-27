using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace XNode.IntegrationTests.Runtime;

public sealed class HttpsDeepIdV2DirectoryProofArtifactSourceTests
{
    private static readonly byte[] Network = Bytes(16, 0x21);
    private static readonly byte[] Nonce = Bytes(32, 0x31);
    private static readonly byte[] Boot = Bytes(16, 0x41);

    [Fact]
    public async Task PostsExactRecipientBoundDid2RequestWithoutGrantingHttpAuthority()
    {
        var did2 = Did2();
        var lookup = Lookup(did2);
        var handler = new DelegateHandler(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("https://registry.example/api/v2/account-directory/proofs",
                request.RequestUri!.AbsoluteUri);
            Assert.True(request.Headers.CacheControl!.NoStore);
            Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestMediaType,
                request.Content!.Headers.ContentType!.MediaType);
            Assert.Equal(DeepIdV2DirectoryProofWireCodec.ResponseMediaType,
                Assert.Single(request.Headers.Accept).MediaType);
            var exact = await request.Content.ReadAsByteArrayAsync();
            Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestLength,
                exact.Length);
            var parsed = DeepIdV2DirectoryProofWireCodec.DecodeRequest(exact);
            Assert.Equal(did2.CanonicalBytes.ToArray(),
                parsed.DeepId.CanonicalBytes.ToArray());
            Assert.Equal(Nonce, parsed.Nonce.ToArray());
            Assert.Equal(Boot, parsed.BootId.ToArray());
            Assert.Equal((ulong)123, parsed.ClientMonotonicSendSample);
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                { RequestMessage = request };
        });
        using var client = new HttpClient(handler);
        var source = new HttpsDeepIdV2DirectoryProofArtifactSource(
            client, "https://registry.example");

        await Assert.ThrowsAsync<IOException>(async () =>
            await source.FetchAsync(lookup, did2, Nonce, Boot, 123, default));
    }

    [Fact]
    public async Task RedirectedOrNonCanonicalResponseFailsBeforeProofParsing()
    {
        var did2 = Did2();
        var handler = new DelegateHandler(request => Task.FromResult(
            Response(new HttpRequestMessage(HttpMethod.Post,
                "https://other.example/api/v2/account-directory/proofs"),
                new byte[128])));
        using var client = new HttpClient(handler);
        var source = new HttpsDeepIdV2DirectoryProofArtifactSource(
            client, "https://registry.example");

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await source.FetchAsync(Lookup(did2), did2, Nonce, Boot, 123,
                default));
    }

    [Fact]
    public async Task MalformedProofBodyCannotBecomeDirectoryAuthority()
    {
        var did2 = Did2();
        var handler = new DelegateHandler(request => Task.FromResult(
            Response(request, new byte[128])));
        using var client = new HttpClient(handler);
        var source = new HttpsDeepIdV2DirectoryProofArtifactSource(
            client, "https://registry.example");

        await Assert.ThrowsAsync<FormatException>(async () =>
            await source.FetchAsync(Lookup(did2), did2, Nonce, Boot, 123,
                default));
    }

    [Fact]
    public async Task DifferentDid2LookupIsRejectedBeforeNetworkAccess()
    {
        var did2 = Did2();
        var other = DeepIdV2Codec.AuthorDid2(Bytes(32, 0x52),
            Bytes(1952, 0x61), Bytes(16, 0x71));
        using var client = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException("The handler must not run.")));
        var source = new HttpsDeepIdV2DirectoryProofArtifactSource(
            client, "https://registry.example");

        await Assert.ThrowsAsync<FormatException>(async () =>
            await source.FetchAsync(Lookup(other), did2, Nonce, Boot, 123,
                default));
    }

    [Theory]
    [InlineData("http://registry.example")]
    [InlineData("https://user@registry.example")]
    [InlineData("https://registry.example/path")]
    [InlineData("https://registry.example?query=1")]
    [InlineData("https://registry.example/%2e%2e/")]
    [InlineData("https://registry.example\\other")]
    public void RejectsNonHttpsOrNonOriginRegistryAddress(string origin)
    {
        using var client = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException("The handler must not run.")));
        Assert.Throws<ArgumentException>(() =>
            new HttpsDeepIdV2DirectoryProofArtifactSource(client, origin));
    }

    [Fact]
    public void RejectsUnboundedRequestDeadline()
    {
        using var client = new HttpClient(new DelegateHandler(_ =>
            throw new InvalidOperationException("The handler must not run.")));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new HttpsDeepIdV2DirectoryProofArtifactSource(client,
                "https://registry.example", TimeSpan.FromMinutes(2)));
    }

    private static ParsedDid2 Did2() => DeepIdV2Codec.AuthorDid2(
        Bytes(32, 0x51), Bytes(1952, 0x61), Bytes(16, 0x71));

    private static ParsedAdl1V2 Lookup(ParsedDid2 did2) =>
        DeepIdV2AccountDirectoryLookupCodec.Author(did2, Network, 0,
            Bytes(32, 0x81), 1, new byte[38], new byte[32]);

    private static HttpResponseMessage Response(HttpRequestMessage request,
        byte[] body)
    {
        var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(
            DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
        content.Headers.ContentLength = body.Length;
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = request,
            Content = content
        };
        response.Headers.CacheControl = new CacheControlHeaderValue
            { NoStore = true };
        return response;
    }

    private static byte[] Bytes(int length, byte value)
    {
        var result = new byte[length];
        result.AsSpan().Fill(value);
        return result;
    }

    private sealed class DelegateHandler(
        Func<HttpRequestMessage, Task<HttpResponseMessage>> handle)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return handle(request);
        }
    }
}
