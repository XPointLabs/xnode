using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;

namespace XNode;

/// <summary>
/// Fetches only raw, request-bound DID2 directory artifacts. A successful HTTP
/// exchange is not directory freshness or publication authority. Production DI
/// must disable automatic redirects, cookies and decompression on its handler.
/// </summary>
internal interface IDeepIdV2DirectoryProofArtifactSource
{
    ValueTask<DeepIdV2DirectoryProofWireResponse> FetchAsync(
        ParsedAdl1V2 lookup, ParsedDid2 did2, ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> bootId, ulong monotonicSendSample,
        CancellationToken cancellationToken);
}

internal sealed class HttpsDeepIdV2DirectoryProofArtifactSource :
    IDeepIdV2DirectoryProofArtifactSource
{
    internal const string EndpointPath = "/api/v2/account-directory/proofs";
    internal static readonly TimeSpan MaximumRequestTimeout =
        TimeSpan.FromSeconds(30);
    private readonly HttpClient client;
    private readonly Uri endpoint;
    private readonly TimeSpan requestTimeout;

    internal HttpsDeepIdV2DirectoryProofArtifactSource(
        HttpClient client, string registryOrigin,
        TimeSpan? requestTimeout = null)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        endpoint = CreateEndpoint(registryOrigin);
        this.requestTimeout = requestTimeout ?? MaximumRequestTimeout;
        if (this.requestTimeout < TimeSpan.FromSeconds(1) ||
            this.requestTimeout > MaximumRequestTimeout)
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
    }

    public async ValueTask<DeepIdV2DirectoryProofWireResponse> FetchAsync(
        ParsedAdl1V2 lookup, ParsedDid2 did2, ReadOnlyMemory<byte> nonce,
        ReadOnlyMemory<byte> bootId, ulong monotonicSendSample,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var encoded = DeepIdV2DirectoryProofWireCodec.EncodeRequest(
            lookup, did2, nonce.Span, bootId.Span, monotonicSendSample);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);
            deadline.CancelAfter(requestTimeout);
            var request = DeepIdV2DirectoryProofWireCodec.DecodeRequest(encoded);
            using var message = new HttpRequestMessage(HttpMethod.Post, endpoint);
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                DeepIdV2DirectoryProofWireCodec.ResponseMediaType));
            message.Headers.CacheControl = new CacheControlHeaderValue
                { NoStore = true };
            message.Content = new ByteArrayContent(encoded);
            message.Content.Headers.ContentType = new MediaTypeHeaderValue(
                DeepIdV2DirectoryProofWireCodec.RequestMediaType);
            message.Content.Headers.ContentLength = encoded.Length;

            using var response = await client.SendAsync(message,
                HttpCompletionOption.ResponseHeadersRead, deadline.Token)
                .ConfigureAwait(false);
            var length = RequireResponse(response);
            var body = await ReadExactAsync(response.Content, length,
                deadline.Token).ConfigureAwait(false);
            try
            {
                return DeepIdV2DirectoryProofWireCodec.DecodeResponse(body,
                    request);
            }
            finally { CryptographicOperations.ZeroMemory(body); }
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private int RequireResponse(HttpResponseMessage response)
    {
        if (response.StatusCode != HttpStatusCode.OK)
            throw new IOException("The DID2 directory proof authority is unavailable.");
        if (response.RequestMessage?.RequestUri is not { } actual ||
            Uri.Compare(actual, endpoint, UriComponents.AbsoluteUri,
                UriFormat.UriEscaped, StringComparison.Ordinal) != 0)
            throw new InvalidDataException("The DID2 proof endpoint changed.");
        var contentType = response.Content.Headers.ContentType;
        if (contentType is null || contentType.Parameters.Count != 0 ||
            !string.Equals(contentType.MediaType,
                DeepIdV2DirectoryProofWireCodec.ResponseMediaType,
                StringComparison.OrdinalIgnoreCase) ||
            response.Content.Headers.ContentEncoding.Count != 0 ||
            response.Headers.CacheControl?.NoStore != true)
            throw new InvalidDataException("The DID2 proof response headers are invalid.");
        var length = response.Content.Headers.ContentLength;
        if (length is null or < 128 or
            > DeepIdV2DirectoryProofWireCodec.MaximumResponseLength)
            throw new InvalidDataException("The DID2 proof response length is invalid.");
        return checked((int)length.Value);
    }

    private static async Task<byte[]> ReadExactAsync(HttpContent content,
        int length, CancellationToken cancellationToken)
    {
        var body = new byte[length];
        try
        {
            await using var stream = await content.ReadAsStreamAsync(
                cancellationToken).ConfigureAwait(false);
            await stream.ReadExactlyAsync(body, cancellationToken)
                .ConfigureAwait(false);
            var extra = new byte[1];
            if (await stream.ReadAsync(extra, cancellationToken)
                    .ConfigureAwait(false) != 0)
                throw new InvalidDataException(
                    "The DID2 proof response exceeds Content-Length.");
            return body;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(body);
            throw;
        }
    }

    private static Uri CreateEndpoint(string exactOrigin)
    {
        if (string.IsNullOrEmpty(exactOrigin) ||
            exactOrigin != exactOrigin.Trim() ||
            exactOrigin.Any(char.IsControl) ||
            exactOrigin.Contains('\u005c') || exactOrigin.Contains('%') ||
            exactOrigin.Contains('?') || exactOrigin.Contains('#') ||
            !Uri.TryCreate(exactOrigin, UriKind.Absolute, out var origin) ||
            origin.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrEmpty(origin.Host) ||
            origin.HostNameType == UriHostNameType.Unknown ||
            !string.IsNullOrEmpty(origin.UserInfo) ||
            origin.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(origin.Query) ||
            !string.IsNullOrEmpty(origin.Fragment))
            throw new ArgumentException(
                "The DID2 Registry address must be an exact HTTPS origin.",
                nameof(exactOrigin));
        return new UriBuilder(Uri.UriSchemeHttps, origin.Host,
            origin.IsDefaultPort ? -1 : origin.Port, EndpointPath).Uri;
    }
}
