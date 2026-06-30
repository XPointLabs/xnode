using System.Net.Http.Json;
using System.Text.Json;
using XNode.Core;
using XNode.Core.Onion;
using XNode.Core.Runtime;
using XNode.Core.Session;

namespace XNode;

public sealed class HttpOnionPeerClient : IOnionPeerClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly RouterNodeOptions _nodeOptions;
    private readonly IClock _clock;

    public HttpOnionPeerClient(HttpClient httpClient, RouterNodeOptions nodeOptions, IClock clock)
    {
        _httpClient = httpClient;
        _nodeOptions = nodeOptions;
        _clock = clock;
    }

    public async Task<SessionRpcResponse> ForwardAsync(
        string rpcEndpoint,
        OnionRequest request,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(rpcEndpoint.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return SessionRpcResponse.Fail("onion-forward", "invalid-onion-peer-endpoint");
        }

        var signed = SignedOnionPeerRequestAuthenticator.Sign(
            _nodeOptions.GetRouterId(),
            _nodeOptions.GetEd25519PrivateKey(),
            request,
            _clock.UtcNow);
        using var response = await _httpClient.PostAsJsonAsync(uri, signed, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        var body = await response.Content.ReadFromJsonAsync<SessionRpcResponse>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);

        if (body is null)
        {
            return SessionRpcResponse.Fail("onion-forward", $"onion-peer-empty-response:{(int)response.StatusCode}");
        }

        return body;
    }
}
