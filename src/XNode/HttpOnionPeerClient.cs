using System.Net.Http.Json;
using System.Text.Json;
using XNode.Core.Onion;
using XNode.Core.Runtime;
using XNode.Core.Session;

namespace XNode;

public sealed class HttpOnionPeerClient : IOnionPeerClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;

    public HttpOnionPeerClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<SessionRpcResponse> ForwardAsync(
        string rpcEndpoint,
        OnionRequest request,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(rpcEndpoint.TrimEnd('/') + "/api/session/rpc", UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return SessionRpcResponse.Fail("onion-forward", "invalid-onion-peer-endpoint");
        }

        var rpc = new SessionRpcRequest(
            Guid.NewGuid().ToString("N"),
            "onion_request",
            JsonSerializer.SerializeToElement(request, JsonOptions));
        using var response = await _httpClient.PostAsJsonAsync(uri, rpc, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        var body = await response.Content.ReadFromJsonAsync<SessionRpcResponse>(JsonOptions, cancellationToken)
            .ConfigureAwait(false);

        if (body is null)
        {
            return SessionRpcResponse.Fail(rpc.Id, $"onion-peer-empty-response:{(int)response.StatusCode}");
        }

        return body;
    }
}
