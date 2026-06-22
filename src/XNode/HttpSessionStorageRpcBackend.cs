using System.Text;
using System.Text.Json;
using XNode.Core.Runtime;

namespace XNode;

public sealed class SessionStorageRpcOptions
{
    public string BaseUrl { get; set; } = "";
}

public sealed class HttpSessionStorageRpcBackend : ISessionStorageRpcBackend
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly SessionStorageRpcOptions _options;

    public HttpSessionStorageRpcBackend(HttpClient httpClient, SessionStorageRpcOptions options)
    {
        _httpClient = httpClient;
        _options = options;

        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            throw new ArgumentException("Storage RPC base URL is required.", nameof(options));
        }

        if (_httpClient.BaseAddress is null)
        {
            _httpClient.BaseAddress = new Uri(_options.BaseUrl.EndsWith('/')
                ? _options.BaseUrl
                : _options.BaseUrl + "/", UriKind.Absolute);
        }
    }

    public async Task<SessionStorageRpcResult> PostAsync(
        string path,
        JsonElement payload,
        CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await _httpClient.PostAsync(path, content, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(body))
        {
            return new SessionStorageRpcResult((int)response.StatusCode, null, response.ReasonPhrase);
        }

        try
        {
            using var document = JsonDocument.Parse(body);
            return new SessionStorageRpcResult(
                (int)response.StatusCode,
                document.RootElement.Clone(),
                response.IsSuccessStatusCode ? null : body);
        }
        catch (JsonException)
        {
            return new SessionStorageRpcResult((int)response.StatusCode, null, body);
        }
    }
}
