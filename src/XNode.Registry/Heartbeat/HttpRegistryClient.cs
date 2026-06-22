using System.Net.Http.Json;

namespace XNode.Registry.Heartbeat;

public sealed class HttpRegistryClient : IRegistryClient
{
    private readonly HttpClient _httpClient;
    private readonly RegistrationHeartbeatOptions _options;

    public HttpRegistryClient(HttpClient httpClient, RegistrationHeartbeatOptions options)
    {
        _httpClient = httpClient;
        _options = options;
    }

    public async Task PublishAsync(RegistryRegistrationPayload payload, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(_options.Endpoint, payload, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }
}
