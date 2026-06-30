using System.Net.Http.Json;
using XNode.Core;
using XNode.Core.Runtime;

namespace XNode.Registry.Bootstrap;

public sealed class RegistryRelayContactBootstrapOptions
{
    public string BaseUrl { get; set; } = "";

    public string RelayContactsPath { get; set; } = "/api/relay-contacts";
}

public sealed class RegistryRelayContactBootstrapBackend : IStorageBackend
{
    private readonly HttpClient _httpClient;
    private readonly RegistryRelayContactBootstrapOptions _options;
    private readonly RouterNodeOptions _nodeOptions;
    private readonly IClock _clock;

    public RegistryRelayContactBootstrapBackend(
        HttpClient httpClient,
        RegistryRelayContactBootstrapOptions options,
        RouterNodeOptions nodeOptions,
        IClock clock)
    {
        _httpClient = httpClient;
        _options = options;
        _nodeOptions = nodeOptions;
        _clock = clock;

        if (string.IsNullOrWhiteSpace(_options.BaseUrl))
        {
            throw new ArgumentException("Registry bootstrap base URL is required.", nameof(options));
        }

        if (_httpClient.BaseAddress is null)
        {
            _httpClient.BaseAddress = new Uri(_options.BaseUrl.EndsWith('/')
                ? _options.BaseUrl
                : _options.BaseUrl + "/", UriKind.Absolute);
        }
    }

    public async Task<IReadOnlyList<RelayContact>> GetBootstrapRelayContactsAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, _options.RelayContactsPath);
        RegistryCatalogRequestSigner.Sign(request, _nodeOptions, _clock.UtcNow);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var contacts = await response.Content.ReadFromJsonAsync<List<RelayContact>>(
            cancellationToken).ConfigureAwait(false);

        return contacts ?? [];
    }

    public Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
