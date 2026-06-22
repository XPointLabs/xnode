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

    public RegistryRelayContactBootstrapBackend(
        HttpClient httpClient,
        RegistryRelayContactBootstrapOptions options)
    {
        _httpClient = httpClient;
        _options = options;

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
        var contacts = await _httpClient.GetFromJsonAsync<List<RelayContact>>(
            _options.RelayContactsPath,
            cancellationToken).ConfigureAwait(false);

        return contacts ?? [];
    }

    public Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
