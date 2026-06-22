using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace XNode.Registry.Heartbeat;

public sealed class RegistrationHeartbeatService : BackgroundService
{
    private readonly RegistrationHeartbeatOptions _options;
    private readonly RegistryRegistrationPayloadFactory _payloadFactory;
    private readonly IRegistryClient _registryClient;
    private readonly ILogger<RegistrationHeartbeatService> _logger;

    public RegistrationHeartbeatService(
        RegistrationHeartbeatOptions options,
        RegistryRegistrationPayloadFactory payloadFactory,
        IRegistryClient registryClient,
        ILogger<RegistrationHeartbeatService>? logger = null)
    {
        _options = options;
        _payloadFactory = payloadFactory;
        _registryClient = registryClient;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<RegistrationHeartbeatService>.Instance;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Registry heartbeat is disabled.");
            return;
        }

        using var timer = new PeriodicTimer(_options.Interval);
        do
        {
            try
            {
                var payload = await _payloadFactory.CreateAsync(stoppingToken).ConfigureAwait(false);
                await _registryClient.PublishAsync(payload, stoppingToken).ConfigureAwait(false);
                _logger.LogDebug("Registry heartbeat published.");
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Registry heartbeat failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }
}
