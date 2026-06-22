namespace XNode.Registry.Heartbeat;

public interface IRegistryClient
{
    Task PublishAsync(RegistryRegistrationPayload payload, CancellationToken cancellationToken);
}
