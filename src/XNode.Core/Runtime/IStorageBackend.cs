namespace XNode.Core.Runtime;

public interface IStorageBackend
{
    Task<IReadOnlyList<RelayContact>> GetBootstrapRelayContactsAsync(CancellationToken cancellationToken);

    Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken);
}

public sealed class EmptyStorageBackend : IStorageBackend
{
    public Task<IReadOnlyList<RelayContact>> GetBootstrapRelayContactsAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult<IReadOnlyList<RelayContact>>(Array.Empty<RelayContact>());
    }

    public Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
