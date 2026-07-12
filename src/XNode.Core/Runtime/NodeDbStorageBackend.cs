using System.Text.Json;
using XNode.Core;
using XNode.Core.NodeDb;
using NodeDatabase = XNode.Core.NodeDb.NodeDb;

namespace XNode.Core.Runtime;

public sealed class NodeDbStorageBackend : IStorageBackend
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly NodeDatabase _nodeDb;
    private readonly RouterNodeOptions _nodeOptions;

    public NodeDbStorageBackend(NodeDatabase nodeDb, RouterNodeOptions nodeOptions)
    {
        _nodeDb = nodeDb;
        _nodeOptions = nodeOptions;
    }

    public Task<IReadOnlyList<RelayContact>> GetBootstrapRelayContactsAsync(CancellationToken cancellationToken)
    {
        var registeredContacts = _nodeDb.GetRegisteredRelays()
            .Select(_nodeDb.GetContact)
            .Where(static contact => contact is not null)
            .Select(static contact => contact!)
            .ToArray();
        return Task.FromResult<IReadOnlyList<RelayContact>>(registeredContacts);
    }

    public async Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken)
    {
        var directory = Path.Combine(_nodeOptions.DataDirectory, "artifacts");
        Directory.CreateDirectory(directory);

        var path = Path.Combine(directory, "router-heartbeat.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(snapshot, JsonOptions), cancellationToken)
            .ConfigureAwait(false);
    }
}
