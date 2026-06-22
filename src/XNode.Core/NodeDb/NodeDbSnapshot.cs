namespace XNode.Core.NodeDb;

public sealed record NodeDbSnapshot(
    int KnownRelayContacts,
    int KnownRouterIds,
    int RegisteredRelays,
    IReadOnlyDictionary<int, ulong> RelayContactBucketHashes);
