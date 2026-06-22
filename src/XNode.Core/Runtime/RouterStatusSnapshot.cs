using XNode.Core.NodeDb;

namespace XNode.Core.Runtime;

public sealed record RouterStatusSnapshot(
    string State,
    string RouterId,
    string Network,
    bool IsRelay,
    DateTimeOffset StartedAt,
    NodeDbSnapshot NodeDb,
    int ActiveSessions,
    bool XrayReady,
    RouterRuntimeMetricsSnapshot Metrics);
