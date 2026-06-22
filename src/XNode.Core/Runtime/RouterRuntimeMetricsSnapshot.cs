namespace XNode.Core.Runtime;

public sealed record RouterRuntimeMetricsSnapshot(
    long RpcRequests,
    long RpcFailures,
    long RelaySyncCycles,
    long RelaySyncFailures,
    long RelayContactsMerged,
    long RelayContactsRejected,
    long HeartbeatsSubmitted,
    long PathSelectionAttempts,
    long PathSelectionFailures,
    long PathRepairAttempts,
    long PathRepairSuccesses,
    int ChurnBlockedRouters);
