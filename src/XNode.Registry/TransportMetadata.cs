namespace XNode.Registry;

public sealed record TransportMetadata(
    bool Enabled,
    bool Running,
    bool Degraded,
    string Mode,
    bool Mocked,
    int RestartCount,
    int ConsecutiveFailures,
    string? LastExitReason,
    DateTimeOffset? LastStartedAt,
    DateTimeOffset? DegradedUntil);
