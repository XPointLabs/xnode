namespace XNode.Transport.Vless;

public sealed record XraySupervisorStatus(
    bool Enabled,
    bool Running,
    bool Mocked,
    bool Degraded,
    string Mode,
    int RestartCount,
    int ConsecutiveFailures,
    int? ProcessId,
    string ConfigPath,
    string? LastExitReason,
    DateTimeOffset? LastStartedAt,
    DateTimeOffset? DegradedUntil);
