namespace XNode.Registry.Heartbeat;

public sealed class RegistrationHeartbeatOptions
{
    public bool Enabled { get; set; } = false;

    public string Endpoint { get; set; } = "http://127.0.0.1:9090/registry/nodes";

    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(30);
}
