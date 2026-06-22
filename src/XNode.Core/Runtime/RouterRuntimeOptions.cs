namespace XNode.Core.Runtime;

public sealed class RouterRuntimeOptions
{
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(30);

    public bool BootstrapFromStorage { get; set; } = true;

    public bool RequireSignedRelayContacts { get; set; } = true;

    public int PathFailureThreshold { get; set; } = 3;

    public TimeSpan PathFailureDecayInterval { get; set; } = TimeSpan.FromMinutes(2);
}
