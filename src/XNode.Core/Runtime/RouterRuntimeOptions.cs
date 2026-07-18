namespace XNode.Core.Runtime;

public sealed class RouterRuntimeOptions
{
    public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(30);

    public bool BootstrapFromStorage { get; set; } = true;

    public bool RequireSignedRelayContacts { get; set; } = true;

    public int PathFailureThreshold { get; set; } = 3;

    public TimeSpan PathFailureDecayInterval { get; set; } = TimeSpan.FromMinutes(2);

    public int MaxPeerRequestBodyBytes { get; set; } = 256 * 1024;

    public int MaxRpcPayloadBytes { get; set; } = 128 * 1024;

    public int MaxOnionEnvelopeBytes { get; set; } = 96 * 1024;

    public int MaxOnionLayerBytes { get; set; } = 96 * 1024;

    public int MaxStoragePayloadBytes { get; set; } = 80 * 1024;

    public int MaxRelayContactsPerResponse { get; set; } = 500;

    public int PublicApiPermitLimit { get; set; } = 240;

    public TimeSpan PublicApiRateLimitWindow { get; set; } = TimeSpan.FromMinutes(1);

    public bool AllowLoopbackPeerEndpoints { get; set; }

    public bool EnablePrivatePeerEndpoints { get; set; }

    public string PrivatePeerNetworkIdentity { get; set; } = "";

    public List<PrivatePeerEndpointAllowlistEntry> PrivatePeerEndpointAllowlist { get; set; } = [];

    public bool EnablePrivateAllowlistMembership { get; set; }

    public List<int> ProductionPublicPeerPorts { get; set; } = [443];

    public bool AllowPublicPeerEndpoints { get; set; } = true;
}

public sealed class PrivatePeerEndpointAllowlistEntry
{
    public string RouterId { get; set; } = "";

    public string IpAddress { get; set; } = "";

    public int Port { get; set; }

    public string Path { get; set; } = "/api/peer/onion";
}
