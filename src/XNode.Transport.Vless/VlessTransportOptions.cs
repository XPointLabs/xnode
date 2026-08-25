namespace XNode.Transport.Vless;

public sealed class VlessTransportOptions
{
    public bool Enabled { get; set; } = true;

    public string XrayExecutablePath { get; set; } = "/usr/local/bin/xray";

    public string GeneratedConfigPath { get; set; } = "/etc/xnode/xray.generated.json";

    public string WorkingDirectory { get; set; } = "/var/lib/xnode/xray";

    public string InboundListenHost { get; set; } = "0.0.0.0";

    public int InboundListenPort { get; set; } = 443;

    public string PublicHost { get; set; } = "node.example.org";

    public int PublicPort { get; set; } = 443;

    public string ApiIngressHost { get; set; } = "127.0.0.1";

    public int ApiIngressPort { get; set; } = 8080;

    public string ClientId { get; set; } = "00000000-0000-0000-0000-000000000001";

    public string MaskDomain { get; set; } = "cloudflare-dns.com";

    public VlessTransportMode TransportMode { get; set; } = VlessTransportMode.Reality;

    public RealityMetadata Reality { get; set; } = new();

    public TlsMetadata Tls { get; set; } = new();

    public string[] Capabilities { get; set; } = new[]
    {
        "privacy-routing-v1",
        "client-bootstrap",
        "vless-ingress"
    };

    public int ConfigVersion { get; set; } = 1;

    public bool MockProcess { get; set; }

    public TimeSpan RestartDelay { get; set; } = TimeSpan.FromSeconds(5);

    public int MaxRestartAttempts { get; set; } = 5;

    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(2);

    public TimeSpan DegradedCooldown { get; set; } = TimeSpan.FromSeconds(30);
}
