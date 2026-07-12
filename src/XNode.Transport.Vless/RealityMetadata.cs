namespace XNode.Transport.Vless;

public sealed class RealityMetadata
{
    public string ServerName { get; set; } = "cloudflare-dns.com";

    public string PublicKey { get; set; } = "";

    [System.Text.Json.Serialization.JsonIgnore]
    public string PrivateKey { get; set; } = "";

    public string ShortId { get; set; } = "";

    public string Fingerprint { get; set; } = "chrome";

    public string SpiderX { get; set; } = "/";
}
