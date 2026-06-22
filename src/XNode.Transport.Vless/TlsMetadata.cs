namespace XNode.Transport.Vless;

public sealed class TlsMetadata
{
    public string ServerName { get; set; } = "";

    public string CertificateFile { get; set; } = "/etc/xnode/tls/fullchain.pem";

    public string KeyFile { get; set; } = "/etc/xnode/tls/privkey.pem";

    public string[] Alpn { get; set; } = new[] { "h2", "http/1.1" };
}
