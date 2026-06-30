namespace XNode.Core;

public sealed class RouterNodeOptions
{
    public string DataDirectory { get; set; } = "/var/lib/xnode";

    public string RouterId { get; set; } = "0000000000000000000000000000000000000000000000000000000000000000";

    public string Ed25519PrivateKey { get; set; } = "";

    public string Ed25519PrivateKeyPath { get; set; } = "";

    public bool IsRelay { get; set; } = true;

    public string Network { get; set; } = "mainnet";

    public string ApiListenUrl { get; set; } = "http://127.0.0.1:8080";

    public string PeerRpcListenUrl { get; set; } = "http://0.0.0.0:8081";

    public string PublicPeerRpcEndpoint { get; set; } = "";

    public string PublicHost { get; set; } = "127.0.0.1";

    public string PublicIp { get; set; } = "";

    public int PublicPort { get; set; } = 443;

    public int PublicPeerRpcPort { get; set; } = 22020;

    public RouterId GetRouterId() => XNode.Core.RouterId.FromHex(RouterId);

    public string GetEd25519PrivateKey()
    {
        if (!string.IsNullOrWhiteSpace(Ed25519PrivateKey))
        {
            return Ed25519PrivateKey.Trim();
        }

        if (string.IsNullOrWhiteSpace(Ed25519PrivateKeyPath))
        {
            throw new InvalidOperationException(
                "Node:Ed25519PrivateKeyPath is required when Node:Ed25519PrivateKey is not set.");
        }

        if (!File.Exists(Ed25519PrivateKeyPath))
        {
            throw new InvalidOperationException(
                $"Node:Ed25519PrivateKeyPath '{Ed25519PrivateKeyPath}' does not exist.");
        }

        var key = File.ReadAllText(Ed25519PrivateKeyPath).Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new InvalidOperationException(
                $"Node:Ed25519PrivateKeyPath '{Ed25519PrivateKeyPath}' is empty.");
        }

        return key;
    }
}
