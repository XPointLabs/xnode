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

    public string ManagedIngressH2ListenUrl { get; set; } = "";

    public string PrivacyPeerH2ListenUrl { get; set; } = "";

    public string[] ManagedIngressTrustedProxyAddresses { get; set; } = [];

    public string PublicHost { get; set; } = "127.0.0.1";

    public int PublicPort { get; set; } = 443;

    public string QuorumCoordinatorNetworks { get; set; } = "";

    public RouterId GetRouterId() => XNode.Core.RouterId.FromHex(RouterId);

    public string GetEd25519PrivateKey()
    {
        if (!string.IsNullOrWhiteSpace(Ed25519PrivateKey))
        {
            return NormalizeEd25519PrivateKey(Ed25519PrivateKey);
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

        return NormalizeEd25519PrivateKey(key);
    }

    private static string NormalizeEd25519PrivateKey(string value)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != 64 || !normalized.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
        {
            throw new InvalidOperationException(
                "Node Ed25519 private seed must be a 32-byte hexadecimal value, optionally prefixed with '0x'.");
        }

        return normalized.ToLowerInvariant();
    }
}
