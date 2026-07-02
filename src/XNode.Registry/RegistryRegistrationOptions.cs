namespace XNode.Registry;

public sealed class RegistryRegistrationOptions
{
    public string OperatorAddress { get; set; } = "";

    public string RewardsAddress { get; set; } = "";

    public int OperatorFeeBps { get; set; }

    public long StakeAtomic { get; set; }

    public long ChainId { get; set; }

    public string Ed25519PublicKey { get; set; } = "";

    public string Ed25519Signature { get; set; } = "";

    public string Ed25519Signature1 { get; set; } = "";

    public string Ed25519Signature2 { get; set; } = "";

    public string BlsPrivateKey { get; set; } = "";

    public string BlsPrivateKeyPath { get; set; } = "";

    public string BlsPublicKey { get; set; } = "";

    public string BlsSignature { get; set; } = "";

    public string EthereumRpcUrl { get; set; } = "";

    public string EthereumFallbackRpcUrls { get; set; } = "";

    public string ServiceNodeRewardsAddress { get; set; } = "";

    public string GetBlsPrivateKey()
    {
        if (!string.IsNullOrWhiteSpace(BlsPrivateKey))
        {
            return BlsPrivateKey.Trim();
        }

        if (string.IsNullOrWhiteSpace(BlsPrivateKeyPath))
        {
            throw new InvalidOperationException(
                "RegistryRegistration:BlsPrivateKeyPath is required when RegistryRegistration:BlsPrivateKey is not set.");
        }

        if (!File.Exists(BlsPrivateKeyPath))
        {
            throw new InvalidOperationException(
                $"RegistryRegistration:BlsPrivateKeyPath '{BlsPrivateKeyPath}' does not exist.");
        }

        var key = File.ReadAllText(BlsPrivateKeyPath).Trim();
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new InvalidOperationException(
                $"RegistryRegistration:BlsPrivateKeyPath '{BlsPrivateKeyPath}' is empty.");
        }

        return key;
    }

    public IReadOnlyList<string> GetEthereumRpcUrls()
    {
        var urls = new List<string>();
        AddIfPresent(EthereumRpcUrl);
        foreach (var item in EthereumFallbackRpcUrls.Split(
            new[] { ',', ';', '\r', '\n', '\t', ' ' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            AddIfPresent(item);
        }

        return urls;

        void AddIfPresent(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            var normalized = value.Trim();
            if (!urls.Contains(normalized, StringComparer.OrdinalIgnoreCase))
            {
                urls.Add(normalized);
            }
        }
    }
}
