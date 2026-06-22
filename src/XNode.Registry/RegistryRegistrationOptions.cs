namespace XNode.Registry;

public sealed class RegistryRegistrationOptions
{
    public string OperatorAddress { get; set; } = "";

    public string RewardsAddress { get; set; } = "";

    public int OperatorFeeBps { get; set; }

    public long StakeAtomic { get; set; }

    public string Ed25519PublicKey { get; set; } = "";

    public string Ed25519Signature { get; set; } = "";

    public string Ed25519Signature1 { get; set; } = "";

    public string Ed25519Signature2 { get; set; } = "";

    public string BlsPrivateKey { get; set; } = "";

    public string BlsPrivateKeyPath { get; set; } = "";

    public string BlsPublicKey { get; set; } = "";

    public string BlsSignature { get; set; } = "";

    public string EthereumRpcUrl { get; set; } = "";

    public string ServiceNodeRewardsAddress { get; set; } = "";

    public string SigningEndpoint { get; set; } = "";

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
}
