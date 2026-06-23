using System.Numerics;
using System.Text;

namespace XNode.Registry;

public sealed record ServiceNodeContractTags(
    byte[] ProofOfPossessionTag,
    byte[] RewardTag,
    byte[] ExitTag,
    byte[] LiquidateTag,
    byte[] HashToG2Tag);

public static class ServiceNodeContractTagBuilder
{
    private const string ProofOfPossessionBaseTag = "BLS_SIG_TRYANDINCREMENT_POP";
    private const string RewardBaseTag = "BLS_SIG_TRYANDINCREMENT_REWARD";
    private const string ExitBaseTag = "BLS_SIG_TRYANDINCREMENT_EXIT";
    private const string LiquidateBaseTag = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE";
    private const string HashToG2BaseTag = "BLS_SIG_HASH_TO_FIELD_TAG";

    public static ServiceNodeContractTags? TryBuild(RegistryRegistrationOptions options)
    {
        if (options.ChainId <= 0 || string.IsNullOrWhiteSpace(options.ServiceNodeRewardsAddress))
        {
            return null;
        }

        return new ServiceNodeContractTags(
            BuildTag(ProofOfPossessionBaseTag, options.ChainId, options.ServiceNodeRewardsAddress),
            BuildTag(RewardBaseTag, options.ChainId, options.ServiceNodeRewardsAddress),
            BuildTag(ExitBaseTag, options.ChainId, options.ServiceNodeRewardsAddress),
            BuildTag(LiquidateBaseTag, options.ChainId, options.ServiceNodeRewardsAddress),
            BuildTag(HashToG2BaseTag, options.ChainId, options.ServiceNodeRewardsAddress));
    }

    public static byte[] BuildTag(string baseTag, long chainId, string contractAddress)
    {
        if (chainId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chainId), "Chain ID must be positive.");
        }

        return Epoche.Keccak256.ComputeHash(Concat(
            Encoding.UTF8.GetBytes(baseTag),
            UInt256ToBytes32(chainId),
            HexToBytes(NormalizeAddress(contractAddress))));
    }

    private static byte[] UInt256ToBytes32(long value)
    {
        var bytes = new BigInteger(value).ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > 32)
        {
            throw new ArgumentException("Value does not fit into uint256.", nameof(value));
        }

        var result = new byte[32];
        bytes.CopyTo(result, 32 - bytes.Length);
        return result;
    }

    private static string NormalizeAddress(string address)
    {
        var normalized = Strip0x(address);
        if (normalized.Length != 40 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException("Expected 20-byte Ethereum address.");
        }

        return normalized.ToLowerInvariant();
    }

    private static byte[] HexToBytes(string hex)
    {
        var normalized = Strip0x(hex);
        if (normalized.Length % 2 == 1)
        {
            normalized = "0" + normalized;
        }

        return Convert.FromHexString(normalized);
    }

    private static string Strip0x(string value) =>
        value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;

    private static byte[] Concat(params byte[][] chunks)
    {
        var result = new byte[chunks.Sum(static item => item.Length)];
        var offset = 0;
        foreach (var chunk in chunks)
        {
            Buffer.BlockCopy(chunk, 0, result, offset, chunk.Length);
            offset += chunk.Length;
        }

        return result;
    }
}
