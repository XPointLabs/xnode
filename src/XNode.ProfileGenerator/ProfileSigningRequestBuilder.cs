using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Deep.Protocol.DeepExtension.Membership;

namespace XNode.ProfileGenerator;

public sealed class ProfileSigningRequest
{
    private readonly byte[] _signingBytes;

    internal ProfileSigningRequest(
        MembershipSignatureDomain domain,
        byte[] signingBytes)
    {
        Domain = domain;
        _signingBytes = signingBytes.ToArray();
        RequestId = $"sha256:{Convert.ToHexString(SHA256.HashData(signingBytes)).ToLowerInvariant()}";
    }

    public MembershipSignatureDomain Domain { get; }
    public string RequestId { get; }

    [JsonIgnore]
    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();

    public override string ToString() =>
        $"{nameof(ProfileSigningRequest)} {Domain} {RequestId}";
}

public static class ProfileSigningRequestBuilder
{
    public static ProfileSigningRequest ForGenesis(ReadOnlySpan<byte> canonicalGenesis) =>
        Build(
            canonicalGenesis,
            MembershipSignatureDomain.Genesis,
            static value =>
            {
                var genesis = MembershipContractCodec.DecodeGenesis(value);
                return MembershipContractCodec.EncodeGenesis(genesis);
            });

    public static ProfileSigningRequest ForDelegation(
        ReadOnlySpan<byte> canonicalDelegationStatement) =>
        Build(
            canonicalDelegationStatement,
            MembershipSignatureDomain.OfflineDelegation,
            static value =>
            {
                var delegation = MembershipContractCodec.DecodeDelegationSigningBytes(value);
                return MembershipContractCodec.GetDelegationSigningBytes(delegation);
            });

    public static ProfileSigningRequest ForBridge(ReadOnlySpan<byte> canonicalBridgeStatement) =>
        Build(
            canonicalBridgeStatement,
            MembershipSignatureDomain.Bridge,
            static value =>
            {
                var bridge = MembershipContractCodec.DecodeBridgeSigningBytes(value);
                return MembershipContractCodec.GetBridgeSigningBytes(bridge);
            });

    private static ProfileSigningRequest Build(
        ReadOnlySpan<byte> canonical,
        MembershipSignatureDomain domain,
        Func<byte[], byte[]> canonicalize)
    {
        if (canonical.Length > ProfileComposerLimits.MaximumComponentBytes)
            throw ProfileErrors.Bounds();
        try
        {
            var source = canonical.ToArray();
            var checkedCanonical = canonicalize(source);
            if (!source.AsSpan().SequenceEqual(checkedCanonical))
                throw ProfileErrors.InvalidInput();
            return new ProfileSigningRequest(
                domain,
                MembershipSigningDomains.Frame(domain, checkedCanonical));
        }
        catch (ProfileContractException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ProfileErrors.Verification();
        }
    }
}
