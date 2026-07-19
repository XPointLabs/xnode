using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace XNode.ProfileGenerator.Tests;

// PRODUCTION PROHIBITION: deterministic public fixture signatures are test-only and are
// not an approved cryptographic profile, signer, verifier, key source, or ceremony.
internal sealed class TestOnlySignatureScheme : IMembershipSignatureVerifier
{
    public byte[] Sign(
        MembershipSignerDescriptor signer,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement) =>
        Digest(signer.SignerId.Span, signer.PublicKey.Span, MembershipSigningDomains.Frame(domain, canonicalStatement));

    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature) =>
        CryptographicOperations.FixedTimeEquals(
            Digest(signerId, publicKey, signingBytes),
            signature);

    private static byte[] Digest(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes)
    {
        var input = new byte[signerId.Length + publicKey.Length + signingBytes.Length];
        signerId.CopyTo(input);
        publicKey.CopyTo(input.AsSpan(signerId.Length));
        signingBytes.CopyTo(input.AsSpan(signerId.Length + publicKey.Length));
        return SHA256.HashData(input);
    }
}

internal static class TestOnlyProfileFixture
{
    public const ulong VerificationTime = 1_100;
    public const ushort Protocol = 2;

    public static TestOnlySignatureScheme SignatureScheme() => new();

    public static NetworkGenesis Genesis() =>
        new()
        {
            NetworkId = Range(0x70, MembershipLimits.NetworkIdLength),
            GenesisSequence = 1,
            PolicyVersion = 1,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            IssuedAtUnixSeconds = 1_000,
            OfflineRoots = OfflineRoots(),
            Policy = MembershipPolicy.Beta(
                OfflineRoots().Select(static signer => signer.SignerId).ToArray())
        };

    public static ProfileAssemblyInput Input(
        bool reverseGenesisSignatures = false,
        bool reverseBridges = false,
        int bridgeCount = 1,
        int contactLength = 48)
    {
        var scheme = SignatureScheme();
        var genesis = Genesis();
        var canonicalGenesis = MembershipContractCodec.EncodeGenesis(genesis);
        var genesisSignatures = Signatures(
            genesis.OfflineRoots,
            MembershipSignatureDomain.Genesis,
            canonicalGenesis,
            3,
            scheme)
            .Select(static signature => new ProfilePublicSignature(
                signature.SignerId.Span,
                signature.Domain,
                signature.Signature.Span))
            .ToArray();
        if (reverseGenesisSignatures)
            Array.Reverse(genesisSignatures);

        var delegation = SignedDelegation(genesis, canonicalGenesis, scheme);
        var bridges = SignedBridges(genesis, canonicalGenesis, delegation, bridgeCount, contactLength, scheme)
            .Select(static value => (ReadOnlyMemory<byte>)MembershipContractCodec.EncodeSignedBridge(value))
            .ToArray();
        if (reverseBridges)
            Array.Reverse(bridges);

        return new ProfileAssemblyInput(
            canonicalGenesis,
            genesisSignatures,
            MembershipContractCodec.EncodeSignedDelegation(delegation),
            bridges);
    }

    public static ProfileVerificationOptions Options(ulong time = VerificationTime) =>
        new(time, 30, Protocol);

    public static SignerDelegation SignedDelegation(
        NetworkGenesis genesis,
        byte[] canonicalGenesis,
        TestOnlySignatureScheme scheme)
    {
        var unsigned = new SignerDelegation
        {
            NetworkId = genesis.NetworkId.ToArray(),
            Sequence = genesis.GenesisSequence + 1,
            PreviousHash = MembershipContractHash.Sha256(canonicalGenesis),
            IssuedAtUnixSeconds = 1_000,
            ValidFromUnixSeconds = 1_000,
            ValidUntilUnixSeconds = 2_000,
            MinimumProtocol = genesis.MinimumProtocol,
            MaximumProtocol = genesis.MaximumProtocol,
            PolicyVersion = genesis.PolicyVersion,
            OnlineSigners = OnlineSigners(),
            Signatures = []
        };
        var signingBytes = MembershipContractCodec.GetDelegationSigningBytes(unsigned);
        return unsigned with
        {
            Signatures = Signatures(
                genesis.OfflineRoots,
                MembershipSignatureDomain.OfflineDelegation,
                signingBytes,
                3,
                scheme)
        };
    }

    public static IReadOnlyList<SignedBridgeSnapshot> SignedBridges(
        NetworkGenesis genesis,
        byte[] canonicalGenesis,
        SignerDelegation delegation,
        int count,
        int contactLength,
        TestOnlySignatureScheme scheme)
    {
        var result = new List<SignedBridgeSnapshot>();
        var previousHash = MembershipContractHash.Sha256(canonicalGenesis);
        var sequence = genesis.GenesisSequence + 1;
        for (var index = 0; index < count; index++)
        {
            var contact = "https://bridge.example.invalid/" +
                new string((char)('a' + index % 20), Math.Max(1, contactLength - 31));
            var preliminary = new BridgeSnapshot
            {
                NetworkId = genesis.NetworkId.ToArray(),
                Sequence = sequence,
                PreviousHash = previousHash,
                IssuedAtUnixSeconds = 1_000,
                ValidFromUnixSeconds = 1_000,
                ValidUntilUnixSeconds = 2_000,
                MinimumProtocol = genesis.MinimumProtocol,
                MaximumProtocol = genesis.MaximumProtocol,
                PolicyVersion = genesis.PolicyVersion,
                EntryContacts =
                [
                    new BridgeEntryContact
                    {
                        EntryId = Range(0xc0 + index, MembershipLimits.SignerIdLength),
                        Contact = contact
                    }
                ],
                ForkWitness = new ForkWitnessRecord
                {
                    CandidateDomain = MembershipSignatureDomain.Bridge,
                    Sequence = sequence,
                    PreviousHash = previousHash,
                    CandidateHash = new byte[MembershipLimits.HashLength]
                }
            };
            var snapshot = preliminary with
            {
                ForkWitness = preliminary.ForkWitness with
                {
                    CandidateHash = MembershipContractHash.Sha256(
                        MembershipContractCodec.GetBridgeCandidateBytes(preliminary))
                }
            };
            var signingBytes = MembershipContractCodec.GetBridgeSigningBytes(snapshot);
            result.Add(new SignedBridgeSnapshot
            {
                Statement = snapshot,
                Signatures = Signatures(
                    delegation.OnlineSigners,
                    MembershipSignatureDomain.Bridge,
                    signingBytes,
                    2,
                    scheme)
            });
            previousHash = MembershipContractHash.Sha256(signingBytes);
            sequence++;
        }

        return result;
    }

    public static IReadOnlyList<MembershipSignature> Signatures(
        IReadOnlyList<MembershipSignerDescriptor> signers,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> canonicalStatement,
        int count,
        TestOnlySignatureScheme scheme)
    {
        var canonical = canonicalStatement.ToArray();
        return signers.Take(count)
            .Select(signer => new MembershipSignature
            {
                SignerId = signer.SignerId.ToArray(),
                Domain = domain,
                Signature = scheme.Sign(signer, domain, canonical)
            })
            .ToArray();
    }

    public static IReadOnlyList<MembershipSignerDescriptor> OfflineRoots() =>
        Enumerable.Range(0, 5)
            .Select(index => Descriptor(0x10 + index * 16, 0x40 + index * 32, MembershipSignerRole.OfflineRoot))
            .ToArray();

    public static IReadOnlyList<MembershipSignerDescriptor> OnlineSigners() =>
        Enumerable.Range(0, 3)
            .Select(index => Descriptor(0xa0 + index * 16, 0x100 + index * 32, MembershipSignerRole.Online))
            .ToArray();

    public static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private static MembershipSignerDescriptor Descriptor(
        int signerStart,
        int keyStart,
        MembershipSignerRole role) =>
        new()
        {
            SignerId = Range(signerStart, MembershipLimits.SignerIdLength),
            Role = role,
            PublicKey = Range(keyStart, MembershipLimits.PublicKeyLength)
        };
}
