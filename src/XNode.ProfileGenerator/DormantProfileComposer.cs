using System.Buffers;
using Deep.Protocol.DeepExtension.Membership;

namespace XNode.ProfileGenerator;

public static class DormantProfileComposer
{
    public const string Status =
        "DORMANT-PROFILE-COMPOSER-GO / PRODUCTION-SIGNER-NO-GO / " +
        "CLIENT-VERIFIER-NO-GO / SELF-HOSTED-RUNTIME-NO-GO";

    public static DormantProfileDocument Compose(
        ProfileAssemblyInput input,
        ProfileVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        if (input is null || options is null || verifier is null)
            throw ProfileErrors.InvalidInput();

        try
        {
            return ComposeCore(input, options, verifier);
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

    private static DormantProfileDocument ComposeCore(
        ProfileAssemblyInput input,
        ProfileVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        var canonicalGenesis = input.GenesisSpan.ToArray();
        var genesis = MembershipContractCodec.DecodeGenesis(canonicalGenesis);
        if (!MembershipContractCodec.EncodeGenesis(genesis).AsSpan().SequenceEqual(canonicalGenesis))
            throw ProfileErrors.Verification();
        if (genesis.Policy.OfflineThreshold != 3 ||
            genesis.OfflineRoots.Count != 5 ||
            genesis.Policy.OnlineThreshold != 2 ||
            genesis.Policy.OnlineSignerCount != 3)
            throw ProfileErrors.Verification();

        var genesisSignatures = input.GenesisSignatureValues
            .Select(static value => value.ToP04())
            .OrderBy(static value => value.SignerId, MemoryComparer.Instance)
            .ToArray();
        RequireExactSignatures(
            genesisSignatures,
            genesis.Policy.OfflineThreshold,
            MembershipSignatureDomain.Genesis);
        var genesisHash = MembershipContractHash.Sha256(canonicalGenesis);
        _ = MembershipContractVerifier.ImportSelfHostedGenesis(
            canonicalGenesis,
            genesis.NetworkId.Span,
            genesisHash,
            genesisSignatures,
            verifier);

        var delegationBytes = input.DelegationSpan.ToArray();
        var delegation = MembershipContractCodec.DecodeSignedDelegation(delegationBytes);
        RequireExactSignatures(
            delegation.Signatures,
            genesis.Policy.OfflineThreshold,
            MembershipSignatureDomain.OfflineDelegation);
        var genesisLastKnownGood = new MembershipLastKnownGood
        {
            NetworkId = genesis.NetworkId.ToArray(),
            PolicyVersion = genesis.PolicyVersion,
            Sequence = genesis.GenesisSequence,
            CanonicalHash = genesisHash
        };
        var verifiedDelegation = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            genesisLastKnownGood,
            options.VerificationTimeUnixSeconds,
            options.AllowedClockSkewSeconds,
            options.Protocol,
            verifier);

        if (input.BridgeValues.Count == 0)
            throw ProfileErrors.InvalidInput();
        var bridges = input.BridgeValues
            .Select(static bytes => new DecodedBridge(
                bytes.ToArray(),
                MembershipContractCodec.DecodeSignedBridge(bytes)))
            .OrderBy(static value => value.Signed.Statement.Sequence)
            .ThenBy(static value => value.Canonical, MemoryComparer.Instance)
            .ToArray();
        if (bridges.Select(static value => Convert.ToHexString(value.Canonical))
            .Distinct(StringComparer.Ordinal).Count() != bridges.Length)
            throw ProfileErrors.InvalidInput();

        var lastKnownGood = genesisLastKnownGood;
        foreach (var bridge in bridges)
        {
            RequireExactSignatures(
                bridge.Signed.Signatures,
                genesis.Policy.OnlineThreshold,
                MembershipSignatureDomain.Bridge);
            var context = new MembershipVerificationContext
            {
                Genesis = genesis,
                ActiveDelegation = delegation,
                AuthorityLastKnownGood = verifiedDelegation.NextAuthorityLastKnownGood,
                RevokedDelegationHashes = [],
                LastKnownGood = lastKnownGood,
                VerificationTimeUnixSeconds = options.VerificationTimeUnixSeconds,
                AllowedClockSkewSeconds = options.AllowedClockSkewSeconds,
                ClientProtocol = options.Protocol
            };
            lastKnownGood = MembershipContractVerifier.VerifyBridge(
                bridge.Signed,
                context,
                verifier).NextLastKnownGood;
        }

        var components = new List<ProfileComponent>(3 + bridges.Length)
        {
            new(ProfileComponentKind.CanonicalGenesis, canonicalGenesis),
            new(ProfileComponentKind.GenesisApprovals, EncodeGenesisApprovals(genesisSignatures)),
            new(ProfileComponentKind.SignedDelegation, delegationBytes)
        };
        components.AddRange(bridges.Select(static value =>
            new ProfileComponent(ProfileComponentKind.SignedBridge, value.Canonical)));

        var filePayload = ProfileFraming.Encode(components);
        var fingerprint =
            $"sha256:{Convert.ToHexString(genesisHash).ToLowerInvariant()}";
        var compatibility =
            $"protocol:{genesis.MinimumProtocol}-{genesis.MaximumProtocol}";
        var display =
            $"self-hosted {fingerprint.AsSpan(7, 16)} {compatibility} sources:{bridges.Length}";
        if (!ProfileComposerLimits.IsDerivedLabelLengthAllowed(fingerprint) ||
            !ProfileComposerLimits.IsDerivedLabelLengthAllowed(compatibility) ||
            !ProfileComposerLimits.IsDerivedLabelLengthAllowed(display))
            throw ProfileErrors.Bounds();

        var qrText = DormantProfileQr.EncodeOrNull(filePayload);
        return new DormantProfileDocument(
            filePayload,
            qrText,
            fingerprint,
            compatibility,
            display,
            components.Count);
    }

    internal static byte[] EncodeGenesisApprovals(
        IReadOnlyList<MembershipSignature> signatures)
    {
        var estimatedLength = 1 + signatures.Sum(static signature =>
            1 + MembershipLimits.SignerIdLength + 2 + signature.Signature.Length);
        var writer = new ArrayBufferWriter<byte>(estimatedLength);
        WriteByte(writer, checked((byte)signatures.Count));
        foreach (var signature in signatures
                     .OrderBy(static value => value.SignerId, MemoryComparer.Instance))
        {
            WriteByte(writer, (byte)signature.Domain);
            Write(writer, signature.SignerId.Span);
            WriteVarUInt(writer, checked((uint)signature.Signature.Length));
            Write(writer, signature.Signature.Span);
        }
        return writer.WrittenSpan.ToArray();
    }

    internal static IReadOnlyList<ProfilePublicSignature> DecodeGenesisApprovals(
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is 0 or > ProfileComposerLimits.MaximumComponentBytes)
            throw ProfileErrors.Framing();
        var offset = 0;
        var count = encoded[offset++];
        if (count == 0 || count > MembershipLimits.MaximumSigners)
            throw ProfileErrors.Framing();
        var result = new ProfilePublicSignature[count];
        ReadOnlySpan<byte> previousSigner = default;
        for (var index = 0; index < count; index++)
        {
            if (encoded.Length - offset < 1 + MembershipLimits.SignerIdLength)
                throw ProfileErrors.Framing();
            var domain = (MembershipSignatureDomain)encoded[offset++];
            var signerId = encoded.Slice(offset, MembershipLimits.SignerIdLength);
            offset += MembershipLimits.SignerIdLength;
            if (index > 0 && MemoryComparer.Compare(previousSigner, signerId) >= 0)
                throw ProfileErrors.Framing();
            var signatureLength = ReadVarUInt(encoded, ref offset);
            if (signatureLength is < MembershipLimits.MinimumSignatureLength
                or > MembershipLimits.MaximumSignatureLength ||
                encoded.Length - offset < signatureLength)
                throw ProfileErrors.Framing();
            var signature = encoded.Slice(offset, signatureLength);
            offset += signatureLength;
            result[index] = new ProfilePublicSignature(signerId, domain, signature);
            previousSigner = signerId;
        }
        if (offset != encoded.Length)
            throw ProfileErrors.Framing();
        return result;
    }

    private static void RequireExactSignatures(
        IReadOnlyList<MembershipSignature> signatures,
        int exactCount,
        MembershipSignatureDomain domain)
    {
        if (signatures is null ||
            signatures.Count != exactCount ||
            signatures.Any(signature => signature is null || signature.Domain != domain) ||
            signatures.Select(static signature => Convert.ToHexString(signature.SignerId.Span))
                .Distinct(StringComparer.Ordinal).Count() != exactCount)
            throw ProfileErrors.Verification();
    }

    private static int ReadVarUInt(ReadOnlySpan<byte> source, ref int offset)
    {
        uint value = 0;
        var shift = 0;
        var count = 0;
        while (true)
        {
            if (offset >= source.Length || count == 5)
                throw ProfileErrors.Framing();
            var current = source[offset++];
            count++;
            if (count == 5 && (current & 0xf0) != 0)
                throw ProfileErrors.Framing();
            value |= (uint)(current & 0x7f) << shift;
            if ((current & 0x80) == 0)
            {
                if (count > 1 && current == 0)
                    throw ProfileErrors.Framing();
                return checked((int)value);
            }
            shift += 7;
        }
    }

    private static void WriteVarUInt(IBufferWriter<byte> writer, uint value)
    {
        do
        {
            var next = (byte)(value & 0x7f);
            value >>= 7;
            if (value != 0)
                next |= 0x80;
            WriteByte(writer, next);
        } while (value != 0);
    }

    private static void WriteByte(IBufferWriter<byte> writer, byte value)
    {
        var span = writer.GetSpan(1);
        span[0] = value;
        writer.Advance(1);
    }

    private static void Write(IBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private sealed record DecodedBridge(byte[] Canonical, SignedBridgeSnapshot Signed);

    private sealed class MemoryComparer : IComparer<ReadOnlyMemory<byte>>, IComparer<byte[]>
    {
        public static MemoryComparer Instance { get; } = new();

        public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) =>
            Compare(x.Span, y.Span);

        public int Compare(byte[]? x, byte[]? y) =>
            (x ?? []).AsSpan().SequenceCompareTo((y ?? []).AsSpan());

        public static int Compare(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y) =>
            x.SequenceCompareTo(y);
    }
}
