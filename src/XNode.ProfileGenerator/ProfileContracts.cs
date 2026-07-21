using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace XNode.ProfileGenerator;

public static class ProfileComposerLimits
{
    public const int MaximumFilePayloadBytes = ProfileCarrierLimits.MaximumFilePayloadBytes;
    public const int MaximumComponentBytes = ProfileCarrierLimits.MaximumComponentBytes;
    public const int MaximumComponents = ProfileCarrierLimits.MaximumComponents;
    public const int RequiredNonBridgeComponents = ProfileCarrierLimits.RequiredNonBridgeComponents;
    public const int MaximumQrTextCharacters = 2_048;
    public const int MaximumDerivedLabelUtf8Bytes = 96;

    public static bool IsFilePayloadLengthAllowed(int length) =>
        length is >= 0 and <= MaximumFilePayloadBytes;

    public static bool IsQrTextLengthAllowed(int length) =>
        length is >= 0 and <= MaximumQrTextCharacters;

    public static bool IsDerivedLabelLengthAllowed(string? value) =>
        value is not null &&
        Encoding.UTF8.GetByteCount(value) <= MaximumDerivedLabelUtf8Bytes;
}

public sealed class ProfileContractException(string message) : Exception(message);

[JsonConverter(typeof(ProfilePublicSignatureJsonConverter))]
public sealed class ProfilePublicSignature
{
    private readonly byte[] _signerId;
    private readonly byte[] _signature;

    public ProfilePublicSignature(
        ReadOnlySpan<byte> signerId,
        MembershipSignatureDomain domain,
        ReadOnlySpan<byte> signature)
    {
        if (signerId.Length != MembershipLimits.SignerIdLength)
            throw ProfileErrors.InvalidInput();
        if (signature.Length is < MembershipLimits.MinimumSignatureLength
            or > MembershipLimits.MaximumSignatureLength)
            throw ProfileErrors.InvalidInput();
        _signerId = signerId.ToArray();
        Domain = domain;
        _signature = signature.ToArray();
    }

    [JsonIgnore]
    public ReadOnlyMemory<byte> SignerId => _signerId.ToArray();

    public MembershipSignatureDomain Domain { get; }

    [JsonIgnore]
    public ReadOnlyMemory<byte> Signature => _signature.ToArray();

    internal MembershipSignature ToP04() =>
        new()
        {
            SignerId = _signerId.ToArray(),
            Domain = Domain,
            Signature = _signature.ToArray()
        };

    internal ReadOnlySpan<byte> SignerIdSpan => _signerId;
    internal ReadOnlySpan<byte> SignatureSpan => _signature;

    public override string ToString() => nameof(ProfilePublicSignature);
}

public sealed class ProfileAssemblyInput
{
    private readonly byte[] _canonicalGenesis;
    private readonly ProfilePublicSignature[] _genesisSignatures;
    private readonly byte[] _canonicalSignedDelegation;
    private readonly byte[][] _canonicalSignedBridges;

    public ProfileAssemblyInput(
        ReadOnlyMemory<byte> canonicalGenesis,
        IEnumerable<ProfilePublicSignature> genesisSignatures,
        ReadOnlyMemory<byte> canonicalSignedDelegation,
        IEnumerable<ReadOnlyMemory<byte>> canonicalSignedBridges)
    {
        _canonicalGenesis = CopyBoundedComponent(canonicalGenesis);
        _canonicalSignedDelegation = CopyBoundedComponent(canonicalSignedDelegation);
        _genesisSignatures = CopySignatures(genesisSignatures);
        _canonicalSignedBridges = CopyBridges(canonicalSignedBridges);
    }

    [JsonIgnore]
    public ReadOnlyMemory<byte> CanonicalGenesis => _canonicalGenesis.ToArray();

    [JsonIgnore]
    public IReadOnlyList<ProfilePublicSignature> GenesisSignatures =>
        _genesisSignatures
            .Select(static value => new ProfilePublicSignature(
                value.SignerIdSpan,
                value.Domain,
                value.SignatureSpan))
            .ToArray();

    [JsonIgnore]
    public ReadOnlyMemory<byte> CanonicalSignedDelegation => _canonicalSignedDelegation.ToArray();

    [JsonIgnore]
    public IReadOnlyList<ReadOnlyMemory<byte>> CanonicalSignedBridges =>
        _canonicalSignedBridges
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
            .ToArray();

    public int GenesisSignatureCount => _genesisSignatures.Length;
    public int BridgeCount => _canonicalSignedBridges.Length;

    public ProfileAssemblyInput WithGenesisSignatures(
        IEnumerable<ProfilePublicSignature> signatures) =>
        new(_canonicalGenesis, signatures, _canonicalSignedDelegation, BridgeMemories());

    public ProfileAssemblyInput WithDelegation(ReadOnlyMemory<byte> signedDelegation) =>
        new(_canonicalGenesis, _genesisSignatures, signedDelegation, BridgeMemories());

    public ProfileAssemblyInput WithBridges(IEnumerable<ReadOnlyMemory<byte>> signedBridges) =>
        new(_canonicalGenesis, _genesisSignatures, _canonicalSignedDelegation, signedBridges);

    internal ReadOnlySpan<byte> GenesisSpan => _canonicalGenesis;
    internal IReadOnlyList<ProfilePublicSignature> GenesisSignatureValues => _genesisSignatures;
    internal ReadOnlySpan<byte> DelegationSpan => _canonicalSignedDelegation;
    internal IReadOnlyList<byte[]> BridgeValues => _canonicalSignedBridges;

    internal ProfileCarrierAssemblyInput ToCarrier() =>
        new(
            _canonicalGenesis,
            _genesisSignatures.Select(static value => value.ToP04()),
            _canonicalSignedDelegation,
            _canonicalSignedBridges.Select(static value => (ReadOnlyMemory<byte>)value));

    public override string ToString() =>
        $"{nameof(ProfileAssemblyInput)} signatures={GenesisSignatureCount} bridges={BridgeCount}";

    private IEnumerable<ReadOnlyMemory<byte>> BridgeMemories() =>
        _canonicalSignedBridges.Select(static value => (ReadOnlyMemory<byte>)value);

    private static byte[] CopyBoundedComponent(ReadOnlyMemory<byte> component)
    {
        if (component.Length > ProfileComposerLimits.MaximumComponentBytes)
            throw ProfileErrors.Bounds();
        return component.ToArray();
    }

    private static ProfilePublicSignature[] CopySignatures(
        IEnumerable<ProfilePublicSignature> values)
    {
        if (values is null)
            throw ProfileErrors.InvalidInput();
        var result = new List<ProfilePublicSignature>(5);
        foreach (var value in values)
        {
            if (value is null || result.Count == MembershipLimits.MaximumSigners)
                throw ProfileErrors.Bounds();
            result.Add(new ProfilePublicSignature(
                value.SignerIdSpan,
                value.Domain,
                value.SignatureSpan));
        }
        return result.ToArray();
    }

    private static byte[][] CopyBridges(IEnumerable<ReadOnlyMemory<byte>> values)
    {
        if (values is null)
            throw ProfileErrors.InvalidInput();
        var maximum = ProfileComposerLimits.MaximumComponents -
            ProfileComposerLimits.RequiredNonBridgeComponents;
        var result = new List<byte[]>(maximum);
        foreach (var value in values)
        {
            if (result.Count == maximum)
                throw ProfileErrors.Bounds();
            result.Add(CopyBoundedComponent(value));
        }
        return result.ToArray();
    }
}

public sealed class ProfileVerificationOptions
{
    public ProfileVerificationOptions(
        ulong verificationTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocol)
    {
        VerificationTimeUnixSeconds = verificationTimeUnixSeconds;
        AllowedClockSkewSeconds = allowedClockSkewSeconds;
        Protocol = protocol;
    }

    public ulong VerificationTimeUnixSeconds { get; }
    public uint AllowedClockSkewSeconds { get; }
    public ushort Protocol { get; }

    internal ProfileCarrierVerificationOptions ToCarrier() =>
        new(VerificationTimeUnixSeconds, AllowedClockSkewSeconds, Protocol);

    public override string ToString() => nameof(ProfileVerificationOptions);
}

public sealed class DormantProfileDocument
{
    private readonly byte[] _filePayload;

    internal DormantProfileDocument(
        byte[] filePayload,
        string? qrText,
        string fingerprint,
        string compatibility,
        string displaySummary,
        int componentCount)
    {
        _filePayload = filePayload.ToArray();
        QrText = qrText;
        Fingerprint = fingerprint;
        Compatibility = compatibility;
        DisplaySummary = displaySummary;
        ComponentCount = componentCount;
    }

    [JsonIgnore]
    public ReadOnlyMemory<byte> FilePayload => _filePayload.ToArray();

    [JsonIgnore]
    public string? QrText { get; }

    public string Fingerprint { get; }
    public string Compatibility { get; }
    public string DisplaySummary { get; }
    public int ComponentCount { get; }

    public override string ToString() => DisplaySummary;
}

internal static class ProfileErrors
{
    public static ProfileContractException InvalidInput() =>
        new("The dormant profile input is invalid.");

    public static ProfileContractException Bounds() =>
        new("A dormant profile bound was exceeded.");

    public static ProfileContractException Verification() =>
        new("P04 rejected a dormant profile artifact.");

    public static ProfileContractException Framing() =>
        new("The dormant profile framing is invalid.");

    public static ProfileContractException FromCarrier(ProfileCarrierException exception) =>
        exception.Error switch
        {
            ProfileCarrierError.InvalidInput => InvalidInput(),
            ProfileCarrierError.BoundsExceeded => Bounds(),
            ProfileCarrierError.InvalidFraming => Framing(),
            ProfileCarrierError.VerificationRejected => Verification(),
            _ => Verification()
        };
}

internal static class DormantProfileDocumentFactory
{
    public static DormantProfileDocument Create(
        ReadOnlySpan<byte> filePayload,
        string fingerprint,
        ushort minimumProtocol,
        ushort maximumProtocol,
        int componentCount,
        int bridgeCount)
    {
        var compatibility = $"protocol:{minimumProtocol}-{maximumProtocol}";
        var display =
            $"self-hosted {fingerprint.AsSpan(7, 16)} {compatibility} sources:{bridgeCount}";
        if (!ProfileComposerLimits.IsDerivedLabelLengthAllowed(fingerprint) ||
            !ProfileComposerLimits.IsDerivedLabelLengthAllowed(compatibility) ||
            !ProfileComposerLimits.IsDerivedLabelLengthAllowed(display))
        {
            throw ProfileErrors.Bounds();
        }

        var payload = filePayload.ToArray();
        return new DormantProfileDocument(
            payload,
            DormantProfileQr.EncodeOrNull(payload),
            fingerprint,
            compatibility,
            display,
            componentCount);
    }
}

internal sealed class ProfilePublicSignatureJsonConverter :
    JsonConverter<ProfilePublicSignature>
{
    public override ProfilePublicSignature Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) =>
        throw new JsonException("Profile signatures cannot be created from JSON.");

    public override void Write(
        Utf8JsonWriter writer,
        ProfilePublicSignature value,
        JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteNumber("domain", (byte)value.Domain);
        writer.WriteEndObject();
    }
}
