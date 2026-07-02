using XNode.Core;
using XNode.Core.Runtime;
using XNode.Transport.Vless;

namespace XNode.Registry;

public sealed class RegistryRegistrationPayloadFactory
{
    private const int Ed25519PublicKeyBytes = 32;
    private const int Ed25519SignatureBytes = 64;

    private readonly RouterNodeOptions _nodeOptions;
    private readonly VlessTransportOptions _transportOptions;
    private readonly RegistryPayloadFactory _payloadFactory;
    private readonly RegistryRegistrationOptions _registrationOptions;
    private readonly Bls12381RegistrationProofService _proofService;
    private readonly ILocalRelayContactProvider _relayContactProvider;

    public RegistryRegistrationPayloadFactory(
        RouterNodeOptions nodeOptions,
        VlessTransportOptions transportOptions,
        RegistryPayloadFactory payloadFactory,
        RegistryRegistrationOptions registrationOptions,
        Bls12381RegistrationProofService proofService,
        ILocalRelayContactProvider relayContactProvider)
    {
        _nodeOptions = nodeOptions;
        _transportOptions = transportOptions;
        _payloadFactory = payloadFactory;
        _registrationOptions = registrationOptions;
        _proofService = proofService;
        _relayContactProvider = relayContactProvider;
    }

    public async Task<RegistryRegistrationPayload> CreateAsync(CancellationToken cancellationToken)
    {
        var runtime = _payloadFactory.Create();
        var relayContact = _relayContactProvider.Create();
        var operatorAddress = NormalizeAddress(_registrationOptions.OperatorAddress);
        var rewardsAddress = string.IsNullOrWhiteSpace(_registrationOptions.RewardsAddress)
            ? operatorAddress
            : NormalizeAddress(_registrationOptions.RewardsAddress);
        var nodePubkey = NormalizeHex(
            string.IsNullOrWhiteSpace(_registrationOptions.Ed25519PublicKey)
                ? _nodeOptions.RouterId
                : _registrationOptions.Ed25519PublicKey,
            Ed25519PublicKeyBytes);
        var proof = await _proofService.CreateProofAsync(
            _registrationOptions,
            nodePubkey,
            cancellationToken).ConfigureAwait(false);
        var (edSig1, edSig2) = GetEd25519SignatureChunks(_registrationOptions);

        return new RegistryRegistrationPayload(
            NodeId: nodePubkey,
            OperatorAddress: operatorAddress,
            RewardsAddress: rewardsAddress,
            BlsPublicKey: new BlsPublicKey(proof.PublicKey),
            BlsSignature: proof.Signature,
            Ed25519PublicKey: nodePubkey,
            Ed25519Signature1: edSig1,
            Ed25519Signature2: edSig2,
            OperatorFeeBps: _registrationOptions.OperatorFeeBps,
            StakeAtomic: _registrationOptions.StakeAtomic,
            Contributors:
            [
                new ContributorStake(operatorAddress, rewardsAddress, _registrationOptions.StakeAtomic)
            ],
            SigningEndpoint: BuildSigningEndpoint(relayContact.RpcEndpoint),
            TransportStatus: runtime.Transport,
            Transport: ToTransportBundle(runtime),
            RelayContact: relayContact);
    }

    private TransportBundle ToTransportBundle(RegistryPayload payload)
    {
        var security = payload.TransportMode switch
        {
            VlessTransportMode.Reality => "reality",
            VlessTransportMode.Tls => "tls",
            _ => "none"
        };

        return new TransportBundle(
            Protocol: "vless",
            Host: payload.PublicHost,
            Port: payload.PublicPort,
            Uuid: _transportOptions.ClientId,
            Flow: payload.TransportMode == VlessTransportMode.Reality ? "xtls-rprx-vision" : "",
            Security: security,
            Sni: payload.TransportMode == VlessTransportMode.Tls
                ? payload.Tls?.ServerName ?? payload.PublicHost
                : payload.MaskDomain,
            PublicKey: payload.Reality?.PublicKey ?? "",
            ShortId: payload.Reality?.ShortId ?? "",
            Fingerprint: payload.Reality?.Fingerprint ?? "chrome",
            Path: payload.Reality?.SpiderX ?? "/",
            Alpn: payload.Tls?.Alpn ?? Array.Empty<string>());
    }

    private (string First, string Second) GetEd25519SignatureChunks(RegistryRegistrationOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.Ed25519Signature))
        {
            var signature = NormalizeHex(options.Ed25519Signature, Ed25519SignatureBytes);
            return (signature[..64], signature[64..]);
        }

        var first = string.IsNullOrWhiteSpace(options.Ed25519Signature1)
            ? new string('0', 64)
            : NormalizeHex(options.Ed25519Signature1, 32);
        var second = string.IsNullOrWhiteSpace(options.Ed25519Signature2)
            ? new string('0', 64)
            : NormalizeHex(options.Ed25519Signature2, 32);
        return (first, second);
    }

    private static string NormalizeAddress(string address)
    {
        var normalized = Strip0x(address);
        if (normalized.Length != 40 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException("RegistryRegistration:OperatorAddress must be a 20-byte Ethereum address.");
        }

        return "0x" + normalized.ToLowerInvariant();
    }

    private static string BuildSigningEndpoint(string peerRpcEndpoint)
    {
        if (!Uri.TryCreate(peerRpcEndpoint.Trim(), UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException("Relay contact RPC endpoint must be an absolute http(s) URL.");
        }

        var builder = new UriBuilder(uri)
        {
            Path = "/api/staking/quorum/sign",
            Query = ""
        };
        return builder.Uri.ToString().TrimEnd('/');
    }

    private static string NormalizeHex(string value, int expectedBytes)
    {
        var normalized = Strip0x(value).ToLowerInvariant();
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new InvalidOperationException($"Expected {expectedBytes}-byte hex value.");
        }

        return normalized;
    }

    private static string Strip0x(string value) =>
        value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
}
