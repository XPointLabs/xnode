using XNode.Core;

namespace XNode.Registry;

public sealed record RegistryRegistrationPayload(
    string NodeId,
    string OperatorAddress,
    string RewardsAddress,
    BlsPublicKey BlsPublicKey,
    string BlsSignature,
    string Ed25519PublicKey,
    string Ed25519Signature1,
    string Ed25519Signature2,
    int OperatorFeeBps,
    long StakeAtomic,
    IReadOnlyList<ContributorStake> Contributors,
    string SigningEndpoint,
    TransportMetadata TransportStatus,
    TransportBundle Transport,
    RelayContact RelayContact);

public sealed record BlsPublicKey(string Data);

public sealed record ContributorStake(
    string Address,
    string Beneficiary,
    long AmountAtomic);

public sealed record TransportBundle(
    string Protocol,
    string Host,
    int Port,
    string Uuid,
    string Flow,
    string Security,
    string Sni,
    string PublicKey,
    string ShortId,
    string Fingerprint,
    string Path,
    IReadOnlyList<string> Alpn);
