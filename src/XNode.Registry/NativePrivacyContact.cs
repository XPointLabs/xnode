namespace XNode.Registry;

public interface ILocalPrivacyContactProvider
{
    NativePrivacyContact Create();
}

public sealed record NativePrivacyContact(
    string RouterId,
    string X25519PublicKey,
    string PeerEndpoint,
    IReadOnlyList<string> Capabilities,
    long SignedAtUnixSeconds,
    long ExpiresAtUnixSeconds,
    string Signature);
