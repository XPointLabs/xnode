namespace XNode.Core.ContactResolver;

/// <summary>Independent native checkpoint of this exact opaque document only.
/// It is not publication, trusted time, issuer or two-store evidence authority.</summary>
internal interface IContactResolverStateCustody
{
    void RequireNetwork(ReadOnlySpan<byte> networkId16);
    void RequireNewScope(string documentPath);
    void Enroll(string documentPath, ReadOnlySpan<byte> expectedSha256, long expectedLength);
    void Recover(string documentPath, Action<string> validateDocument);
    void RequireSnapshot(string documentPath);
    void RequireDocumentSnapshot(string documentPath, ReadOnlySpan<byte> sha256, long length);
    void Prepare(string documentPath, string temporaryPath, ReadOnlySpan<byte> expectedSha256, long expectedLength);
    void Commit(string documentPath);
}
