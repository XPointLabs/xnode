using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;

namespace XNode.Core.ContactResolver;

/// <summary>Structural dispatch scope, never signature or mutation authority.
/// Reusable publication has exactly one dispatch form: a fresh XPL1 lease.
/// The original XPU1 remains the immutable saga, effect and receipt identity.</summary>
internal sealed class ContactPublicationDispatchRequest
{
    private ContactPublicationDispatchRequest(Xpu1Request original,
        ParsedDeepIdV2PublicationLease? lease)
    { OriginalRequest = original; Lease = lease; }

    internal Xpu1Request OriginalRequest { get; }
    internal ParsedDeepIdV2PublicationLease? Lease { get; }
    internal ReadOnlyMemory<byte> CanonicalBytes => Lease?.CanonicalBytes ?? OriginalRequest.CanonicalBytes;
    internal ReadOnlyMemory<byte> NetworkId => OriginalRequest.NetworkId;
    internal ReadOnlyMemory<byte> ViewHash => Lease?.ViewHash ?? OriginalRequest.ViewHash;
    internal ReadOnlyMemory<byte> PlacementHash => Lease?.PlacementHash ?? OriginalRequest.PlacementHash;
    internal ReadOnlyMemory<byte> LocatorHash => OriginalRequest.LocatorHash;
    internal ulong IssuedAtUnixSeconds => Lease?.IssuedAtUnixSeconds ?? OriginalRequest.IssuedAtUnixSeconds;
    internal ulong ExpiresAtUnixSeconds => Lease?.ExpiresAtUnixSeconds ?? OriginalRequest.ExpiresAtUnixSeconds;

    internal static ContactPublicationDispatchRequest Decode(ReadOnlySpan<byte> canonical)
    {
        if (canonical.Length >= 4 && canonical[..4].SequenceEqual("XPL1"u8))
        {
            var lease = DeepIdV2PublicationLeaseCodec.Decode(canonical);
            return new(lease.OriginalRequest, lease);
        }
        var original = Xpu1Codec.Decode(canonical);
        if (original.UsageLimit != 1)
            throw new CryptographicException("Reusable publication requires a fresh publication lease.");
        return new(original, null);
    }

    internal ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        IContactPublicationAuthorizationVerifier verifier, CancellationToken cancellationToken) =>
        Lease is { } lease ? verifier.VerifyLeaseAsync(lease, cancellationToken)
            : verifier.VerifyAsync(OriginalRequest, cancellationToken);
}
