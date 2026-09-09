using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace XNode;

/// <summary>
/// One current recipient candidate rebuilt exclusively from a Protocol-minted
/// resolve closure and the current network authority. The publication verifier
/// remains responsible for matching the exact XPI1 service/device/DMD/XPS
/// lineage; this value is never selected by raw metadata.
/// </summary>
internal sealed record ContactPreKeyRecipientAuthorityCandidate(
    VerifiedContactBundleClosure Bundle,
    VerifiedContactNetworkAuthority Authority);

internal interface IContactPreKeyRecipientAuthoritySource
{
    ValueTask<IReadOnlyList<ContactPreKeyRecipientAuthorityCandidate>>
        ReadCurrentCandidatesAsync(
            ReadOnlyMemory<byte> networkId,
            CancellationToken cancellationToken);
}

internal sealed class ProtocolContactPreKeyRecipientAuthoritySource(
    IContactPreKeyRecipientResolveEvidenceSource evidence,
    IContactRouteRecipientEvidenceProjector projector,
    IContactRouteCurrentNetworkAuthoritySource currentAuthorities,
    IContactRouteNetworkAuthorityVerifier authorityVerifier)
    : IContactPreKeyRecipientAuthoritySource
{
    private readonly IContactPreKeyRecipientResolveEvidenceSource evidence =
        evidence ?? throw new ArgumentNullException(nameof(evidence));
    private readonly IContactRouteRecipientEvidenceProjector projector =
        projector ?? throw new ArgumentNullException(nameof(projector));
    private readonly IContactRouteCurrentNetworkAuthoritySource currentAuthorities =
        currentAuthorities ?? throw new ArgumentNullException(nameof(currentAuthorities));
    private readonly IContactRouteNetworkAuthorityVerifier authorityVerifier =
        authorityVerifier ?? throw new ArgumentNullException(nameof(authorityVerifier));

    public async ValueTask<IReadOnlyList<ContactPreKeyRecipientAuthorityCandidate>>
        ReadCurrentCandidatesAsync(
            ReadOnlyMemory<byte> networkId,
            CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var current = await currentAuthorities
            .ReadCurrentRouteAuthorityAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!Same(current.NetworkId.Span, networkId.Span))
        {
            return Array.Empty<ContactPreKeyRecipientAuthorityCandidate>();
        }

        var retained = await evidence.ReadCurrentCandidatesAsync(networkId, cancellationToken)
            .ConfigureAwait(false);
        var output = new List<ContactPreKeyRecipientAuthorityCandidate>(retained.Count);
        foreach (var candidate in retained)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var recipient = await projector.VerifyCurrentAsync(
                    candidate.Evidence,
                    networkId,
                    candidate.LocatorHash,
                    cancellationToken)
                .ConfigureAwait(false);
            if (recipient is null)
            {
                continue;
            }

            var authority = await authorityVerifier.VerifyAsync(
                    current, recipient, cancellationToken)
                .ConfigureAwait(false);
            if (!Same(authority.NetworkId.Span, networkId.Span)
                || authority.AuthorityGeneration != current.AuthorityGeneration
                || authority.TrustedLowerUnixSeconds != current.TrustedLowerUnixSeconds
                || authority.TrustedUpperUnixSeconds != current.TrustedUpperUnixSeconds)
            {
                throw new InvalidDataException(
                    "A pre-key recipient candidate does not bind the current authority snapshot.");
            }
            output.Add(new(candidate.Evidence.Contact, authority));
        }
        return output.AsReadOnly();
    }

    private static bool Same(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}
