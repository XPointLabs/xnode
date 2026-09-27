using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.ContactPreKey;

namespace XNode;

/// <summary>
/// Joins a durably reassembled XPP1 candidate to a recipient-specific,
/// nonce-bound current DID2 proof and the complete DCA1/DCR1/XPI1 inventory.
/// This is not replica placement, publication receipt or claim authority.
/// </summary>
internal sealed class DeepIdV2PublicationCandidateAuthority(
    IDeepIdV2CurrentDirectoryProofSource proofs,
    IOnionMonotonicClock clock)
{
    private readonly IDeepIdV2CurrentDirectoryProofSource proofs = proofs ??
        throw new ArgumentNullException(nameof(proofs));
    private readonly IOnionMonotonicClock clock = clock ??
        throw new ArgumentNullException(nameof(clock));

    internal async ValueTask<ParsedXpp1V2> VerifyCommittedCandidateAsync(
        DeepIdV2PublicationJournal journal, ParsedDcr1V2 closure,
        VerifiedDca1V2 authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(authorization);
        var staged = journal.ReadCommitted();
        if (staged is not
            { Disposition: PublicationStageDisposition.CandidateReady,
              Candidate: not null, PublisherDid2: not null })
            throw new InvalidOperationException(
                "DID2 publication candidate is not durably complete.");

        var freshness = await proofs.ReadCurrentAsync(staged.PublisherDid2,
            cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException(
                "The current DID2 directory proof is absent.");
        var now = await clock.ReadAsync(cancellationToken)
            .ConfigureAwait(false) ??
            throw new CryptographicException(
                "The DID2 monotonic clock is unavailable.");
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            freshness, authorization, now.BootId.Span, now.SampleSeconds);
        DeepIdV2PreKeyPublicationAuthorizationVerifier.Verify(
            staged.PublisherDid2, closure, current, staged.Candidate,
            now.BootId.Span, now.SampleSeconds);
        return staged.Candidate;
    }
}
