using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.ContactPreKey;

namespace XNode;

internal sealed record DeepIdV2VerifiedPublicationCandidate(
    ParsedXpp1V2 Publication, ParsedDid2 PublisherDid2,
    DeepIdV2CurrentContactAuthorization CurrentAuthorization);

/// <summary>
/// Joins a durably reassembled XPP1 candidate to a recipient-specific,
/// nonce-bound current DID2 proof and signed public DCA1/XPS1/XPI1 support.
/// The selected replica never opens the encrypted DCR1 contact object.
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

    internal async ValueTask<DeepIdV2VerifiedPublicationCandidate>
        VerifyCommittedCandidateAsync(
        DeepIdV2PublicationJournal journal,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(journal);
        var staged = journal.ReadCommitted();
        if (staged is not
            { Disposition: PublicationStageDisposition.CandidateReady,
              Candidate: not null, PublisherDid2: not null } ||
            staged.PublisherDca1.Length !=
                DeepIdV2ContactAuthorizationCodec.CanonicalLength ||
            staged.PublisherXps1.Length !=
                DeepIdV2BoundedPreKeyPublicationCodec.Xps1Length)
            throw new InvalidOperationException(
                "DID2 publication candidate is not durably complete.");

        // Reject malformed public support before a network proof request.
        var dca = DeepIdV2ContactAuthorizationCodec.Decode(
            staged.PublisherDca1.Span);

        var freshness = await proofs.ReadCurrentAsync(staged.PublisherDid2,
            cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException(
                "The current DID2 directory proof is absent.");
        var checkpoint = freshness.CurrentCheckpoint ??
            throw new CryptographicException(
                "DID2 publication needs the exact current account checkpoint.");
        var authorization = DeepIdV2ContactAuthorizationCodec.Verify(
            dca, checkpoint.Binding, checkpoint.Directory);
        var now = await clock.ReadAsync(cancellationToken)
            .ConfigureAwait(false) ??
            throw new CryptographicException(
                "The DID2 monotonic clock is unavailable.");
        var current = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            freshness, authorization, now.BootId.Span, now.SampleSeconds);
        DeepIdV2ReplicaPreKeyInventoryVerifier.VerifyComplete(
            staged.PublisherDid2, staged.PublisherXps1.Span,
            current, staged.Candidate,
            now.BootId.Span, now.SampleSeconds);
        return new DeepIdV2VerifiedPublicationCandidate(staged.Candidate,
            staged.PublisherDid2, current);
    }
}
