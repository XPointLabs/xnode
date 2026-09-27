using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>
/// UAT-only final DID2 inventory commit. No receipt is signed before the
/// replica independently refreshes current DID2/device authority and exact
/// NETCODEC placement, then durably advances service-capability lineage.
/// A single XIC1 is not sufficient to enable a claim.
/// </summary>
internal sealed class DeepIdV2PublicationFinalCommitter(
    RouterNodeOptions node,
    DeepIdV2PublicationCandidateAuthority candidates,
    IDeepIdV2PreKeyPlacementSource placements,
    IOnionMonotonicClock clock,
    IMailboxStorageSecurity security,
    IMailboxDurabilityBarrier durability)
{
    private readonly RouterNodeOptions node = node ??
        throw new ArgumentNullException(nameof(node));
    private readonly DeepIdV2PublicationCandidateAuthority candidates = candidates ??
        throw new ArgumentNullException(nameof(candidates));
    private readonly IDeepIdV2PreKeyPlacementSource placements = placements ??
        throw new ArgumentNullException(nameof(placements));
    private readonly IOnionMonotonicClock clock = clock ??
        throw new ArgumentNullException(nameof(clock));
    private readonly IMailboxStorageSecurity security = security ??
        throw new ArgumentNullException(nameof(security));
    private readonly IMailboxDurabilityBarrier durability = durability ??
        throw new ArgumentNullException(nameof(durability));

    internal async ValueTask<ParsedXic1V2> CommitAsync(
        DeepIdV2PublicationJournal journal,
        ContactServicePlacementCapability claimedPlacement,
        RouterId? authenticatedSender,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(journal);
        ArgumentNullException.ThrowIfNull(claimedPlacement);
        // The authenticated wire request necessarily carries an untrusted
        // projection. Only the independently re-minted placement below may
        // authorize a receipt; the projection must match it byte-for-byte.
        var verified = await candidates.VerifyCommittedCandidateAsync(journal,
            cancellationToken).ConfigureAwait(false);
        var publication = verified.Publication;
        var serviceCapability = publication.Manifest.Field(2);
        var current = await placements.MintPreKeyPublicationAsync(
            verified.PublisherDid2, serviceCapability, cancellationToken)
            .ConfigureAwait(false);
        _ = current.VerifiedPlacement;
        ContactReplicaRequestReceiver.EnsureExactPlacement(claimedPlacement,
            current);
        var localId = node.GetRouterId().ToBytes();
        if (current.RequestKind !=
                ContactServiceRequestKind.PublishPreKeyInventory ||
            !current.VerifiedPlacement.Binds(
                ContactServiceRequestKind.PublishPreKeyInventory,
                serviceCapability) ||
            !Fixed(current.NetworkId.Span, publication.NetworkId.Span) ||
            !Fixed(current.PlacementHash.Span,
                publication.PlacementHash.Span) ||
            !Fixed(current.ShardKey.Span, serviceCapability.Span) ||
            !current.ContainsReplica(localId) ||
            (authenticatedSender is { } peer &&
             !Fixed(current.OtherReplica(localId), peer.ToBytes())))
            throw new UnauthorizedAccessException(
                "DID2 final commit differs from current selected placement.");

        var now = await clock.ReadAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new CryptographicException(
                "The DID2 final commit monotonic clock is unavailable.");
        var refreshed = DeepIdV2CurrentContactAuthorizationVerifier.Verify(
            verified.CurrentAuthorization.Freshness,
            verified.CurrentAuthorization.Authorization,
            now.BootId.Span, now.SampleSeconds);
        current.VerifiedPlacement.Network.EnsureCurrent();
        current.EnsureUsable(refreshed.TrustedUpperUnixSeconds);
        var notBefore = BinaryPrimitives.ReadUInt64BigEndian(
            publication.Manifest.Field(14).Span);
        var expiresAt = BinaryPrimitives.ReadUInt64BigEndian(
            publication.Manifest.Field(15).Span);
        if (refreshed.TrustedLowerUnixSeconds < notBefore ||
            refreshed.TrustedUpperUnixSeconds >= expiresAt)
            throw new CryptographicException(
                "DID2 final commit is outside the signed inventory interval.");

        var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
        try
        {
            var signer = PublicKeyAuth.GenerateKeyPair(seed);
            try
            {
                if (!Fixed(signer.PublicKey, localId))
                    throw new CryptographicException(
                        "DID2 final receipt signer is not the selected local node.");
                using var store = new DeepIdV2InventoryCommitStore(
                    node.DataDirectory, publication.NetworkId.Span,
                    serviceCapability.Span, localId, security, durability);
                return store.CommitAuthorized(publication,
                    refreshed.TrustedLowerUnixSeconds,
                    input => PublicKeyAuth.SignDetached(input,
                        signer.PrivateKey));
            }
            finally { CryptographicOperations.ZeroMemory(signer.PrivateKey); }
        }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
