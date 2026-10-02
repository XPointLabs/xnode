using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactResolver;

namespace XNode;

/// <summary>
/// Mints the exact two-replica Contact placement from a complete, current
/// NETCODEC capability. No raw XNV/PMT projection can enter this adapter.
/// </summary>
internal sealed class VerifiedContactServicePlacementAuthoritySource(
    IDeepIdV2ContactStoreAuthoritySource snapshots,
    IOnionMonotonicClock clock) : IContactServicePlacementAuthoritySource
{
    private readonly IDeepIdV2ContactStoreAuthoritySource snapshots =
        snapshots ?? throw new ArgumentNullException(nameof(snapshots));
    private readonly IOnionMonotonicClock clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async ValueTask<ContactServicePlacementCapability> MintAsync(
        ContactServiceRequestKind requestKind,
        ReadOnlyMemory<byte> shardKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRequest(requestKind, shardKey.Span);

        var snapshot = await snapshots.ReadPublicationAuthorityAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "The Contact directory authority returned no current snapshot.");
        snapshot.Network.EnsureCurrent();
        var verified = ContactServicePlacementFactory.Create(
            snapshot.Network,
            requestKind,
            shardKey);
        var reading = await clock.ReadAsync(cancellationToken).ConfigureAwait(false) ??
            throw new CryptographicException("Contact placement monotonic time is unavailable.");
        if (!snapshot.Freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("Contact placement proof is no longer current.");
        var upper = checked(snapshot.Freshness.TrustedUpperUnixSeconds +
            checked(reading.SampleSeconds - snapshot.Freshness.MonotonicSample));
        snapshot.Network.EnsureCurrent();
        return ContactServicePlacementCapability.FromNetcodec(
            verified,
            requestKind,
            shardKey,
            upper);
    }

    private static void ValidateRequest(
        ContactServiceRequestKind requestKind,
        ReadOnlySpan<byte> shardKey)
    {
        if (!Enum.IsDefined(requestKind))
        {
            throw new ArgumentOutOfRangeException(nameof(requestKind));
        }
        if (shardKey.Length != 32 || shardKey.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A Contact placement shard key must be exactly 32 nonzero bytes.",
                nameof(shardKey));
        }
    }
}

/// <summary>
/// Verifies XPA1 only through the Protocol threshold verifier and an atomically
/// supplied current authority/freshness/time snapshot.
/// </summary>
internal sealed class VerifiedContactPublicationAuthorizationVerifier(
    IDeepIdV2ContactStoreAuthoritySource snapshots)
    : IContactPublicationAuthorizationVerifier
{
    private readonly IDeepIdV2ContactStoreAuthoritySource snapshots =
        snapshots ?? throw new ArgumentNullException(nameof(snapshots));

    public async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var snapshot = await snapshots.ReadPublicationAuthorityAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "The Contact directory authority returned no current snapshot.");
        snapshot.Network.EnsureCurrent();
        var placement = ContactServicePlacementFactory.Create(
            snapshot.Network,
            ContactServiceRequestKind.PublishInvite,
            request.LocatorHash);
        return await Xpa1PublicationAuthorizationVerifier.VerifyAsync(
                request,
                snapshot.Authority,
                snapshot.Freshness,
                placement,
                snapshot.TrustedTime,
                cancellationToken)
            .ConfigureAwait(false);
    }
}
