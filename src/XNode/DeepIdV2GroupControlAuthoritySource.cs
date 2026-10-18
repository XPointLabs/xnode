using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;

namespace XNode;

/// <summary>Current control authority derives only from independently verified DID2/NETCODEC custody.</summary>
internal sealed class DeepIdV2GroupControlAuthoritySource(IDeepIdV2ContactStoreAuthoritySource source, IOnionMonotonicClock clock) : IGroupControlAuthoritySource
{
    public async ValueTask<VerifiedGroupControlRequestAuthority> AuthorizeAsync(GroupControlOperation operation,
        GroupRecord exactRequest, CancellationToken cancellationToken)
    {
        if (operation switch { GroupControlOperation.Write => exactRequest is not GroupControlWriteRecord,
            GroupControlOperation.Fetch => exactRequest is not GroupControlQueryRecord, _ => true })
            throw new GroupControlAuthorityUnavailableException();
        var current = await source.ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false);
        var placement = GroupControlPlacementVerifier.CreateForRequest(current.Network, exactRequest);
        var reading = await clock.ReadAsync(cancellationToken).ConfigureAwait(false) ?? throw new GroupControlAuthorityUnavailableException();
        if (!current.Freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds)) throw new GroupControlAuthorityUnavailableException();
        var upper = checked(current.Freshness.TrustedUpperUnixSeconds + reading.SampleSeconds - current.Freshness.MonotonicSample);
        var issued = BinaryPrimitives.ReadUInt64BigEndian(exactRequest.Field(5).Span);
        var expires = BinaryPrimitives.ReadUInt64BigEndian(exactRequest.Field(6).Span);
        if (!exactRequest.Field(1).Span.SequenceEqual(current.Network.NetworkId.Span) ||
            !exactRequest.Field(3).Span.SequenceEqual(placement.ViewHash.Span) ||
            !exactRequest.Field(4).Span.SequenceEqual(placement.PlacementHash.Span) ||
            issued > upper || expires <= upper || expires <= issued || expires - issued > 120 ||
            expires > current.Network.MaximumRecordExpiryUnixSeconds)
            throw new GroupControlAuthorityUnavailableException();
        current.Network.EnsureCurrent();
        return new(operation, current.Network.NetworkId.Span, placement.ViewHash.Span, placement.PlacementHash.Span,
            exactRequest.Field(16).Span, exactRequest.Field(17).Span,
            SHA256.HashData([.. placement.ViewHash.Span, .. placement.PlacementHash.Span]), expires, placement.ReplicaIds);
    }
}
