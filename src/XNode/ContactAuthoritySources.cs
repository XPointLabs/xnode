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
/// One atomically observed set of Protocol-owned authority capabilities. The
/// eventual directory runtime is responsible for producing it from an exact
/// XNA1/XVP1/XNV1/XNH1/XND1/PMT2/ADH1/DTT1 closure and protected LKG state.
/// </summary>
internal sealed record ContactVerifiedAuthoritySnapshot(
    VerifiedOnionNetworkContext Network,
    VerifiedXPointNetworkAuthority Authority,
    VerifiedAccountDirectoryFreshness DirectoryFreshness,
    OnionTrustedTimeAuthority TrustedTimeAuthority)
{
    internal void EnsureConsistent()
    {
        ArgumentNullException.ThrowIfNull(Network);
        ArgumentNullException.ThrowIfNull(Authority);
        ArgumentNullException.ThrowIfNull(DirectoryFreshness);
        ArgumentNullException.ThrowIfNull(TrustedTimeAuthority);
        Network.EnsureCurrent();
        if (!Fixed(Network.NetworkId.Span, Authority.NetworkId.Span)
            || !Fixed(Network.NetworkId.Span, DirectoryFreshness.NetworkId.Span))
        {
            throw new InvalidOperationException(
                "The Contact authority snapshot spans different networks.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Production seam for the directory authority runtime. Implementations must
/// return only Protocol-minted capabilities from one current durable snapshot;
/// this interface is not a raw-artifact or caller-key verification boundary.
/// </summary>
internal interface IContactVerifiedAuthoritySnapshotSource
{
    ValueTask<ContactVerifiedAuthoritySnapshot> ReadCurrentAsync(
        CancellationToken cancellationToken);
}

/// <summary>
/// Mints the exact two-replica Contact placement from a complete, current
/// NETCODEC capability. No raw XNV/PMT projection can enter this adapter.
/// </summary>
internal sealed class VerifiedContactServicePlacementAuthoritySource(
    IContactVerifiedAuthoritySnapshotSource snapshots,
    IClock clock) : IContactServicePlacementAuthoritySource
{
    private readonly IContactVerifiedAuthoritySnapshotSource snapshots =
        snapshots ?? throw new ArgumentNullException(nameof(snapshots));
    private readonly IClock clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async ValueTask<ContactServicePlacementCapability> MintAsync(
        ContactServiceRequestKind requestKind,
        ReadOnlyMemory<byte> shardKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateRequest(requestKind, shardKey.Span);

        var snapshot = await snapshots.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "The Contact directory authority returned no current snapshot.");
        snapshot.EnsureConsistent();
        var verified = ContactServicePlacementFactory.Create(
            snapshot.Network,
            requestKind,
            shardKey);
        return ContactServicePlacementCapability.FromNetcodec(
            verified,
            requestKind,
            shardKey,
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
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
    IContactVerifiedAuthoritySnapshotSource snapshots)
    : IContactPublicationAuthorizationVerifier
{
    private readonly IContactVerifiedAuthoritySnapshotSource snapshots =
        snapshots ?? throw new ArgumentNullException(nameof(snapshots));

    public async ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        var snapshot = await snapshots.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "The Contact directory authority returned no current snapshot.");
        snapshot.EnsureConsistent();
        var placement = ContactServicePlacementFactory.Create(
            snapshot.Network,
            ContactServiceRequestKind.PublishInvite,
            request.LocatorHash);
        return await Xpa1PublicationAuthorizationVerifier.VerifyAsync(
                request,
                snapshot.Authority,
                snapshot.DirectoryFreshness,
                placement,
                snapshot.TrustedTimeAuthority,
                cancellationToken)
            .ConfigureAwait(false);
    }
}

/// <summary>
/// Recipient-specific source that may return only a capability produced by
/// ContactCodec.VerifyRouteUpdateClosure from current directory/network facts.
/// </summary>
internal interface IVerifiedContactRouteClosureSource
{
    ValueTask<VerifiedContactRouteClosure?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

/// <summary>
/// Re-verifies and exports the exact current XIR1 route closure expected by
/// XIS1. There is deliberately no HTTP or raw-byte fallback.
/// </summary>
internal sealed class VerifiedContactRouteClosureSource(
    IVerifiedContactRouteClosureSource source,
    IClock clock) : IContactRouteClosureSource
{
    private readonly IVerifiedContactRouteClosureSource source =
        source ?? throw new ArgumentNullException(nameof(source));
    private readonly IClock clock = clock ?? throw new ArgumentNullException(nameof(clock));

    public async ValueTask<ReadOnlyMemory<byte>?> ReadAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ValidateSelector(networkId.Span, locatorHash.Span);

        var supplied = await source.ReadCurrentAsync(
                networkId,
                locatorHash,
                cancellationToken)
            .ConfigureAwait(false);
        if (supplied is null)
        {
            return null;
        }

        try
        {
            // Re-run the Protocol-owned graph, authority, threshold-signature and
            // trusted-time checks instead of trusting an arbitrary host projection.
            var verified = ContactCodec.VerifyRouteUpdateClosure(
                supplied.Invite,
                supplied.Reachability,
                supplied.Authorization,
                supplied.Route,
                supplied.Successor,
                supplied.Projection,
                supplied.Selection,
                supplied.Authority);
            EnsureSelector(verified, networkId.Span, locatorHash.Span);
            EnsureCurrent(verified, checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
            return ContactRouteClosureCanonicalizer.EncodeVerified(verified);
        }
        catch (Exception exception) when (exception is ContactFormatException
            or CryptographicException
            or ArgumentException
            or OverflowException)
        {
            throw new InvalidOperationException(
                "The current verified Contact route capability is invalid.",
                exception);
        }
    }

    private static void ValidateSelector(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locatorHash)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A Contact route network id must be exactly 16 nonzero bytes.",
                nameof(networkId));
        }
        if (locatorHash.Length != 32 || locatorHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A Contact route locator must be exactly 32 nonzero bytes.",
                nameof(locatorHash));
        }
    }

    private static void EnsureSelector(
        VerifiedContactRouteClosure closure,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locatorHash)
    {
        if (!Fixed(closure.Invite.Field(1).Span, networkId)
            || !Fixed(closure.Invite.Field(2).Span, locatorHash))
        {
            throw new InvalidOperationException(
                "The verified Contact route does not bind the requested locator.");
        }
    }

    private static void EnsureCurrent(
        VerifiedContactRouteClosure closure,
        ulong nowUnixSeconds)
    {
        var authority = closure.Authority;
        if (!Within(authority.NotBeforeUnixSeconds, authority.ExpiresAtUnixSeconds, nowUnixSeconds)
            || !Within(closure.Invite, 13, 14, nowUnixSeconds)
            || !Within(closure.Reachability, 16, 17, nowUnixSeconds)
            || !Within(closure.Authorization, 12, 13, nowUnixSeconds)
            || !Within(closure.Route, 17, 18, nowUnixSeconds)
            || !Within(closure.Successor, 10, 11, nowUnixSeconds)
            || !Within(closure.Projection, 11, 12, nowUnixSeconds)
            || !Within(closure.Selection, 8, 9, nowUnixSeconds))
        {
            throw new InvalidOperationException(
                "The verified Contact route closure is no longer current.");
        }
    }

    private static bool Within(
        ContactRecord record,
        int notBeforeTag,
        int expiresAtTag,
        ulong nowUnixSeconds) => Within(
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(notBeforeTag).Span),
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(expiresAtTag).Span),
            nowUnixSeconds);

    private static bool Within(ulong notBefore, ulong expiresAt, ulong now) =>
        notBefore <= now && now < expiresAt;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class ContactRouteClosureCanonicalizer
{
    internal const int MinimumEncodedBytes = 4_143;
    internal const int MaximumEncodedBytes = 23_295;

    internal static byte[] EncodeVerified(VerifiedContactRouteClosure closure)
    {
        ArgumentNullException.ThrowIfNull(closure);
        ContactRecord[] records =
        [
            closure.Reachability,
            closure.Authorization,
            closure.Route,
            closure.Successor,
            closure.Projection,
            closure.Selection
        ];
        string[] expectedMagics = ["XRR1", "XRA1", "XRC1", "XSS1", "PMT2", "PMS2"];
        var canonicals = new byte[records.Length][];
        var total = 1;
        for (var index = 0; index < records.Length; index++)
        {
            if (!StringComparer.Ordinal.Equals(records[index].Magic, expectedMagics[index]))
            {
                throw new InvalidOperationException(
                    "The verified Contact route closure record order is invalid.");
            }
            canonicals[index] = records[index].CanonicalBytes.ToArray();
            total = checked(total + sizeof(uint) + canonicals[index].Length);
        }
        if (total is < MinimumEncodedBytes or > MaximumEncodedBytes)
        {
            throw new InvalidOperationException(
                "The verified Contact route closure is outside the XIS1 bounds.");
        }

        var encoded = new byte[total];
        encoded[0] = checked((byte)records.Length);
        var offset = 1;
        foreach (var canonical in canonicals)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                encoded.AsSpan(offset, sizeof(uint)),
                checked((uint)canonical.Length));
            offset += sizeof(uint);
            canonical.CopyTo(encoded, offset);
            offset += canonical.Length;
        }
        return encoded;
    }
}
