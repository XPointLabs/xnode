using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace XNode.Core.ContactResolver;

internal sealed partial class OpaqueDcrPublishRequest
{
    // Raw opaque storage inputs never mint retained-read custody. The production
    // publication paths use this factory with an actual closed XPA capability.
    private RetainedPublication? retainedPublication;
    internal RetainedPublication? Retained => retainedPublication;

    internal static async ValueTask<OpaqueDcrPublishRequest> FromAuthorizedPublicationAsync(
        VerifiedXpa1PublicationAuthorization authorization, Xpu1Request request,
        CancellationToken cancellationToken)
    {
        ContactServiceOpaqueFacade.ValidatePublicationAuthorization(authorization, request);
        await authorization.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        var route = ContactRouteClosureCodec.Decode(request.ExactRouteClosure.Span);
        var result = new OpaqueDcrPublishRequest(request.LocatorHash.Span,
            request.OperationId.Span, request.RequestHash.Span, request.Generation,
            request.PredecessorObjectHash.Span, request.ObjectCiphertextHash.Span,
            request.ObjectCiphertext.Span, request.ExactRouteClosure.Span, request.UsageLimit,
            request.EffectiveExpiresAtUnixSeconds,
            MailboxGrantCapabilityDigest.Compute(route.Reachability.Field(10).Span,
                ContactMailboxGrantRole.Deposit),
            MailboxGrantCapabilityDigest.Compute(request.OwnerRetrieveCapability.Span,
                ContactMailboxGrantRole.Retrieve));
        if (!OpaqueValue.FixedEquals(route.Reachability.Field(1).Span, request.NetworkId.Span))
            throw new CryptographicException("Retained publication network binding differs.");
        var lastAdmission = Math.Min(request.EffectiveExpiresAtUnixSeconds,
            ContactResolverOpaqueStore.LastPossibleRouteAdmission(route));
        // The original XPU/XPA request window and a short grant are NOT the
        // accepted object's lifetime. This is a conservative upper bound only.
        var readUntil = checked(lastAdmission + ContactResolverOpaqueStore.MailboxObjectHorizonSeconds);
        result.retainedPublication = new(request.NetworkId.ToArray(), lastAdmission, readUntil);
        await authorization.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    internal sealed record RetainedPublication(byte[] NetworkId, ulong LastAdmission, ulong ReadUntil);
}

internal enum RetainedMailboxRouteDisposition { Found = 1, NotFound = 2, Expired = 3, Conflict = 4 }

/// <summary>Private lookup facts, not a verified grant/issuer capability or a
/// Current route response. No two-store attestation, revocation or ACK authority.</summary>
internal sealed class RetainedMailboxRouteLookup
{
    private readonly byte[] route;
    internal RetainedMailboxRouteLookup(RetainedMailboxRouteDisposition disposition,
        ReadOnlySpan<byte> route, ulong readUntil)
    { Disposition = disposition; this.route = route.ToArray(); ReadUntilUnixSeconds = readUntil; }
    internal RetainedMailboxRouteDisposition Disposition { get; }
    internal ReadOnlyMemory<byte> ExactRouteClosure => route.ToArray();
    internal ulong ReadUntilUnixSeconds { get; }
}

internal sealed partial class ContactResolverOpaqueStore
{
    internal const ulong MailboxObjectHorizonSeconds = 30 * 24 * 60 * 60;

    internal async ValueTask<RetainedMailboxRouteLookup> ResolveRetainedMailboxRouteAsync(
        VerifiedMailboxRetainedReadRequestV2 request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var exact = ContactCodec.Decode(ProtocolMagic.XMG1, request.ExactXmg1.Span);
        var first = await request.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        RetainedMailboxRouteLookup result;
        ulong revision;
        lock (gate)
        {
            ThrowIfDisposed();
            revision = stateRevision;
            result = LookupRetainedRoute(exact, first.UpperUnixSeconds);
        }
        // Never hold the storage lock across authority/clock callbacks. Any
        // intervening durable mutation invalidates this captured result.
        var final = await request.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
        if (!OpaqueValue.FixedEquals(first.BootId.Span, final.BootId.Span)
            || final.MonotonicSample < first.MonotonicSample)
            throw new CryptographicException("Retained lookup crossed a protected clock discontinuity.");
        lock (gate)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            if (revision != stateRevision)
                throw new InvalidOperationException("Retained lookup snapshot changed during authority recheck.");
            if (result.Disposition == RetainedMailboxRouteDisposition.Found
                && final.UpperUnixSeconds >= result.ReadUntilUnixSeconds)
                return new(RetainedMailboxRouteDisposition.Expired, [], 0);
            return result;
        }
    }

    private RetainedMailboxRouteLookup LookupRetainedRoute(ContactRecord request, ulong upper)
    {
        var publication = FindPublication(request.Field(3).Span);
        if (publication?.ForkLatched == true)
            return new(RetainedMailboxRouteDisposition.Conflict, [], 0);
        var digest = MailboxGrantCapabilityDigest.Compute(request.Field(4).Span,
            ContactMailboxGrantRole.Retrieve);
        RetainedMailboxRouteState? match = null;
        var expired = false;
        foreach (var item in state.RetainedMailboxRoutes)
        {
            if (!OpaqueValue.FixedEquals(item.NetworkId, request.Field(1).Span)
                || !OpaqueValue.FixedEquals(item.LocatorHash, request.Field(3).Span)
                || !OpaqueValue.FixedEquals(item.RetrieveCapabilityDigest, digest))
                continue;
            var route = ContactRouteClosureCodec.Decode(item.RouteClosure);
            if (!OpaqueValue.FixedEquals(ContactCodec.ArtifactReference(ProtocolMagic.PMT2,
                    route.Projection).CanonicalBytes.Span, request.Field(7).Span)
                || !OpaqueValue.FixedEquals(route.Selection.ArtifactHash.Span, request.Field(8).Span))
                continue;
            if (upper >= item.ReadUntilUnixSeconds) { expired = true; continue; }
            // Stable owner Retrieve capability and PMS2 may be reused across
            // successors. Never infer an exact closure by choosing the latest.
            if (match is not null && !match.RouteClosure.AsSpan().SequenceEqual(item.RouteClosure))
                return new(RetainedMailboxRouteDisposition.Conflict, [], 0);
            if (match is null || match.ReadUntilUnixSeconds < item.ReadUntilUnixSeconds)
                match = item;
        }
        return match is null
            ? new(expired ? RetainedMailboxRouteDisposition.Expired : RetainedMailboxRouteDisposition.NotFound, [], 0)
            : new(RetainedMailboxRouteDisposition.Found, match.RouteClosure, match.ReadUntilUnixSeconds);
    }

    private bool HasRetainedRouteCapacity(OpaqueDcrPublishRequest request) => request.Retained is null
        || (state.RetainedMailboxRoutes.Count < options.MaximumRetainedMailboxRoutes
            && state.RetainedMailboxRoutes.Sum(static item => (long)item.RouteClosure.Length)
                + request.CanonicalRouteClosure.Length <= options.MaximumRetainedMailboxRouteBytes);

    private void RetainMailboxRoute(OpaqueDcrPublishRequest request)
    {
        if (request.Retained is not { } retained) return;
        state.RetainedMailboxRoutes.Add(new()
        {
            NetworkId = retained.NetworkId.ToArray(), LocatorHash = request.LocatorHash.ToArray(),
            PublicationRequestHash = request.RequestHash.ToArray(),
            RetrieveCapabilityDigest = request.RetrieveCapabilityDigest.ToArray(),
            RouteClosure = request.CanonicalRouteClosure.ToArray(),
            LastAdmissionUnixSeconds = retained.LastAdmission,
            ReadUntilUnixSeconds = retained.ReadUntil
        });
    }

    internal static ulong LastPossibleRouteAdmission(ParsedContactRouteClosure route) =>
        new[] { U64(route.Reachability.Field(17)), U64(route.Authorization.Field(13)),
            U64(route.Route.Field(18)), U64(route.Successor.Field(11)),
            U64(route.Projection.Field(12)), U64(route.Selection.Field(9)) }.Min();

    private static ulong U64(ReadOnlyMemory<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value.Span);

    private void ValidateRetainedMailboxRoutes(PersistedState candidate)
    {
        if (candidate.RetainedMailboxRoutes is null
            || candidate.RetainedMailboxRoutes.Count > options.MaximumRetainedMailboxRoutes)
            throw new InvalidDataException("Retained mailbox route count is invalid.");
        byte[] previous = [];
        long bytes = 0;
        foreach (var item in candidate.RetainedMailboxRoutes)
        {
            Validate32(item.PublicationRequestHash); Validate32(item.LocatorHash);
            Validate32(item.RetrieveCapabilityDigest);
            if (item.NetworkId is null || item.NetworkId.Length != 16 || OpaqueValue.IsZero(item.NetworkId)
                || item.RouteClosure is null
                || item.RouteClosure.Length is < ContactRouteClosureCodec.MinimumEncodedBytes
                    or > ContactRouteClosureCodec.MaximumEncodedBytes
                || (previous.Length != 0 && previous.AsSpan().SequenceCompareTo(item.PublicationRequestHash) >= 0))
                throw new InvalidDataException("Retained mailbox route scope/order is invalid.");
            var route = ContactRouteClosureCodec.Decode(item.RouteClosure);
            if (!OpaqueValue.FixedEquals(item.NetworkId, route.Reachability.Field(1).Span)
                || item.LastAdmissionUnixSeconds == 0
                || item.LastAdmissionUnixSeconds > LastPossibleRouteAdmission(route)
                || item.LastAdmissionUnixSeconds > ulong.MaxValue - MailboxObjectHorizonSeconds
                || item.ReadUntilUnixSeconds != item.LastAdmissionUnixSeconds + MailboxObjectHorizonSeconds
                || OpaqueValue.FixedEquals(item.RetrieveCapabilityDigest,
                    MailboxGrantCapabilityDigest.Compute(route.Reachability.Field(10).Span,
                        ContactMailboxGrantRole.Deposit)))
                throw new InvalidDataException("Retained mailbox route horizon/binding is invalid.");
            previous = item.PublicationRequestHash;
            bytes = checked(bytes + item.RouteClosure.Length);
        }
        if (bytes > options.MaximumRetainedMailboxRouteBytes)
            throw new InvalidDataException("Retained mailbox route byte quota is exceeded.");
    }

    private sealed class RetainedMailboxRouteState
    {
        public byte[] NetworkId { get; set; } = [];
        public byte[] LocatorHash { get; set; } = [];
        public byte[] PublicationRequestHash { get; set; } = [];
        public byte[] RetrieveCapabilityDigest { get; set; } = [];
        public byte[] RouteClosure { get; set; } = [];
        public ulong LastAdmissionUnixSeconds { get; set; }
        public ulong ReadUntilUnixSeconds { get; set; }
    }
}
