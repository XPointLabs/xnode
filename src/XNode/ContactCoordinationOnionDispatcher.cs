using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;

namespace XNode;

internal sealed class ContactCoordinationOnionDispatcher(
    IDeepIdV2ContactStoreAuthoritySource authoritySource,
    HttpContactCoordinationBackendClient backend, RouterNodeOptions node, IOnionMonotonicClock clock)
{
    internal async Task<NativeMailboxDispatchResult> DispatchAsync(
        VerifiedCanonicalOnionRequest request, CancellationToken cancellationToken)
    {
        var forwarded = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Operation != OnionOperation.ContactResolve)
                return NativeMailboxDispatchResult.RejectedBeforeForward();
            var parsed = ContactCoordinationOnionCodec.DecodeRequest(request.CanonicalBytes.Span);
            var before = await authoritySource.ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false);
            var placement = await RequireCurrentAsync(before, parsed, cancellationToken).ConfigureAwait(false);
            // Conservatively mark unknown before the backend call: an exception
            // cannot prove that its exact durable request did not reach the issuer.
            forwarded = true;
            var body = await backend.SendAsync(parsed.Target, parsed.ExactBody, cancellationToken).ConfigureAwait(false);
            var after = await authoritySource.ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false);
            var current = await RequireCurrentAsync(after, parsed, cancellationToken).ConfigureAwait(false);
            if (!Fixed(placement.ViewHash.Span, current.ViewHash.Span) ||
                !Fixed(placement.PlacementHash.Span, current.PlacementHash.Span) ||
                !Fixed(before.Freshness.NextProtectedLkg.CoreHash.Span, after.Freshness.NextProtectedLkg.CoreHash.Span))
                throw new CryptographicException("Coordination authority changed during the backend exchange.");
            before.Network.EnsureCurrent();
            var exact = ContactCoordinationOnionCodec.EncodeResponse(parsed, body);
            cancellationToken.ThrowIfCancellationRequested();
            return new(StatusCodes.Status200OK, exact);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception error) when (error is OnionBoundaryException or CryptographicException or FormatException or ArgumentException or
            InvalidOperationException or IOException or OverflowException)
        {
            return forwarded ? NativeMailboxDispatchResult.OutcomeUnknownAfterForward() :
                NativeMailboxDispatchResult.RejectedBeforeForward();
        }
    }

    private async ValueTask<VerifiedContactServicePlacement> RequireCurrentAsync(
        DeepIdV2ContactStoreAuthority current, ParsedContactCoordinationOnionRequest request, CancellationToken ct)
    {
        current.Network.EnsureCurrent();
        if (!Fixed(current.Network.NetworkId.Span, request.NetworkId.Span) ||
            !current.Network.BindsProjection(request.ProjectionReference))
            throw new CryptographicException("Coordination is not bound to current network projection.");
        var placement = ContactServicePlacementFactory.Create(current.Network,
            ContactServiceRequestKind.CoordinateContact, request.GatewayShard);
        var local = node.GetRouterId().ToBytes();
        if (!placement.RankedReplicaNodeIds.Any(id => Fixed(id.Span, local)))
            throw new CryptographicException("The receiving exit is not a selected coordination gateway.");
        var now = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("The gateway monotonic clock is unavailable.");
        if (!current.Freshness.IsCurrentAtMonotonic(now.BootId.Span, now.SampleSeconds))
            throw new CryptographicException("The gateway directory proof expired.");
        var elapsed = checked(now.SampleSeconds - current.Freshness.MonotonicSample);
        var lower = checked(current.Freshness.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(current.Freshness.TrustedUpperUnixSeconds + elapsed);
        var body = request.ExactBody;
        var issued = request.Target == ContactCoordinationTarget.Route ?
            BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1",
                ContactRouteAuthorityWireCodec.DecodeRequest(body.Span).ExactXra1.Span).Field(12).Span) :
            ContactPublicationAuthorityWireCodec.DecodeRequest(body.Span).IssuedAtUnixSeconds;
        if (lower < issued || upper >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw new CryptographicException("Coordination does not cover the complete current trusted interval.");
        current.Network.EnsureCurrent();
        return placement;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed class ContactCoordinationOptions
{
    public bool Enabled { get; set; }
    public string BackendOrigin { get; set; } = string.Empty;

    internal Uri? Validate(bool privacyEnabled, bool hasIndependentObserver)
    {
        if (BackendOrigin is null) throw new InvalidOperationException("Coordination configuration has a null origin.");
        if (!Enabled)
        {
            if (BackendOrigin.Length != 0) throw new InvalidOperationException("Coordination configuration is partial while disabled.");
            return null;
        }
        if (!privacyEnabled || !hasIndependentObserver || !Uri.TryCreate(BackendOrigin, UriKind.Absolute, out var origin) ||
            origin.Scheme != Uri.UriSchemeHttps || origin.AbsolutePath != "/" || origin.UserInfo.Length != 0 ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0)
            throw new InvalidOperationException("Coordination requires authenticated ONION, independent DID2 authority and one HTTPS backend origin.");
        return origin;
    }
}
