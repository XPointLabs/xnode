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
    HttpContactCoordinationBackendClient backend, RouterNodeOptions node, IOnionMonotonicClock clock,
    ILogger<ContactCoordinationOnionDispatcher> logger)
{
    internal async Task<NativeMailboxDispatchResult> DispatchAsync(
        VerifiedCanonicalOnionRequest request, CancellationToken cancellationToken)
    {
        var forwarded = false;
        var phase = DiagnosticPhase.Decode;
        var diagnostic = new CurrentnessDiagnostic();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Operation != OnionOperation.ContactResolve)
                return NativeMailboxDispatchResult.RejectedBeforeForward();
            var parsed = ContactCoordinationOnionCodec.DecodeRequest(request.CanonicalBytes.Span);
            phase = DiagnosticPhase.AuthorityBefore;
            var before = await authoritySource.ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false);
            phase = DiagnosticPhase.CurrentnessBefore;
            var placement = await RequireCurrentAsync(before, parsed, diagnostic, cancellationToken).ConfigureAwait(false);
            // Conservatively mark unknown before the backend call: an exception
            // cannot prove that its exact durable request did not reach the issuer.
            forwarded = true;
            phase = DiagnosticPhase.Backend;
            diagnostic.Check = CurrentnessCheck.None;
            var body = await backend.SendAsync(parsed.Target, parsed.ExactBody, cancellationToken).ConfigureAwait(false);
            phase = DiagnosticPhase.AuthorityAfter;
            var after = await authoritySource.ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false);
            phase = DiagnosticPhase.CurrentnessAfter;
            var current = await RequireCurrentAsync(after, parsed, diagnostic, cancellationToken).ConfigureAwait(false);
            phase = DiagnosticPhase.Pairing;
            diagnostic.Check = CurrentnessCheck.None;
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
            var result = forwarded ? NativeMailboxDispatchResult.OutcomeUnknownAfterForward() :
                NativeMailboxDispatchResult.RejectedBeforeForward();
            // Closed metadata only: never pass the exception, its message, request,
            // credential, capability, node identity or authority bytes to logging.
            logger.LogWarning("DID2 coordination rejected: phase={Phase}, check={Check}, certainty={Certainty}, category={Category}.",
                phase, diagnostic.Check, result.Certainty, FailureCategory(error));
            return result;
        }
    }

    private async ValueTask<VerifiedContactServicePlacement> RequireCurrentAsync(
        DeepIdV2ContactStoreAuthority current, ParsedContactCoordinationOnionRequest request,
        CurrentnessDiagnostic diagnostic, CancellationToken ct)
    {
        diagnostic.Check = CurrentnessCheck.Network;
        current.Network.EnsureCurrent();
        diagnostic.Check = CurrentnessCheck.Projection;
        if (!Fixed(current.Network.NetworkId.Span, request.NetworkId.Span) ||
            !current.Network.BindsProjection(request.ProjectionReference))
            throw new CryptographicException("Coordination is not bound to current network projection.");
        diagnostic.Check = CurrentnessCheck.Placement;
        var placement = ContactServicePlacementFactory.Create(current.Network,
            ContactServiceRequestKind.CoordinateContact, request.GatewayShard);
        diagnostic.Check = CurrentnessCheck.Gateway;
        var local = node.GetRouterId().ToBytes();
        if (!placement.RankedReplicaNodeIds.Any(id => Fixed(id.Span, local)))
            throw new CryptographicException("The receiving exit is not a selected coordination gateway.");
        diagnostic.Check = CurrentnessCheck.Clock;
        var now = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("The gateway monotonic clock is unavailable.");
        diagnostic.Check = CurrentnessCheck.ProofFreshness;
        if (!current.Freshness.IsCurrentAtMonotonic(now.BootId.Span, now.SampleSeconds))
            throw new CryptographicException("The gateway directory proof expired.");
        diagnostic.Check = CurrentnessCheck.TimeArithmetic;
        var elapsed = checked(now.SampleSeconds - current.Freshness.MonotonicSample);
        var lower = checked(current.Freshness.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(current.Freshness.TrustedUpperUnixSeconds + elapsed);
        var body = request.ExactBody;
        var issued = request.Target == ContactCoordinationTarget.Route ?
            BinaryPrimitives.ReadUInt64BigEndian(ContactCodec.Decode("XRA1",
                ContactRouteAuthorityWireCodec.DecodeRequest(body.Span).ExactXra1.Span).Field(12).Span) :
            ContactPublicationAuthorityWireCodec.DecodeRequest(body.Span).IssuedAtUnixSeconds;
        diagnostic.Check = CurrentnessCheck.IssuedLowerBound;
        if (lower < issued)
            throw new CryptographicException("Coordination does not cover the complete current trusted interval.");
        diagnostic.Check = CurrentnessCheck.RequestExpiry;
        if (upper >= request.ExpiresAtUnixSeconds)
            throw new CryptographicException("Coordination does not cover the complete current trusted interval.");
        diagnostic.Check = CurrentnessCheck.PlacementExpiry;
        if (request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds)
            throw new CryptographicException("Coordination does not cover the complete current trusted interval.");
        diagnostic.Check = CurrentnessCheck.Network;
        current.Network.EnsureCurrent();
        diagnostic.Check = CurrentnessCheck.None;
        return placement;
    }

    private static string FailureCategory(Exception error) => error switch
    {
        OnionBoundaryException => "boundary",
        CryptographicException => "cryptographic",
        FormatException or ArgumentException => "canonical",
        InvalidOperationException => "state",
        IOException => "io",
        OverflowException => "arithmetic",
        _ => throw new InvalidOperationException("Unclassified coordination rejection.")
    };

    private enum DiagnosticPhase { Decode, AuthorityBefore, CurrentnessBefore, Backend, AuthorityAfter, CurrentnessAfter, Pairing }
    private enum CurrentnessCheck { None, Network, Projection, Placement, Gateway, Clock, ProofFreshness, TimeArithmetic, IssuedLowerBound, RequestExpiry, PlacementExpiry }
    private sealed class CurrentnessDiagnostic { internal CurrentnessCheck Check { get; set; } }

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
