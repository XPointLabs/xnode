using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;

namespace XNode;

/// <summary>
/// Locator-keyed source of a Protocol-minted contact resolve/claim closure.
/// Implementations may return only evidence derived from a Protocol-minted
/// permanent resolve or one-time claim closure; raw DPD1/DCA1/XIR1/PMS2
/// records and caller-provided trust flags are deliberately absent.
/// </summary>
internal interface IContactRouteRecipientResolveClosureSource
{
    ValueTask<ContactRouteRecipientResolveEvidence?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal sealed class ContactRouteRecipientResolveEvidence
{
    private readonly byte[] exactRouteClosure;

    private ContactRouteRecipientResolveEvidence(
        VerifiedContactBundleClosure contact,
        VerifiedDevice publisherDevice,
        ReadOnlySpan<byte> exactRouteClosure)
    {
        Contact = contact ?? throw new ArgumentNullException(nameof(contact));
        PublisherDevice = publisherDevice
            ?? throw new ArgumentNullException(nameof(publisherDevice));
        if (exactRouteClosure.Length is < ContactRouteClosureCanonicalizer.MinimumEncodedBytes
            or > ContactRouteClosureCanonicalizer.MaximumEncodedBytes)
        {
            throw new ArgumentException(
                "The authenticated recipient route closure is outside its exact bound.",
                nameof(exactRouteClosure));
        }
        this.exactRouteClosure = exactRouteClosure.ToArray();
    }

    internal VerifiedContactBundleClosure Contact { get; }
    internal VerifiedDevice PublisherDevice { get; }
    internal ReadOnlyMemory<byte> ExactRouteClosure => exactRouteClosure.ToArray();

    internal static ContactRouteRecipientResolveEvidence FromPermanent(
        VerifiedPermanentContactResolveClosure resolved)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        return new(resolved.Contact, resolved.PublisherDevice, resolved.ExactRouteClosure.Span);
    }

    internal static ContactRouteRecipientResolveEvidence FromOneTime(
        VerifiedContactClaimClosure claimed)
    {
        ArgumentNullException.ThrowIfNull(claimed);
        return new(
            claimed.Contact,
            claimed.PublisherDevice,
            claimed.Claim.ExactRouteClosure.Span);
    }
}

internal sealed class ClosedContactRouteRecipientResolveClosureSource
    : IContactRouteRecipientResolveClosureSource
{
    public ValueTask<ContactRouteRecipientResolveEvidence?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = networkId;
        _ = locatorHash;
        return ValueTask.FromResult<ContactRouteRecipientResolveEvidence?>(null);
    }
}

/// <summary>
/// Converts one immutable, current contact resolve/claim closure into the
/// exact recipient material consumed by the Contact network-authority verifier.
/// The resolve closure keeps DPD1, DCA1 and XIR1 in one verified identity
/// transaction and authenticates the exact route-closure bytes containing
/// PMS2. The downstream Protocol verifier still independently binds PMS2 to
/// the current XNV1/PMT2 snapshot before authority can be minted.
/// </summary>
internal sealed class ProtocolContactRouteRecipientAuthoritySource(
    IContactRouteRecipientResolveClosureSource resolutions,
    IContactRouteRecipientEvidenceProjector projector)
    : IContactRouteRecipientAuthoritySource
{
    private readonly IContactRouteRecipientResolveClosureSource resolutions =
        resolutions ?? throw new ArgumentNullException(nameof(resolutions));
    private readonly IContactRouteRecipientEvidenceProjector projector =
        projector ?? throw new ArgumentNullException(nameof(projector));

    public async ValueTask<ContactRouteRecipientAuthorityMaterial?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        HttpsContactRouteClosureArtifactSource.ValidateSelector(
            networkId.Span, locatorHash.Span);
        cancellationToken.ThrowIfCancellationRequested();

        var resolved = await resolutions.ReadCurrentAsync(
            networkId, locatorHash, cancellationToken).ConfigureAwait(false);
        if (resolved is null)
        {
            return null;
        }

        return await projector.VerifyCurrentAsync(
            resolved, networkId, locatorHash, cancellationToken).ConfigureAwait(false);
    }
}

internal interface IContactRouteRecipientEvidenceProjector
{
    ValueTask<ContactRouteRecipientAuthorityMaterial?> VerifyCurrentAsync(
        ContactRouteRecipientResolveEvidence resolved,
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal sealed class ProtocolContactRouteRecipientEvidenceProjector(
    IContactRouteClosureArtifactCodec codec,
    IOnionMonotonicClock monotonicClock)
    : IContactRouteRecipientEvidenceProjector
{
    private const int Xir1SupportBytes = 40 + 611;

    private readonly IContactRouteClosureArtifactCodec codec =
        codec ?? throw new ArgumentNullException(nameof(codec));
    private readonly IOnionMonotonicClock monotonicClock =
        monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));

    public async ValueTask<ContactRouteRecipientAuthorityMaterial?> VerifyCurrentAsync(
        ContactRouteRecipientResolveEvidence resolved,
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolved);
        HttpsContactRouteClosureArtifactSource.ValidateSelector(
            networkId.Span, locatorHash.Span);
        cancellationToken.ThrowIfCancellationRequested();
        var reading = await monotonicClock.ReadAsync(cancellationToken)
            .ConfigureAwait(false);
        if (reading is null)
        {
            return null;
        }

        try
        {
            return VerifyAndProject(
                resolved,
                networkId.Span,
                locatorHash.Span,
                reading);
        }
        catch (Exception exception) when (ExpectedEvidenceRejection(exception))
        {
            return null;
        }
    }

    private ContactRouteRecipientAuthorityMaterial? VerifyAndProject(
        ContactRouteRecipientResolveEvidence resolved,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locatorHash,
        OnionMonotonicReading reading)
    {
        var contact = resolved.Contact;
        var freshness = contact.Freshness;
        var authorization = contact.Authorization;
        var verifiedDca1 = authorization.Verified;
        var dca1 = verifiedDca1.Record;
        var device = resolved.PublisherDevice;
        var certificate = device.Certificate;

        if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue
            || freshness.CurrentCheckpoint is null
            || !freshness.IsCurrentAtMonotonic(
                reading.BootId.Span, reading.SampleSeconds)
            || !ReferenceEquals(verifiedDca1.Directory, contact.Directory)
            || !ReferenceEquals(verifiedDca1.Binding, contact.Binding)
            || !Same(networkId, freshness.NetworkId.Span)
            || !Same(networkId, dca1.NetworkId.Span)
            || !Same(networkId, certificate.NetworkId.Span)
            || !Same(dca1.PublisherDeviceId.Span, certificate.DeviceId.Span)
            || dca1.NotBeforeUnixSeconds > freshness.TrustedLowerUnixSeconds
            || dca1.ExpiresAtUnixSeconds <= freshness.TrustedUpperUnixSeconds
            || certificate.IssuedAtUnixSeconds > freshness.TrustedLowerUnixSeconds
            || certificate.ExpiresAtUnixSeconds <= freshness.TrustedUpperUnixSeconds
            || !ContainsExactDevice(contact, device))
        {
            return null;
        }

        var xirSupport = contact.Bundle.Field(14);
        if (xirSupport.Length != Xir1SupportBytes)
        {
            return null;
        }
        var exactXir1 = xirSupport.Slice(40, 611).ToArray();
        var exactRouteClosure = resolved.ExactRouteClosure.ToArray();
        try
        {
            var xir1 = codec.Decode("XIR1", exactXir1);
            var route = HttpsContactRouteClosureArtifactSource.Decode(
                exactRouteClosure, codec);
            var pms2 = route.Selection;
            var exactPms2 = pms2.CanonicalBytes.ToArray();
            try
            {
                if (!Same(networkId, xir1.Field(1).Span)
                    || !Same(locatorHash, xir1.Field(2).Span)
                    || !Same(networkId, pms2.Field(1).Span)
                    || !Same(Reference("DPD1", certificate.CanonicalHash.Span),
                        xir1.Field(15).Span)
                    || !Same(Reference("DCA1", dca1.RecordHash.Span),
                        xir1.Field(16).Span)
                    || ReadUInt64(xir1.Field(13).Span)
                        > freshness.TrustedLowerUnixSeconds
                    || ReadUInt64(xir1.Field(14).Span)
                        <= freshness.TrustedUpperUnixSeconds
                    || ReadUInt64(pms2.Field(8).Span)
                        > freshness.TrustedLowerUnixSeconds
                    || ReadUInt64(pms2.Field(9).Span)
                        <= freshness.TrustedUpperUnixSeconds)
                {
                    return null;
                }

                var currentAuthorization =
                    ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
                        verifiedDca1,
                        freshness.TrustedUpperUnixSeconds);
                return new ContactRouteRecipientAuthorityMaterial(
                    exactXir1,
                    device,
                    currentAuthorization,
                    exactPms2);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exactPms2);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exactXir1);
            CryptographicOperations.ZeroMemory(exactRouteClosure);
        }
    }

    private static bool ContainsExactDevice(
        VerifiedContactBundleClosure contact,
        VerifiedDevice expected)
    {
        var certificate = expected.Certificate;
        var active = contact.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Same(candidate.Certificate.DeviceId.Span, certificate.DeviceId.Span));
        return active is not null
            && Same(active.Certificate.CanonicalHash.Span, certificate.CanonicalHash.Span)
            && Same(active.Certificate.CanonicalBytes.Span, certificate.CanonicalBytes.Span);
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        if (magic.Length != 4 || hash.Length != 32)
        {
            throw new InvalidDataException("A recipient authority reference is malformed.");
        }
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static ulong ReadUInt64(ReadOnlySpan<byte> value)
    {
        if (value.Length != sizeof(ulong))
        {
            throw new InvalidDataException("A recipient authority time field is malformed.");
        }
        return BinaryPrimitives.ReadUInt64BigEndian(value);
    }

    private static bool Same(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool ExpectedEvidenceRejection(Exception exception) =>
        exception is ContactFormatException
            or CryptographicException
            or InvalidDataException
            or ArgumentException
            or InvalidOperationException
            or OverflowException;
}
