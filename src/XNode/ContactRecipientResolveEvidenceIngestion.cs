using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace XNode;

/// <summary>
/// Accepts recipient evidence only from a response opened and authenticated by
/// the production ONION client codec. The exact address is still untrusted here;
/// the durable owner independently rebuilds the complete DID1/DIA1, DCR1 and
/// route closure before committing it.
/// </summary>
internal interface IPrivacyRoutedContactRecipientResolveEvidenceIngestion
{
    ValueTask ObserveAsync(
        ReadOnlyMemory<byte> exactAddress,
        PrivacyRoutingOpenedResponse authenticatedResponse,
        CancellationToken cancellationToken);
}

internal sealed class PrivacyRoutedContactRecipientResolveEvidenceIngestion(
    IContactRouteRecipientResolveEvidenceOwner owner)
    : IPrivacyRoutedContactRecipientResolveEvidenceIngestion
{
    private readonly IContactRouteRecipientResolveEvidenceOwner owner =
        owner ?? throw new ArgumentNullException(nameof(owner));

    public async ValueTask ObserveAsync(
        ReadOnlyMemory<byte> exactAddress,
        PrivacyRoutingOpenedResponse authenticatedResponse,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatedResponse);
        cancellationToken.ThrowIfCancellationRequested();
        var authenticatedResult = authenticatedResponse.Result;
        var authenticatedRequest = authenticatedResult.Request;
        if (authenticatedRequest.Operation != OnionOperation.ContactResolve)
        {
            throw new InvalidDataException(
                "Recipient resolve evidence requires an authenticated ContactResolve path.");
        }

        var exactXiq1 = authenticatedRequest.CanonicalBytes;
        var request = Xiq1Codec.Decode(exactXiq1.Span);
        if (!Fixed(request.NetworkId.Span, authenticatedRequest.Network.NetworkId.Span))
        {
            throw new InvalidDataException(
                "The authenticated ONION network does not match exact XIQ1.");
        }

        if (authenticatedResult.Kind != OnionTerminalResultKind.Success)
        {
            return;
        }

        var exactXis1 = authenticatedResult.Body;
        var result = Xis1Codec.Decode(exactXis1.Span, exactXiq1.Span);
        if (result.Status != Xis1Status.Success)
        {
            return;
        }

        var kind = ExactAddressKind(exactAddress.Span);
        EnsureResultCanFeed(kind, result);

        await owner.ObserveAsync(
            new ContactRecipientResolveEvidenceSubmission(
                kind,
                request.NetworkId.Span,
                request.LocatorHash.Span,
                exactAddress.Span,
                exactXiq1.Span,
                exactXis1.Span),
            cancellationToken).ConfigureAwait(false);
    }

    internal static void EnsureResultCanFeed(
        ContactRecipientResolveEvidenceKind kind,
        Xis1Result result)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (!Enum.IsDefined(kind) || result.Status != Xis1Status.Success)
        {
            throw new InvalidDataException(
                "Only a successful exact XIS1 can feed recipient authority.");
        }
        if (kind == ContactRecipientResolveEvidenceKind.Permanent)
        {
            if (result.MutationOutcome != ContactServiceMutationOutcome.None
                || result.Field(22).Length != 193
                || !result.Field(23).IsEmpty)
            {
                throw new InvalidDataException(
                    "Permanent recipient evidence requires an exact non-consuming XIS1 success.");
            }
        }
        else if (result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted
            || result.Field(22).Length != sizeof(ulong)
            || result.Field(23).Length != 193)
        {
            throw new InvalidDataException(
                "One-time recipient evidence requires an exact durably committed claim XIS1.");
        }
    }

    internal static ContactRecipientResolveEvidenceKind ExactAddressKind(
        ReadOnlySpan<byte> exactAddress)
    {
        if (exactAddress.Length >= 4
            && exactAddress[..4].SequenceEqual(ProtocolMagicBytes.DID1))
        {
            _ = ApplicationCoreCodec.DecodeDid1(exactAddress);
            return ContactRecipientResolveEvidenceKind.Permanent;
        }
        if (exactAddress.Length >= 4
            && exactAddress[..4].SequenceEqual(ProtocolMagicBytes.DIA1))
        {
            _ = ContactCodec.Decode(ProtocolMagic.DIA1, exactAddress);
            return ContactRecipientResolveEvidenceKind.OneTime;
        }
        throw new InvalidDataException(
            "Recipient resolve evidence requires exact DID1 or DIA1 bytes.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Production client-side resolve path. It opens the opaque ONION response with
/// the request's reply context before any exact XIS1 can reach the evidence
/// owner. Registry or direct-service response bytes cannot enter this path.
/// </summary>
internal interface IPrivacyRoutedContactRecipientResolveClient
{
    ValueTask<PrivacyRoutingOpenedResponse> OpenAndObserveAsync(
        ReadOnlyMemory<byte> exactAddress,
        ReadOnlyMemory<byte> opaqueResponseFrame,
        OnionReplyContext replyContext,
        CancellationToken cancellationToken);
}

internal sealed class PrivacyRoutedContactRecipientResolveClient(
    PrivacyRoutingCodec codec,
    IPrivacyRoutedContactRecipientResolveEvidenceIngestion ingestion)
    : IPrivacyRoutedContactRecipientResolveClient
{
    private readonly PrivacyRoutingCodec codec =
        codec ?? throw new ArgumentNullException(nameof(codec));
    private readonly IPrivacyRoutedContactRecipientResolveEvidenceIngestion ingestion =
        ingestion ?? throw new ArgumentNullException(nameof(ingestion));

    public async ValueTask<PrivacyRoutingOpenedResponse> OpenAndObserveAsync(
        ReadOnlyMemory<byte> exactAddress,
        ReadOnlyMemory<byte> opaqueResponseFrame,
        OnionReplyContext replyContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(replyContext);
        cancellationToken.ThrowIfCancellationRequested();
        var opened = await codec.OpenResponseAsync(
            opaqueResponseFrame,
            replyContext,
            cancellationToken).ConfigureAwait(false);
        await ingestion.ObserveAsync(
            exactAddress,
            opened,
            cancellationToken).ConfigureAwait(false);
        return opened;
    }
}
