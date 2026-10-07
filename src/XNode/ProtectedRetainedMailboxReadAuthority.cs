using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactResolver;

namespace XNode;

/// <summary>Actual single-node current-source and independent document custody
/// around a retained read/signature. Not two-store quorum or issuer authority.</summary>
internal sealed class ProtectedRetainedMailboxReadAuthority(
    IDeepIdV2ContactStoreAuthoritySource source, RouterNodeOptions node,
    ContactServiceLocalReplicaRuntime local)
{
    private readonly byte[] localId = node.GetRouterId().ToBytes();

    internal ValueTask<RetainedMailboxRouteLookup> ReadAsync(ContactServicePlacementCapability placement,
        ReadOnlyMemory<byte> exactXmg2, CancellationToken ct) =>
        WithProtectedReadAsync(placement, exactXmg2,
            static (facts, _) => ValueTask.FromResult(facts), ct);

    internal ValueTask<ContactServiceReplicaReceipt> IssueAsync(ContactServicePlacementCapability placement,
        ReadOnlyMemory<byte> exactXmg2, ContactServiceReplicaReceiptRequest receipt, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (receipt.Kind != ContactServiceReceiptKind.MailboxRetainedRead)
            throw new ContactServiceReceiptAuthorityException("Retained signing requires its independent receipt purpose.");
        // Capture untrusted caller bytes before any authority/clock callback.
        var exact = ContactReplicaPayloadCodec.DecodeRetainedMailboxGrantRequest(exactXmg2.Span);
        var tuple = receipt.CanonicalTuple.ToArray();
        return WithProtectedReadAsync(placement, exact, async (facts, token) =>
        {
            if (facts.Disposition != RetainedMailboxRouteDisposition.Found)
                throw new ContactServiceReceiptAuthorityException("This store has no protected retained admission.");
            var request = ContactCodec.Decode(ProtocolMagic.XMG2, exact);
            var expected = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(exact),
                request.Field(3).Span, Deep.Protocol.ContactV1.MailboxGrantCapabilityDigest.Compute(
                    request.Field(4).Span, Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve),
                SHA256.HashData(facts.ExactRouteClosure.Span), facts.ReadUntilUnixSeconds);
            if (!Fixed(expected, tuple))
                throw new ContactServiceReceiptAuthorityException("Retained tuple differs from actual protected local read-back.");
            local.EnsureSigningCustody(placement);
            var result = await local.Binding.ReceiptAuthority.IssueAsync(
                new(ContactServiceReceiptKind.MailboxRetainedRead, expected), token).ConfigureAwait(false);
            if (!Fixed(result.ReplicaId.Span, localId) || !ContactServiceReceiptTranscript.Verify(
                placement.VerifiedPlacement.Network.ResolveNodeIdentityPublicKey(localId).Span,
                MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(expected), result.Signature.Span))
                throw new ContactServiceReceiptAuthorityException("Retained signer differs from the actual current descriptor key.");
            return result;
        }, ct);
    }

    private async ValueTask<T> WithProtectedReadAsync<T>(ContactServicePlacementCapability placement,
        ReadOnlyMemory<byte> exactXmg2,
        Func<RetainedMailboxRouteLookup, CancellationToken, ValueTask<T>> action, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(placement); ct.ThrowIfCancellationRequested();
        var exact = ContactReplicaPayloadCodec.DecodeRetainedMailboxGrantRequest(exactXmg2.Span);
        var snapshot = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
        var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(snapshot.Network, snapshot.Authority,
            snapshot.MailboxAuthority.ExactPma2, snapshot.TrustedTime, ct).ConfigureAwait(false);
        var request = await host.VerifyRetainedReadRequestAsync(exact, ct).ConfigureAwait(false);
        var history = OnionNetworkProtectedHistoryCodec.Encode(snapshot.Network);
        await RequirePlacementAsync(snapshot, request).ConfigureAwait(false);

        async ValueTask RequireSourceAsync()
        {
            ct.ThrowIfCancellationRequested();
            var current = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
            if (!Fixed(OnionNetworkProtectedHistoryCodec.Encode(current.Network), history) ||
                !Fixed(current.Authority.AuthorityCoreReference.Span, snapshot.Authority.AuthorityCoreReference.Span) ||
                !Fixed(current.Authority.Dts1PolicyCoreReference.Span, snapshot.Authority.Dts1PolicyCoreReference.Span) ||
                !Fixed(current.Authority.TimeSourcePolicyHash.Span, snapshot.Authority.TimeSourcePolicyHash.Span) ||
                !Fixed(current.MailboxAuthority.ExactPma2.Span, snapshot.MailboxAuthority.ExactPma2.Span))
                throw new CryptographicException("Actual retained-read authority changed during the operation.");
            var currentHost = await MailboxHostAuthorityV2Verifier.VerifyAsync(current.Network, current.Authority,
                current.MailboxAuthority.ExactPma2, current.TrustedTime, ct).ConfigureAwait(false);
            var currentRequest = await currentHost.VerifyRetainedReadRequestAsync(exact, ct).ConfigureAwait(false);
            await RequirePlacementAsync(current, currentRequest).ConfigureAwait(false);
            await request.EnsureCurrentAsync(ct).ConfigureAwait(false);
        }

        async ValueTask RequirePlacementAsync(DeepIdV2ContactStoreAuthority current,
            VerifiedMailboxRetainedReadRequestV2 currentRequest)
        {
            var raw = ContactCodec.Decode(ProtocolMagic.XMG2, exact);
            var window = await currentRequest.ReadCurrentTimeAsync(ct).ConfigureAwait(false);
            var actual = ContactServicePlacementCapability.FromNetcodec(ContactServicePlacementFactory.Create(
                current.Network, ContactServiceRequestKind.ResolveInvite, raw.Field(3)),
                ContactServiceRequestKind.ResolveInvite, raw.Field(3), window.UpperUnixSeconds);
            ContactReplicaRequestReceiver.EnsureExactPlacement(placement, actual);
            if (!actual.ContainsReplica(localId)) throw new CryptographicException("Local node is not a current retained evidence store.");
            local.EnsureSigningCustody(actual);
            ct.ThrowIfCancellationRequested();
        }

        return await local.WithProtectedRetainedMailboxRouteAsync(request, async (facts, token) =>
        {
            await RequireSourceAsync().ConfigureAwait(false);
            var result = await action(facts, token).ConfigureAwait(false);
            await RequireSourceAsync().ConfigureAwait(false);
            return result;
        }, ct).ConfigureAwait(false);
    }

    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
