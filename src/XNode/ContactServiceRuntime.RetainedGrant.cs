using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.ContactResolver;

namespace XNode;

internal sealed partial class ProductionContactServiceOpaqueDispatcher
{
    // Retrieve uses original protected custody from the outset, not a fallback
    // after a current-route miss. Deposit continues its current-only branch.
    private ValueTask<ReadOnlyMemory<byte>> DispatchRetainedRetrieveGrantAsync(
        ContactServicePlacementCapability placement, AuthenticatedRemoteContactServiceReplica remote,
        ContactRecord request, CancellationToken ct)
    {
        var owner = retainedReads ?? throw new ContactServiceUnavailableException(
            "Retained Retrieve requires the actual protected current-source owner.");
        var exact = request.CanonicalBytes.ToArray();
        // Keep the local protected revision and actual current source checked
        // around the complete two-store -> private issuer -> response boundary.
        return owner.WithProtectedReadAsync<ReadOnlyMemory<byte>>(placement, exact, async (first, token) =>
        {
            var second = await remote.ReadRetainedMailboxGrantRouteAsync(token).ConfigureAwait(false);
            RequireSameRetainedFacts(first, second);
            var tuple = MailboxRetainedReadEvidenceAuthentication.CreateTuple(SHA256.HashData(exact),
                request.Field(3).Span, Deep.Protocol.ContactV1.MailboxGrantCapabilityDigest.Compute(
                    request.Field(4).Span, Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve),
                SHA256.HashData(first.ExactRouteClosure.Span), first.ReadUntilUnixSeconds);
            var receipt = new ContactServiceReplicaReceiptRequest(ContactServiceReceiptKind.MailboxRetainedRead, tuple);
            var localTask = owner.IssueAsync(placement, exact, receipt, token).AsTask();
            var remoteTask = remote.IssueAsync(receipt, token).AsTask();
            await Task.WhenAll(localTask, remoteTask).ConfigureAwait(false);
            var evidence = new[] {
                VerifyRetainedReceipt(await localTask.ConfigureAwait(false), node.GetRouterId().ToBytes()),
                VerifyRetainedReceipt(await remoteTask.ConfigureAwait(false), remote.ReplicaId.Span)
            };
            MailboxGrantReplicaEvidence VerifyRetainedReceipt(ContactServiceReplicaReceipt actual, ReadOnlySpan<byte> expected)
            {
                placement.VerifiedPlacement.Network.EnsureCurrent();
                if (!Fixed(actual.ReplicaId.Span, expected) || actual.Signature.Length != 64 ||
                    !ContactServiceReceiptTranscript.Verify(
                        placement.VerifiedPlacement.Network.ResolveNodeIdentityPublicKey(expected.ToArray()).Span,
                        MailboxRetainedReadEvidenceAuthentication.GetSigningBytes(tuple), actual.Signature.Span))
                    throw new ContactServiceReceiptAuthorityException("Invalid independently protected retained evidence.");
                return new(actual.ReplicaId.ToArray(), actual.Signature.ToArray());
            }
            var responseBytes = await mailboxGrantAuthority.AuthorizeAsync(new(
                placement.VerifiedPlacement, exact, MailboxGrantAcquisitionResultCode.Success,
                first.ExactRouteClosure, 1, 0, BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span), evidence,
                MailboxGrantAuthorityEvidenceKind.RetainedRead, first.ReadUntilUnixSeconds), token).ConfigureAwait(false);
            // A remote state/source loss after attestation cannot be reported as
            // successful current custody by the forwarding node.
            RequireSameRetainedFacts(first, await remote.ReadRetainedMailboxGrantRouteAsync(token).ConfigureAwait(false));
            var response = ContactCodec.Decode(ProtocolMagic.XMC2, responseBytes.Span);
            ContactCodec.ValidateMailboxGrantResultBinding(request, response);
            ContactCodec.ValidateMailboxGrantResultRouteBinding(response, ContactRouteClosureCodec.Decode(first.ExactRouteClosure.Span));
            if (responseBytes.Length != 510 || response.Field(8).Length != 304 ||
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(response.Field(8).Span).Domain !=
                    Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve)
                throw new ContactServiceUnavailableException("Retained Retrieve requires its exact successful role grant.");
            token.ThrowIfCancellationRequested(); return response.CanonicalBytes.ToArray();
        }, ct);
    }

    private static void RequireSameRetainedFacts(RetainedMailboxRouteLookup first, RetainedMailboxRouteLookup second)
    {
        if (first.Disposition != RetainedMailboxRouteDisposition.Found ||
            second.Disposition != RetainedMailboxRouteDisposition.Found || first.ReadUntilUnixSeconds == 0 ||
            first.ReadUntilUnixSeconds != second.ReadUntilUnixSeconds ||
            !Fixed(first.ExactRouteClosure.Span, second.ExactRouteClosure.Span))
            throw new ContactServiceUnavailableException("Independent protected retained stores do not agree.");
    }
}
