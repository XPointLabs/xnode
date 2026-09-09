using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;

namespace XNode;

internal sealed class ContactReplicaRequestReceiver
{
    private readonly RouterNodeOptions node;
    private readonly ContactServiceAuthoritySources authorities;
    private readonly ContactServiceLocalReplicaRuntime local;
    private readonly IClock clock;

    public ContactReplicaRequestReceiver(
        RouterNodeOptions node,
        ContactServiceAuthoritySources authorities,
        ContactServiceLocalReplicaRuntime local,
        IClock clock)
    {
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.authorities = authorities ?? throw new ArgumentNullException(nameof(authorities));
        this.local = local ?? throw new ArgumentNullException(nameof(local));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    internal async ValueTask<ContactReplicaRpcResponse> ReceiveAsync(
        ContactReplicaRpcCommand command,
        RouterId authenticatedSender,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var localId = node.GetRouterId().ToBytes();
        var current = await authorities.Placements.MintAsync(
            command.Placement.RequestKind,
            command.Placement.ShardKey,
            cancellationToken).ConfigureAwait(false);
        current.EnsureUsable(checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
        EnsureExactPlacement(command.Placement, current);
        var remoteId = current.OtherReplica(localId);
        if (!Fixed(remoteId, authenticatedSender.ToBytes())
            || !OperationMatches(command.Operation, current.RequestKind))
        {
            throw new UnauthorizedAccessException(
                "The authenticated peer is outside the exact contact placement or operation class.");
        }

        var payload = command.Operation switch
        {
            ContactReplicaRpcOperation.PublishDcr => await PublishAuthorizedAsync(
                command,
                current,
                cancellationToken).ConfigureAwait(false),
            ContactReplicaRpcOperation.ReadCurrentDcr => ContactReplicaPayloadCodec.Encode(
                await local.Binding.ResolverReplica.ResolveCurrentDcrAsync(
                    RequireFixed32(command.Payload.Span),
                    cancellationToken).ConfigureAwait(false)),
            ContactReplicaRpcOperation.ResolveDcr => ContactReplicaPayloadCodec.Encode(
                await local.Binding.ResolverReplica.ResolveDcrAsync(
                    ContactReplicaPayloadCodec.DecodeDcrResolveRequest(command.Payload.Span),
                    cancellationToken).ConfigureAwait(false)),
            ContactReplicaRpcOperation.ReadDcrClaim => ContactReplicaPayloadCodec.Encode(
                await local.Binding.ResolverReplica.ReadDcrClaimAsync(
                    ContactReplicaPayloadCodec.DecodeDcrResolveRequest(command.Payload.Span),
                    cancellationToken).ConfigureAwait(false)),
            ContactReplicaRpcOperation.WriteXur => ContactReplicaPayloadCodec.Encode(
                await local.Binding.ResolverReplica.WriteXurSuccessorAsync(
                    ContactReplicaPayloadCodec.DecodeXurWrite(command.Payload.Span),
                    cancellationToken).ConfigureAwait(false)),
            ContactReplicaRpcOperation.ReadXur => await ReadXurAsync(
                command.Payload,
                cancellationToken).ConfigureAwait(false),
            ContactReplicaRpcOperation.ClaimPreKey => ContactReplicaPayloadCodec.Encode(
                await local.Binding.PreKeyReplica.ClaimAsync(
                    ContactReplicaPayloadCodec.DecodePreKeyClaimRequest(command.Payload.Span),
                    cancellationToken).ConfigureAwait(false)),
            ContactReplicaRpcOperation.LatchPreKeyFork => await LatchForkAsync(
                command.Payload,
                cancellationToken).ConfigureAwait(false),
            ContactReplicaRpcOperation.IssueReceipt => await IssueReceiptAsync(
                command.Payload,
                current.RequestKind,
                cancellationToken).ConfigureAwait(false),
            ContactReplicaRpcOperation.ApplyPreKeyPublication =>
                await ApplyPreKeyPublicationAsync(
                    command.Payload,
                    current,
                    cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidDataException("The contact replica RPC operation is unknown.")
        };
        return new ContactReplicaRpcResponse(
            command.Operation,
            command.CorrelationId.ToArray(),
            localId,
            payload);
    }

    private async ValueTask<byte[]> ApplyPreKeyPublicationAsync(
        ReadOnlyMemory<byte> payload,
        ContactServicePlacementCapability current,
        CancellationToken cancellationToken)
    {
        var request = ContactReplicaPayloadCodec.DecodeBoundedPreKeyPublication(payload.Span);
        if (current.RequestKind != Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishPreKeyInventory
            || !Fixed(request.NetworkId.Span, current.NetworkId.Span)
            || !Fixed(request.ViewHash.Span, current.ViewHash.Span)
            || !Fixed(request.PlacementHash.Span, current.PlacementHash.Span)
            || !Fixed(local.ResolvePublicationServiceCapability(request).Span, current.ShardKey.Span))
        {
            throw new UnauthorizedAccessException(
                "The exact bounded XPP1 request is outside the locally minted placement.");
        }
        var recipients = authorities.PreKeyRecipients
            ?? throw new InvalidOperationException(
                "Bounded XPP1 replica activation requires verified recipient evidence.");
        var snapshots = authorities.Snapshots
            ?? throw new InvalidOperationException(
                "Bounded XPP1 replica activation requires a verified authority snapshot.");
        var candidates = await recipients.ReadCurrentCandidatesAsync(
                request.NetworkId,
                cancellationToken)
            .ConfigureAwait(false);
        var snapshot = await snapshots.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        snapshot.EnsureConsistent();
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        var exactReceipt = await local.ApplyPublicationAsync(
                request,
                current,
                candidates,
                snapshot.TrustedTimeAuthority,
                now,
                cancellationToken)
            .ConfigureAwait(false);
        return ContactReplicaPayloadCodec.EncodeBoundedPreKeyReceipt(
            Xic1BoundedCodec.Decode(exactReceipt.Span));
    }

    private async ValueTask<byte[]> ReadXurAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var request = ContactReplicaPayloadCodec.DecodeReadXur(payload.Span);
        var result = await local.Binding.ResolverReplica.ResolveXurSuccessorsAsync(
            request.Capability,
            request.XurHash,
            request.After,
            request.Maximum,
            cancellationToken).ConfigureAwait(false);
        return ContactReplicaPayloadCodec.Encode(result);
    }

    private async ValueTask<byte[]> PublishAuthorizedAsync(
        ContactReplicaRpcCommand command,
        ContactServicePlacementCapability current,
        CancellationToken cancellationToken)
    {
        var request = ContactReplicaPayloadCodec.DecodeAuthorizedPublish(command.Payload.Span);
        if (!Fixed(request.NetworkId.Span, current.NetworkId.Span)
            || !Fixed(request.ViewHash.Span, current.ViewHash.Span)
            || !Fixed(request.PlacementHash.Span, current.PlacementHash.Span)
            || !Fixed(request.LocatorHash.Span, current.ShardKey.Span))
        {
            throw new UnauthorizedAccessException(
                "The exact XPU1 request is outside the locally minted placement.");
        }

        var result = await new ContactAuthorizedPublicationReplica(
            local.Binding.ResolverReplica,
            authorities.PublicationAuthorizations,
            local.AuthorizationSaga,
            clock).PublishAsync(request, cancellationToken).ConfigureAwait(false);
        return ContactReplicaPayloadCodec.Encode(result);
    }

    private async ValueTask<byte[]> LatchForkAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        await local.Binding.PreKeyReplica.LatchForkAsync(
            RequireFixed32(payload.Span),
            cancellationToken).ConfigureAwait(false);
        return [];
    }

    private async ValueTask<byte[]> IssueReceiptAsync(
        ReadOnlyMemory<byte> payload,
        Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind requestKind,
        CancellationToken cancellationToken)
    {
        var request = ContactReplicaPayloadCodec.DecodeReceiptRequest(payload.Span);
        await VerifyReceiptEvidenceAsync(
            request.Request,
            request.EvidenceOperation,
            request.EvidencePayload,
            requestKind,
            cancellationToken).ConfigureAwait(false);
        var receipt = await local.Binding.ReceiptAuthority.IssueAsync(
            request.Request,
            cancellationToken).ConfigureAwait(false);
        return ContactReplicaPayloadCodec.Encode(receipt);
    }

    private async ValueTask VerifyReceiptEvidenceAsync(
        ContactServiceReplicaReceiptRequest receipt,
        ContactReplicaRpcOperation operation,
        ReadOnlyMemory<byte> payload,
        Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind requestKind,
        CancellationToken cancellationToken)
    {
        byte[] expected;
        switch (receipt.Kind)
        {
            case ContactServiceReceiptKind.PublishCommit
                when requestKind == Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishInvite
                    && operation == ContactReplicaRpcOperation.PublishDcr:
            {
                var request = ContactReplicaPayloadCodec.DecodeAuthorizedPublish(payload.Span);
                ContactPublicationAuthorizationSagaDisposition authorizationDisposition;
                try
                {
                    authorizationDisposition = local.AuthorizationSaga.Read(
                        ContactServiceOpaqueFacade.Xpa1AuthorizationId(request.ExactXpa1.Span));
                }
                catch (Exception exception) when (exception is KeyNotFoundException or IOException)
                {
                    throw new ContactServiceReceiptAuthorityException(
                        "The local XPA saga has no committed publication authorization.",
                        exception);
                }

                if (authorizationDisposition
                    != ContactPublicationAuthorizationSagaDisposition.ExistingCommitted)
                {
                    throw new ContactServiceReceiptAuthorityException(
                        "The local XPA saga has not committed this publication authorization.");
                }
                var result = await local.Binding.ResolverReplica.ResolveCurrentDcrAsync(
                    request.LocatorHash,
                    cancellationToken).ConfigureAwait(false);
                if (result.Disposition != ContactResolverReadDisposition.Current
                    || result.Publication is null
                    || !Fixed(
                        result.Publication.ObjectCiphertextHash,
                        request.ObjectCiphertextHash.Span))
                {
                    throw new ContactServiceReceiptAuthorityException(
                        "The local resolver replica has no durable publication for the receipt.");
                }
                expected = Concat(
                    request.RequestHash.ToArray(),
                    result.Publication.ObjectCiphertextHash,
                    U64(checked(result.Publication.Generation + 1)));
                break;
            }
            case ContactServiceReceiptKind.UpdateCommit
                when requestKind == Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishContactUpdate
                    && operation == ContactReplicaRpcOperation.WriteXur:
            {
                var request = ContactReplicaPayloadCodec.DecodeXurWrite(payload.Span);
                var result = await local.Binding.ResolverReplica.WriteXurSuccessorAsync(
                    request,
                    cancellationToken).ConfigureAwait(false);
                RequireDurable(result.Disposition);
                expected = Concat(
                    request.RequestHash.ToArray(),
                    U64(result.Generation),
                    result.ObjectHash,
                    U64(result.Generation));
                break;
            }
            case ContactServiceReceiptKind.PreKeyClaimCommit
                when requestKind == Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.ClaimPreKey
                    && operation == ContactReplicaRpcOperation.ClaimPreKey:
            {
                var request = ContactReplicaPayloadCodec.DecodePreKeyClaimRequest(payload.Span);
                var result = await local.Binding.PreKeyReplica.ClaimAsync(
                    request,
                    cancellationToken).ConfigureAwait(false);
                if (result.Disposition is not ContactPreKeyClaimDisposition.Claimed
                    and not ContactPreKeyClaimDisposition.ExactReplay)
                {
                    throw new ContactServiceReceiptAuthorityException(
                        "The local pre-key replica has no durable result for the receipt.");
                }
                expected = ContactServiceReceiptTranscript.PreKeyClaimTuple(result);
                break;
            }
            case ContactServiceReceiptKind.InviteClaimCommit
                when requestKind == Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.ResolveInvite
                    && operation is ContactReplicaRpcOperation.ResolveDcr
                        or ContactReplicaRpcOperation.ReadDcrClaim:
            {
                var request = ContactReplicaPayloadCodec.DecodeDcrResolveRequest(payload.Span);
                var result = operation == ContactReplicaRpcOperation.ResolveDcr
                    ? await local.Binding.ResolverReplica.ResolveDcrAsync(
                        request,
                        cancellationToken).ConfigureAwait(false)
                    : await local.Binding.ResolverReplica.ReadDcrClaimAsync(
                        request,
                        cancellationToken).ConfigureAwait(false);
                if (result.Disposition is not ContactResolverResolveDisposition.Committed
                    and not ContactResolverResolveDisposition.ExactReplay
                    || result.Publication is null
                    || result.ClaimCommitGeneration == 0
                    || result.ResponseUnixSeconds == 0
                    || result.CanonicalRouteClosure.Length == 0)
                {
                    throw new ContactServiceReceiptAuthorityException(
                        "The local invite replica has no durable result for the receipt.");
                }
                expected = Concat(
                    request.RequestHash.ToArray(),
                    request.LocatorHash.ToArray(),
                    U64(result.Publication.Generation),
                    U64(result.Publication.EffectiveExpiresAtUnixSeconds),
                    result.Publication.ObjectCiphertextHash,
                    SHA256.HashData(result.CanonicalRouteClosure),
                    U64(result.ClaimCommitGeneration),
                    U64(result.ResponseUnixSeconds));
                break;
            }
            default:
                throw new ContactServiceReceiptAuthorityException(
                    "The receipt kind is not authorized by the exact operation placement.");
        }

        if (!Fixed(expected, receipt.CanonicalTuple.Span))
        {
            throw new ContactServiceReceiptAuthorityException(
                "The requested receipt tuple does not match the local durable replica result.");
        }
    }

    private static bool OperationMatches(
        ContactReplicaRpcOperation operation,
        Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind requestKind) => requestKind switch
        {
            Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishInvite =>
                operation is ContactReplicaRpcOperation.PublishDcr
                    or ContactReplicaRpcOperation.IssueReceipt,
            Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.ResolveInvite =>
                operation is ContactReplicaRpcOperation.ReadCurrentDcr
                    or ContactReplicaRpcOperation.ResolveDcr
                    or ContactReplicaRpcOperation.ReadDcrClaim
                    or ContactReplicaRpcOperation.IssueReceipt,
            Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.ClaimPreKey =>
                operation is ContactReplicaRpcOperation.ClaimPreKey
                    or ContactReplicaRpcOperation.LatchPreKeyFork
                    or ContactReplicaRpcOperation.IssueReceipt,
            Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishContactUpdate =>
                operation is ContactReplicaRpcOperation.WriteXur
                    or ContactReplicaRpcOperation.IssueReceipt,
            Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.QueryContactUpdate =>
                operation == ContactReplicaRpcOperation.ReadXur,
            Deep.Protocol.XPointNetworkV1.ContactServiceRequestKind.PublishPreKeyInventory =>
                operation == ContactReplicaRpcOperation.ApplyPreKeyPublication,
            _ => false
        };

    private static void EnsureExactPlacement(
        ContactServicePlacementCapability received,
        ContactServicePlacementCapability current)
    {
        if (received.RequestKind != current.RequestKind
            || received.ServiceClass != current.ServiceClass
            || received.SelectionEpoch != current.SelectionEpoch
            || received.ValidUntilUnixSeconds != current.ValidUntilUnixSeconds
            || !Fixed(received.NetworkId.Span, current.NetworkId.Span)
            || !Fixed(received.ViewHash.Span, current.ViewHash.Span)
            || !Fixed(received.PlacementHash.Span, current.PlacementHash.Span)
            || !Fixed(received.ShardKey.Span, current.ShardKey.Span)
            || received.ReplicaIds.Count != current.ReplicaIds.Count
            || !received.ReplicaIds.Zip(current.ReplicaIds)
                .All(pair => Fixed(pair.First.Span, pair.Second.Span)))
        {
            throw new UnauthorizedAccessException(
                "The remote contact placement projection is not the locally minted exact capability.");
        }
    }

    private static ReadOnlyMemory<byte> RequireFixed32(ReadOnlySpan<byte> value) =>
        value.Length == 32 && value.IndexOfAnyExcept((byte)0) >= 0
            ? value.ToArray()
            : throw new InvalidDataException("A non-zero 32-byte replica value is required.");

    private static void RequireDurable(ContactResolverMutationDisposition disposition)
    {
        if (disposition is not ContactResolverMutationDisposition.Committed
            and not ContactResolverMutationDisposition.ExactReplay)
        {
            throw new ContactServiceReceiptAuthorityException(
                "The local resolver replica has no durable result for the receipt.");
        }
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Concat(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}
