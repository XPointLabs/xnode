using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;

namespace XNode;

internal enum ContactReplicaRpcOperation : byte
{
    PublishDcr = 1,
    ReadCurrentDcr = 2,
    ResolveDcr = 3,
    ReadDcrClaim = 4,
    WriteXur = 5,
    ReadXur = 6,
    ClaimPreKey = 7,
    LatchPreKeyFork = 8,
    IssueReceipt = 9,
    ApplyPreKeyPublication = 10
}

internal sealed class ContactServicePlacementCapability
{
    private readonly byte[] networkId;
    private readonly byte[] viewHash;
    private readonly byte[] placementHash;
    private readonly byte[] shardKey;
    private readonly byte[][] replicaIds;
    private readonly VerifiedContactServicePlacement? verifiedPlacement;

    private ContactServicePlacementCapability(
        ContactServiceRequestKind requestKind,
        ContactServiceClass serviceClass,
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32,
        ReadOnlySpan<byte> shardKey32,
        ulong selectionEpoch,
        ulong validUntilUnixSeconds,
        IReadOnlyList<ReadOnlyMemory<byte>> rankedReplicaNodeIds,
        VerifiedContactServicePlacement? verifiedPlacement = null)
    {
        if (networkId16.Length != 16
            || viewHash32.Length != 32
            || placementHash32.Length != 32
            || shardKey32.Length != 32
            || networkId16.IndexOfAnyExcept((byte)0) < 0
            || viewHash32.IndexOfAnyExcept((byte)0) < 0
            || placementHash32.IndexOfAnyExcept((byte)0) < 0
            || shardKey32.IndexOfAnyExcept((byte)0) < 0
            || rankedReplicaNodeIds.Count != 2)
        {
            throw new ArgumentException(
                "A contact placement capability requires exact non-zero NETCODEC fields and two replicas.");
        }

        var expectedClass = ContactReplicaRequestBinding.ServiceClass(requestKind);
        if (serviceClass != expectedClass)
        {
            throw new ArgumentException("The contact placement request kind and service class disagree.");
        }

        replicaIds = rankedReplicaNodeIds
            .Select(static value => value.ToArray())
            .ToArray();
        if (replicaIds.Any(static value => value.Length != 32
                || value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            || CryptographicOperations.FixedTimeEquals(replicaIds[0], replicaIds[1]))
        {
            throw new ArgumentException("The contact placement replica set is invalid.");
        }

        RequestKind = requestKind;
        ServiceClass = serviceClass;
        networkId = networkId16.ToArray();
        viewHash = viewHash32.ToArray();
        placementHash = placementHash32.ToArray();
        shardKey = shardKey32.ToArray();
        SelectionEpoch = selectionEpoch;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
        this.verifiedPlacement = verifiedPlacement;
    }

    internal ContactServiceRequestKind RequestKind { get; }
    internal ContactServiceClass ServiceClass { get; }
    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> ViewHash => viewHash.ToArray();
    internal ReadOnlyMemory<byte> PlacementHash => placementHash.ToArray();
    internal ReadOnlyMemory<byte> ShardKey => shardKey.ToArray();
    internal ulong SelectionEpoch { get; }
    internal ulong ValidUntilUnixSeconds { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ReplicaIds =>
        Array.AsReadOnly(replicaIds
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
            .ToArray());
    internal VerifiedContactServicePlacement VerifiedPlacement => verifiedPlacement
        ?? throw new InvalidOperationException(
            "An untrusted wire placement projection cannot authorize bounded XPP1 activation.");

    internal static ContactServicePlacementCapability FromNetcodec(
        VerifiedContactServicePlacement placement,
        ContactServiceRequestKind requestKind,
        ReadOnlyMemory<byte> shardKey,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(placement);
        if (!placement.Binds(requestKind, shardKey)
            || placement.ValidUntilUnixSeconds <= nowUnixSeconds)
        {
            throw new InvalidOperationException(
                "The NETCODEC contact placement capability is stale or does not bind the request.");
        }

        return new ContactServicePlacementCapability(
            requestKind,
            placement.ServiceClass,
            placement.Network.NetworkId.Span,
            placement.ViewHash.Span,
            placement.PlacementHash.Span,
            shardKey.Span,
            placement.SelectionEpoch,
            placement.ValidUntilUnixSeconds,
            placement.RankedReplicaNodeIds,
            placement);
    }

    // This constructs only an untrusted wire/test projection. A receiver must compare every
    // field with a freshly minted capability before dispatch; production senders use FromNetcodec.
    internal static ContactServicePlacementCapability FromUntrustedProjection(
        ContactServiceRequestKind requestKind,
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32,
        ReadOnlySpan<byte> shardKey32,
        ulong selectionEpoch,
        ulong validUntilUnixSeconds,
        IReadOnlyList<ReadOnlyMemory<byte>> replicaIds) => new(
            requestKind,
            ContactReplicaRequestBinding.ServiceClass(requestKind),
            networkId16,
            viewHash32,
            placementHash32,
            shardKey32,
            selectionEpoch,
            validUntilUnixSeconds,
            replicaIds);

    internal bool ContainsReplica(ReadOnlySpan<byte> replicaId)
    {
        foreach (var value in replicaIds)
        {
            if (Fixed(value, replicaId))
            {
                return true;
            }
        }
        return false;
    }

    internal byte[] OtherReplica(ReadOnlySpan<byte> localReplicaId)
    {
        if (!ContainsReplica(localReplicaId))
        {
            throw new InvalidOperationException(
                "The local node is outside the exact contact placement capability.");
        }

        foreach (var value in replicaIds)
        {
            if (!Fixed(value, localReplicaId))
            {
                return value.ToArray();
            }
        }
        throw new InvalidOperationException("The exact contact placement has no remote replica.");
    }

    internal void EnsureUsable(ulong nowUnixSeconds)
    {
        if (ValidUntilUnixSeconds <= nowUnixSeconds)
        {
            throw new InvalidOperationException("The contact placement capability has expired.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class ContactReplicaRequestBinding
{
    internal static ContactServiceRequestKind RequestKind(ContactServiceOperation operation) =>
        operation switch
        {
            ContactServiceOperation.PublishDcr => ContactServiceRequestKind.PublishInvite,
            ContactServiceOperation.ResolveDcr => ContactServiceRequestKind.ResolveInvite,
            ContactServiceOperation.ClaimPreKey => ContactServiceRequestKind.ClaimPreKey,
            ContactServiceOperation.WriteContactUpdate => ContactServiceRequestKind.PublishContactUpdate,
            ContactServiceOperation.FetchContactUpdates => ContactServiceRequestKind.QueryContactUpdate,
            ContactServiceOperation.PublishPreKeyInventory => ContactServiceRequestKind.PublishPreKeyInventory,
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    internal static ContactServiceClass ServiceClass(ContactServiceRequestKind requestKind) =>
        requestKind switch
        {
            ContactServiceRequestKind.PublishInvite or ContactServiceRequestKind.ResolveInvite =>
                ContactServiceClass.InviteResolver,
            ContactServiceRequestKind.ClaimPreKey => ContactServiceClass.PreKeyClaim,
            ContactServiceRequestKind.PublishPreKeyInventory => ContactServiceClass.PreKeyClaim,
            ContactServiceRequestKind.PublishContactUpdate or
                ContactServiceRequestKind.QueryContactUpdate => ContactServiceClass.ContactUpdate,
            _ => throw new ArgumentOutOfRangeException(nameof(requestKind))
        };

    internal static ReadOnlyMemory<byte> ShardKey(
        Deep.Protocol.ContactV1.ContactServiceRequestRecord request) => request switch
        {
            Deep.Protocol.ContactV1.Xpu1Request value => value.LocatorHash,
            Deep.Protocol.ContactV1.Xiq1Request value => value.LocatorHash,
            Deep.Protocol.ContactV1.Xpk1Request value => value.ServiceCapability,
            Deep.Protocol.ContactV1.Xuw1Request value => value.ServiceCapability,
            Deep.Protocol.ContactV1.Xuq1Request value => value.ServiceCapability,
            _ => throw new ArgumentOutOfRangeException(nameof(request))
        };
}

internal sealed record ContactReplicaRpcCommand(
    ContactServicePlacementCapability Placement,
    ContactReplicaRpcOperation Operation,
    ReadOnlyMemory<byte> CorrelationId,
    ReadOnlyMemory<byte> Payload);

internal sealed record ContactReplicaRpcResponse(
    ContactReplicaRpcOperation Operation,
    ReadOnlyMemory<byte> CorrelationId,
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> Payload);

internal interface IContactReplicaPeerClient
{
    ValueTask<ContactReplicaRpcResponse> SendAsync(
        ContactReplicaRpcCommand command,
        CancellationToken cancellationToken);
}

internal sealed class AuthenticatedRemoteContactServiceReplica :
    IContactResolverReplica,
    IContactPreKeyReplica,
    IContactServiceReplicaReceiptAuthority
{
    private readonly ContactServicePlacementCapability placement;
    private readonly IContactReplicaPeerClient peerClient;
    private readonly byte[] replicaId;
    private readonly byte[] exactServiceRequest;
    private readonly object evidenceGate = new();
    private readonly Dictionary<ContactServiceReceiptKind, ReceiptEvidence> receiptEvidence = [];

    internal AuthenticatedRemoteContactServiceReplica(
        ContactServicePlacementCapability placement,
        ReadOnlySpan<byte> localReplicaId,
        IContactReplicaPeerClient peerClient,
        ReadOnlyMemory<byte> exactServiceRequest = default)
    {
        this.placement = placement ?? throw new ArgumentNullException(nameof(placement));
        this.peerClient = peerClient ?? throw new ArgumentNullException(nameof(peerClient));
        replicaId = placement.OtherReplica(localReplicaId);
        this.exactServiceRequest = exactServiceRequest.ToArray();
    }

    public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

    public async ValueTask<ContactResolverMutationResult> PublishDcrAsync(
        OpaqueDcrPublishRequest request,
        CancellationToken cancellationToken)
    {
        if (exactServiceRequest.Length == 0)
        {
            throw new InvalidOperationException(
                "Remote XPU1 publication requires the exact canonical authorized service request.");
        }
        var exactXpu1 = Deep.Protocol.ContactV1.Xpu1Codec.Decode(exactServiceRequest);
        if (!Fixed(exactXpu1.RequestHash.Span, request.RequestHash)
            || !Fixed(exactXpu1.LocatorHash.Span, request.LocatorHash)
            || !Fixed(exactXpu1.ObjectCiphertextHash.Span, request.ObjectCiphertextHash))
        {
            throw new InvalidDataException(
                "The exact XPU1 request does not bind the resolver mutation.");
        }
        var payload = ContactReplicaPayloadCodec.EncodeAuthorizedPublish(exactServiceRequest);
        Remember(ContactServiceReceiptKind.PublishCommit, ContactReplicaRpcOperation.PublishDcr, payload);
        var response = await SendAsync(ContactReplicaRpcOperation.PublishDcr, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodeMutation(response.Payload.Span);
    }

    public async ValueTask<ContactResolverDcrReadResult> ResolveCurrentDcrAsync(
        ReadOnlyMemory<byte> locatorHash32,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync(
            ContactReplicaRpcOperation.ReadCurrentDcr,
            ContactReplicaPayloadCodec.EncodeFixed32(locatorHash32.Span),
            cancellationToken);
        return ContactReplicaPayloadCodec.DecodeDcrRead(response.Payload.Span);
    }

    public async ValueTask<ContactResolverDcrResolveResult> ResolveDcrAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken)
    {
        var payload = ContactReplicaPayloadCodec.Encode(request);
        Remember(ContactServiceReceiptKind.InviteClaimCommit, ContactReplicaRpcOperation.ResolveDcr, payload);
        var response = await SendAsync(ContactReplicaRpcOperation.ResolveDcr, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodeDcrResolve(response.Payload.Span);
    }

    public async ValueTask<ContactResolverDcrResolveResult> ReadDcrClaimAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken)
    {
        var payload = ContactReplicaPayloadCodec.Encode(request);
        Remember(ContactServiceReceiptKind.InviteClaimCommit, ContactReplicaRpcOperation.ReadDcrClaim, payload);
        var response = await SendAsync(ContactReplicaRpcOperation.ReadDcrClaim, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodeDcrResolve(response.Payload.Span);
    }

    public async ValueTask<ContactResolverMutationResult> WriteXurSuccessorAsync(
        OpaqueXurWriteRequest request,
        CancellationToken cancellationToken)
    {
        var payload = ContactReplicaPayloadCodec.Encode(request);
        Remember(ContactServiceReceiptKind.UpdateCommit, ContactReplicaRpcOperation.WriteXur, payload);
        var response = await SendAsync(ContactReplicaRpcOperation.WriteXur, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodeMutation(response.Payload.Span);
    }

    public async ValueTask<ContactResolverXurReadResult> ResolveXurSuccessorsAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        ReadOnlyMemory<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents,
        CancellationToken cancellationToken)
    {
        var payload = ContactReplicaPayloadCodec.EncodeReadXur(
            serviceCapability32.Span,
            exactXur1Hash32.Span,
            afterGeneration,
            maximumEvents);
        var response = await SendAsync(ContactReplicaRpcOperation.ReadXur, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodeXurRead(response.Payload.Span);
    }

    public async ValueTask<ContactPreKeyClaimResult> ClaimAsync(
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken)
    {
        var payload = ContactReplicaPayloadCodec.Encode(request);
        Remember(ContactServiceReceiptKind.PreKeyClaimCommit, ContactReplicaRpcOperation.ClaimPreKey, payload);
        var response = await SendAsync(ContactReplicaRpcOperation.ClaimPreKey, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodePreKeyClaim(response.Payload.Span);
    }

    public async ValueTask LatchForkAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        CancellationToken cancellationToken)
    {
        _ = await SendAsync(
            ContactReplicaRpcOperation.LatchPreKeyFork,
            ContactReplicaPayloadCodec.EncodeFixed32(serviceCapability32.Span),
            cancellationToken);
    }

    internal async ValueTask<Xic1BoundedReceipt> ApplyPreKeyPublicationAsync(
        Xpp1BoundedRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var response = await SendAsync(
            ContactReplicaRpcOperation.ApplyPreKeyPublication,
            ContactReplicaPayloadCodec.EncodeBoundedPreKeyPublication(request),
            cancellationToken).ConfigureAwait(false);
        return ContactReplicaPayloadCodec.DecodeBoundedPreKeyReceipt(response.Payload.Span);
    }

    public async ValueTask<ContactServiceReplicaReceipt> IssueAsync(
        ContactServiceReplicaReceiptRequest request,
        CancellationToken cancellationToken)
    {
        ReceiptEvidence evidence;
        lock (evidenceGate)
        {
            if (!receiptEvidence.TryGetValue(request.Kind, out evidence!))
            {
                throw new ContactServiceReceiptAuthorityException(
                    "No exact durable remote operation is bound to this receipt request.");
            }
        }

        var payload = ContactReplicaPayloadCodec.EncodeReceiptRequest(
            request,
            evidence.Operation,
            evidence.Payload.Span);
        var response = await SendAsync(ContactReplicaRpcOperation.IssueReceipt, payload, cancellationToken);
        return ContactReplicaPayloadCodec.DecodeReceipt(response.Payload.Span);
    }

    private async ValueTask<ContactReplicaRpcResponse> SendAsync(
        ContactReplicaRpcOperation operation,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var correlation = RandomNumberGenerator.GetBytes(32);
        var response = await peerClient.SendAsync(
            new ContactReplicaRpcCommand(placement, operation, correlation, payload),
            cancellationToken);
        if (response.Operation != operation
            || !Fixed(response.CorrelationId.Span, correlation)
            || !Fixed(response.ReplicaId.Span, replicaId))
        {
            throw new IOException("The contact replica response correlation or peer binding is invalid.");
        }
        return response;
    }

    private void Remember(
        ContactServiceReceiptKind kind,
        ContactReplicaRpcOperation operation,
        ReadOnlyMemory<byte> payload)
    {
        lock (evidenceGate)
        {
            receiptEvidence[kind] = new ReceiptEvidence(operation, payload.ToArray());
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed record ReceiptEvidence(
        ContactReplicaRpcOperation Operation,
        ReadOnlyMemory<byte> Payload);
}

internal static class ContactReplicaWireCodec
{
    internal const int MaximumRequestBytes = 70_400;
    internal const int MaximumResponseBytes = 2_200_000;
    private const byte Version = 1;
    private static ReadOnlySpan<byte> RequestMagic => "CRQ1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "CRS1"u8;

    internal static byte[] Encode(ContactReplicaRpcCommand command)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.CorrelationId.Length != 32 || command.Payload.Length > MaximumRequestBytes)
        {
            throw new InvalidDataException("The contact replica request is outside its closed bounds.");
        }

        var replicas = command.Placement.ReplicaIds;
        var output = new byte[236 + command.Payload.Length];
        RequestMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)command.Operation;
        output[6] = (byte)command.Placement.RequestKind;
        output[7] = (byte)command.Placement.ServiceClass;
        command.Placement.NetworkId.Span.CopyTo(output.AsSpan(8));
        command.Placement.ViewHash.Span.CopyTo(output.AsSpan(24));
        command.Placement.PlacementHash.Span.CopyTo(output.AsSpan(56));
        command.Placement.ShardKey.Span.CopyTo(output.AsSpan(88));
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(120), command.Placement.SelectionEpoch);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(128), command.Placement.ValidUntilUnixSeconds);
        replicas[0].Span.CopyTo(output.AsSpan(136));
        replicas[1].Span.CopyTo(output.AsSpan(168));
        command.CorrelationId.Span.CopyTo(output.AsSpan(200));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(232), checked((uint)command.Payload.Length));
        command.Payload.Span.CopyTo(output.AsSpan(236));
        if (output.Length > MaximumRequestBytes)
        {
            throw new InvalidDataException("The contact replica request exceeds its transport bound.");
        }
        return output;
    }

    internal static ContactReplicaRpcCommand DecodeRequest(ReadOnlySpan<byte> exact)
    {
        if (exact.Length is < 236 or > MaximumRequestBytes
            || !exact[..4].SequenceEqual(RequestMagic)
            || exact[4] != Version
            || !Enum.IsDefined((ContactReplicaRpcOperation)exact[5])
            || !Enum.IsDefined((ContactServiceRequestKind)exact[6])
            || !Enum.IsDefined((ContactServiceClass)exact[7]))
        {
            throw new InvalidDataException("The contact replica request envelope is malformed.");
        }
        var length = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(232, 4));
        if (length != exact.Length - 236)
        {
            throw new InvalidDataException("The contact replica request length is non-canonical.");
        }

        var kind = (ContactServiceRequestKind)exact[6];
        var capability = ContactServicePlacementCapability.FromUntrustedProjection(
            kind,
            exact.Slice(8, 16),
            exact.Slice(24, 32),
            exact.Slice(56, 32),
            exact.Slice(88, 32),
            BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(120, 8)),
            BinaryPrimitives.ReadUInt64BigEndian(exact.Slice(128, 8)),
            [exact.Slice(136, 32).ToArray(), exact.Slice(168, 32).ToArray()]);
        if (capability.ServiceClass != (ContactServiceClass)exact[7])
        {
            throw new InvalidDataException("The contact replica service class is invalid.");
        }
        return new ContactReplicaRpcCommand(
            capability,
            (ContactReplicaRpcOperation)exact[5],
            exact.Slice(200, 32).ToArray(),
            exact[236..].ToArray());
    }

    internal static byte[] Encode(ContactReplicaRpcResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.CorrelationId.Length != 32
            || response.ReplicaId.Length != 32
            || response.Payload.Length > MaximumResponseBytes - 76)
        {
            throw new InvalidDataException("The contact replica response is outside its closed bounds.");
        }
        var output = new byte[76 + response.Payload.Length];
        ResponseMagic.CopyTo(output);
        output[4] = Version;
        output[5] = (byte)response.Operation;
        output[6] = 0;
        output[7] = 0;
        response.CorrelationId.Span.CopyTo(output.AsSpan(8));
        response.ReplicaId.Span.CopyTo(output.AsSpan(40));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(72), checked((uint)response.Payload.Length));
        response.Payload.Span.CopyTo(output.AsSpan(76));
        return output;
    }

    internal static ContactReplicaRpcResponse DecodeResponse(ReadOnlySpan<byte> exact)
    {
        if (exact.Length is < 76 or > MaximumResponseBytes
            || !exact[..4].SequenceEqual(ResponseMagic)
            || exact[4] != Version
            || exact[6] != 0
            || exact[7] != 0
            || !Enum.IsDefined((ContactReplicaRpcOperation)exact[5])
            || BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(72, 4)) != exact.Length - 76)
        {
            throw new InvalidDataException("The contact replica response envelope is malformed.");
        }
        return new ContactReplicaRpcResponse(
            (ContactReplicaRpcOperation)exact[5],
            exact.Slice(8, 32).ToArray(),
            exact.Slice(40, 32).ToArray(),
            exact[76..].ToArray());
    }
}
