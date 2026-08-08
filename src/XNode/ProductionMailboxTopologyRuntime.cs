using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

public sealed class ProductionMailboxReplicaAuthority(
    ProductionMailboxAuthorityProvider topology,
    MailboxClientAdapterOptions adapter)
    : IMailboxClientReplicaAuthorizer
{
    public bool IsConfigured => topology.SupportsAdapter(adapter);

    public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
        ulong epoch,
        ReadOnlyMemory<byte> membershipCommitment,
        ReadOnlyMemory<byte> placementCommitment,
        ReadOnlyMemory<byte> blindedPlacementId,
        ReadOnlyMemory<byte> selectionInputCommitment,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var resolved = topology.TryResolve(
            epoch,
            membershipCommitment,
            placementCommitment,
            blindedPlacementId,
            selectionInputCommitment,
            out var selection);
        return ValueTask.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>(
            resolved && selection is not null
                ? selection.Replicas.Select(static replica =>
                    (ReadOnlyMemory<byte>)replica.ReplicaId.ToArray()).ToArray()
                : []);
    }
}

public sealed class ProductionMailboxReplicaFanout
    : IMailboxClientReplicaFanout,
      IMailboxClientTombstoneFanout
{
    private readonly IProductionMailboxTopologyProvider _topology;
    private readonly IMailboxReplicaPeerClient _peerClient;
    private readonly RouterId _localRouterId;
    private readonly byte[] _localSeed;
    private readonly SodiumMailboxPeerReplicationCrypto _crypto = new();

    public ProductionMailboxReplicaFanout(
        IProductionMailboxTopologyProvider topology,
        RouterNodeOptions node,
        IMailboxReplicaPeerClient peerClient)
    {
        _topology = topology;
        _peerClient = peerClient;
        _localRouterId = node.GetRouterId();
        _localSeed = Convert.FromHexString(node.GetEd25519PrivateKey());
    }

    public bool IsConfigured => _topology.IsConfigured;

    public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
        MailboxReplicaStoreContext context,
        CancellationToken cancellationToken) => SendAsync(
            MailboxPeerReplicationOperation.Store,
            context.Epoch,
            context.OperationId,
            context.BlindedMailboxId,
            context.PlacementCommitment,
            context.BlindedPlacementId,
            context.MembershipCommitment,
            context.Cursor,
            context.AcceptedAtUnixSeconds,
            context.ExpiresAtUnixSeconds,
            context.CanonicalEnvelope,
            context.ExpectedReplicaIds,
            cancellationToken);

    public Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
        MailboxReplicaTombstoneContext context,
        CancellationToken cancellationToken) => SendAsync(
            MailboxPeerReplicationOperation.Tombstone,
            context.Epoch,
            context.OperationId,
            context.BlindedMailboxId,
            context.PlacementCommitment,
            context.BlindedPlacementId,
            context.MembershipCommitment,
            context.Cursor,
            context.AcceptedAtUnixSeconds,
            context.ExpiresAtUnixSeconds,
            context.EnvelopeDigest,
            context.ExpectedReplicaIds,
            cancellationToken);

    private async Task<IReadOnlyList<ReadOnlyMemory<byte>>> SendAsync(
        MailboxPeerReplicationOperation operation,
        ulong epoch,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> placement,
        ReadOnlyMemory<byte> placementId,
        ReadOnlyMemory<byte> membership,
        ulong cursor,
        ulong acceptedAt,
        ulong expiresAt,
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var selectionInput = ProductionMailboxReplicaSelection
            .ComputeSelectionInputCommitment(new BlindedPlacementId(placementId.ToArray()));
        if (!_topology.TryResolve(
                epoch,
                membership,
                placement,
                placementId,
                selectionInput,
                out var selection)
            || selection is null
            || selection.Replicas.Count != 2
            || expectedReplicaIds.Count != 2
            || !ExactReplicaOrder(selection.Replicas, expectedReplicaIds))
        {
            return [];
        }

        var local = selection.Replicas.SingleOrDefault(replica =>
            replica.ReplicaId.Span.SequenceEqual(_localRouterId.ToBytes()));
        var remote = selection.Replicas.SingleOrDefault(replica =>
            !replica.ReplicaId.Span.SequenceEqual(_localRouterId.ToBytes()));
        if (local is null || remote is null)
        {
            return [];
        }

        var localProof = MailboxPeerReplicationCodec.DecodeMembershipProof(
            local.CanonicalMembershipProof.Span);
        var remoteProof = MailboxPeerReplicationCodec.DecodeMembershipProof(
            remote.CanonicalMembershipProof.Span);
        if (!CryptographicOperations.FixedTimeEquals(
                _crypto.GetPublicKey(_localSeed),
                localProof.SigningPublicKey.Span))
        {
            return [];
        }

        var descriptor = MailboxReplicaRouteProofCodec.Decode(
            remoteProof.CanonicalInclusionProof.Span).Descriptor;
        if (!SameOrigin(descriptor.RpcEndpoint, remote.HttpsEndpoint))
        {
            return [];
        }

        var unsigned = new MailboxPeerWireRequestV2
        {
            Operation = operation,
            Epoch = epoch,
            OperationId = operationId,
            SenderRouterId = localProof.ReplicaId,
            RecipientRouterId = remoteProof.ReplicaId,
            MembershipCommitment = membership,
            PlacementCommitment = placement,
            BlindedMailboxId = mailboxId,
            Cursor = cursor,
            CreatedAtUnixSeconds = acceptedAt,
            ExpiresAtUnixSeconds = expiresAt,
            ReplayNonce = ReplayNonce(operation, epoch, operationId.Span, cursor, payload.Span),
            PayloadDigest = SHA256.HashData(payload.Span),
            Payload = payload.ToArray(),
            SenderMembershipProof = localProof,
            RecipientMembershipProof = remoteProof,
            Signature = ReadOnlyMemory<byte>.Empty
        };
        var canonical = MailboxPeerWireV2Codec.Encode(
            _crypto.SignRequest(unsigned, _localSeed));
        var route = operation == MailboxPeerReplicationOperation.Store
            ? MailboxWireHttpContract.PeerStoreRoute
            : MailboxWireHttpContract.PeerTombstoneRoute;
        var response = await _peerClient.SendAsync(
            new MailboxReplicaPeer(
                RouterId.FromBytes(remote.ReplicaId.Span),
                new Uri(remote.HttpsEndpoint, route).AbsoluteUri)
            {
                CurrentSpkiSha256 = remote.CurrentSpkiSha256.ToArray(),
                NextSpkiSha256 = remote.NextSpkiSha256.ToArray()
            },
            operation,
            canonical,
            cancellationToken).ConfigureAwait(false);
        return response is null ? [] : [response.Value.ToArray()];
    }

    private static bool SameOrigin(string descriptorEndpoint, Uri topologyEndpoint) =>
        Uri.TryCreate(descriptorEndpoint, UriKind.Absolute, out var descriptor)
        && string.Equals(descriptor.Scheme, topologyEndpoint.Scheme, StringComparison.Ordinal)
        && string.Equals(descriptor.Host, topologyEndpoint.Host, StringComparison.OrdinalIgnoreCase)
        && descriptor.Port == topologyEndpoint.Port;

    private static bool ExactReplicaOrder(
        IReadOnlyList<ProductionMailboxTopologyReplica> selected,
        IReadOnlyList<ReadOnlyMemory<byte>> expected) =>
        selected.Count == expected.Count
        && Enumerable.Range(0, selected.Count).All(index =>
            CryptographicOperations.FixedTimeEquals(
                selected[index].ReplicaId.Span,
                expected[index].Span));

    private static byte[] ReplayNonce(
        MailboxPeerReplicationOperation operation,
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        ulong cursor,
        ReadOnlySpan<byte> payload)
    {
        Span<byte> header = stackalloc byte[1 + 8 + 16 + 8 + 32];
        header[0] = (byte)operation;
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(1, 8), epoch);
        operationId.CopyTo(header.Slice(9, 16));
        BinaryPrimitives.WriteUInt64BigEndian(header.Slice(25, 8), cursor);
        SHA256.HashData(payload).CopyTo(header.Slice(33, 32));
        return SHA256.HashData(header);
    }
}
