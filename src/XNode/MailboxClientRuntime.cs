using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

public sealed class MailboxClientDevelopmentFixtureOptions
{
    public bool Enabled { get; set; }
    public string NetworkId { get; set; } = "";
    public string IssuerPublicKey { get; set; } = "";
    public ulong MinimumGeneration { get; set; }
    public ulong MaximumGeneration { get; set; }
    public ulong IssuerValidFromUnixSeconds { get; set; }
    public ulong IssuerValidUntilUnixSeconds { get; set; }
    public string CoordinatorUrl { get; set; } = "";
    public string CurrentPlacementId { get; set; } = "";
    public string CurrentPlacementCommitment { get; set; } = "";
    public string NextPlacementId { get; set; } = "";
    public string NextPlacementCommitment { get; set; } = "";
    public string[] ReplicaIds { get; set; } = [];
    public string[] ReplicaSigningPublicKeys { get; set; } = [];
    public string CurrentLocalMembershipProof { get; set; } = "";
    public string CurrentRemoteMembershipProof { get; set; } = "";
    public string NextLocalMembershipProof { get; set; } = "";
    public string NextRemoteMembershipProof { get; set; } = "";
    public string[] RevokedSerials { get; set; } = [];
}

public sealed record MailboxClientActivationPlan(
    MailboxClientActivationOptions Activation,
    MailboxClientAdapterOptions Adapter,
    bool RoutesMapped,
    bool DevelopmentFixture);

public static class MailboxClientComposition
{
    public static MailboxClientActivationPlan Validate(
        MailboxClientActivationOptions activation,
        MailboxClientAdapterOptions adapter,
        RouterNodeOptions node,
        ReplicatedMailboxOptions mailbox,
        bool isDevelopment,
        MailboxPeerAuthorityOptions? peerAuthority = null,
        ProductionMailboxAuthorityOptions? productionAuthority = null)
    {
        ArgumentNullException.ThrowIfNull(activation);
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(mailbox);
        if (!activation.Enabled)
        {
            if (adapter.Enabled)
            {
                throw new InvalidOperationException(
                    "MailboxClientAdapter cannot be enabled while MailboxClient ingress is dormant.");
            }

            adapter.Validate();
            return new(activation, adapter, false, false);
        }

        if (!isDevelopment)
        {
            if (productionAuthority?.Enabled == true)
            {
                throw new InvalidOperationException(
                    "MailboxClient Production activation remains fail-closed until a verified " +
                    "production topology artifact supplies two replicas, canonical MIP1 proofs, " +
                    "and HTTPS endpoints with SPKI pins.");
            }

            throw new InvalidOperationException(
                "MailboxClient Production activation requires PMA1, PMR1, and a verified " +
                "production topology artifact.");
        }

        if (!activation.DevelopmentFixture.Enabled)
        {
            throw new InvalidOperationException(
                "MailboxClient Development activation requires the explicit Development fixture.");
        }

        if (!mailbox.Enabled || !adapter.Enabled)
        {
            throw new InvalidOperationException(
                "MailboxClient Development activation requires Mailbox and MailboxClientAdapter.");
        }

        adapter.Validate();
        ValidateFixture(activation.DevelopmentFixture, adapter, node);
        if (peerAuthority is null
            || peerAuthority.CurrentEpoch != adapter.CurrentEpoch
            || peerAuthority.NextEpoch != adapter.NextEpoch
            || !string.Equals(
                peerAuthority.CurrentMembershipCommitment,
                adapter.CurrentMembershipCommitment,
                StringComparison.Ordinal)
            || !string.Equals(
                peerAuthority.NextMembershipCommitment,
                adapter.NextMembershipCommitment,
                StringComparison.Ordinal)
            || peerAuthority.CurrentEpochExpiresAtUnixSeconds
                < adapter.CurrentExpiresAtUnixSeconds
            || peerAuthority.NextEpochExpiresAtUnixSeconds
                < adapter.NextExpiresAtUnixSeconds
            || !PinsPlacement(
                peerAuthority,
                adapter.CurrentEpoch,
                activation.DevelopmentFixture.CurrentPlacementCommitment,
                activation.DevelopmentFixture.ReplicaIds)
            || !PinsPlacement(
                peerAuthority,
                adapter.NextEpoch,
                activation.DevelopmentFixture.NextPlacementCommitment,
                activation.DevelopmentFixture.ReplicaIds))
        {
            throw new InvalidOperationException(
                "MailboxClient Development authority must exactly match MailboxPeerAuthority.");
        }

        return new(activation, adapter, true, true);
    }

    private static bool PinsPlacement(
        MailboxPeerAuthorityOptions authority,
        ulong epoch,
        string placementCommitment,
        string[] replicaIds) =>
        authority.PlacementSelections.Any(selection =>
            selection.Epoch == epoch
            && string.Equals(
                selection.PlacementCommitment,
                placementCommitment,
                StringComparison.Ordinal)
            && (string.Equals(
                    selection.FirstRouterId,
                    replicaIds[0],
                    StringComparison.Ordinal)
                && string.Equals(
                    selection.SecondRouterId,
                    replicaIds[1],
                    StringComparison.Ordinal)
                || string.Equals(
                    selection.FirstRouterId,
                    replicaIds[1],
                    StringComparison.Ordinal)
                && string.Equals(
                    selection.SecondRouterId,
                    replicaIds[0],
                    StringComparison.Ordinal)));

    private static void ValidateFixture(
        MailboxClientDevelopmentFixtureOptions fixture,
        MailboxClientAdapterOptions adapter,
        RouterNodeOptions node)
    {
        var network = Decode(fixture.NetworkId, 16, "network id");
        var issuer = Decode(fixture.IssuerPublicKey, 32, "issuer public key");
        var currentPlacement = Decode(
            fixture.CurrentPlacementCommitment,
            32,
            "current placement commitment");
        var currentPlacementId = Decode(
            fixture.CurrentPlacementId,
            32,
            "current placement id");
        var nextPlacement = Decode(
            fixture.NextPlacementCommitment,
            32,
            "next placement commitment");
        var nextPlacementId = Decode(
            fixture.NextPlacementId,
            32,
            "next placement id");
        if (network.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || fixture.MinimumGeneration == 0
            || fixture.MaximumGeneration < fixture.MinimumGeneration
            || fixture.IssuerValidFromUnixSeconds >= fixture.IssuerValidUntilUnixSeconds
            || CryptographicOperations.FixedTimeEquals(currentPlacement, nextPlacement)
            || !Fixed(
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(currentPlacementId)),
                currentPlacement)
            || !Fixed(
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(nextPlacementId)),
                nextPlacement)
            || !Uri.TryCreate(
                fixture.CoordinatorUrl,
                UriKind.Absolute,
                out var coordinator)
            || coordinator.Scheme is not ("https" or "http")
            || !string.IsNullOrEmpty(coordinator.UserInfo)
            || coordinator.AbsolutePath != "/"
            || !string.IsNullOrEmpty(coordinator.Query)
            || !string.IsNullOrEmpty(coordinator.Fragment)
            || Uri.CheckHostName(node.PublicHost) == UriHostNameType.Unknown
            || !string.Equals(
                coordinator.Host,
                node.PublicHost,
                StringComparison.OrdinalIgnoreCase)
            || coordinator.Port != node.PublicPort)
        {
            throw new InvalidOperationException(
                "MailboxClient Development authority window is invalid.");
        }

        if (fixture.ReplicaIds.Length != 2
            || fixture.ReplicaSigningPublicKeys.Length != 2)
        {
            throw new InvalidOperationException(
                "MailboxClient Development fixture requires exactly two replicas.");
        }

        var ids = fixture.ReplicaIds
            .Select(value => Decode(value, RouterId.ByteLength, "replica id"))
            .ToArray();
        var signingKeys = fixture.ReplicaSigningPublicKeys
            .Select(value => Decode(value, 32, "replica signing public key"))
            .ToArray();
        if (CryptographicOperations.FixedTimeEquals(ids[0], ids[1])
            || ids.Any(id => CryptographicOperations.FixedTimeEquals(id, issuer))
            || !Fixed(ids[0], signingKeys[0])
            || !Fixed(ids[1], signingKeys[1]))
        {
            throw new InvalidOperationException(
                "MailboxClient Development issuer and replica keys must be distinct.");
        }

        var localId = node.GetRouterId().ToBytes();
        _ = new MailboxClientReceiptCrypto(
            node.GetRouterId(),
            node.GetEd25519PrivateKey());
        if (!ids.Any(id => id.AsSpan().SequenceEqual(localId)))
        {
            throw new InvalidOperationException(
                "MailboxClient Development placement must include the local router.");
        }

        var proofVerifier = new MembershipRoutesMailboxReplicaProofVerifier();
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        ValidateProofPair(
            fixture.CurrentLocalMembershipProof,
            fixture.CurrentRemoteMembershipProof,
            adapter.CurrentEpoch,
            Convert.FromHexString(adapter.CurrentMembershipCommitment),
            ids,
            localId,
            proofVerifier,
            now);
        ValidateProofPair(
            fixture.NextLocalMembershipProof,
            fixture.NextRemoteMembershipProof,
            adapter.NextEpoch,
            Convert.FromHexString(adapter.NextMembershipCommitment),
            ids,
            localId,
            proofVerifier,
            now);

        foreach (var revoked in fixture.RevokedSerials)
        {
            _ = Decode(revoked, 16, "revoked serial");
        }

        if (adapter.CurrentEpoch < fixture.MinimumGeneration
            || adapter.NextEpoch > fixture.MaximumGeneration)
        {
            throw new InvalidOperationException(
                "MailboxClient Development issuer generation range does not cover E/E+1.");
        }
    }

    private static void ValidateProofPair(
        string localEncoded,
        string remoteEncoded,
        ulong epoch,
        byte[] commitment,
        byte[][] configuredIds,
        byte[] localId,
        IMailboxReplicaMembershipProofVerifier verifier,
        ulong now)
    {
        var local = DecodeProof(localEncoded, "local MIP1");
        var remote = DecodeProof(remoteEncoded, "remote MIP1");
        if (local.Epoch != epoch
            || remote.Epoch != epoch
            || !Fixed(local.MembershipCommitment.Span, commitment)
            || !Fixed(remote.MembershipCommitment.Span, commitment)
            || !Fixed(local.ReplicaId.Span, localId)
            || Fixed(remote.ReplicaId.Span, localId)
            || !configuredIds[0].AsSpan().SequenceEqual(local.ReplicaId.Span)
                && !configuredIds[1].AsSpan().SequenceEqual(local.ReplicaId.Span)
            || !configuredIds[0].AsSpan().SequenceEqual(remote.ReplicaId.Span)
                && !configuredIds[1].AsSpan().SequenceEqual(remote.ReplicaId.Span)
            || !Fixed(local.ReplicaId.Span, local.SigningPublicKey.Span)
            || !Fixed(remote.ReplicaId.Span, remote.SigningPublicKey.Span)
            || !verifier.VerifyStorageReplica(local, now)
            || !verifier.VerifyStorageReplica(remote, now))
        {
            throw new InvalidOperationException(
                "MailboxClient Development MIP1/RIP1 authority is invalid or stale.");
        }
    }

    internal static MailboxReplicaMembershipProof DecodeProof(
        string encoded,
        string field)
    {
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            var proof = MailboxPeerReplicationCodec.DecodeMembershipProof(bytes);
            if (!bytes.AsSpan().SequenceEqual(
                    MailboxPeerReplicationCodec.EncodeMembershipProof(proof)))
            {
                throw new InvalidOperationException();
            }

            return proof;
        }
        catch (Exception exception) when (
            exception is FormatException
                or MailboxPeerReplicationException
                or InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"MailboxClient Development {field} must be canonical base64 MIP1.",
                exception);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    internal static byte[] Decode(string? value, int bytes, string field)
    {
        if (value is null
            || value.Length != bytes * 2
            || value.Any(static character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new InvalidOperationException(
                $"MailboxClient Development {field} must be {bytes}-byte lowercase hex.");
        }

        var decoded = Convert.FromHexString(value);
        if (decoded.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidOperationException(
                $"MailboxClient Development {field} cannot be zero.");
        }

        return decoded;
    }
}

public sealed class DevelopmentMailboxCapabilityAuthority
    : IMailboxCapabilityAuthoritySource
{
    private readonly MailboxClientDevelopmentFixtureOptions _fixture;
    private readonly MailboxClientAdapterOptions _adapter;
    private readonly byte[] _network;
    private readonly byte[] _issuer;
    private readonly byte[] _currentPlacement;
    private readonly byte[] _nextPlacement;

    public DevelopmentMailboxCapabilityAuthority(
        MailboxClientActivationOptions activation,
        MailboxClientAdapterOptions adapter)
    {
        _fixture = activation.DevelopmentFixture;
        _adapter = adapter;
        _network = MailboxClientComposition.Decode(_fixture.NetworkId, 16, "network id");
        _issuer = MailboxClientComposition.Decode(
            _fixture.IssuerPublicKey,
            32,
            "issuer public key");
        _currentPlacement = MailboxClientComposition.Decode(
            _fixture.CurrentPlacementCommitment,
            32,
            "current placement commitment");
        _nextPlacement = MailboxClientComposition.Decode(
            _fixture.NextPlacementCommitment,
            32,
            "next placement commitment");
    }

    public bool IsConfigured => true;

    public ulong ReplayValidityEndsAt(
        MailboxCapabilityAuthorityQuery query,
        MailboxAuthenticatedGrant grant) =>
        Math.Max(
            grant.ExpiresAtUnixSeconds,
            query.Epoch == _adapter.CurrentEpoch
                ? _adapter.CurrentExpiresAtUnixSeconds
                : query.Epoch == _adapter.NextEpoch
                    ? _adapter.NextExpiresAtUnixSeconds
                    : grant.ExpiresAtUnixSeconds);

    public bool TryResolve(
        MailboxCapabilityAuthorityQuery query,
        out MailboxAuthenticatedVerificationPolicy? policy)
    {
        var placement = query.Epoch == _adapter.CurrentEpoch
            ? _currentPlacement
            : query.Epoch == _adapter.NextEpoch
                ? _nextPlacement
                : [];
        var expectedMembership = query.Epoch == _adapter.CurrentEpoch
            ? Convert.FromHexString(_adapter.CurrentMembershipCommitment)
            : query.Epoch == _adapter.NextEpoch
                ? Convert.FromHexString(_adapter.NextMembershipCommitment)
                : [];
        var domainMatches = query.Operation == MailboxAuthenticatedOperation.Store
            ? query.Domain == MailboxCapabilityDomain.Deposit
            : query.Domain == MailboxCapabilityDomain.Retrieve;
        if (!domainMatches
            || query.Lifecycle != MailboxCapabilityLifecycle.Active
            || query.Generation < _fixture.MinimumGeneration
            || query.Generation > _fixture.MaximumGeneration
            || !Fixed(query.NetworkId.Span, _network)
            || !Fixed(query.IssuerPublicKey.Span, _issuer)
            || !Fixed(query.PlacementCommitment.Span, placement)
            || !Fixed(query.MembershipCommitment.Span, expectedMembership))
        {
            policy = null;
            return false;
        }

        policy = new()
        {
            NetworkId = _network.ToArray(),
            Epoch = query.Epoch,
            PlacementCommitment = placement.ToArray(),
            MembershipCommitment = expectedMembership.ToArray(),
            NowUnixSeconds = 0,
            MinimumGeneration = _fixture.MinimumGeneration,
            TrustedIssuers =
            [
                new MailboxCapabilityIssuerAuthority
                {
                    PublicKey = _issuer.ToArray(),
                    Domain = query.Domain,
                    AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                    MinimumGeneration = _fixture.MinimumGeneration,
                    MaximumGeneration = _fixture.MaximumGeneration,
                    ValidFromUnixSeconds = _fixture.IssuerValidFromUnixSeconds,
                    ValidUntilUnixSeconds = _fixture.IssuerValidUntilUnixSeconds
                }
            ]
        };
        return true;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed class DevelopmentMailboxCapabilityRevocations
    : IMailboxCapabilityRevocationPolicy
{
    private readonly HashSet<string> _revoked;

    public DevelopmentMailboxCapabilityRevocations(
        MailboxClientActivationOptions activation)
    {
        _revoked = activation.DevelopmentFixture.RevokedSerials
            .Select(value => Convert.ToHexString(
                MailboxClientComposition.Decode(value, 16, "revoked serial")))
            .ToHashSet(StringComparer.Ordinal);
    }

    public bool IsConfigured => true;

    public bool IsRevoked(MailboxCapabilityRevocationQuery query) =>
        _revoked.Contains(Convert.ToHexString(query.Serial.Span));
}

public sealed class DevelopmentMailboxReplicaAuthority
    : IMailboxClientReplicaAuthorizer
{
    private readonly MailboxClientAdapterOptions _adapter;
    private readonly MailboxClientDevelopmentFixtureOptions _fixture;
    private readonly IReadOnlyList<ReadOnlyMemory<byte>> _replicas;

    public DevelopmentMailboxReplicaAuthority(
        MailboxClientActivationOptions activation,
        MailboxClientAdapterOptions adapter)
    {
        _adapter = adapter;
        _fixture = activation.DevelopmentFixture;
        _replicas = _fixture.ReplicaIds
            .Select(value => (ReadOnlyMemory<byte>)MailboxClientComposition.Decode(
                value,
                RouterId.ByteLength,
                "replica id"))
            .ToArray();
    }

    public bool IsConfigured => true;

    public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
        ulong epoch,
        ReadOnlyMemory<byte> membershipCommitment,
        ReadOnlyMemory<byte> placementCommitment,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var expectedMembership = _adapter.GetMembershipCommitment(epoch);
        var expectedPlacement = epoch == _adapter.CurrentEpoch
            ? MailboxClientComposition.Decode(
                _fixture.CurrentPlacementCommitment,
                32,
                "current placement commitment")
            : epoch == _adapter.NextEpoch
                ? MailboxClientComposition.Decode(
                    _fixture.NextPlacementCommitment,
                    32,
                    "next placement commitment")
                : [];
        var allowed = expectedPlacement.Length != 0
            && Fixed(membershipCommitment.Span, expectedMembership)
            && Fixed(placementCommitment.Span, expectedPlacement);
        return ValueTask.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>(
            allowed ? _replicas : []);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public sealed class DevelopmentMailboxReplicaFanout
    : IMailboxClientReplicaFanout,
      IMailboxClientTombstoneFanout
{
    private readonly MailboxClientDevelopmentFixtureOptions _fixture;
    private readonly MailboxClientAdapterOptions _adapter;
    private readonly IMailboxReplicaPeerClient _peerClient;
    private readonly byte[] _localSeed;
    private readonly SodiumMailboxPeerReplicationCrypto _crypto = new();

    public DevelopmentMailboxReplicaFanout(
        MailboxClientActivationOptions activation,
        MailboxClientAdapterOptions adapter,
        RouterNodeOptions node,
        IMailboxReplicaPeerClient peerClient)
    {
        _fixture = activation.DevelopmentFixture;
        _adapter = adapter;
        _peerClient = peerClient;
        _localSeed = Convert.FromHexString(node.GetEd25519PrivateKey());
    }

    public bool IsConfigured => true;

    public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
        MailboxReplicaStoreContext context,
        CancellationToken cancellationToken) =>
        SendAsync(
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
            cancellationToken);

    public Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
        MailboxReplicaTombstoneContext context,
        CancellationToken cancellationToken) =>
        SendAsync(
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
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (placementId.Length != MailboxClientLimits.BlindedIdentifierLength
            || !CryptographicOperations.FixedTimeEquals(
                MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(placementId.ToArray())),
                placement.Span))
        {
            throw new InvalidOperationException(
                "MailboxClient Development placement binding is invalid.");
        }

        var proofs = Proofs(epoch);
        var remoteDescriptor = MailboxReplicaRouteProofCodec.Decode(
            proofs.Remote.CanonicalInclusionProof.Span).Descriptor;
        var now = acceptedAt;
        var unsigned = new MailboxPeerWireRequestV2
        {
            Operation = operation,
            Epoch = epoch,
            OperationId = operationId,
            SenderRouterId = proofs.Local.ReplicaId,
            RecipientRouterId = proofs.Remote.ReplicaId,
            MembershipCommitment = membership,
            PlacementCommitment = placement,
            BlindedMailboxId = mailboxId,
            Cursor = cursor,
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = expiresAt,
            ReplayNonce = ReplayNonce(
                operation,
                epoch,
                operationId.Span,
                cursor,
                payload.Span),
            PayloadDigest = SHA256.HashData(payload.Span),
            Payload = payload.ToArray(),
            SenderMembershipProof = proofs.Local,
            RecipientMembershipProof = proofs.Remote,
            Signature = ReadOnlyMemory<byte>.Empty
        };
        var canonical = MailboxPeerWireV2Codec.Encode(
            _crypto.SignRequest(unsigned, _localSeed));
        var route = operation == MailboxPeerReplicationOperation.Store
            ? MailboxWireHttpContract.PeerStoreRoute
            : MailboxWireHttpContract.PeerTombstoneRoute;
        var endpoint = new Uri(new Uri(remoteDescriptor.RpcEndpoint), route).AbsoluteUri;
        var response = await _peerClient.SendAsync(
            new MailboxReplicaPeer(
                RouterId.FromBytes(proofs.Remote.ReplicaId.Span),
                endpoint),
            operation,
            canonical,
            cancellationToken).ConfigureAwait(false);
        return response is null ? [] : [response.Value.ToArray()];
    }

    private static byte[] ReplayNonce(
        MailboxPeerReplicationOperation operation,
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        ulong cursor,
        ReadOnlySpan<byte> payload)
    {
        Span<byte> header = stackalloc byte[1 + 8 + 16 + 8 + 32];
        header[0] = (byte)operation;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            header.Slice(1, 8),
            epoch);
        operationId.CopyTo(header.Slice(9, 16));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
            header.Slice(25, 8),
            cursor);
        SHA256.HashData(payload).CopyTo(header.Slice(33, 32));
        return SHA256.HashData(header);
    }

    private (MailboxReplicaMembershipProof Local, MailboxReplicaMembershipProof Remote)
        Proofs(ulong epoch) =>
        epoch == _adapter.CurrentEpoch
            ? (
                MailboxClientComposition.DecodeProof(
                    _fixture.CurrentLocalMembershipProof,
                    "current local MIP1"),
                MailboxClientComposition.DecodeProof(
                    _fixture.CurrentRemoteMembershipProof,
                    "current remote MIP1"))
            : epoch == _adapter.NextEpoch
                ? (
                    MailboxClientComposition.DecodeProof(
                        _fixture.NextLocalMembershipProof,
                        "next local MIP1"),
                    MailboxClientComposition.DecodeProof(
                        _fixture.NextRemoteMembershipProof,
                        "next remote MIP1"))
                : throw new InvalidOperationException(
                    "MailboxClient Development epoch is not pinned.");
}

public sealed class MailboxClientRuntimeReadiness
{
    private MailboxClientActivationStatus _status;

    public MailboxClientRuntimeReadiness(MailboxClientActivationPlan plan)
    {
        _status = plan.RoutesMapped
            ? MailboxClientActivationGuard.Starting()
            : MailboxClientActivationGuard.EnsureDormant(plan.Activation);
    }

    public bool Ready => Volatile.Read(ref _status).Reason == "ready";
    public MailboxClientActivationStatus Status => Volatile.Read(ref _status);

    public void MarkReady(
        MailboxAuthenticatedRuntimeStatus authenticated,
        MailboxClientAdapterStatus adapter)
    {
        if (!authenticated.Ready || !adapter.Ready)
        {
            throw new InvalidOperationException(
                "Mailbox client dependencies are not ready after initialization.");
        }

        Volatile.Write(ref _status, MailboxClientActivationGuard.Ready());
    }

    public void MarkFailed(string reason) =>
        Volatile.Write(ref _status, MailboxClientActivationGuard.Failed(reason));
}

public sealed class MailboxClientAdapterHostedService : IHostedService
{
    private readonly MailboxClientActivationPlan _plan;
    private readonly MailboxClientStoreAdapter? _adapter;
    private readonly MailboxAuthenticatedCapabilityRuntime? _authenticated;
    private readonly MailboxClientRuntimeReadiness _readiness;
    private readonly MailboxPeerRuntimeReadiness _peerReadiness;

    public MailboxClientAdapterHostedService(
        MailboxClientActivationPlan plan,
        IServiceProvider services,
        MailboxClientRuntimeReadiness readiness,
        MailboxPeerRuntimeReadiness peerReadiness)
    {
        _plan = plan;
        _readiness = readiness;
        _peerReadiness = peerReadiness;
        if (plan.RoutesMapped)
        {
            _adapter = services.GetRequiredService<MailboxClientStoreAdapter>();
            _authenticated =
                services.GetRequiredService<MailboxAuthenticatedCapabilityRuntime>();
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_plan.RoutesMapped)
        {
            return;
        }

        try
        {
            if (!_peerReadiness.Ready)
            {
                throw new InvalidOperationException(
                    "Mailbox peer runtime must initialize before client ingress.");
            }

            await _adapter!.InitializeAsync(cancellationToken);
            _readiness.MarkReady(_authenticated!.Status, _adapter.Status);
        }
        catch
        {
            _readiness.MarkFailed("startup-initialization-failed");
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

public sealed class MailboxAuthenticatedStateGcHostedService(
    MailboxAuthenticatedCapabilityRuntime runtime,
    IClock clock)
    : BackgroundService
{
    private const int MaximumEntriesPerPass = 1024;
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        CollectOneBatch();
        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            CollectOneBatch();
        }
    }

    private void CollectOneBatch() =>
        runtime.CollectExpired(
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()),
            MaximumEntriesPerPass);
}

public sealed class MailboxClientIngressLimiter
{
    private readonly object _gate = new();
    private readonly Dictionary<MailboxAuthenticatedOperation, Endpoint> _endpoints = [];

    public bool TryEnter(
        MailboxHttpEndpointContract contract,
        ulong nowUnixSeconds,
        out IDisposable lease)
    {
        var operation = contract.AuthenticatedOperation
            ?? throw new ArgumentException(
                "Client ingress contracts require an authenticated operation.",
                nameof(contract));
        lock (_gate)
        {
            if (!_endpoints.TryGetValue(operation, out var endpoint))
            {
                endpoint = new(contract.MaximumConcurrentRequests);
                _endpoints.Add(operation, endpoint);
            }

            Reset(endpoint, nowUnixSeconds);
            if (endpoint.WindowCount >= contract.RequestsPerMinute
                || !endpoint.Concurrency.Wait(0))
            {
                lease = EmptyLease.Instance;
                return false;
            }

            endpoint.WindowCount++;
            lease = new Releaser(endpoint.Concurrency);
            return true;
        }
    }

    private static void Reset(Endpoint endpoint, ulong now)
    {
        if (endpoint.WindowStartedAt == 0
            || now >= endpoint.WindowStartedAt + MailboxWireHttpContract.RateWindowSeconds)
        {
            endpoint.WindowStartedAt = now;
            endpoint.WindowCount = 0;
        }
    }

    private sealed class Endpoint(int concurrency)
    {
        public ulong WindowStartedAt { get; set; }
        public int WindowCount { get; set; }
        public SemaphoreSlim Concurrency { get; } = new(concurrency, concurrency);
    }

    private sealed class Releaser(SemaphoreSlim endpoint) : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                endpoint.Release();
            }
        }
    }

    private sealed class EmptyLease : IDisposable
    {
        public static EmptyLease Instance { get; } = new();
        public void Dispose()
        {
        }
    }
}

public sealed class MailboxClientVerifiedHolderLimiter
{
    private const int MaximumPartitions = 4096;
    private const int RequestsPerMinute = 120;
    private static ReadOnlySpan<byte> Domain =>
        "XNODE-MAILBOX-VERIFIED-HOLDER-LIMITER-V1\0"u8;

    private readonly object _gate = new();
    private readonly Dictionary<string, Window> _windows =
        new(StringComparer.Ordinal);

    public bool TryAccept(
        ReadOnlySpan<byte> holderPublicKey,
        MailboxAuthenticatedOperation operation,
        ulong nowUnixSeconds)
    {
        if (holderPublicKey.Length != 32
            || holderPublicKey.IndexOfAnyExcept((byte)0) < 0
            || operation is not (
                MailboxAuthenticatedOperation.Store
                or MailboxAuthenticatedOperation.Retrieve
                or MailboxAuthenticatedOperation.Ack))
        {
            return false;
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        hash.AppendData([(byte)operation]);
        hash.AppendData(holderPublicKey);
        var key = Convert.ToHexString(hash.GetHashAndReset());

        lock (_gate)
        {
            if (!_windows.TryGetValue(key, out var window))
            {
                if (_windows.Count >= MaximumPartitions)
                {
                    var expired = _windows
                        .Where(item =>
                            nowUnixSeconds >= item.Value.StartedAtUnixSeconds
                                + MailboxWireHttpContract.RateWindowSeconds)
                        .OrderBy(static item => item.Value.StartedAtUnixSeconds)
                        .ThenBy(static item => item.Key, StringComparer.Ordinal)
                        .FirstOrDefault();
                    if (expired.Key is null)
                    {
                        return false;
                    }

                    _windows.Remove(expired.Key);
                }

                window = new()
                {
                    StartedAtUnixSeconds = nowUnixSeconds
                };
                _windows.Add(key, window);
            }

            if (nowUnixSeconds >= window.StartedAtUnixSeconds
                    + MailboxWireHttpContract.RateWindowSeconds
                || nowUnixSeconds < window.StartedAtUnixSeconds)
            {
                window.StartedAtUnixSeconds = nowUnixSeconds;
                window.Count = 0;
            }

            if (window.Count >= RequestsPerMinute)
            {
                return false;
            }

            window.Count++;
            return true;
        }
    }

    private sealed class Window
    {
        public ulong StartedAtUnixSeconds { get; set; }
        public int Count { get; set; }
    }
}
