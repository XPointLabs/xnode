using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode;

public sealed class DeepIdV2ReplicaStageOptions
{
    public bool Enabled { get; set; }

    internal bool Validate(bool placementEnabled, bool v1ContactEnabled,
        bool developmentOrUat)
    {
        if (Enabled && (!placementEnabled || v1ContactEnabled ||
                !developmentOrUat))
            throw new InvalidOperationException(
                "DID2 replica staging requires an independent UAT V2 placement boundary.");
        return Enabled;
    }
}

/// <summary>
/// Authenticated peer-only DID2 fragment staging. CandidateReady means only
/// that exact XPP1 bytes survived durable reassembly; no XIC1 is issued here.
/// </summary>
internal sealed class DeepIdV2ReplicaStageReceiver : IContactReplicaCommandReceiver
{
    private const int MaximumOperationsPerNetwork = 64;
    private readonly RouterNodeOptions node;
    private readonly IDeepIdV2PreKeyPlacementSource placements;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly string root;
    private readonly SemaphoreSlim stageGate = new(1, 1);

    public DeepIdV2ReplicaStageReceiver(RouterNodeOptions node,
        IDeepIdV2PreKeyPlacementSource placements,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.placements = placements ?? throw new ArgumentNullException(nameof(placements));
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        root = Path.Combine(Path.GetFullPath(node.DataDirectory),
            "did2-prekey-stage");
        RejectExistingLinks(root);
        security.SecureDirectory(root);
        RejectExistingLinks(root);
    }

    public async ValueTask<ContactReplicaRpcResponse> ReceiveAsync(
        ContactReplicaRpcCommand command, RouterId authenticatedSender,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.Operation !=
                ContactReplicaRpcOperation.StageDid2PreKeyPublication ||
            command.Placement.RequestKind !=
                ContactServiceRequestKind.PublishPreKeyInventory)
            throw new InvalidDataException(
                "DID2 stage receiver rejects all non-V2 replica operations.");
        var decoded = DeepIdV2ReplicaStagePayloadCodec.Decode(
            command.Payload.Span);
        var localId = node.GetRouterId().ToBytes();
        // The caller-supplied projection can only reject, never authorize.
        // Avoid an authority fetch for an obviously unrelated authenticated peer.
        if (!command.Placement.ContainsReplica(localId) ||
            !Fixed(command.Placement.OtherReplica(localId),
                authenticatedSender.ToBytes()))
            throw new UnauthorizedAccessException(
                "DID2 fragment peer is outside the claimed placement.");
        var current = await placements.MintPreKeyPublicationAsync(
            decoded.Publisher, command.Placement.ShardKey,
            cancellationToken).ConfigureAwait(false);
        ContactReplicaRequestReceiver.EnsureExactPlacement(
            command.Placement, current);
        if (!Fixed(current.OtherReplica(localId),
                authenticatedSender.ToBytes()) ||
            !Fixed(decoded.Fragment.NetworkId.Span, current.NetworkId.Span) ||
            !Fixed(decoded.Fragment.ViewHash.Span, current.ViewHash.Span) ||
            !Fixed(decoded.Fragment.PlacementHash.Span,
                current.PlacementHash.Span))
            throw new UnauthorizedAccessException(
                "DID2 fragment is outside the authenticated current placement.");

        await stageGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var networkRoot = Path.Combine(root,
                Convert.ToHexString(current.NetworkId.Span));
            var operationPath = Path.Combine(networkRoot,
                Convert.ToHexString(decoded.Fragment.PublicationOperationId.Span));
            if (decoded.Fragment.Phase != Xpp1V2FragmentPhase.Manifest &&
                !Directory.Exists(operationPath))
                return Response(command, localId,
                    PublicationStageDisposition.Incomplete);

            RejectExistingLinks(networkRoot);
            security.SecureDirectory(networkRoot);
            RejectExistingLinks(networkRoot);
            using var rootLease = new FileStream(Path.Combine(root,
                "stage.lock"), new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough
            });
            security.SecureFile(rootLease.Name);
            if (!Directory.Exists(operationPath) &&
                Directory.EnumerateDirectories(networkRoot).Take(
                    MaximumOperationsPerNetwork + 1).Count() >=
                MaximumOperationsPerNetwork)
                throw new InvalidOperationException(
                    "DID2 pre-key staging has reached its operation limit.");
            RejectExistingLinks(operationPath);
            using var journal = new DeepIdV2PublicationJournal(operationPath,
                current.NetworkId.Span,
                decoded.Fragment.PublicationOperationId.Span,
                current.ViewHash.Span, current.PlacementHash.Span,
                current.ShardKey.Span, security, durability);
            var staged = journal.Stage(decoded.Fragment.CanonicalBytes.Span,
                decoded.Publisher);
            if (staged.Disposition is PublicationStageDisposition.WrongScope
                or PublicationStageDisposition.ForkLatched)
                throw new InvalidDataException(
                    "DID2 publication fragment conflicts with durable scope.");
            if (staged.Disposition == PublicationStageDisposition.CandidateReady)
            {
                var committed = journal.ReadCommitted();
                if (committed?.Candidate is null ||
                    !Fixed(committed.Candidate.CanonicalBytes.Span,
                        staged.Candidate!.CanonicalBytes.Span))
                    throw new InvalidDataException(
                        "DID2 publication candidate is not durably complete.");
            }
            return Response(command, localId, staged.Disposition);
        }
        finally { stageGate.Release(); }
    }

    private static ContactReplicaRpcResponse Response(
        ContactReplicaRpcCommand command, byte[] localId,
        PublicationStageDisposition disposition) => new(
            command.Operation, command.CorrelationId.ToArray(), localId,
            DeepIdV2ReplicaStagePayloadCodec.EncodeStatus(disposition));

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void RejectExistingLinks(string path)
    {
        var full = Path.GetFullPath(path);
        var basePath = Path.GetPathRoot(full) ??
            throw new InvalidDataException("DID2 stage path has no root.");
        var current = basePath;
        foreach (var part in Path.GetRelativePath(basePath, full).Split(
                     [Path.DirectorySeparatorChar,
                      Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, part);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new CryptographicException(
                    "DID2 stage custody path contains a link.");
        }
    }
}

internal sealed record DeepIdV2ReplicaStagePayload(
    ParsedDid2 Publisher, ParsedXpp1V2Fragment Fragment);

internal static class DeepIdV2ReplicaStagePayloadCodec
{
    internal static byte[] Encode(ParsedDid2 publisher,
        ReadOnlySpan<byte> exactFragment)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
            exactFragment);
        if (fragment.Phase == Xpp1V2FragmentPhase.Manifest &&
            !CryptographicOperations.FixedTimeEquals(
                fragment.PublisherDid2.Span,
                publisher.CanonicalBytes.Span))
            throw new InvalidDataException(
                "DID2 replica manifest publisher hint is inconsistent.");
        var output = new byte[DeepIdV2Codec.Did2Length + exactFragment.Length];
        publisher.CanonicalBytes.Span.CopyTo(output);
        exactFragment.CopyTo(output.AsSpan(DeepIdV2Codec.Did2Length));
        return output;
    }

    internal static DeepIdV2ReplicaStagePayload Decode(ReadOnlySpan<byte> body)
    {
        if (body.Length is < DeepIdV2Codec.Did2Length + 325 or
            > DeepIdV2Codec.Did2Length +
                DeepIdV2BoundedPreKeyPublicationCodec.MaximumCanonicalBytes)
            throw new InvalidDataException(
                "DID2 replica fragment payload is outside its closed bound.");
        var publisher = DeepIdV2Codec.DecodeDid2(
            body[..DeepIdV2Codec.Did2Length]);
        var fragment = DeepIdV2BoundedPreKeyPublicationCodec.Decode(
            body[DeepIdV2Codec.Did2Length..]);
        if (fragment.Phase == Xpp1V2FragmentPhase.Manifest &&
            !CryptographicOperations.FixedTimeEquals(
                publisher.CanonicalBytes.Span,
                fragment.PublisherDid2.Span))
            throw new InvalidDataException(
                "DID2 replica manifest publisher hint is inconsistent.");
        return new DeepIdV2ReplicaStagePayload(publisher, fragment);
    }

    internal static byte[] EncodeStatus(
        PublicationStageDisposition disposition) =>
        disposition switch
        {
            PublicationStageDisposition.Staged => [1],
            PublicationStageDisposition.Incomplete => [2],
            PublicationStageDisposition.ExactReplay => [3],
            PublicationStageDisposition.CandidateReady => [4],
            _ => throw new InvalidDataException(
                "DID2 replica stage has no admissible result.")
        };
}
