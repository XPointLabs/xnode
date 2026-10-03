using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using System.Security.Cryptography;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

internal interface ICurrentMailboxReplicaPeerClient
{
    ValueTask<ReadOnlyMemory<byte>?> SendAsync(VerifiedOnionNextHopTransport recipient,
        MailboxPeerReplicationOperation operation, ReadOnlyMemory<byte> exactRequest, CancellationToken token);
}

/// <summary>Same current admission/replay/storage owner as the recipient. A
/// remote failure leaves real local custody and peer Pending, never quorum.</summary>
internal sealed partial class CurrentMailboxReplicationCoordinator(CurrentMailboxReplicaReceiver local,
    ICurrentMailboxReplicaPeerClient peer, ReplicatedMailboxOptions options)
{
    private readonly TimeSpan timeout = CaptureTimeout(options);
    internal ValueTask<MailboxPeerQuorumResult> ReplicateAsync(ReadOnlyMemory<byte> exactRequest,
        MailboxPeerReplicationOperation operation, CancellationToken token = default) =>
        local.WithPeerAsync<MailboxPeerQuorumResult>(exactRequest, operation, MailboxPeerWireResponseReplicaV2.Sender,
            (current, ct) => ReplicateAdmittedAsync(current, operation, ct), token);

    internal ValueTask<MailboxPeerQuorumResult> StoreClientAsync(ReadOnlyMemory<byte> canonicalClientRequest,
        MailboxClientOperationLedger ledger, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(ledger);
        var client = MailboxAuthenticatedClientRequestCodec.Decode(canonicalClientRequest.Span);
        var ownedClient = MailboxAuthenticatedClientRequestCodec.Encode(client);
        if (client.Binding.Operation != MailboxAuthenticatedOperation.Store)
            throw new CryptographicException("Current Store requires its exact client operation.");
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(client.Binding.CanonicalRequest.Span);
        return local.WithClientRequestAsync<MailboxPeerQuorumResult>(ownedClient, MailboxAuthenticatedOperation.Store,
            async (request, ct) =>
            {
                // The native ledger owns the random nonce and the COMPLETE signed
                // request before the first peer reservation/write. No remint on retry.
                var requireExisting = request.ReplayDisposition != MailboxAuthenticatedReplayDisposition.NewReserved ||
                    await local.HasStoreCustodyAsync(request.Scope, envelope, ct).ConfigureAwait(false);
                var intent = await ledger.ReserveCurrentStoreAsync(envelope, request.Scope.Host.MembershipCommitment,
                    request.Scope.Replicas.Select(replica => replica.NodeId).ToArray(), request.Scope.Lease,
                    (cursor, upper) => local.AuthorStoreRequest(request.Scope, client.Binding.CanonicalRequest, cursor, upper), ct,
                    requireExisting: requireExisting).ConfigureAwait(false);
                return await StoreAdmittedClientAsync(request, intent.CanonicalPeerRequest, ct).ConfigureAwait(false);
            }, token);
    }

    // An internal producer supplies its exact peer request. This is not a
    // client wire extension or a raw authority adapter. Bind it to captured
    // MAU3 before either replay owner is touched, then use the SAME native scope.
    internal ValueTask<MailboxPeerQuorumResult> StoreClientAsync(ReadOnlyMemory<byte> canonicalClientRequest,
        ReadOnlyMemory<byte> canonicalPeerRequest, CancellationToken token = default)
    {
        var client = MailboxAuthenticatedClientRequestCodec.Decode(canonicalClientRequest.Span);
        var ownedClient = MailboxAuthenticatedClientRequestCodec.Encode(client);
        var replication = MailboxPeerWireV2Codec.Decode(canonicalPeerRequest.Span);
        var ownedPeer = MailboxPeerWireV2Codec.Encode(replication);
        var exactGrant = MailboxAuthenticatedCapabilityCodec.EncodeGrant(client.Presentation.Grant);
        var first = replication.SenderMembershipProof.CanonicalInclusionProof;
        var second = replication.RecipientMembershipProof.CanonicalInclusionProof;
        if (client.Binding.Operation != MailboxAuthenticatedOperation.Store || replication.Operation != MailboxPeerReplicationOperation.Store ||
            !replication.SenderRouterId.Span.SequenceEqual(local.LocalNodeId.Span) ||
            !replication.Payload.Span.SequenceEqual(client.Binding.CanonicalRequest.Span) ||
            first.Length != 342 || second.Length != 342 || !first.Span.SequenceEqual(second.Span) ||
            !first.Span[38..].SequenceEqual(exactGrant))
            throw new CryptographicException("Client Store and current peer request differ.");
        return local.WithClientRequestAsync<MailboxPeerQuorumResult>(ownedClient, MailboxAuthenticatedOperation.Store,
            (request, ct) => StoreAdmittedClientAsync(request, ownedPeer, ct), token);
    }

    private async ValueTask<MailboxPeerQuorumResult> StoreAdmittedClientAsync(CurrentMailboxAdmission.Request request,
        ReadOnlyMemory<byte> ownedPeer, CancellationToken ct)
    {
        var recovered = request.RecoveredOutcome;
        if (recovered is not null)
        {
            if (recovered.Kind != MailboxClientCanonicalOutcomeKind.Success || recovered.Operation != MailboxAuthenticatedOperation.Store)
                throw new InvalidDataException("Client Store outcome is not a durable quorum.");
            await local.WithAdmittedPeerAsync(ownedPeer, MailboxPeerReplicationOperation.Store, MailboxPeerWireResponseReplicaV2.Sender,
                request.Scope, async (current, innerToken) =>
                { await current.ValidateQuorumAsync(recovered.CanonicalBytes, innerToken).ConfigureAwait(false); return 0; }, ct).ConfigureAwait(false);
            var completed = await request.CompleteRecoveredAsync(ct).ConfigureAwait(false);
            return new(MailboxPeerQuorumStatus.Durable, completed.CanonicalBytes, 2);
        }
        if (!await request.TryAcquireExecutionAsync(ct).ConfigureAwait(false))
            return new(MailboxPeerQuorumStatus.PartialFailure, ReadOnlyMemory<byte>.Empty, 0);
        var maximum = MailboxWireHttpContract.Store.MaximumResponseBytes;
        await request.ReserveOutcomeCapacityAsync(maximum, ct).ConfigureAwait(false);
        var result = await local.WithAdmittedPeerAsync(ownedPeer, MailboxPeerReplicationOperation.Store,
            MailboxPeerWireResponseReplicaV2.Sender, request.Scope,
            (current, innerToken) => ReplicateAdmittedAsync(current, MailboxPeerReplicationOperation.Store, innerToken), ct).ConfigureAwait(false);
        if (result.Status != MailboxPeerQuorumStatus.Durable) return result;
        var persisted = await request.PersistSuccessAsync(result.CanonicalMqr3, maximum, ct).ConfigureAwait(false);
        return new(MailboxPeerQuorumStatus.Durable, persisted.CanonicalBytes, 2);
    }

    private async ValueTask<MailboxPeerQuorumResult> ReplicateAdmittedAsync(CurrentMailboxReplicaReceiver.PeerOperation current,
        MailboxPeerReplicationOperation operation, CancellationToken ct)
    {
        var localReceipt = await current.ApplyAndSignLocalAsync(ct).ConfigureAwait(false);
        // ReadOnlyMemory's implicit array conversion makes a mixed
        // memory/null conditional produce empty memory, not null.
        // Pending must contact the peer, never verify an empty receipt.
        ReadOnlyMemory<byte>? remote = null;
        if (current.Verified.ReplayDisposition == MailboxPeerReplayDisposition.IdempotentCompleted)
            remote = current.Verified.CachedResponse;
        if (remote is null)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(timeout);
            try
            {
                remote = await peer.SendAsync(current.RecipientTransport, operation,
                current.CanonicalRequest, deadline.Token).ConfigureAwait(false);
            }
            catch (Exception error) when (error is HttpRequestException or IOException ||
                error is OperationCanceledException && !ct.IsCancellationRequested)
            { remote = null; }
        }
        await current.EnsureCurrentAsync(ct).ConfigureAwait(false);
        if (remote is null) return new(MailboxPeerQuorumStatus.PartialFailure, ReadOnlyMemory<byte>.Empty, 1);
        ReadOnlyMemory<byte> quorum;
        try { quorum = await current.CreateQuorumAsync(localReceipt, remote.Value, ct).ConfigureAwait(false); }
        catch (MailboxPeerReplicationException) { return new(MailboxPeerQuorumStatus.PartialFailure, ReadOnlyMemory<byte>.Empty, 1); }
        if (current.Verified.ReplayDisposition != MailboxPeerReplayDisposition.IdempotentCompleted)
            await current.CommitRecipientAsync(remote.Value, ct).ConfigureAwait(false);
        return new(MailboxPeerQuorumStatus.Durable, quorum, 2);
    }
    private static TimeSpan CaptureTimeout(ReplicatedMailboxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options); options.Validate();
        if (!options.Enabled) throw new InvalidOperationException("Current mailbox replication is disabled.");
        return options.PeerTimeout;
    }
}
