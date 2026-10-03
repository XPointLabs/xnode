using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

internal sealed partial class CurrentMailboxReplicationCoordinator
{
    internal ValueTask<ReadOnlyMemory<byte>> AcknowledgeClientAsync(ReadOnlyMemory<byte> canonicalClientRequest,
        MailboxClientOperationLedger ledger, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(ledger);
        var client = MailboxAuthenticatedClientRequestCodec.Decode(canonicalClientRequest.Span);
        var owned = MailboxAuthenticatedClientRequestCodec.Encode(client);
        if (client.Binding.Operation != MailboxAuthenticatedOperation.Ack)
            throw new CryptographicException("Current ACK requires its exact client operation.");
        var body = MailboxAuthenticatedRequestTranscript.DecodeAckBody(client.Binding.CanonicalRequest.Span);
        return local.WithClientRequestAsync<ReadOnlyMemory<byte>>(owned, MailboxAuthenticatedOperation.Ack,
            async (request, ct) =>
            {
                var scope = request.Scope;
                var recovered = request.RecoveredOutcome;
                if (recovered is null && !await request.TryAcquireExecutionAsync(ct).ConfigureAwait(false))
                    throw new InvalidOperationException("Current ACK already has an active execution.");
                var maximum = MailboxWireHttpContract.Acknowledge.MaximumResponseBytes;
                if (recovered is null) await request.ReserveOutcomeCapacityAsync(maximum, ct).ConfigureAwait(false);
                var intent = await ledger.ReserveCurrentAckAsync(body, scope.Host.MembershipCommitment,
                    scope.Replicas.Select(replica => replica.NodeId).ToArray(), scope.Lease,
                    async inner =>
                    {
                        // A live page token admits a new exact batch. Recovery
                        // instead uses the already persisted request-bound intent;
                        // current grant/revocation/time and peer checks still apply.
                        await local.RequireAckContinuationAsync(scope, body, inner).ConfigureAwait(false);
                        return await local.ReadAckTargetsAsync(scope, body, inner).ConfigureAwait(false);
                    },
                    (target, upper) => local.AuthorTombstoneRequest(scope, body, target, upper),
                    request.ReplayDisposition != MailboxAuthenticatedReplayDisposition.NewReserved, ct).ConfigureAwait(false);
                MailboxAggregateAckResponse? saved = null;
                if (recovered is not null)
                {
                    if (recovered.Kind != MailboxClientCanonicalOutcomeKind.Success || recovered.Operation != MailboxAuthenticatedOperation.Ack)
                        throw new InvalidDataException("Current ACK outcome differs from the operation.");
                    saved = MailboxAggregateAckCodec.DecodeMqr3(recovered.CanonicalBytes.Span);
                    if (saved.Epoch != body.Epoch || !saved.OperationId.Span.SequenceEqual(body.OperationId.Span) ||
                        saved.TombstoneQuorums.Count != intent.Items.Count)
                        throw new InvalidDataException("Current ACK outcome differs from its exact request.");
                }
                var quorums = new List<ReadOnlyMemory<byte>>(intent.Items.Count);
                for (var index = 0; index < intent.Items.Count; index++)
                {
                    var item = intent.Items[index];
                    if (item.CanonicalPeerRequest.IsEmpty) throw new InvalidDataException("Current ACK exact intent is missing.");
                    if (saved is not null && !item.CachedReceipt.Span.SequenceEqual(saved.TombstoneQuorums[index].Span))
                        throw new InvalidDataException("Current ACK aggregate differs from its persisted item quorum.");
                    var quorum = await local.WithAdmittedPeerAsync<ReadOnlyMemory<byte>>(item.CanonicalPeerRequest,
                        MailboxPeerReplicationOperation.Tombstone, MailboxPeerWireResponseReplicaV2.Sender, scope,
                        async (current, inner) =>
                        {
                            if (!item.CachedReceipt.IsEmpty)
                            {
                                await current.ValidateQuorumAsync(item.CachedReceipt, inner).ConfigureAwait(false);
                                return item.CachedReceipt;
                            }
                            var result = await ReplicateAdmittedAsync(current, MailboxPeerReplicationOperation.Tombstone, inner).ConfigureAwait(false);
                            if (result.Status != MailboxPeerQuorumStatus.Durable)
                                throw new IOException("Current ACK retains pending custody until both replicas acknowledge deletion.");
                            await ledger.SaveCurrentAckQuorumAsync(intent.OperationKey, item.Cursor, result.CanonicalMqr3,
                                scope.Lease, inner).ConfigureAwait(false);
                            return result.CanonicalMqr3;
                        }, ct).ConfigureAwait(false);
                    quorums.Add(quorum);
                }
                if (recovered is not null)
                    return (await request.CompleteRecoveredAsync(ct).ConfigureAwait(false)).CanonicalBytes;
                // Reuse only the neutral MAR1 framing. The older aggregate helper
                // requires an obsolete capability DTO; actual current peer owners
                // above authenticate every ordered PRQ2/MQR3 instead.
                var canonical = MailboxAggregateAckCodec.EncodeMqr3(new()
                { Epoch = body.Epoch, OperationId = body.OperationId, TombstoneQuorums = quorums });
                return (await request.PersistSuccessAsync(canonical, maximum, ct).ConfigureAwait(false)).CanonicalBytes;
            }, token);
    }
}
