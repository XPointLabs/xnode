using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientOperationLedger
{
    internal async Task<MailboxClientAckReservation> ReserveCurrentAckAsync(MailboxAuthenticatedAckBody body,
        ReadOnlyMemory<byte> membership, IReadOnlyList<ReadOnlyMemory<byte>> replicas, MailboxCurrentOperationLease lease,
        Func<CancellationToken, Task<IReadOnlyList<MailboxCurrentAckTarget>>> readTargets,
        Func<MailboxCurrentAckTarget, ulong, ReadOnlyMemory<byte>> author, bool requireExisting, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(body.Epoch, body.OperationId.Span,
            body.MailboxId, body.PlacementId, body.IsFinalPage, body.ContinuationToken.Span, body.Acknowledgements);
        var key = BuildAckOperationKey(body.Epoch, body.MailboxId.Bytes.Span, body.OperationId.Span);
        var digest = ToLowerHex(binding.RequestDigest.Span, 32, nameof(body));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var document = await LoadAsync(token).ConfigureAwait(false);
            if (document.AckOperations.TryGetValue(key, out var existing))
            {
                if (!FixedHexEquals(existing.RequestDigest, digest)) throw new MailboxClientOperationConflictException();
                if (existing.Items.Any(item => string.IsNullOrEmpty(item.PeerRequest)))
                    throw new InvalidDataException("Current ACK has lost its exact peer intent.");
                if (existing.Items.Length != body.Acknowledgements.Count ||
                    !FixedHexEquals(existing.MembershipCommitment, ToLowerHex(membership.Span, 32, nameof(membership))) ||
                    !existing.ExpectedReplicaIds.SequenceEqual(replicas.Select(replica => ToLowerHex(replica.Span, 32, nameof(replicas))), StringComparer.Ordinal))
                    throw new InvalidDataException("Current ACK intent differs from the admitted request.");
                for (var index = 0; index < existing.Items.Length; index++)
                    if (existing.Items[index].Cursor != body.Acknowledgements[index].Cursor ||
                        !FixedHexEquals(existing.Items[index].EnvelopeDigest,
                            ToLowerHex(body.Acknowledgements[index].EnvelopeDigest.Span, 32, nameof(body))))
                        throw new InvalidDataException("Current ACK intent differs from its ordered targets.");
                _ = await lease.CheckAsync(token).ConfigureAwait(false);
                return ToAckReservation(key, existing);
            }
            if (requireExisting) throw new InvalidDataException("Known current ACK has lost its exact peer intent.");
            if (LedgerEntryCost(document) + 1L + body.Acknowledgements.Count > _maxEntries)
                throw new MailboxClientLedgerCapacityException();
            var targets = await readTargets(token).ConfigureAwait(false);
            var upper = await lease.CheckAsync(token).ConfigureAwait(false);
            if (targets.Count != body.Acknowledgements.Count) throw new InvalidDataException("Current ACK target count differs.");
            var items = new MailboxClientLedgerAckItem[targets.Count];
            for (var index = 0; index < targets.Count; index++)
            {
                var target = targets[index]; var requested = body.Acknowledgements[index];
                if (target.Cursor != requested.Cursor || !target.EnvelopeDigest.Span.SequenceEqual(requested.EnvelopeDigest.Span) ||
                    target.ExpiresAtUnixSeconds <= upper) throw new InvalidDataException("Current ACK target differs.");
                var exact = author(target, upper); var peer = MailboxPeerWireV2Codec.Decode(exact.Span);
                var canonical = MailboxPeerWireV2Codec.Encode(peer);
                if (!canonical.AsSpan().SequenceEqual(exact.Span)) throw new InvalidDataException("Current ACK producer is not canonical.");
                items[index] = new(target.Cursor, ToLowerHex(target.EnvelopeDigest.Span, 32, nameof(target)),
                    target.ExpiresAtUnixSeconds, "reserved", "", 0, "", "", "", Convert.ToBase64String(canonical));
            }
            var operation = new MailboxClientLedgerAckOperation(body.Epoch,
                ToLowerHex(body.MailboxId.Bytes.Span, 32, nameof(body)), ToLowerHex(body.OperationId.Span, 16, nameof(body)),
                digest, ToLowerHex(MailboxPlacementCommitment.Compute(body.PlacementId), 32, nameof(body)),
                ToLowerHex(membership.Span, 32, nameof(membership)),
                replicas.Select(replica => ToLowerHex(replica.Span, 32, nameof(replicas))).ToArray(),
                upper, items.Max(item => item.ExpiresAtUnixSeconds), items);
            document.AckOperations.Add(key, operation);
            // Whole batch intent precedes every peer reservation/tombstone/HTTP.
            // No host UTC collection and no second journal or reminted retry.
            await SaveAsync(document, token, lease).ConfigureAwait(false);
            return ToAckReservation(key, operation);
        }
        finally { _gate.Release(); }
    }

    internal async Task SaveCurrentAckQuorumAsync(string key, ulong cursor, ReadOnlyMemory<byte> quorum,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        _ = MailboxReceiptV3Codec.DecodeDurableQuorum(quorum.Span);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var document = await LoadAsync(token).ConfigureAwait(false); var operation = GetAckOperation(document, key);
            var index = FindAckItem(operation, cursor); var item = operation.Items[index];
            if (string.IsNullOrEmpty(item.PeerRequest)) throw new InvalidDataException("Current ACK intent is missing.");
            var encoded = Convert.ToBase64String(quorum.Span);
            if (item.State == "durable")
            {
                if (!FixedBase64Equals(item.Receipt, encoded)) throw new InvalidDataException("Current ACK quorum changed.");
                return;
            }
            operation.Items[index] = item with { State = "durable", Receipt = encoded };
            document.AckOperations[key] = operation;
            await SaveAsync(document, token, lease).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private static void ValidateCurrentAckItem(MailboxClientLedgerAckOperation operation, MailboxClientLedgerAckItem item)
    {
        if (!IsCanonicalBase64(item.PeerRequest, MailboxPeerWireV2Limits.MaximumTombstoneRequestLength))
            throw new InvalidDataException("Current ACK intent is malformed.");
        var request = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(item.PeerRequest));
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone || request.Epoch != operation.Epoch ||
            request.Cursor != item.Cursor || request.CreatedAtUnixSeconds != operation.AcceptedAtUnixSeconds ||
            request.ExpiresAtUnixSeconds != item.ExpiresAtUnixSeconds || operation.ExpectedReplicaIds.Length != 2 ||
            !FixedHexEquals(operation.OperationId, Convert.ToHexString(request.OperationId.Span).ToLowerInvariant()) ||
            !FixedHexEquals(operation.MailboxId, Convert.ToHexString(request.BlindedMailboxId.Span).ToLowerInvariant()) ||
            !FixedHexEquals(operation.PlacementCommitment, Convert.ToHexString(request.PlacementCommitment.Span).ToLowerInvariant()) ||
            !FixedHexEquals(operation.MembershipCommitment, Convert.ToHexString(request.MembershipCommitment.Span).ToLowerInvariant()) ||
            !FixedHexEquals(item.EnvelopeDigest, Convert.ToHexString(request.Payload.Span).ToLowerInvariant()) ||
            !operation.ExpectedReplicaIds.Contains(Convert.ToHexString(request.SenderRouterId.Span).ToLowerInvariant(), StringComparer.Ordinal) ||
            !operation.ExpectedReplicaIds.Contains(Convert.ToHexString(request.RecipientRouterId.Span).ToLowerInvariant(), StringComparer.Ordinal) ||
            request.SenderMembershipProof.CanonicalInclusionProof.Length != 342 ||
            !request.SenderMembershipProof.CanonicalInclusionProof.Span.SequenceEqual(request.RecipientMembershipProof.CanonicalInclusionProof.Span))
            throw new InvalidDataException("Current ACK intent differs from its native operation.");
        // Independent signatures/grant/descriptor/quorum authentication belongs
        // to the actual current admission, not this structural persistence check.
        if (item.State == "durable") _ = MailboxReceiptV3Codec.DecodeDurableQuorum(Convert.FromBase64String(item.Receipt));
    }
}
