using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientOperationLedger
{
    internal async Task EnsureCurrentStorePrefixAsync(MailboxEncryptedEnvelope envelope,
        ReadOnlyMemory<byte> membershipCommitment, VerifiedMailboxHostAuthorityV2 host, MailboxCurrentOperationLease lease,
        MailboxPeerMutationStore mutations, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        var key = BuildOperationKey(envelope.Epoch, envelope.MailboxId.Bytes.Span, envelope.OperationId.Span);
        var mailbox = ToLowerHex(envelope.MailboxId.Bytes.Span, 32, nameof(envelope));
        var placement = ToLowerHex(MailboxPlacementCommitment.Compute(envelope.PlacementId), 32, nameof(envelope));
        var membership = ToLowerHex(membershipCommitment.Span, 32, nameof(membershipCommitment));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            // Native effects can survive loss/rollback of the allocation file.
            // They are a rejection fence, never proof of two-node settlement or
            // permission to reconstruct an intent or advance a cursor.
            await mutations.RequireCurrentStoreIntentCustodyAsync(envelope, membershipCommitment,
                document, lease, token).ConfigureAwait(false);
            if (!document.Operations.ContainsKey(key))
                await RequireCurrentStorePrefixAsync(document, envelope.Epoch, mailbox, placement, membership, host, lease, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private async Task RequireCurrentStorePrefixAsync(MailboxClientLedgerDocument document, ulong epoch,
        string mailbox, string placement, string membership, VerifiedMailboxHostAuthorityV2 host,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        foreach (var prior in document.Operations.Values.Where(prior =>
            prior.Epoch == epoch && FixedHexEquals(prior.MailboxId, mailbox) &&
            FixedHexEquals(prior.PlacementCommitment, placement) && FixedHexEquals(prior.MembershipCommitment, membership)))
        {
            if (string.IsNullOrEmpty(prior.PeerRequest))
                throw new InvalidOperationException("Current Store prefix has an unsettled exact intent.");
            if (prior.State == "durable")
            {
                if (string.IsNullOrEmpty(prior.Receipt))
                    throw new InvalidDataException("Current durable Store has lost its settlement.");
                await host.VerifyStoreSettlementAsync(Convert.FromBase64String(prior.PeerRequest),
                    Convert.FromBase64String(prior.Receipt), token).ConfigureAwait(false);
            }
            else
            {
                if (prior.State is not ("reserved" or "retryable" or "completing") || prior.Receipt.Length != 0)
                    throw new InvalidOperationException("Current Store prefix has an unsettled exact intent.");
                try { await host.VerifyStoreExpiryExclusionAsync(Convert.FromBase64String(prior.PeerRequest), token).ConfigureAwait(false); }
                catch (System.Security.Cryptography.CryptographicException error)
                { throw new InvalidOperationException("Current Store prefix has an unsettled exact intent.", error); }
            }
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            await RequireUnchangedCurrentStoreAsync(prior, lease, token).ConfigureAwait(false);
        }
    }

    internal async Task SaveCurrentStoreQuorumAsync(string key, ReadOnlyMemory<byte> quorum,
        VerifiedMailboxHostAuthorityV2 host, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        // Own and bound bytes before callbacks, and independently authenticate
        // the exact native intent. A persisted state label is never proof.
        var owned = MailboxReceiptV3Codec.EncodeDurableQuorum(MailboxReceiptV3Codec.DecodeDurableQuorum(quorum.Span));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            var operation = GetOperation(document, key);
            if (string.IsNullOrEmpty(operation.PeerRequest))
                throw new InvalidDataException("Current Store has lost its exact intent.");
            await host.VerifyStoreSettlementAsync(Convert.FromBase64String(operation.PeerRequest), owned, token).ConfigureAwait(false);
            var encoded = Convert.ToBase64String(owned);
            if (operation.State == "durable")
            {
                if (!FixedBase64Equals(operation.Receipt, encoded))
                    throw new InvalidDataException("Current Store settlement changed.");
                return;
            }
            document.Operations[key] = operation with { State = "durable", Receipt = encoded };
            await SaveAsync(document, token, lease).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
}
