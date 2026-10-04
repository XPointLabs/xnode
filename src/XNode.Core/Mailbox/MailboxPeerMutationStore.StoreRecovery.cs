using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode.Core.Mailbox;

public sealed partial class MailboxPeerMutationStore
{
    // Called only by the loaded operation-ledger owner under the same current
    // admission lease, before client replay. This uses actual bounded native
    // files/index, not caller counts, UTC, or a replacement cursor authority.
    internal async Task RequireCurrentStoreIntentCustodyAsync(MailboxEncryptedEnvelope envelope,
        ReadOnlyMemory<byte> membership, MailboxClientLedgerDocument document,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var mailbox = Hex(envelope.MailboxId.Bytes.Span);
            var scope = RetrieveScope(envelope.Epoch, mailbox,
                Hex(MailboxPlacementCommitment.Compute(envelope.PlacementId)), Hex(membership.Span));
            var requestedKey = MailboxClientOperationLedger.BuildOperationKey(envelope.Epoch,
                envelope.MailboxId.Bytes.Span, envelope.OperationId.Span);
            document.Operations.TryGetValue(requestedKey, out var original);
            if (_retrieveIndex.TryGetValue(scope, out var index))
            {
                foreach (var pair in index)
                {
                    // Exact recovery allocates nothing and must be able to
                    // reconcile its original intent. Unrelated lost custody
                    // blocks NEW allocation, not that bounded reconciliation.
                    if (original is not null && pair.Key != original.Cursor) continue;
                    if (pair.Value.Count != 1)
                        throw new InvalidDataException("Current Store has ambiguous native cursor custody.");
                    var path = pair.Value.Single();
                    var record = Read(path);
                    if (record.Cursor != pair.Key || RetrieveScope(record) != scope ||
                        Path.GetFileNameWithoutExtension(path) != RecordKey(record.Epoch, record.MailboxId, record.EnvelopeDigest))
                        throw new InvalidDataException("Current Store recovery index differs from native custody.");
                    var key = MailboxClientOperationLedger.BuildOperationKey(record.Epoch,
                        Convert.FromHexString(record.MailboxId), Convert.FromHexString(record.OperationId));
                    if (original is not null && key != requestedKey)
                        throw new InvalidDataException("Current Store recovery cursor belongs to another operation.");
                    if (!document.Operations.TryGetValue(key, out var intent) || string.IsNullOrEmpty(intent.PeerRequest))
                        throw new InvalidDataException("Current Store has lost a native mutation's exact intent.");
                    var peer = MailboxPeerWireV2Codec.Decode(Convert.FromBase64String(intent.PeerRequest));
                    var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(peer.Payload.Span);
                    if (!record.MatchesStoreContext(peer, body) || !FixedHex(record.ReplayNonce, peer.ReplayNonce.Span) ||
                        !FixedHex(record.BlobId, peer.PayloadDigest.Span))
                        throw new InvalidDataException("Current Store intent differs from native mutation custody.");
                    _ = await lease.CheckAsync(token).ConfigureAwait(false);
                }
            }
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
}
