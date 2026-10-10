using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

public sealed partial class MailboxPeerMutationStore
{
    internal async Task ValidateCurrentRecoveryAsync(MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            MailboxNativeRecovery.RequireDirectory(_directory, token);
            var unmatched = new Dictionary<string, PersistedMutation>(StringComparer.Ordinal);
            var count = 0;
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                if (++count > _options.MaxPeerMutationRecords)
                    throw new InvalidDataException("Mailbox recovery mutation inventory exceeds its bound.");
                MailboxNativeRecovery.RequireFile(path, token);
                var record = Read(path);
                var scope = RetrieveScope(record);
                if (Path.GetFileNameWithoutExtension(path) != RecordKey(record.Epoch, record.MailboxId, record.EnvelopeDigest) ||
                    !_retrievePaths.TryGetValue(path, out var indexed) || indexed != (scope, record.Cursor) ||
                    !_retrieveIndex.TryGetValue(scope, out var cursors) ||
                    !cursors.TryGetValue(record.Cursor, out var paths) || paths.Count != 1 || !paths.Contains(path) ||
                    !unmatched.TryAdd(record.MailboxId + "/" + record.BlobId, record))
                    throw new InvalidDataException("Mailbox recovery mutation differs from native index custody.");
            }
            if (count != _recordCount || count != _retrievePaths.Count)
                throw new InvalidDataException("Mailbox recovery mutation custody is missing.");
            await _blobStore.ValidateCurrentRecoveryAsync(blob =>
            {
                token.ThrowIfCancellationRequested();
                if (!unmatched.Remove(blob.MailboxId + "/" + blob.BlobId, out var record) || record.State == "tombstoned")
                    throw new InvalidDataException("Mailbox recovery blob has no live mutation custody.");
                var bytes = Convert.FromBase64String(blob.Ciphertext);
                var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(bytes);
                if (!FixedHex(record.BlobId, SHA256.HashData(bytes)) || envelope.Epoch != record.Epoch ||
                    !FixedHex(record.OperationId, envelope.OperationId.Span) ||
                    !FixedHex(record.MailboxId, envelope.MailboxId.Bytes.Span) ||
                    !FixedHex(record.PlacementId, envelope.PlacementId.Bytes.Span) ||
                    !FixedHex(record.EnvelopeDigest, envelope.DeduplicationDigest.Span) ||
                    envelope.ExpiresAtUnixSeconds != record.ExpiresAtUnixSeconds ||
                    blob.ExpiresAtUnixMs != checked((long)record.ExpiresAtUnixSeconds * 1000))
                    throw new InvalidDataException("Mailbox recovery envelope differs from mutation custody.");
            }, lease, token).ConfigureAwait(false);
            var upper = await lease.CheckAsync(token).ConfigureAwait(false);
            // Pending prefixes remain available for exact retry; readiness must
            // not complete them or turn uncertainty into a success receipt.
            if (unmatched.Values.Any(record => record.State == "completed" && record.ExpiresAtUnixSeconds > upper))
                throw new InvalidDataException("Mailbox recovery live completed Store has lost its blob.");
        }
        catch (MailboxAuthenticatedCapabilityException error)
        {
            throw new InvalidDataException("Mailbox recovery envelope framing is corrupt.", error);
        }
        finally { _gate.Release(); }
    }
}
