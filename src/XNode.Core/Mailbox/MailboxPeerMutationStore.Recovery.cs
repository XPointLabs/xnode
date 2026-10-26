using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode.Core.Mailbox;

public sealed partial class MailboxPeerMutationStore
{
    internal async Task ValidateNewNativeScopeAsync(CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_recordCount != 0 || _retrievePaths.Count != 0 || _retrieveIndex.Count != 0 || _collectionQueue.Count != 0)
                throw new InvalidDataException("New mailbox enrollment cannot adopt native mutations.");
            MailboxNativeRecovery.RequireNewDirectory(_directory, ".lease", token);
            await _blobStore.ValidateNewNativeScopeAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal Task ValidateCurrentRecoveryAsync(MailboxCurrentOperationLease lease, CancellationToken token,
        IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor>? floors = null) =>
        ValidateCurrentInventoryAsync(lease, null, token, floors);

    internal Task ValidateCurrentOperationAsync(MailboxCurrentCustodyReadScope scope, CancellationToken token,
        IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor> floors) =>
        ValidateCurrentInventoryAsync(null, scope, token, floors);

    private async Task ValidateCurrentInventoryAsync(MailboxCurrentOperationLease? lease,
        MailboxCurrentCustodyReadScope? readScope, CancellationToken token,
        IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor>? floors)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        var transferGate = false;
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (readScope is null) _ = await lease!.CheckAsync(token).ConfigureAwait(false);
            else readScope.RequireActive();
            MailboxNativeRecovery.RequireDirectory(_directory, token);
            var unmatched = new Dictionary<string, PersistedMutation>(StringComparer.Ordinal);
            var records = new Dictionary<string, PersistedMutation>(StringComparer.Ordinal);
            var count = 0;
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                if (++count > _options.MaxPeerMutationRecords)
                    throw new InvalidDataException("Mailbox recovery mutation inventory exceeds its bound.");
                MailboxNativeRecovery.RequireFile(path, token);
                var record = Read(path);
                records.Add(Path.GetFileNameWithoutExtension(path), record);
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
            // Join independent facts and blobs to the SAME freshly read native
            // records while holding this mutation owner, not two inventories
            // separated by a gate release and another authority callback.
            if (floors is not null) ValidateCurrentFloorRecords(floors, records, token);
            void RequireMutation(EncryptedMailboxBlob blob)
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
            }
            if (readScope is null)
                await _blobStore.ValidateCurrentRecoveryAsync(RequireMutation, lease!, token).ConfigureAwait(false);
            else
                await _blobStore.ValidateCurrentOperationAsync(RequireMutation, readScope, token).ConfigureAwait(false);
            // Pending prefixes remain available for exact retry; readiness must
            // not complete them or turn uncertainty into a success receipt.
            if (readScope is null)
            {
                var upper = await lease!.CheckAsync(token).ConfigureAwait(false);
                if (unmatched.Values.Any(record => record.State == "completed" && record.ExpiresAtUnixSeconds > upper))
                    throw new InvalidDataException("Mailbox recovery live completed Store has lost its blob.");
            }
            else
            {
                foreach (var record in unmatched.Values)
                    if (record.State == "completed") readScope.RequireMissingCompletedBlobExpired(record.ExpiresAtUnixSeconds);
                readScope.RequireActive(); token.ThrowIfCancellationRequested();
                // Keep the native inventory owner through the enclosing final
                // callback, exactly as recovery's post-scan fence does. This
                // loan ends before any request action or network dispatch.
                readScope.HoldMutationOwner(_gate);
                transferGate = true;
            }
        }
        catch (MailboxAuthenticatedCapabilityException error)
        {
            throw new InvalidDataException("Mailbox recovery envelope framing is corrupt.", error);
        }
        finally { if (!transferGate) _gate.Release(); }
    }
}
