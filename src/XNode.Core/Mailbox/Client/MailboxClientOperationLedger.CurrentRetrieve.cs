using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientOperationLedger
{
    // Actual ledger owner holds ledger -> mutation, never the inverse. No
    // caller-supplied set of trusted exclusions, mutable cache or new journal.
    internal async Task<MailboxCurrentRetrieveWindow> ReadCurrentWindowAsync(
        MailboxAuthenticatedRetrieveBody request, ReadOnlyMemory<byte> membership, ulong snapshot,
        MailboxPeerMutationStore mutations, VerifiedMailboxHostAuthorityV2 host,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        if (_currentCustody is null) throw new InvalidOperationException("Current operation custody is required.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            return await mutations.ReadCurrentWindowAsync(request, membership, snapshot, this, document,
                host, lease, token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    // Called only while this owner's ledger gate is held, including the native
    // reader's mutation serialization. Native caller separately matches every
    // original PRQ2/blob/cursor binding and rereads the record after callbacks.
    internal async Task RequireCurrentStoreExpiryAsync(MailboxClientLedgerOperation original,
        VerifiedMailboxHostAuthorityV2 host, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        if (original.State is not ("reserved" or "retryable" or "completing") ||
            original.PeerRequest.Length == 0 || original.Receipt.Length != 0)
            throw new InvalidDataException("Pending Store cannot use durable or terminal custody as exclusion.");
        try { await host.VerifyStoreExpiryExclusionAsync(Convert.FromBase64String(original.PeerRequest), token).ConfigureAwait(false); }
        catch (CryptographicException error)
        { throw new InvalidDataException("Current retrieve has unresolved native Store custody.", error); }
        _ = await lease.CheckAsync(token).ConfigureAwait(false);
        await RequireUnchangedCurrentStoreAsync(original, lease, token).ConfigureAwait(false);
    }

    private async Task RequireUnchangedCurrentStoreAsync(MailboxClientLedgerOperation original,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        var fresh = await LoadAsync(token, lease).ConfigureAwait(false);
        var key = BuildOperationKey(original.Epoch, Convert.FromHexString(original.MailboxId),
            Convert.FromHexString(original.OperationId));
        if (!fresh.Operations.TryGetValue(key, out var actual) || !CryptographicOperations.FixedTimeEquals(
            JsonSerializer.SerializeToUtf8Bytes(original, JsonOptions), JsonSerializer.SerializeToUtf8Bytes(actual, JsonOptions)))
            throw new InvalidDataException("Current Store changed during historical verification.");
    }

    private async Task RequireUnchangedCurrentDocumentAsync(MailboxClientLedgerDocument original,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        var fresh = await LoadAsync(token, lease).ConfigureAwait(false);
        if (original.SchemaVersion != fresh.SchemaVersion || original.NextCoordinatorSequence != fresh.NextCoordinatorSequence ||
            original.RetiredCursorFloor != fresh.RetiredCursorFloor ||
            !SameSnapshotEntries(original.NextCursorByMailbox, fresh.NextCursorByMailbox) ||
            !SameSnapshotEntries(original.Operations, fresh.Operations) || !SameSnapshotEntries(original.AckOperations, fresh.AckOperations) ||
            !SameSnapshotEntries(original.ClientReplayFloors, fresh.ClientReplayFloors) || !SameSnapshotEntries(original.PeerReplayFloors, fresh.PeerReplayFloors))
            throw new InvalidDataException("Current operation snapshot changed during historical verification.");
    }

    private static bool SameSnapshotEntries<T>(Dictionary<string, T> original, Dictionary<string, T> fresh) =>
        original.Count == fresh.Count && original.All(pair => fresh.TryGetValue(pair.Key, out var actual) &&
            CryptographicOperations.FixedTimeEquals(JsonSerializer.SerializeToUtf8Bytes(pair.Value, JsonOptions),
                JsonSerializer.SerializeToUtf8Bytes(actual, JsonOptions)));
}
