using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode.Core.Mailbox;

public sealed partial class MailboxPeerMutationStore
{
    internal async Task<MailboxCurrentPeerReplayFloor> CaptureCurrentPeerFactAsync(
        VerifiedMailboxPeerWireRequestV2 verified, MailboxPeerReplaySnapshot replay,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var request = verified.Request;
            var isStore = request.Operation == MailboxPeerReplicationOperation.Store;
            var envelope = verified.Envelope;
            var target = RecordKey(request.Epoch, Hex(request.BlindedMailboxId.Span),
                Hex(isStore ? (envelope ?? throw new InvalidDataException("Current Store envelope is missing.")).DeduplicationDigest.Span
                    : request.Payload.Span));
            var path = Path.Combine(_directory, target + ".json");
            PersistedMutation record;
            if (File.Exists(path))
            {
                record = Read(path);
                if (isStore ? !record.MatchesStoreContext(request, envelope!) : !record.MatchesTombstoneTarget(request))
                    throw new InvalidDataException("Current native mutation differs from authenticated peer intent.");
            }
            else if (isStore) record = PersistedMutation.StorePending(verified, envelope!);
            else throw new InvalidDataException("Current tombstone native target is missing.");
            var tombstone = "";
            if (!isStore)
            {
                if (record.State is "tombstone-pending" or "tombstoned")
                {
                    if (!record.MatchesTombstoneOperation(request))
                        throw new InvalidDataException("Current tombstone intent differs from native custody.");
                }
                else record = record.BeginTombstone(verified);
                tombstone = TombstoneIdentity(record);
            }
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            return new(MailboxCurrentPeerReplayFloor.ReplayIdentity(replay), target,
                StoreIdentity(record), tombstone, false, "", replay.RetainUntilUnixSeconds);
        }
        finally { _gate.Release(); }
    }

    private static void ValidateCurrentFloorRecords(IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor> floors,
        IReadOnlyDictionary<string, PersistedMutation> records, CancellationToken token)
    {
        var targets = floors.Values.Select(floor => floor.TargetKey).ToHashSet(StringComparer.Ordinal);
        foreach (var key in records.Keys)
        {
            token.ThrowIfCancellationRequested();
            if (!targets.Contains(key))
                throw new InvalidDataException("Current native peer mutation has no independent fact.");
        }
        foreach (var floor in floors.Values)
        {
            token.ThrowIfCancellationRequested();
            if (!records.TryGetValue(floor.TargetKey, out var record))
            {
                if (floor.MutationCompleted || floor.TombstoneDigest.Length != 0)
                    throw new InvalidDataException("Current peer mutation has lost independent custody.");
                continue; // Known Pending Store before its first mutation.
            }
            if (RecordKey(record.Epoch, record.MailboxId, record.EnvelopeDigest) != floor.TargetKey ||
                StoreIdentity(record) != floor.StoreDigest ||
                floor.MutationCompleted && (floor.TombstoneDigest.Length == 0 ? record.State == "pending" : record.State != "tombstoned") ||
                floor.TombstoneDigest.Length != 0 && (record.State is "tombstone-pending" or "tombstoned") &&
                    TombstoneIdentity(record) != floor.TombstoneDigest)
                throw new InvalidDataException("Current peer mutation rolled back independent custody.");
        }
    }

    private static string StoreIdentity(PersistedMutation record) => MailboxCurrentPeerReplayFloor.Digest(
        JsonSerializer.SerializeToUtf8Bytes(record with
        {
            State = "pending", TombstoneOperationId = "", TombstoneReplayNonce = "",
            TombstoneCreatedAtUnixSeconds = 0, TombstoneReservedAtUnixSeconds = 0
        }, JsonOptions));

    private static string TombstoneIdentity(PersistedMutation record) => MailboxCurrentPeerReplayFloor.Digest(
        JsonSerializer.SerializeToUtf8Bytes(record with { State = "tombstone-pending" }, JsonOptions));
}
