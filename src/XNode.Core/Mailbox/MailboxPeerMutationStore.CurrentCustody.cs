using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode.Core.Mailbox;

public sealed partial class MailboxPeerMutationStore
{
    // Called inside the operation ledger's authenticated snapshot callback,
    // after complete replay/native/blob recovery has proven actual absence.
    internal async Task<MailboxCurrentPeerReplayFloor> CaptureAbsentTargetFactAsync(
        PreparedMailboxPeerReservationV2 prepared, IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor> floors,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        var request = prepared.Request;
        if (request.Operation != MailboxPeerReplicationOperation.Tombstone)
            throw new InvalidDataException("Negative custody cannot authorize Store.");
        var target = RecordKey(request.Epoch, Hex(request.BlindedMailboxId.Span), Hex(request.Payload.Span));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            if (File.Exists(Path.Combine(_directory, target + ".json")))
                throw new InvalidDataException("Negative custody requires actual native target absence.");
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
        var known = floors.Values.Where(f => f.TargetKey == target && f.TombstoneDigest.Length == 0).ToArray();
        if (known.Length == 0 || known.Any(f => f.MutationCompleted || f.ResponseDigest.Length != 0 ||
            f.RetainUntilUnixSeconds != prepared.Snapshot.RetainUntilUnixSeconds || f.StoreDigest != known[0].StoreDigest))
            throw new InvalidDataException("Negative custody requires the independently known original pre-effect Store.");
        var replay = MailboxCurrentPeerReplayFloor.ReplayIdentity(prepared.Snapshot);
        return new(replay, target, known[0].StoreDigest,
            MailboxCurrentPeerReplayFloor.AbsentTargetDigest(target, known[0].StoreDigest, replay),
            false, "", prepared.Snapshot.RetainUntilUnixSeconds);
    }
    internal async Task RequireCompletedPreparedStoreAsync(PreparedMailboxPeerReservationV2 prepared,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var request = prepared.Request;
            var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span);
            var record = Read(StorePath(request.Epoch, request.BlindedMailboxId.Span, envelope.DeduplicationDigest.Span));
            if (request.Operation != MailboxPeerReplicationOperation.Store || record.State != "completed" ||
                !record.MatchesStoreContext(request, envelope) ||
                !FixedHex(record.ReplayNonce, request.ReplayNonce.Span) ||
                record.StoreReservedAtUnixSeconds != prepared.Snapshot.ReservedAtUnixSeconds)
                throw new InvalidDataException("Source recovery evidence requires its actual completed original Store.");
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task RequirePreparedStoreTargetAbsentAsync(PreparedMailboxPeerReservationV2 prepared,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var request = prepared.Request;
            if (request.Operation != MailboxPeerReplicationOperation.Store)
                throw new InvalidDataException("Only a source-proven pre-effect Store may recover an unpaired reservation.");
            var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span);
            var target = RecordKey(request.Epoch, Hex(request.BlindedMailboxId.Span), Hex(envelope.DeduplicationDigest.Span));
            if (File.Exists(Path.Combine(_directory, target + ".json")))
                throw new InvalidDataException("Unpaired peer recovery cannot adopt an existing native mutation.");
            // Complete recovery additionally joins ALL actual blobs to ALL
            // protected mutation records; an unpaired blob therefore refuses.
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal Task<MailboxCurrentPeerReplayFloor> CapturePreparedPeerFactAsync(
        PreparedMailboxPeerReservationV2 prepared, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        prepared.RequireReservable();
        var request = prepared.Request;
        return CaptureCurrentPeerFactCoreAsync(request,
            request.Operation == MailboxPeerReplicationOperation.Store
                ? MailboxAuthenticatedRequestTranscript.DecodeStoreBody(request.Payload.Span) : null,
            prepared.Snapshot, lease, token);
    }

    private async Task<MailboxCurrentPeerReplayFloor> CaptureCurrentPeerFactCoreAsync(
        MailboxPeerWireRequestV2 request, MailboxEncryptedEnvelope? envelope, MailboxPeerReplaySnapshot replay,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            var isStore = request.Operation == MailboxPeerReplicationOperation.Store;
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
            else if (isStore) record = PersistedMutation.StorePending(request, envelope!,
                new MailboxPeerReplayClaim
                {
                    ScopeKey = replay.ScopeKey, RequestDigest = replay.RequestDigest,
                    SenderRouterId = request.SenderRouterId, RecipientRouterId = request.RecipientRouterId,
                    ReplayNonce = request.ReplayNonce, OperationId = request.OperationId, Operation = request.Operation,
                    Epoch = replay.Epoch, CreatedAtUnixSeconds = replay.CreatedAtUnixSeconds,
                    ExpiresAtUnixSeconds = replay.ExpiresAtUnixSeconds, ReservedAtUnixSeconds = replay.ReservedAtUnixSeconds,
                    EpochExpiresAtUnixSeconds = replay.EpochExpiresAtUnixSeconds, RetainUntilUnixSeconds = replay.RetainUntilUnixSeconds
                });
            else throw new InvalidDataException("Current tombstone native target is missing.");
            var tombstone = "";
            if (!isStore)
            {
                if (record.State is "tombstone-pending" or "tombstoned")
                {
                    if (record.State == "tombstone-pending" && !record.MatchesTombstoneOperation(request))
                        throw new InvalidDataException("Current tombstone intent differs from native custody.");
                }
                else record = record.BeginTombstone(request, replay.ReservedAtUnixSeconds);
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
            if (floor.IsAbsentTarget)
            {
                if (records.ContainsKey(floor.TargetKey))
                    throw new InvalidDataException("Negative tombstone target is no longer absent.");
                continue;
            }
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
