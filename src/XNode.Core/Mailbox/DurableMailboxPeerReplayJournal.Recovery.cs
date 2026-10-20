using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode.Core.Mailbox;

public sealed partial class DurableMailboxPeerReplayJournal
{
    // Denial-only join of actual protected old ACK bytes to actual native
    // custody. No policy clock, reservation, repair or old-grant effect.
    internal void RequireOriginalAckIntent(ReadOnlyMemory<byte> exact, MailboxCurrentPeerReplayFloor? floor)
    {
        var request = MailboxPeerWireV2Codec.Decode(exact.Span);
        var scope = MailboxPeerReplayStateMachine.ComputeScopeKey(request.SenderRouterId.Span,
            request.RecipientRouterId.Span, request.Epoch, request.ReplayNonce.Span);
        var digest = MailboxPeerWireV2Codec.GetReplayRequestDigest(exact.Span);
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var path = RecordPath(Hex(scope));
            if (floor is null)
            {
                if (request.Operation != MailboxPeerReplicationOperation.Tombstone || File.Exists(path))
                    throw new InvalidDataException("Unadmitted old ACK intent has unexpected native custody.");
                return;
            }
            var actual = Read(path).Snapshot();
            if (request.Operation != MailboxPeerReplicationOperation.Tombstone || !floor.MutationCompleted ||
                floor.TombstoneDigest.Length == 0 || floor.IsAbsentTarget ||
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(actual.RequestDigest.Span, digest) ||
                MailboxCurrentPeerReplayFloor.ReplayIdentity(actual) != floor.ReplayDigest)
                throw new InvalidDataException("Original ACK intent differs from independently protected native custody.");
        }
    }
    internal void RequireExistingPreparedPending(PreparedMailboxPeerReservationV2 prepared)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var expected = prepared.Snapshot;
            var actual = Read(RecordPath(Hex(expected.ScopeKey.Span))).Snapshot();
            if (actual.Status != MailboxPeerReplayRecordStatus.Pending || !actual.CanonicalResponse.IsEmpty ||
                MailboxCurrentPeerReplayFloor.ReplayIdentity(actual with { ReservedAtUnixSeconds = expected.ReservedAtUnixSeconds }) !=
                MailboxCurrentPeerReplayFloor.ReplayIdentity(expected))
                throw new InvalidDataException("Historical repair requires the exact existing pre-effect Pending.");
        }
    }

    internal void ReconcileUnpairedCurrentPending(PreparedMailboxPeerReservationV2 prepared,
        MailboxCurrentPeerReplayFloor floor)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (File.Exists(RecordPath(Hex(prepared.Snapshot.ScopeKey.Span))))
                _ = RestoreCurrentPreparedPending(prepared, floor);
        }
    }

    // The independent write-ahead digest, never a bare native file, identifies
    // the original admission second. At most 121 bounded candidates; no caller
    // supplied historical time and no extension of current request authority.
    internal bool RestoreCurrentPreparedPending(PreparedMailboxPeerReservationV2 prepared,
        MailboxCurrentPeerReplayFloor floor)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            var snapshot = prepared.Snapshot;
            var path = RecordPath(Hex(snapshot.ScopeKey.Span));
            var existing = File.Exists(path) ? Read(path) : null;
            if (existing is not null && MailboxCurrentPeerReplayFloor.ReplayIdentity(existing.Snapshot()) == floor.ReplayDigest)
                return false;
            if (floor.MutationCompleted || floor.ResponseDigest.Length != 0)
                throw new InvalidDataException("Completed peer history cannot be reconstructed from preparation.");
            if (existing is not null && (existing.Snapshot().Status != MailboxPeerReplayRecordStatus.Pending ||
                MailboxCurrentPeerReplayFloor.ReplayIdentity(existing.Snapshot() with
                    { ReservedAtUnixSeconds = snapshot.ReservedAtUnixSeconds }) !=
                MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot)))
                throw new InvalidDataException("Only the exact pre-effect Pending may reconcile its prepared admission.");
            for (ulong offset = 0; offset <= MailboxPeerWireV2Limits.MaximumPastAgeSeconds; offset++)
            {
                var second = checked(snapshot.CreatedAtUnixSeconds + offset);
                if (second >= snapshot.ExpiresAtUnixSeconds) break;
                var candidate = snapshot with { ReservedAtUnixSeconds = second,
                    Status = MailboxPeerReplayRecordStatus.Pending, CanonicalResponse = ReadOnlyMemory<byte>.Empty };
                if (MailboxCurrentPeerReplayFloor.ReplayIdentity(candidate) != floor.ReplayDigest ||
                    candidate.RetainUntilUnixSeconds != floor.RetainUntilUnixSeconds) continue;
                var request = prepared.Request;
                var claim = new MailboxPeerReplayClaim
                {
                    ScopeKey = candidate.ScopeKey, RequestDigest = candidate.RequestDigest,
                    SenderRouterId = request.SenderRouterId, RecipientRouterId = request.RecipientRouterId,
                    ReplayNonce = request.ReplayNonce, OperationId = request.OperationId, Operation = request.Operation,
                    Epoch = candidate.Epoch, CreatedAtUnixSeconds = candidate.CreatedAtUnixSeconds,
                    ExpiresAtUnixSeconds = candidate.ExpiresAtUnixSeconds, ReservedAtUnixSeconds = second,
                    EpochExpiresAtUnixSeconds = candidate.EpochExpiresAtUnixSeconds,
                    RetainUntilUnixSeconds = candidate.RetainUntilUnixSeconds
                };
                if (existing is null)
                    _ = EvaluateAndReserve(claim); // Actual durable write under the same reentrant owner lock.
                else
                    Write(path, PersistedReplay.From(existing.PartitionKey, candidate));
                return true;
            }
            throw new InvalidDataException("Prepared peer request does not match its independent original digest.");
        }
    }

    internal void ValidateCurrentFloors(IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor> floors,
        CancellationToken token, MailboxPeerReplaySnapshot? sourceProvenPreEffectRecovery = null) =>
        ValidateNativeRecovery(token, floors, sourceProvenPreEffectRecovery);

    internal void ValidateNewNativeScope(CancellationToken token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_recordCount != 0 || _partitionCounts.Count != 0 || _collectionQueue.Count != 0)
                throw new InvalidDataException("New mailbox enrollment cannot adopt native peer replay.");
            MailboxNativeRecovery.RequireNewDirectory(_directory, ".lease", token);
        }
    }

    internal void ValidateNativeRecovery(CancellationToken token,
        IReadOnlyDictionary<string, MailboxCurrentPeerReplayFloor>? floors = null,
        MailboxPeerReplaySnapshot? sourceProvenPreEffectRecovery = null)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            MailboxNativeRecovery.RequireDirectory(_directory, token);
            var partitions = new Dictionary<string, int>(StringComparer.Ordinal);
            var actualKeys = new HashSet<string>(StringComparer.Ordinal);
            var count = 0;
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                if (++count > checked(_options.MaxPeerReplayRecords + _options.MaxPeerReplayGcBatch))
                    throw new InvalidDataException("Mailbox recovery peer replay exceeds its bound.");
                MailboxNativeRecovery.RequireFile(path, token);
                var record = Read(path);
                var snapshot = record.Snapshot(); var key = Hex(snapshot.ScopeKey.Span);
                actualKeys.Add(key);
                if (Path.GetFileNameWithoutExtension(path) != key)
                    throw new InvalidDataException("Mailbox recovery peer replay differs from its native key.");
                // One actual read under the same native owner joins grammar,
                // native index custody and independent floors. No callback,
                // effect or retained snapshot separates two validation passes.
                if (floors is not null)
                {
                    if (!floors.TryGetValue(key, out var floor))
                    {
                        // This bounded inspection is reachable ONLY after the
                        // receiver verified exact source durable forwarding and
                        // separately required native mutation/blob absence.
                        if (sourceProvenPreEffectRecovery is null || snapshot.Status != MailboxPeerReplayRecordStatus.Pending ||
                            !snapshot.CanonicalResponse.IsEmpty ||
                            MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot with
                                { ReservedAtUnixSeconds = sourceProvenPreEffectRecovery.ReservedAtUnixSeconds }) !=
                            MailboxCurrentPeerReplayFloor.ReplayIdentity(sourceProvenPreEffectRecovery))
                            throw new InvalidDataException("Current native peer replay has no independent fact.");
                    }
                    else if ((!MatchesPreparedFloor(snapshot, floor)) ||
                        snapshot.RetainUntilUnixSeconds != floor.RetainUntilUnixSeconds ||
                        floor.ResponseDigest.Length != 0 && (snapshot.Status != MailboxPeerReplayRecordStatus.Completed ||
                        MailboxCurrentPeerReplayFloor.Digest(snapshot.CanonicalResponse.Span) != floor.ResponseDigest))
                        throw new InvalidDataException("Current peer replay rolled back its independent fact.");
                }
                partitions[record.PartitionKey] = partitions.GetValueOrDefault(record.PartitionKey) + 1;
            }
            // A protected Pending prefix may precede its FIRST native write.
            // It can only recreate the hash-bound original upon authenticated
            // retry, not establish success or authorize different work.
            if (floors is not null && floors.Any(pair => !actualKeys.Contains(pair.Key) &&
                (pair.Value.MutationCompleted || pair.Value.ResponseDigest.Length != 0)))
                throw new InvalidDataException("Current peer replay has lost completed independent history.");
            if (count != _recordCount || partitions.Count != _partitionCounts.Count ||
                partitions.Any(pair => _partitionCounts.GetValueOrDefault(pair.Key) != pair.Value))
                throw new InvalidDataException("Mailbox recovery peer replay custody is missing.");
        }
    }

    private static bool MatchesPreparedFloor(MailboxPeerReplaySnapshot snapshot, MailboxCurrentPeerReplayFloor floor)
    {
        if (MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot) == floor.ReplayDigest) return true;
        if (snapshot.Status != MailboxPeerReplayRecordStatus.Pending || floor.MutationCompleted || floor.ResponseDigest.Length != 0)
            return false;
        for (ulong offset = 0; offset <= MailboxPeerWireV2Limits.MaximumPastAgeSeconds; offset++)
        {
            var second = checked(snapshot.CreatedAtUnixSeconds + offset);
            if (second >= snapshot.ExpiresAtUnixSeconds) break;
            if (MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot with { ReservedAtUnixSeconds = second }) == floor.ReplayDigest)
                return true;
        }
        return false;
    }
}
