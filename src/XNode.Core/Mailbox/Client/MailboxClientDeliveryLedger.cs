using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed record MailboxClientRetrieveCandidate(
    ulong Cursor,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> EnvelopeDigest,
    ReadOnlyMemory<byte> BlobDigest,
    bool BlobCleaned);

public sealed record MailboxClientRetrieveWindow(
    ulong SnapshotHighWater,
    IReadOnlyList<MailboxClientRetrieveCandidate> Candidates);

public sealed record MailboxClientAckItemReservation(
    ulong Cursor,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> EnvelopeDigest,
    MailboxClientLedgerState State,
    string Error,
    MailboxClientCompletionReservation? Completion,
    ReadOnlyMemory<byte> CachedReceipt);

public sealed record MailboxClientAckReservation(
    string OperationKey,
    ulong Epoch,
    ReadOnlyMemory<byte> MailboxId,
    ReadOnlyMemory<byte> OperationId,
    ReadOnlyMemory<byte> RequestDigest,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    IReadOnlyList<ReadOnlyMemory<byte>> ExpectedReplicaIds,
    ulong AcceptedAtUnixSeconds,
    IReadOnlyList<MailboxClientAckItemReservation> Items);

internal sealed record MailboxClientLedgerAckOperation(
    ulong Epoch,
    string MailboxId,
    string OperationId,
    string RequestDigest,
    string PlacementCommitment,
    string MembershipCommitment,
    string[] ExpectedReplicaIds,
    ulong AcceptedAtUnixSeconds,
    ulong ExpiresAtUnixSeconds,
    MailboxClientLedgerAckItem[] Items);

internal sealed record MailboxClientLedgerAckItem(
    ulong Cursor,
    string EnvelopeDigest,
    ulong ExpiresAtUnixSeconds,
    string State,
    string Error,
    ulong CoordinatorSequence,
    string FirstReplicaReceipt,
    string SecondReplicaReceipt,
    string Receipt);

public sealed partial class MailboxClientOperationLedger
{
    public async Task<MailboxClientRetrieveWindow> ReadRetrieveCandidatesAsync(
        ulong epoch,
        ReadOnlyMemory<byte> mailboxId,
        ulong afterCursor,
        ulong snapshotHighWater,
        int maximumCount,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (epoch == 0 || maximumCount is < 1 or > MailboxClientLimits.MaximumPageItems + 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        }

        var mailboxKey = BuildMailboxKey(epoch, mailboxId.Span);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpiredAndCompact(document, NowUnixSeconds());
            var now = NowUnixSeconds();
            document.NextCursorByMailbox.TryGetValue(mailboxKey, out var currentHighWater);
            var effectiveHighWater = snapshotHighWater == 0
                ? currentHighWater
                : snapshotHighWater;
            if (afterCursor > effectiveHighWater)
            {
                throw new MailboxClientContinuationException();
            }

            var result = document.Operations.Values
                .Where(operation =>
                    operation.Epoch == epoch
                    && string.Equals(
                        BuildMailboxKey(
                            operation.Epoch,
                            DecodeLowerHex(operation.MailboxId, 32)),
                        mailboxKey,
                        StringComparison.Ordinal)
                    && operation.State == "durable"
                    && !operation.Tombstoned
                    && operation.ExpiresAtUnixSeconds > now
                    && operation.Cursor > afterCursor
                    && operation.Cursor <= effectiveHighWater)
                .OrderBy(static operation => operation.Cursor)
                .Take(maximumCount)
                .Select(static operation => new MailboxClientRetrieveCandidate(
                    operation.Cursor,
                    operation.ExpiresAtUnixSeconds,
                    DecodeLowerHex(operation.EnvelopeDigest, 32),
                    DecodeLowerHex(operation.BlobDigest, 32),
                    operation.BlobCleaned))
                .ToArray();
            if (changed)
            {
                await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            }

            return new(effectiveHighWater, result);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<MailboxClientAckReservation> ReserveAckAsync(
        ulong epoch,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> requestDigest,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> placementCommitment,
        ReadOnlyMemory<byte> membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        ulong acceptedAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (epoch == 0
            || acceptedAtUnixSeconds == 0
            || acknowledgements is null
            || acknowledgements.Count is < 1 or > MailboxClientLimits.MaximumPageItems)
        {
            throw new ArgumentOutOfRangeException(nameof(acknowledgements));
        }

        var operationKey = BuildAckOperationKey(epoch, mailboxId.Span, operationId.Span);
        var mailboxKey = BuildMailboxKey(epoch, mailboxId.Span);
        var requestKey = ToLowerHex(requestDigest.Span, 32, nameof(requestDigest));
        var placementKey = ToLowerHex(
            placementCommitment.Span,
            MailboxReceiptV2Limits.DigestLength,
            nameof(placementCommitment));
        var membershipKey = ToLowerHex(
            membershipCommitment.Span,
            MailboxReceiptV2Limits.DigestLength,
            nameof(membershipCommitment));
        var replicaKeys = expectedReplicaIds
            .Select(static replica => ToLowerHex(
                replica.Span,
                MailboxReceiptV2Limits.ReplicaIdLength,
                nameof(expectedReplicaIds)))
            .ToArray();
        if (replicaKeys.Length is < 2 or > 9
            || replicaKeys.Distinct(StringComparer.Ordinal).Count() != replicaKeys.Length)
        {
            throw new ArgumentException("Expected mailbox replicas are invalid.", nameof(expectedReplicaIds));
        }

        var requested = acknowledgements
            .Select(static acknowledgement => (
                acknowledgement.Cursor,
                Digest: ToLowerHex(
                    acknowledgement.EnvelopeDigest.Span,
                    MailboxClientLimits.DigestLength,
                    nameof(acknowledgements))))
            .ToArray();
        if (requested.Any(static item => item.Cursor == 0)
            || !requested.Select(static item => item.Cursor)
                .SequenceEqual(requested.Select(static item => item.Cursor).Order()))
        {
            throw new ArgumentException("Acknowledgements must use increasing cursors.", nameof(acknowledgements));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpiredAndCompact(document, NowUnixSeconds());
            if (document.AckOperations.TryGetValue(operationKey, out var existing))
            {
                if (!FixedHexEquals(existing.RequestDigest, requestKey))
                {
                    throw new MailboxClientOperationConflictException();
                }

                if (changed)
                {
                    await SaveAsync(document, cancellationToken).ConfigureAwait(false);
                }

                return ToAckReservation(operationKey, existing);
            }

            if (LedgerEntryCost(document) + 1L + requested.Length > _maxEntries)
            {
                throw new MailboxClientLedgerCapacityException();
            }

            var storesByCursor = document.Operations.Values
                .Where(operation =>
                    operation.Epoch == epoch
                    && string.Equals(
                        BuildMailboxKey(
                            operation.Epoch,
                            DecodeLowerHex(operation.MailboxId, 32)),
                        mailboxKey,
                        StringComparison.Ordinal))
                .ToDictionary(static operation => operation.Cursor);
            var stores = new List<MailboxClientLedgerOperation>(requested.Length);
            foreach (var acknowledgement in requested)
            {
                if (!storesByCursor.TryGetValue(acknowledgement.Cursor, out var store)
                    || store.State != "durable"
                    || store.Tombstoned
                    || store.ExpiresAtUnixSeconds <= acceptedAtUnixSeconds
                    || !FixedHexEquals(store.EnvelopeDigest, acknowledgement.Digest)
                    || !FixedHexEquals(store.PlacementCommitment, placementKey)
                    || !FixedHexEquals(store.MembershipCommitment, membershipKey)
                    || !store.ExpectedReplicaIds.SequenceEqual(replicaKeys, StringComparer.Ordinal))
                {
                    throw new MailboxClientAckTargetException();
                }

                stores.Add(store);
            }

            var items = stores.Select(store => new MailboxClientLedgerAckItem(
                store.Cursor,
                store.EnvelopeDigest,
                store.ExpiresAtUnixSeconds,
                "reserved",
                "",
                0,
                "",
                "",
                "")).ToArray();
            var operation = new MailboxClientLedgerAckOperation(
                epoch,
                ToLowerHex(mailboxId.Span, 32, nameof(mailboxId)),
                ToLowerHex(operationId.Span, 16, nameof(operationId)),
                requestKey,
                placementKey,
                membershipKey,
                replicaKeys,
                acceptedAtUnixSeconds,
                items.Max(static item => item.ExpiresAtUnixSeconds),
                items);
            foreach (var store in stores)
            {
                var key = BuildOperationKey(
                    store.Epoch,
                    DecodeLowerHex(store.MailboxId, 32),
                    DecodeLowerHex(store.OperationId, 16));
                document.Operations[key] = store with
                {
                    Tombstoned = true,
                    TombstonedAtUnixSeconds = store.Tombstoned
                        ? store.TombstonedAtUnixSeconds
                        : acceptedAtUnixSeconds
                };
            }

            document.AckOperations.Add(operationKey, operation);
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            return ToAckReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<MailboxClientAckReservation?> TryReadAckReservationAsync(
        ulong epoch,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> operationId,
        ReadOnlyMemory<byte> requestDigest,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var operationKey = BuildAckOperationKey(epoch, mailboxId.Span, operationId.Span);
        var requestKey = ToLowerHex(requestDigest.Span, 32, nameof(requestDigest));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpiredAndCompact(document, NowUnixSeconds());
            if (!document.AckOperations.TryGetValue(operationKey, out var operation))
            {
                if (changed)
                {
                    await SaveAsync(document, cancellationToken).ConfigureAwait(false);
                }

                return null;
            }

            if (!FixedHexEquals(operation.RequestDigest, requestKey))
            {
                throw new MailboxClientOperationConflictException();
            }

            if (changed)
            {
                await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            }

            return ToAckReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<MailboxClientRetrieveCandidate>> ReadAckTargetsAsync(
        ulong epoch,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> placementCommitment,
        ReadOnlyMemory<byte> membershipCommitment,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (epoch == 0
            || acknowledgements is null
            || acknowledgements.Count is < 1 or > MailboxClientLimits.MaximumPageItems)
        {
            throw new ArgumentOutOfRangeException(nameof(acknowledgements));
        }

        var mailboxKey = BuildMailboxKey(epoch, mailboxId.Span);
        var placementKey = ToLowerHex(placementCommitment.Span, 32, nameof(placementCommitment));
        var membershipKey = ToLowerHex(
            membershipCommitment.Span,
            32,
            nameof(membershipCommitment));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpiredAndCompact(document, NowUnixSeconds());
            var stores = document.Operations.Values
                .Where(operation =>
                    operation.Epoch == epoch
                    && string.Equals(
                        BuildMailboxKey(
                            operation.Epoch,
                            DecodeLowerHex(operation.MailboxId, 32)),
                        mailboxKey,
                        StringComparison.Ordinal))
                .ToDictionary(static operation => operation.Cursor);
            var result = new List<MailboxClientRetrieveCandidate>(acknowledgements.Count);
            foreach (var acknowledgement in acknowledgements)
            {
                if (!stores.TryGetValue(acknowledgement.Cursor, out var store)
                    || store.State != "durable"
                    || store.Tombstoned
                    || store.ExpiresAtUnixSeconds <= NowUnixSeconds()
                    || !string.Equals(
                        store.PlacementCommitment,
                        placementKey,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        store.MembershipCommitment,
                        membershipKey,
                        StringComparison.Ordinal)
                    || !CryptographicOperations.FixedTimeEquals(
                        DecodeLowerHex(store.EnvelopeDigest, 32),
                        acknowledgement.EnvelopeDigest.Span))
                {
                    throw new MailboxClientAckTargetException();
                }

                result.Add(new(
                    store.Cursor,
                    store.ExpiresAtUnixSeconds,
                    DecodeLowerHex(store.EnvelopeDigest, 32),
                    DecodeLowerHex(store.BlobDigest, 32),
                    store.BlobCleaned));
            }

            if (changed)
            {
                await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            }

            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<(ReadOnlyMemory<byte> MailboxId, ReadOnlyMemory<byte> BlobDigest)>>
        ReadTombstoneCleanupBatchAsync(
            int maximumCount,
            CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (maximumCount is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCount));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var changed = RemoveExpiredAndCompact(document, NowUnixSeconds());
            var result = document.Operations.Values
                .Where(static operation => operation.Tombstoned && !operation.BlobCleaned)
                .OrderBy(static operation => operation.Epoch)
                .ThenBy(static operation => operation.MailboxId, StringComparer.Ordinal)
                .ThenBy(static operation => operation.Cursor)
                .Take(maximumCount)
                .Select(static operation => (
                    (ReadOnlyMemory<byte>)DecodeLowerHex(operation.MailboxId, 32),
                    (ReadOnlyMemory<byte>)DecodeLowerHex(operation.BlobDigest, 32)))
                .ToArray();
            if (changed)
            {
                await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            }

            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task MarkTombstoneCleanupCompleteAsync(
        IReadOnlyList<(ReadOnlyMemory<byte> MailboxId, ReadOnlyMemory<byte> BlobDigest)> cleaned,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (cleaned is null || cleaned.Count is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(cleaned));
        }

        var keys = cleaned.Select(static item => (
            Mailbox: ToLowerHex(item.MailboxId.Span, 32, nameof(cleaned)),
            Blob: ToLowerHex(item.BlobDigest.Span, 32, nameof(cleaned)))).ToArray();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            foreach (var key in keys)
            {
                var pair = document.Operations.SingleOrDefault(candidate =>
                    string.Equals(candidate.Value.MailboxId, key.Mailbox, StringComparison.Ordinal)
                    && string.Equals(candidate.Value.BlobDigest, key.Blob, StringComparison.Ordinal));
                if (string.IsNullOrEmpty(pair.Key)
                    || !pair.Value.Tombstoned)
                {
                    throw new InvalidDataException("Mailbox tombstone cleanup target is invalid.");
                }

                document.Operations[pair.Key] = pair.Value with { BlobCleaned = true };
            }

            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<MailboxClientAckReservation> MarkAckRetryableAsync(
        string operationKey,
        ulong cursor,
        string error,
        CancellationToken cancellationToken) =>
        MutateAckItemAsync(
            operationKey,
            cursor,
            item => item.State is "completing" or "durable"
                ? throw new InvalidDataException("Completed mailbox ack cannot become retryable.")
                : item with { State = "retryable", Error = CanonicalError(error) },
            cancellationToken);

    public async Task<MailboxClientAckReservation> BeginAckCompletionAsync(
        string operationKey,
        ulong cursor,
        ReadOnlyMemory<byte> firstReplicaReceipt,
        ReadOnlyMemory<byte> secondReplicaReceipt,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var first = Convert.ToBase64String(firstReplicaReceipt.Span);
        var second = Convert.ToBase64String(secondReplicaReceipt.Span);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var operation = GetAckOperation(document, operationKey);
            var itemIndex = FindAckItem(operation, cursor);
            var item = operation.Items[itemIndex];
            if (item.State is "completing" or "durable")
            {
                if (!FixedBase64Equals(item.FirstReplicaReceipt, first)
                    || !FixedBase64Equals(item.SecondReplicaReceipt, second))
                {
                    throw new InvalidDataException(
                        "Ack coordinator sequence is bound to another statement.");
                }

                return ToAckReservation(operationKey, operation);
            }

            if (document.NextCoordinatorSequence == ulong.MaxValue)
            {
                throw new MailboxClientLedgerCapacityException();
            }

            var sequence = ++document.NextCoordinatorSequence;
            operation.Items[itemIndex] = item with
            {
                State = "completing",
                Error = "",
                CoordinatorSequence = sequence,
                FirstReplicaReceipt = first,
                SecondReplicaReceipt = second,
                Receipt = ""
            };
            document.AckOperations[operationKey] = operation;
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            return ToAckReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<MailboxClientAckReservation> CompleteAckAsync(
        string operationKey,
        ulong cursor,
        ulong coordinatorSequence,
        ReadOnlyMemory<byte> receipt,
        CancellationToken cancellationToken) =>
        MutateAckItemAsync(
            operationKey,
            cursor,
            item =>
            {
                var encoded = Convert.ToBase64String(receipt.Span);
                if (item.State == "durable")
                {
                    if (item.CoordinatorSequence != coordinatorSequence
                        || !FixedBase64Equals(item.Receipt, encoded))
                    {
                        throw new InvalidDataException("Durable mailbox ack receipt conflicts.");
                    }

                    return item;
                }

                if (item.State != "completing"
                    || item.CoordinatorSequence != coordinatorSequence
                    || string.IsNullOrEmpty(item.FirstReplicaReceipt)
                    || string.IsNullOrEmpty(item.SecondReplicaReceipt))
                {
                    throw new InvalidDataException("Mailbox ack completion is missing.");
                }

                return item with { State = "durable", Receipt = encoded, Error = "" };
            },
            cancellationToken);

    private async Task<MailboxClientAckReservation> MutateAckItemAsync(
        string operationKey,
        ulong cursor,
        Func<MailboxClientLedgerAckItem, MailboxClientLedgerAckItem> mutation,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(cancellationToken).ConfigureAwait(false);
            var operation = GetAckOperation(document, operationKey);
            var itemIndex = FindAckItem(operation, cursor);
            operation.Items[itemIndex] = mutation(operation.Items[itemIndex]);
            document.AckOperations[operationKey] = operation;
            ValidateDocument(document);
            await SaveAsync(document, cancellationToken).ConfigureAwait(false);
            return ToAckReservation(operationKey, operation);
        }
        finally
        {
            _gate.Release();
        }
    }

    private static void ValidateAckOperations(
        MailboxClientLedgerDocument document,
        HashSet<ulong> sequences,
        ref ulong maximumSequence)
    {
        var ackTargets = new HashSet<(ulong Epoch, string MailboxId, ulong Cursor)>();
        foreach (var pair in document.AckOperations)
        {
            var operation = pair.Value
                ?? throw new InvalidDataException("Mailbox ack authority contains null.");
            var mailbox = DecodeLowerHex(operation.MailboxId, 32);
            var expectedKey = BuildAckOperationKey(
                operation.Epoch,
                mailbox,
                DecodeLowerHex(operation.OperationId, 16));
            _ = DecodeLowerHex(operation.RequestDigest, 32);
            _ = DecodeLowerHex(operation.PlacementCommitment, 32);
            _ = DecodeLowerHex(operation.MembershipCommitment, 32);
            if (!string.Equals(pair.Key, expectedKey, StringComparison.Ordinal)
                || operation.Epoch == 0
                || operation.AcceptedAtUnixSeconds == 0
                || operation.ExpiresAtUnixSeconds <= operation.AcceptedAtUnixSeconds
                || operation.ExpectedReplicaIds is null
                || operation.ExpectedReplicaIds.Length is < 2 or > 9
                || operation.ExpectedReplicaIds.Any(static replica => replica is null)
                || operation.ExpectedReplicaIds
                    .Select(replica => Convert.ToHexString(
                        DecodeLowerHex(replica, 32)).ToLowerInvariant())
                    .Distinct(StringComparer.Ordinal)
                    .Count() != operation.ExpectedReplicaIds.Length
                || operation.Items is null
                || operation.Items.Length is < 1 or > MailboxClientLimits.MaximumPageItems)
            {
                throw new InvalidDataException("Mailbox ack authority is invalid.");
            }

            ulong priorCursor = 0;
            ulong maximumItemExpiry = 0;
            foreach (var item in operation.Items)
            {
                if (item is null
                    || item.Cursor <= priorCursor
                    || item.ExpiresAtUnixSeconds <= operation.AcceptedAtUnixSeconds
                    || item.ExpiresAtUnixSeconds > operation.ExpiresAtUnixSeconds)
                {
                    throw new InvalidDataException("Mailbox ack item scope is invalid.");
                }

                var digest = DecodeLowerHex(item.EnvelopeDigest, 32);
                var store = document.Operations.Values.SingleOrDefault(candidate =>
                    candidate.Epoch == operation.Epoch
                    && candidate.Cursor == item.Cursor
                    && string.Equals(candidate.MailboxId, operation.MailboxId, StringComparison.Ordinal));
                if (store is null
                    || !store.Tombstoned
                    || store.State != "durable"
                    || store.ExpiresAtUnixSeconds != item.ExpiresAtUnixSeconds
                    || !string.Equals(
                        store.PlacementCommitment,
                        operation.PlacementCommitment,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        store.MembershipCommitment,
                        operation.MembershipCommitment,
                        StringComparison.Ordinal)
                    || !CryptographicOperations.FixedTimeEquals(
                        DecodeLowerHex(store.EnvelopeDigest, 32),
                        digest)
                    || !store.ExpectedReplicaIds.SequenceEqual(
                        operation.ExpectedReplicaIds,
                        StringComparer.Ordinal))
                {
                    throw new InvalidDataException("Mailbox ack item target is invalid.");
                }

                if (!ackTargets.Add((operation.Epoch, operation.MailboxId, item.Cursor)))
                {
                    throw new InvalidDataException(
                        "Mailbox ack target is bound to multiple operations.");
                }

                ValidateAckItemState(item);
                if (item.CoordinatorSequence != 0)
                {
                    maximumSequence = Math.Max(maximumSequence, item.CoordinatorSequence);
                    if (!sequences.Add(item.CoordinatorSequence))
                    {
                        throw new InvalidDataException("Mailbox coordinator sequence was reused.");
                    }
                }

                priorCursor = item.Cursor;
                maximumItemExpiry = Math.Max(maximumItemExpiry, item.ExpiresAtUnixSeconds);
            }

            if (operation.ExpiresAtUnixSeconds != maximumItemExpiry)
            {
                throw new InvalidDataException(
                    "Mailbox ack replay authority must expire with its latest item.");
            }
        }
    }

    private static void ValidateAckItemState(MailboxClientLedgerAckItem item)
    {
        if (item.State is null
            || item.Error is null
            || item.FirstReplicaReceipt is null
            || item.SecondReplicaReceipt is null
            || item.Receipt is null)
        {
            throw new InvalidDataException("Mailbox ack state contains null fields.");
        }

        if (item.Error.Length != 0)
        {
            try
            {
                _ = CanonicalError(item.Error);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Mailbox ack error is non-canonical.", exception);
            }
        }

        var rawCompletionEmpty = item.FirstReplicaReceipt.Length == 0
            && item.SecondReplicaReceipt.Length == 0;
        var hasCompletion = item.CoordinatorSequence != 0
            && IsCanonicalBase64(
                item.FirstReplicaReceipt,
                MailboxReceiptV2Limits.MaximumReplicaLength)
            && IsCanonicalBase64(
                item.SecondReplicaReceipt,
                MailboxReceiptV2Limits.MaximumReplicaLength);
        var rawReceiptEmpty = item.Receipt.Length == 0;
        var hasReceipt = IsCanonicalBase64(
            item.Receipt,
            MailboxReceiptV2Limits.MaximumQuorumLength);
        var valid = item.State switch
        {
            "reserved" => item.CoordinatorSequence == 0
                && rawCompletionEmpty && rawReceiptEmpty && item.Error.Length == 0,
            "retryable" => item.CoordinatorSequence == 0
                && rawCompletionEmpty && rawReceiptEmpty && item.Error.Length != 0,
            "completing" => hasCompletion && rawReceiptEmpty && item.Error.Length == 0,
            "durable" => hasCompletion && hasReceipt && item.Error.Length == 0,
            _ => false
        };
        if (!valid)
        {
            throw new InvalidDataException("Mailbox ack state is inconsistent.");
        }
    }

    private static bool RemoveExpiredAckOperations(
        MailboxClientLedgerDocument document,
        ulong nowUnixSeconds)
    {
        var expired = document.AckOperations
            .Where(pair => pair.Value.ExpiresAtUnixSeconds <= nowUnixSeconds)
            .Select(static pair => pair.Key)
            .ToArray();
        foreach (var key in expired)
        {
            document.AckOperations.Remove(key);
        }

        return expired.Length != 0;
    }

    private static long LedgerEntryCost(MailboxClientLedgerDocument document)
    {
        long cost = document.Operations.Count + document.AckOperations.Count;
        foreach (var operation in document.AckOperations.Values)
        {
            if (operation?.Items is null)
            {
                return long.MaxValue;
            }

            cost += operation.Items.Length;
        }

        return cost;
    }

    public static string BuildAckOperationKey(
        ulong epoch,
        ReadOnlySpan<byte> mailboxId,
        ReadOnlySpan<byte> operationId) =>
        $"ack:{BuildOperationKey(epoch, mailboxId, operationId)}";

    private static MailboxClientLedgerAckOperation GetAckOperation(
        MailboxClientLedgerDocument document,
        string operationKey) =>
        document.AckOperations.TryGetValue(operationKey, out var operation)
            ? operation
            : throw new InvalidDataException("Mailbox ack reservation is missing.");

    private static int FindAckItem(MailboxClientLedgerAckOperation operation, ulong cursor)
    {
        var index = Array.FindIndex(operation.Items, item => item.Cursor == cursor);
        return index >= 0
            ? index
            : throw new InvalidDataException("Mailbox ack item reservation is missing.");
    }

    private static MailboxClientAckReservation ToAckReservation(
        string operationKey,
        MailboxClientLedgerAckOperation operation) =>
        new(
            operationKey,
            operation.Epoch,
            DecodeLowerHex(operation.MailboxId, 32),
            DecodeLowerHex(operation.OperationId, 16),
            DecodeLowerHex(operation.RequestDigest, 32),
            DecodeLowerHex(operation.PlacementCommitment, 32),
            DecodeLowerHex(operation.MembershipCommitment, 32),
            operation.ExpectedReplicaIds
                .Select(static replica => (ReadOnlyMemory<byte>)DecodeLowerHex(replica, 32))
                .ToArray(),
            operation.AcceptedAtUnixSeconds,
            operation.Items.Select(static item => new MailboxClientAckItemReservation(
                item.Cursor,
                item.ExpiresAtUnixSeconds,
                DecodeLowerHex(item.EnvelopeDigest, 32),
                ParseState(item.State),
                item.Error,
                item.CoordinatorSequence == 0
                    ? null
                    : new(
                        item.CoordinatorSequence,
                        Convert.FromBase64String(item.FirstReplicaReceipt),
                        Convert.FromBase64String(item.SecondReplicaReceipt)),
                item.Receipt.Length == 0
                    ? ReadOnlyMemory<byte>.Empty
                    : Convert.FromBase64String(item.Receipt))).ToArray());
}

public sealed class MailboxClientAckTargetException : Exception;
public sealed class MailboxClientContinuationException : Exception;
