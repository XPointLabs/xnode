using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientStoreAdapter
{
    private const int ContinuationSigningLength = 168;
    private const int ContinuationTokenLength = ContinuationSigningLength + 64;
    private const byte RetrieveContinuationPurpose = 1;
    private const byte AckPagePurpose = 2;
    private const byte CanonicalContinuationPurposes =
        RetrieveContinuationPurpose | AckPagePurpose;
    private static ReadOnlySpan<byte> ContinuationMagic => "XCT1"u8;
    private int _activeDeliveryOperations;

    public async Task<MailboxClientRetrieveResult> RetrieveAsync(
        ReadOnlyMemory<byte> canonicalRetrieveRequest,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var status = Status;
        if (!status.Enabled)
        {
            return MailboxClientRetrieveResult.Failure(
                MailboxClientRetrieveStatus.Disabled,
                "disabled");
        }

        if (!status.RetrieveReady)
        {
            return MailboxClientRetrieveResult.Failure(
                MailboxClientRetrieveStatus.NotReady,
                status.RetrieveReason);
        }

        var deliveryRetained = false;
        MailboxCapabilityBinding? verifiedReservation = null;
        try
        {
            MailboxRetrieveRequest request;
            var owned = canonicalRetrieveRequest.ToArray();
            try
            {
                request = MailboxClientCodec.DecodeRetrieve(
                    owned,
                    CreateDecodePolicy(),
                    new VerifierDeferredReplayGuard());
            }
            catch (Exception exception) when (
                exception is MailboxClientException or MailboxCapabilityException)
            {
                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Malformed,
                    "non-canonical-mrt1");
            }

            var placementCommitment = MailboxPlacementCommitment.Compute(
                request.PlacementId);
            var membershipCommitment = _options.GetMembershipCommitment(request.Epoch);
            var requestDigest = SHA256.HashData(owned);
            verifiedReservation = await _verifier.VerifyAsync(
                owned,
                MailboxClientOperation.Retrieve,
                cancellationToken).ConfigureAwait(false);
            if (!BindingMatches(
                    verifiedReservation,
                    MailboxClientOperation.Retrieve,
                    request.Epoch,
                    request.OperationId.Span,
                    request.MailboxId.Bytes.Span,
                    placementCommitment,
                    membershipCommitment,
                    requestDigest,
                    request.RetrieveCapability))
            {
                if (verifiedReservation is not null)
                {
                    AbortCapability(verifiedReservation);
                    verifiedReservation = null;
                }

                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Unauthorized,
                    "capability-binding-rejected");
            }

            if (!TryRetainDeliveryOperation())
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Rejected,
                    "delivery-operation-capacity");
            }

            deliveryRetained = true;
            IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds;
            try
            {
                expectedReplicaIds = NormalizeReplicaAuthority(
                    await _replicaAuthorizer.SelectReplicaIdsAsync(
                        request.Epoch,
                        membershipCommitment.ToArray(),
                        placementCommitment.ToArray(),
                        cancellationToken).ConfigureAwait(false));
            }
            catch (ArgumentException)
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Unauthorized,
                    "replica-authority-invalid");
            }

            if (!expectedReplicaIds.Any(
                    id => id.Span.SequenceEqual(_crypto.LocalRouterId)))
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Unauthorized,
                    "local-replica-not-authorized");
            }

            if (!TryValidateRetrieveContinuation(
                    request,
                    placementCommitment,
                    membershipCommitment,
                    expectedReplicaIds,
                    out var continuation))
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Unauthorized,
                    "continuation-token-rejected");
            }

            MailboxClientRetrieveWindow window;
            try
            {
                Observe(
                    MailboxClientOperation.Retrieve,
                    MailboxClientObservedAccess.LedgerRead);
                window = await _ledger.ReadRetrieveCandidatesAsync(
                    request.Epoch,
                    request.MailboxId.Bytes,
                    request.AfterCursor,
                    continuation?.SnapshotHighWater ?? 0,
                    request.MaximumItems + 1,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (MailboxClientContinuationException)
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientRetrieveResult.Failure(
                    MailboxClientRetrieveStatus.Unauthorized,
                    "continuation-token-rejected");
            }

            var items = new List<MailboxRetrievedEnvelope>(window.Candidates.Count);
            foreach (var candidate in window.Candidates)
            {
                Observe(
                    MailboxClientOperation.Retrieve,
                    MailboxClientObservedAccess.BlobRead);
                var envelope = await ReadCandidateEnvelopeAsync(
                    request.Epoch,
                    request.MailboxId.Bytes,
                    request.PlacementId.Bytes,
                    candidate,
                    cancellationToken).ConfigureAwait(false);
                if (envelope is null)
                {
                    AbortCapability(verifiedReservation);
                    verifiedReservation = null;
                    return MailboxClientRetrieveResult.Failure(
                        MailboxClientRetrieveStatus.Rejected,
                        "mailbox-storage-corrupt");
                }

                items.Add(new()
                {
                    Cursor = candidate.Cursor,
                    Envelope = envelope
                });
            }

            var selectedCount = Math.Min(request.MaximumItems, items.Count);
            byte[] encodedPage;
            while (true)
            {
                var selected = items.Take(selectedCount).ToArray();
                var hasMore = items.Count > selectedCount;
                if (hasMore && selected.Length == 0)
                {
                    AbortCapability(verifiedReservation);
                    verifiedReservation = null;
                    return MailboxClientRetrieveResult.Failure(
                        MailboxClientRetrieveStatus.Rejected,
                        "retrieve-page-byte-capacity");
                }

                byte[] token;
                try
                {
                    token = hasMore
                        ? CreateContinuationToken(
                            request.Epoch,
                            selected[^1].Cursor,
                            window.SnapshotHighWater,
                            request.MaximumItems,
                            request.MailboxId.Bytes.Span,
                            placementCommitment,
                            membershipCommitment,
                            AcknowledgementDigest(selected))
                        : [];
                }
                catch (InvalidOperationException)
                {
                    AbortCapability(verifiedReservation);
                    verifiedReservation = null;
                    return MailboxClientRetrieveResult.Failure(
                        MailboxClientRetrieveStatus.Rejected,
                        "continuation-window-expired");
                }

                var page = new MailboxRetrievePage
                {
                    Epoch = request.Epoch,
                    OperationId = request.OperationId.ToArray(),
                    NextCursor = selected.Length == 0 ? 0 : selected[^1].Cursor,
                    HasMore = hasMore,
                    ContinuationToken = token,
                    Items = selected
                };
                try
                {
                    encodedPage = MailboxClientCodec.EncodeRetrievePage(page);
                    break;
                }
                catch (MailboxClientException exception) when (
                    exception.Error == MailboxClientError.EncodedLengthOutOfRange
                    && selectedCount > 0)
                {
                    selectedCount--;
                }
            }

            CompleteCapability(verifiedReservation!, encodedPage);
            verifiedReservation = null;
            return new(
                MailboxClientRetrieveStatus.Success,
                encodedPage,
                "");
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested
            && verifiedReservation is not null)
        {
            AbortCapability(verifiedReservation);
            throw;
        }
        catch when (verifiedReservation is not null)
        {
            AbortCapability(verifiedReservation);
            throw;
        }
        finally
        {
            if (deliveryRetained)
            {
                ReleaseDeliveryOperation();
            }
        }
    }

    public async Task<MailboxClientAckResult> AcknowledgeAsync(
        ReadOnlyMemory<byte> canonicalAckRequest,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var status = Status;
        if (!status.Enabled)
        {
            return MailboxClientAckResult.Failure(MailboxClientAckStatus.Disabled, "disabled");
        }

        if (!status.AcknowledgeReady)
        {
            return MailboxClientAckResult.Failure(
                MailboxClientAckStatus.NotReady,
                status.AcknowledgeReason);
        }

        var deliveryRetained = false;
        MailboxCapabilityBinding? verifiedReservation = null;
        try
        {
            MailboxAckRequest request;
            var owned = canonicalAckRequest.ToArray();
            var requestDigest = SHA256.HashData(owned);
            try
            {
                request = MailboxClientCodec.DecodeAck(
                    owned,
                    CreateDecodePolicy(),
                    new VerifierDeferredReplayGuard());
            }
            catch (Exception exception) when (
                exception is MailboxClientException or MailboxCapabilityException)
            {
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Malformed,
                    "non-canonical-mak1");
            }

            var placementCommitment = MailboxPlacementCommitment.Compute(
                request.PlacementId);
            var membershipCommitment = _options.GetMembershipCommitment(request.Epoch);
            verifiedReservation = await _verifier.VerifyAsync(
                owned,
                MailboxClientOperation.Acknowledge,
                cancellationToken).ConfigureAwait(false);
            if (!BindingMatches(
                    verifiedReservation,
                    MailboxClientOperation.Acknowledge,
                    request.Epoch,
                    request.OperationId.Span,
                    request.MailboxId.Bytes.Span,
                    placementCommitment,
                    membershipCommitment,
                    requestDigest,
                    request.RetrieveCapability))
            {
                if (verifiedReservation is not null)
                {
                    AbortCapability(verifiedReservation);
                    verifiedReservation = null;
                }

                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Unauthorized,
                    "capability-binding-rejected");
            }

            if (!TryRetainDeliveryOperation())
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Rejected,
                    "delivery-operation-capacity");
            }

            deliveryRetained = true;
            IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds;
            try
            {
                expectedReplicaIds = NormalizeReplicaAuthority(
                    await _replicaAuthorizer.SelectReplicaIdsAsync(
                        request.Epoch,
                        membershipCommitment.ToArray(),
                        placementCommitment.ToArray(),
                        cancellationToken).ConfigureAwait(false));
            }
            catch (ArgumentException)
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Unauthorized,
                    "replica-authority-invalid");
            }

            if (expectedReplicaIds.Count < 2
                || !expectedReplicaIds.Take(2).Any(
                    id => id.Span.SequenceEqual(_crypto.LocalRouterId)))
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Unauthorized,
                    "local-replica-not-authorized");
            }

            if (!ValidateAckContinuation(
                    request,
                    placementCommitment,
                    membershipCommitment,
                    expectedReplicaIds))
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Unauthorized,
                    "continuation-token-rejected");
            }

            MailboxClientAckReservation? existingReservation;
            try
            {
                Observe(
                    MailboxClientOperation.Acknowledge,
                    MailboxClientObservedAccess.LedgerRead);
                existingReservation = await _ledger.TryReadAckReservationAsync(
                    request.Epoch,
                    request.MailboxId.Bytes,
                    request.OperationId,
                    requestDigest,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (MailboxClientOperationConflictException)
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Conflict,
                    "operation-id-conflict");
            }

            if (existingReservation is null)
            {
                IReadOnlyList<MailboxClientRetrieveCandidate> targets;
                try
                {
                    Observe(
                        MailboxClientOperation.Acknowledge,
                        MailboxClientObservedAccess.LedgerRead);
                    targets = await _ledger.ReadAckTargetsAsync(
                        request.Epoch,
                        request.MailboxId.Bytes,
                        placementCommitment,
                        membershipCommitment,
                        request.Acknowledgements,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (MailboxClientAckTargetException)
                {
                    AbortCapability(verifiedReservation);
                    verifiedReservation = null;
                    return MailboxClientAckResult.Failure(
                        MailboxClientAckStatus.Rejected,
                        "ack-target-mismatch");
                }

                foreach (var target in targets)
                {
                    if (target.BlobCleaned)
                    {
                        continue;
                    }

                    Observe(
                        MailboxClientOperation.Acknowledge,
                        MailboxClientObservedAccess.BlobRead);
                    var envelope = await ReadCandidateEnvelopeAsync(
                        request.Epoch,
                        request.MailboxId.Bytes,
                        request.PlacementId.Bytes,
                        target,
                        cancellationToken).ConfigureAwait(false);
                    if (envelope is null)
                    {
                        AbortCapability(verifiedReservation);
                        verifiedReservation = null;
                        return MailboxClientAckResult.Failure(
                            MailboxClientAckStatus.Rejected,
                            "ack-target-storage-mismatch");
                    }
                }
            }

            var operationKey = MailboxClientOperationLedger.BuildAckOperationKey(
                request.Epoch,
                request.MailboxId.Bytes.Span,
                request.OperationId.Span);
            var singleFlight = TryRetainSingleFlight(operationKey);
            if (singleFlight is null)
            {
                AbortCapability(verifiedReservation);
                verifiedReservation = null;
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Rejected,
                    "single-flight-capacity");
            }

            var entered = false;
            try
            {
                await singleFlight.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                entered = true;
                var verified = verifiedReservation!;
                verifiedReservation = null;
                return await AcknowledgeSingleFlightAsync(
                    request,
                    requestDigest,
                    placementCommitment,
                    membershipCommitment,
                    expectedReplicaIds,
                    verified,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if (entered)
                {
                    singleFlight.Gate.Release();
                }

                ReleaseSingleFlight(operationKey, singleFlight);
            }
        }
        catch (OperationCanceledException) when (
            cancellationToken.IsCancellationRequested
            && verifiedReservation is not null)
        {
            AbortCapability(verifiedReservation);
            throw;
        }
        catch when (verifiedReservation is not null)
        {
            AbortCapability(verifiedReservation);
            throw;
        }
        finally
        {
            if (deliveryRetained)
            {
                ReleaseDeliveryOperation();
            }
        }
    }

    private async Task<MailboxClientAckResult> AcknowledgeSingleFlightAsync(
        MailboxAckRequest request,
        byte[] requestDigest,
        byte[] placementCommitment,
        byte[] membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        MailboxCapabilityBinding verified,
        CancellationToken cancellationToken)
    {
        MailboxClientAckReservation reservation;
        try
        {
            Observe(
                MailboxClientOperation.Acknowledge,
                MailboxClientObservedAccess.LedgerMutation);
            reservation = await _ledger.ReserveAckAsync(
                request.Epoch,
                request.OperationId,
                requestDigest,
                request.MailboxId.Bytes,
                placementCommitment,
                membershipCommitment,
                expectedReplicaIds,
                request.Acknowledgements,
                NowUnixSeconds(),
                cancellationToken).ConfigureAwait(false);
        }
        catch (MailboxClientOperationConflictException)
        {
            AbortCapability(verified);
            return MailboxClientAckResult.Failure(
                MailboxClientAckStatus.Conflict,
                "operation-id-conflict");
        }
        catch (MailboxClientLedgerCapacityException)
        {
            AbortCapability(verified);
            return MailboxClientAckResult.Failure(
                MailboxClientAckStatus.Rejected,
                "operation-ledger-capacity");
        }
        catch (MailboxClientAckTargetException)
        {
            AbortCapability(verified);
            return MailboxClientAckResult.Failure(
                MailboxClientAckStatus.Rejected,
                "ack-target-mismatch");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            AbortCapability(verified);
            throw;
        }

        if (!FixedEquals(reservation.PlacementCommitment.Span, placementCommitment)
            || !FixedEquals(reservation.MembershipCommitment.Span, membershipCommitment)
            || !ReplicaSetsEqual(reservation.ExpectedReplicaIds, expectedReplicaIds))
        {
            CompleteTerminal(verified!, "ack-authority-rotated");
            return MailboxClientAckResult.Failure(
                MailboxClientAckStatus.Unauthorized,
                "ack-authority-rotated");
        }

        var completed = new List<MailboxClientAckReceipt>(reservation.Items.Count);
        foreach (var initialItem in reservation.Items)
        {
            var item = reservation.Items.Single(candidate => candidate.Cursor == initialItem.Cursor);
            var context = CreateTombstoneContext(
                reservation,
                item,
                request.PlacementId.Bytes);
            if (item.State == MailboxClientLedgerState.Durable)
            {
                if (!VerifyAckCached(item, context, expectedReplicaIds))
                {
                    CompleteTerminal(verified!, "cached-ack-quorum-invalid");
                    return MailboxClientAckResult.Failure(
                        MailboxClientAckStatus.Rejected,
                        "cached-ack-quorum-invalid");
                }

                completed.Add(new(item.Cursor, item.EnvelopeDigest, item.CachedReceipt.ToArray()));
                continue;
            }

            if (item.State == MailboxClientLedgerState.Completing)
            {
                var resumed = await ResumeAckCompletionAsync(
                    reservation,
                    item,
                    context,
                    expectedReplicaIds,
                    cancellationToken).ConfigureAwait(false);
                if (resumed is null)
                {
                    CompleteTerminal(verified!, "ack-completion-invalid");
                    return MailboxClientAckResult.Failure(
                        MailboxClientAckStatus.Rejected,
                        "ack-completion-invalid");
                }

                completed.Add(resumed);
                Observe(
                    MailboxClientOperation.Acknowledge,
                    MailboxClientObservedAccess.LedgerMutation);
                reservation = await _ledger.ReserveAckAsync(
                    request.Epoch,
                    request.OperationId,
                    requestDigest,
                    request.MailboxId.Bytes,
                    placementCommitment,
                    membershipCommitment,
                    expectedReplicaIds,
                    request.Acknowledgements,
                    reservation.AcceptedAtUnixSeconds,
                    cancellationToken).ConfigureAwait(false);
                continue;
            }

            var localReceipt = CreateLocalTombstoneReceipt(context);
            IReadOnlyList<ReadOnlyMemory<byte>> remoteReceipts;
            try
            {
                Observe(
                    MailboxClientOperation.Acknowledge,
                    MailboxClientObservedAccess.PeerMutation);
                remoteReceipts = await _tombstoneFanout.TombstoneAsync(
                    CopyTombstoneContext(context),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is HttpRequestException or IOException or OperationCanceledException)
            {
                if (exception is OperationCanceledException
                    && cancellationToken.IsCancellationRequested)
                {
                    throw;
                }

                await _ledger.MarkAckRetryableAsync(
                    reservation.OperationKey,
                    item.Cursor,
                    "tombstone-fanout-unavailable",
                    cancellationToken).ConfigureAwait(false);
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.QuorumUnavailable,
                    "tombstone-fanout-unavailable");
            }

            var receipts = SelectTombstoneQuorum(
                localReceipt,
                remoteReceipts,
                context,
                expectedReplicaIds);
            if (receipts is null)
            {
                await _ledger.MarkAckRetryableAsync(
                    reservation.OperationKey,
                    item.Cursor,
                    "durable-tombstone-quorum-not-reached",
                    cancellationToken).ConfigureAwait(false);
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.QuorumUnavailable,
                    "durable-tombstone-quorum-not-reached");
            }

            Observe(
                MailboxClientOperation.Acknowledge,
                MailboxClientObservedAccess.LedgerMutation);
            reservation = await _ledger.BeginAckCompletionAsync(
                reservation.OperationKey,
                item.Cursor,
                receipts.Value.First,
                receipts.Value.Second,
                cancellationToken).ConfigureAwait(false);
            item = reservation.Items.Single(candidate => candidate.Cursor == item.Cursor);
            context = CreateTombstoneContext(
                reservation,
                item,
                request.PlacementId.Bytes);
            var receipt = await ResumeAckCompletionAsync(
                reservation,
                item,
                context,
                expectedReplicaIds,
                cancellationToken).ConfigureAwait(false);
            if (receipt is null)
            {
                CompleteTerminal(verified!, "ack-completion-invalid");
                return MailboxClientAckResult.Failure(
                    MailboxClientAckStatus.Rejected,
                    "ack-completion-invalid");
            }

            completed.Add(receipt);
        }

        // The durable ACK is already journaled. Ciphertext reclamation is best-effort
        // here and remains restart-recoverable if local storage is temporarily unavailable.
        await TryCleanupTombstonesAfterAckAsync(
            Math.Min(reservation.Items.Count, 100)).ConfigureAwait(false);
        var canonicalAckOutcome = MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = request.Epoch,
                OperationId = request.OperationId.ToArray(),
                TombstoneQuorums = completed
                    .Select(static receipt =>
                        (ReadOnlyMemory<byte>)receipt.DurableQuorumReceipt.ToArray())
                    .ToArray()
            });
        CompleteCapability(verified!, canonicalAckOutcome);
        return new(MailboxClientAckStatus.Durable, completed, "");
    }

    private async Task<MailboxClientAckReceipt?> ResumeAckCompletionAsync(
        MailboxClientAckReservation reservation,
        MailboxClientAckItemReservation item,
        MailboxReplicaTombstoneContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        CancellationToken cancellationToken)
    {
        if (item.Completion is null)
        {
            return null;
        }

        MailboxReplicaReceiptV2 first;
        MailboxReplicaReceiptV2 second;
        try
        {
            first = MailboxReceiptV2Codec.DecodeReplica(
                item.Completion.FirstReplicaReceipt.Span);
            second = MailboxReceiptV2Codec.DecodeReplica(
                item.Completion.SecondReplicaReceipt.Span);
        }
        catch (MailboxReceiptException)
        {
            return null;
        }

        if (!TombstoneAuthoritiesMatch(first, second, context, expectedReplicaIds))
        {
            return null;
        }

        var quorum = SignQuorum(first, second, item.Completion.CoordinatorSequence);
        var encoded = MailboxReceiptV3Codec.EncodeDurableQuorum(quorum);
        if (!VerifyTombstoneQuorum(
                encoded,
                context,
                expectedReplicaIds,
                item.Completion.CoordinatorSequence))
        {
            return null;
        }

        Observe(
            MailboxClientOperation.Acknowledge,
            MailboxClientObservedAccess.LedgerMutation);
        await _ledger.CompleteAckAsync(
            reservation.OperationKey,
            item.Cursor,
            item.Completion.CoordinatorSequence,
            encoded,
            cancellationToken).ConfigureAwait(false);
        return new(item.Cursor, item.EnvelopeDigest.ToArray(), encoded);
    }

    private (byte[] First, byte[] Second)? SelectTombstoneQuorum(
        MailboxReplicaReceiptV2 localReceipt,
        IReadOnlyList<ReadOnlyMemory<byte>>? remoteReceipts,
        MailboxReplicaTombstoneContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds)
    {
        if (remoteReceipts is null || remoteReceipts.Count > 9)
        {
            return null;
        }

        var receiptsById = new Dictionary<string, MailboxReplicaReceiptV2>(StringComparer.Ordinal)
        {
            [Convert.ToHexString(localReceipt.ReplicaId.Span).ToLowerInvariant()] = localReceipt
        };
        foreach (var encoded in remoteReceipts)
        {
            try
            {
                var receipt = MailboxReceiptV2Codec.DecodeReplica(encoded.Span);
                var id = Convert.ToHexString(receipt.ReplicaId.Span).ToLowerInvariant();
                if (!receiptsById.ContainsKey(id)
                    && expectedReplicaIds.Any(expected =>
                        expected.Span.SequenceEqual(receipt.ReplicaId.Span))
                    && VerifyTombstoneReplica(receipt, context))
                {
                    receiptsById.Add(id, receipt);
                }
            }
            catch (MailboxReceiptException)
            {
                // Malformed or context-mismatched replica evidence never counts.
            }
        }

        var required = expectedReplicaIds.Take(2)
            .Select(id => Convert.ToHexString(id.Span).ToLowerInvariant())
            .ToArray();
        return required.All(receiptsById.ContainsKey)
            ? (
                MailboxReceiptV2Codec.EncodeReplica(receiptsById[required[0]]),
                MailboxReceiptV2Codec.EncodeReplica(receiptsById[required[1]]))
            : null;
    }

    private bool TombstoneAuthoritiesMatch(
        MailboxReplicaReceiptV2 first,
        MailboxReplicaReceiptV2 second,
        MailboxReplicaTombstoneContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds)
    {
        var expected = expectedReplicaIds.Take(2)
            .Select(id => Convert.ToHexString(id.Span).ToLowerInvariant())
            .Order(StringComparer.Ordinal)
            .ToArray();
        var actual = new[] { first, second }
            .Select(receipt => Convert.ToHexString(receipt.ReplicaId.Span).ToLowerInvariant())
            .Order(StringComparer.Ordinal)
            .ToArray();
        return expected.SequenceEqual(actual, StringComparer.Ordinal)
            && VerifyTombstoneReplica(first, context)
            && VerifyTombstoneReplica(second, context);
    }

    private bool VerifyAckCached(
        MailboxClientAckItemReservation item,
        MailboxReplicaTombstoneContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds) =>
        item.Completion is not null
        && !item.CachedReceipt.IsEmpty
        && VerifyTombstoneQuorum(
            item.CachedReceipt.Span,
            context,
            expectedReplicaIds,
            item.Completion.CoordinatorSequence);

    private bool VerifyTombstoneQuorum(
        ReadOnlySpan<byte> encoded,
        MailboxReplicaTombstoneContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        ulong coordinatorSequence)
    {
        try
        {
            var coordinator = MailboxReceiptV3Codec.DecodeDurableQuorum(encoded);
            if (!VerifyTombstoneReplica(coordinator.FirstReplica, context)
                || !VerifyTombstoneReplica(coordinator.SecondReplica, context)
                || !_crypto.VerifyCoordinator(
                    coordinator.CoordinatorId.Span,
                    MailboxReceiptV3Codec.GetQuorumSigningBytes(coordinator),
                    coordinator.Signature.Span))
            {
                return false;
            }

            var actualIds = new[]
                {
                    coordinator.FirstReplica,
                    coordinator.SecondReplica
                }
                .Select(receipt => Convert.ToHexString(receipt.ReplicaId.Span).ToLowerInvariant())
                .Order(StringComparer.Ordinal)
                .ToArray();
            var expectedIds = expectedReplicaIds.Take(2)
                .Select(id => Convert.ToHexString(id.Span).ToLowerInvariant())
                .Order(StringComparer.Ordinal)
                .ToArray();
            return coordinator.CoordinatorSequence == coordinatorSequence
                && coordinator.CoordinatorId.Span.SequenceEqual(
                    _crypto.LocalRouterId)
                && actualIds.SequenceEqual(expectedIds, StringComparer.Ordinal);
        }
        catch (MailboxReceiptException)
        {
            return false;
        }
    }

    private bool VerifyTombstoneReplica(
        MailboxReplicaReceiptV2 receipt,
        MailboxReplicaTombstoneContext context)
    {
        var valid = receipt.Status == MailboxReceiptStatus.Durable
            && receipt.Disposition == MailboxReplicaDisposition.Tombstone
            && receipt.OperationId.Span.SequenceEqual(context.OperationId.Span)
            && receipt.Epoch == context.Epoch
            && receipt.Cursor == context.Cursor
            && receipt.AcceptedAtUnixSeconds == context.AcceptedAtUnixSeconds
            && receipt.DurableAtUnixSeconds == context.AcceptedAtUnixSeconds
            && receipt.ExpiresAtUnixSeconds == context.ExpiresAtUnixSeconds
            && receipt.BlindedMailboxId.Span.SequenceEqual(context.BlindedMailboxId.Span)
            && receipt.PlacementCommitment.Span.SequenceEqual(context.PlacementCommitment.Span)
            && receipt.MembershipCommitment.Span.SequenceEqual(context.MembershipCommitment.Span)
            && receipt.EnvelopeDigest.Span.SequenceEqual(context.EnvelopeDigest.Span);
        return valid && _crypto.VerifyReplica(
            receipt.ReplicaId.Span,
            MailboxReceiptV2Codec.GetReplicaSigningBytes(receipt),
            receipt.Signature.Span);
    }

    private MailboxReplicaReceiptV2 CreateLocalTombstoneReceipt(
        MailboxReplicaTombstoneContext context)
    {
        var unsigned = new MailboxReplicaReceiptV2
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = MailboxReplicaDisposition.Tombstone,
            ReplicaId = _crypto.LocalRouterId,
            OperationId = context.OperationId,
            Epoch = context.Epoch,
            Cursor = context.Cursor,
            AcceptedAtUnixSeconds = context.AcceptedAtUnixSeconds,
            DurableAtUnixSeconds = context.AcceptedAtUnixSeconds,
            ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds,
            BlindedMailboxId = context.BlindedMailboxId,
            PlacementCommitment = context.PlacementCommitment,
            MembershipCommitment = context.MembershipCommitment,
            EnvelopeDigest = context.EnvelopeDigest,
            Signature = new byte[64]
        };
        return unsigned with
        {
            Signature = _crypto.SignLocal(MailboxReceiptV2Codec.GetReplicaSigningBytes(unsigned))
        };
    }

    private static MailboxReplicaTombstoneContext CreateTombstoneContext(
        MailboxClientAckReservation reservation,
        MailboxClientAckItemReservation item,
        ReadOnlyMemory<byte> placementId) =>
        new(
            item.Cursor,
            reservation.Epoch,
            reservation.OperationId.ToArray(),
            reservation.MailboxId.ToArray(),
            reservation.PlacementCommitment.ToArray(),
            reservation.MembershipCommitment.ToArray(),
            item.EnvelopeDigest.ToArray(),
            item.ExpiresAtUnixSeconds,
            reservation.AcceptedAtUnixSeconds,
            reservation.ExpectedReplicaIds
                .Select(static id => (ReadOnlyMemory<byte>)id.ToArray())
                .ToArray())
        {
            BlindedPlacementId = placementId.ToArray()
        };

    private static MailboxReplicaTombstoneContext CopyTombstoneContext(
        MailboxReplicaTombstoneContext context) =>
        context with
        {
            OperationId = context.OperationId.ToArray(),
            BlindedMailboxId = context.BlindedMailboxId.ToArray(),
            PlacementCommitment = context.PlacementCommitment.ToArray(),
            MembershipCommitment = context.MembershipCommitment.ToArray(),
            BlindedPlacementId = context.BlindedPlacementId.ToArray(),
            EnvelopeDigest = context.EnvelopeDigest.ToArray(),
            ExpectedReplicaIds = context.ExpectedReplicaIds
                .Select(static id => (ReadOnlyMemory<byte>)id.ToArray())
                .ToArray()
        };

    private static MailboxDurableQuorumExpectationV2 TombstoneExpectation(
        MailboxReplicaTombstoneContext context) =>
        new()
        {
            OperationId = context.OperationId,
            Epoch = context.Epoch,
            Cursor = context.Cursor,
            Disposition = MailboxReplicaDisposition.Tombstone,
            BlindedMailboxId = context.BlindedMailboxId,
            PlacementCommitment = context.PlacementCommitment,
            MembershipCommitment = context.MembershipCommitment,
            EnvelopeDigest = context.EnvelopeDigest,
            ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds
        };

    private async Task<MailboxEncryptedEnvelope?> ReadCandidateEnvelopeAsync(
        ulong epoch,
        ReadOnlyMemory<byte> mailboxId,
        ReadOnlyMemory<byte> placementId,
        MailboxClientRetrieveCandidate candidate,
        CancellationToken cancellationToken)
    {
        var mailboxKey = Convert.ToHexString(mailboxId.Span).ToLowerInvariant();
        var blobKey = Convert.ToHexString(candidate.BlobDigest.Span).ToLowerInvariant();
        var blob = await _store.ReadExactAsync(
            mailboxKey,
            blobKey,
            cancellationToken).ConfigureAwait(false);
        if (blob is null)
        {
            return null;
        }

        try
        {
            var canonicalEnvelope = Convert.FromBase64String(blob.Ciphertext);
            var envelope = MailboxClientCodec.DecodeEncryptedEnvelope(
                canonicalEnvelope,
                CreateDecodePolicy());
            return envelope.Epoch == epoch
                && envelope.ExpiresAtUnixSeconds == candidate.ExpiresAtUnixSeconds
                && FixedEquals(envelope.MailboxId.Bytes.Span, mailboxId.Span)
                && FixedEquals(envelope.PlacementId.Bytes.Span, placementId.Span)
                && FixedEquals(
                    envelope.DeduplicationDigest.Span,
                    candidate.EnvelopeDigest.Span)
                && FixedEquals(SHA256.HashData(canonicalEnvelope), candidate.BlobDigest.Span)
                    ? envelope
                    : null;
        }
        catch (Exception exception) when (
            exception is FormatException or MailboxClientException)
        {
            return null;
        }
    }

    private bool TryValidateRetrieveContinuation(
        MailboxRetrieveRequest request,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        out ContinuationAuthority? authority)
    {
        authority = null;
        if (request.AfterCursor == 0)
        {
            return request.ContinuationToken.IsEmpty;
        }

        if (!TryReadContinuationToken(
                request.ContinuationToken.Span,
                request.Epoch,
                request.AfterCursor,
                request.MailboxId.Bytes.Span,
                placementCommitment,
                membershipCommitment,
                RetrieveContinuationPurpose,
                expectedReplicaIds,
                out var decoded)
            || request.MaximumItems > decoded.MaximumItems)
        {
            return false;
        }

        authority = decoded;
        return true;
    }

    private bool ValidateAckContinuation(
        MailboxAckRequest request,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds) =>
        request.IsFinalPage
            ? request.ContinuationToken.IsEmpty
            : TryReadContinuationToken(
                request.ContinuationToken.Span,
                request.Epoch,
                request.Acknowledgements[^1].Cursor,
                request.MailboxId.Bytes.Span,
                placementCommitment,
                membershipCommitment,
                AckPagePurpose,
                expectedReplicaIds,
                out var authority)
            && FixedEquals(
                authority.PageAcknowledgementDigest.Span,
                AcknowledgementDigest(request.Acknowledgements));

    private byte[] CreateContinuationToken(
        ulong epoch,
        ulong cursor,
        ulong snapshotHighWater,
        ushort maximumItems,
        ReadOnlySpan<byte> mailboxId,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        ReadOnlySpan<byte> pageAcknowledgementDigest)
    {
        var now = NowUnixSeconds();
        var epochExpiry = epoch == _options.CurrentEpoch
            ? _options.CurrentExpiresAtUnixSeconds
            : _options.NextExpiresAtUnixSeconds;
        var lifetimeSeconds = checked((ulong)_options.ContinuationTokenLifetime.TotalSeconds);
        var expiresAt = Math.Min(epochExpiry, checked(now + lifetimeSeconds));
        if (cursor == 0
            || snapshotHighWater < cursor
            || maximumItems is 0 or > MailboxClientLimits.MaximumPageItems
            || pageAcknowledgementDigest.Length != MailboxClientLimits.DigestLength
            || expiresAt <= now)
        {
            throw new InvalidOperationException("Continuation token window is exhausted.");
        }

        var token = new byte[ContinuationTokenLength];
        ContinuationMagic.CopyTo(token);
        token[4] = 1;
        // MRP1 exposes one opaque token which is intentionally authorized for exactly two
        // domain-separated uses: continuing MRT1 and acknowledging that exact page via MAK1.
        token[5] = CanonicalContinuationPurposes;
        BinaryPrimitives.WriteUInt16BigEndian(token.AsSpan(6, 2), maximumItems);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(8, 8), epoch);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(16, 8), cursor);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(24, 8), expiresAt);
        BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(32, 8), snapshotHighWater);
        mailboxId.CopyTo(token.AsSpan(40, 32));
        placementCommitment.CopyTo(token.AsSpan(72, 32));
        membershipCommitment.CopyTo(token.AsSpan(104, 32));
        pageAcknowledgementDigest.CopyTo(token.AsSpan(136, 32));
        _crypto.SignLocal(token.AsSpan(0, ContinuationSigningLength))
            .CopyTo(token, ContinuationSigningLength);
        return token;
    }

    private bool TryReadContinuationToken(
        ReadOnlySpan<byte> token,
        ulong epoch,
        ulong cursor,
        ReadOnlySpan<byte> mailboxId,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        byte requiredPurpose,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        out ContinuationAuthority authority)
    {
        authority = default;
        if (token.Length != ContinuationTokenLength
            || !token[..4].SequenceEqual(ContinuationMagic)
            || token[4] != 1
            || token[5] != CanonicalContinuationPurposes
            || requiredPurpose is not (
                RetrieveContinuationPurpose or AckPagePurpose)
            || (token[5] & requiredPurpose) != requiredPurpose
            || BinaryPrimitives.ReadUInt16BigEndian(token.Slice(6, 2))
                is 0 or > MailboxClientLimits.MaximumPageItems
            || BinaryPrimitives.ReadUInt64BigEndian(token.Slice(8, 8)) != epoch
            || BinaryPrimitives.ReadUInt64BigEndian(token.Slice(16, 8)) != cursor
            || BinaryPrimitives.ReadUInt64BigEndian(token.Slice(24, 8)) <= NowUnixSeconds()
            || BinaryPrimitives.ReadUInt64BigEndian(token.Slice(32, 8)) < cursor
            || !FixedEquals(token.Slice(40, 32), mailboxId)
            || !FixedEquals(token.Slice(72, 32), placementCommitment)
            || !FixedEquals(token.Slice(104, 32), membershipCommitment))
        {
            return false;
        }

        var signatureValid = false;
        foreach (var replicaId in expectedReplicaIds)
        {
            if (_crypto.VerifyReplica(
                    replicaId.Span,
                    token[..ContinuationSigningLength],
                    token[ContinuationSigningLength..]))
            {
                signatureValid = true;
                break;
            }
        }

        if (!signatureValid)
        {
            return false;
        }

        authority = new(
            BinaryPrimitives.ReadUInt64BigEndian(token.Slice(32, 8)),
            BinaryPrimitives.ReadUInt16BigEndian(token.Slice(6, 2)),
            token.Slice(136, 32).ToArray());
        return true;
    }

    private static byte[] AcknowledgementDigest(
        IReadOnlyList<MailboxRetrievedEnvelope> items)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> cursor = stackalloc byte[8];
        foreach (var item in items)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, item.Cursor);
            hash.AppendData(cursor);
            hash.AppendData(item.Envelope.DeduplicationDigest.Span);
        }

        return hash.GetHashAndReset();
    }

    private static byte[] AcknowledgementDigest(
        IReadOnlyList<MailboxAcknowledgement> items)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> cursor = stackalloc byte[8];
        foreach (var item in items)
        {
            BinaryPrimitives.WriteUInt64BigEndian(cursor, item.Cursor);
            hash.AppendData(cursor);
            hash.AppendData(item.EnvelopeDigest.Span);
        }

        return hash.GetHashAndReset();
    }

    private readonly record struct ContinuationAuthority(
        ulong SnapshotHighWater,
        ushort MaximumItems,
        ReadOnlyMemory<byte> PageAcknowledgementDigest);

    private static bool BindingMatches(
        MailboxCapabilityBinding? binding,
        MailboxClientOperation operation,
        ulong epoch,
        ReadOnlySpan<byte> operationId,
        ReadOnlySpan<byte> mailboxId,
        ReadOnlySpan<byte> placementCommitment,
        ReadOnlySpan<byte> membershipCommitment,
        ReadOnlySpan<byte> canonicalRequestDigest,
        MailboxCapabilityPresentation capability) =>
        binding is not null
        && binding.AllowedOperation == operation
        && binding.Epoch == epoch
        && FixedEquals(binding.OuterOperationId.Span, operationId)
        && FixedEquals(binding.BlindedMailboxId.Span, mailboxId)
        && FixedEquals(binding.PlacementCommitment.Span, placementCommitment)
        && FixedEquals(binding.MembershipCommitment.Span, membershipCommitment)
        && FixedEquals(binding.CanonicalRequestDigest.Span, canonicalRequestDigest)
        && FixedEquals(
            binding.CanonicalCapabilityDigest.Span,
            SHA256.HashData(MailboxCapabilityCodec.Encode(capability)))
        && binding.ReplayCounter == capability.ReplayCounter
        && FixedEquals(binding.IdempotencyKey.Span, capability.IdempotencyKey.Span)
        && binding.ReplayDisposition is (
            MailboxCapabilityReplayDisposition.New
            or MailboxCapabilityReplayDisposition.IdempotentReplay);

    private async Task TryCleanupTombstonesAfterAckAsync(int maximumItems)
    {
        try
        {
            await CleanupTombstonesAsync(
                maximumItems,
                CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException)
        {
            // ACK durability and logical deletion do not depend on physical reclamation.
            // The pending BlobCleaned=false journal entry is retried by InitializeAsync.
        }
    }

    private Task CleanupTombstonesAsync(CancellationToken cancellationToken) =>
        CleanupTombstonesAsync(
            _options.MaxTombstoneCleanupPerInitialization,
            cancellationToken);

    private async Task CleanupTombstonesAsync(
        int maximumItems,
        CancellationToken cancellationToken)
    {
        var remaining = maximumItems;
        while (remaining > 0)
        {
            var batch = await _ledger.ReadTombstoneCleanupBatchAsync(
                Math.Min(remaining, 100),
                cancellationToken).ConfigureAwait(false);
            if (batch.Count == 0)
            {
                return;
            }

            foreach (var item in batch)
            {
                await _store.DeleteExactAsync(
                    Convert.ToHexString(item.MailboxId.Span).ToLowerInvariant(),
                    Convert.ToHexString(item.BlobDigest.Span).ToLowerInvariant(),
                    cancellationToken).ConfigureAwait(false);
            }

            await _ledger.MarkTombstoneCleanupCompleteAsync(
                batch,
                cancellationToken).ConfigureAwait(false);
            remaining -= batch.Count;
            if (batch.Count < 100)
            {
                return;
            }
        }
    }

    private bool TryRetainDeliveryOperation()
    {
        lock (_singleFlightsGate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_activeDeliveryOperations >= _maxSingleFlights)
            {
                return false;
            }

            _activeDeliveryOperations++;
            return true;
        }
    }

    private void ReleaseDeliveryOperation()
    {
        lock (_singleFlightsGate)
        {
            _activeDeliveryOperations--;
        }
    }
}
