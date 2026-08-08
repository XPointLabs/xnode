using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientStoreAdapter : IDisposable
{
    private readonly MailboxClientAdapterOptions _options;
    private readonly ReplicatedMailboxOptions _storeOptions;
    private readonly ReplicatedMailboxStore _store;
    private readonly MailboxClientOperationLedger _ledger;
    private readonly IMailboxClientReplicaAuthorizer _replicaAuthorizer;
    private readonly IMailboxClientReplicaFanout _fanout;
    private readonly IMailboxClientTombstoneFanout _tombstoneFanout;
    private readonly MailboxClientReceiptCrypto _crypto;
    private readonly IClock _clock;
    internal IMailboxClientRequestObserver RequestObserver { get; set; } =
        new NullMailboxClientRequestObserver();
    private readonly Dictionary<string, SingleFlightEntry> _singleFlights =
        new(StringComparer.Ordinal);
    private readonly object _singleFlightsGate = new();
    private readonly int _maxSingleFlights;
    private readonly IDisposable _adapterClaim;
    private int _disposed;
    private int _activeInitializations;

    public MailboxClientStoreAdapter(
        MailboxClientAdapterOptions options,
        ReplicatedMailboxOptions storeOptions,
        ReplicatedMailboxStore store,
        MailboxClientOperationLedger ledger,
        IMailboxClientReplicaAuthorizer replicaAuthorizer,
        IMailboxClientReplicaFanout fanout,
        MailboxClientReceiptCrypto crypto,
        IClock? clock = null,
        IMailboxClientTombstoneFanout? tombstoneFanout = null)
    {
        options.Validate();
        storeOptions.Validate();
        _options = options;
        _storeOptions = storeOptions;
        _store = store;
        _ledger = ledger;
        _adapterClaim = ledger.ClaimAdapter();
        _replicaAuthorizer = replicaAuthorizer;
        _fanout = fanout;
        _tombstoneFanout = tombstoneFanout ?? new DisabledMailboxClientTombstoneFanout();
        _crypto = crypto;
        _clock = clock ?? new SystemClock();
        _maxSingleFlights = options.MaxConcurrentSingleFlights;
    }

    public MailboxClientAdapterStatus Status
    {
        get
        {
            var enabled = _options.Enabled;
            var authorizerConfigured = _replicaAuthorizer.IsConfigured;
            var storeFanoutConfigured = _fanout.IsConfigured;
            var tombstoneFanoutConfigured = _tombstoneFanout.IsConfigured;
            var commonReason = !enabled
                ? "disabled"
                : !authorizerConfigured
                            ? "replica-authorizer-missing"
                            : "ready";
            var commonReady = commonReason == "ready";
            var storeReason = !commonReady
                ? commonReason
                : !storeFanoutConfigured
                    ? "replica-fanout-missing"
                    : "ready";
            var acknowledgeReason = !commonReady
                ? commonReason
                : !tombstoneFanoutConfigured
                    ? "tombstone-fanout-missing"
                    : "ready";
            var storeReady = storeReason == "ready";
            var retrieveReady = commonReady;
            var acknowledgeReady = acknowledgeReason == "ready";
            var ready = storeReady && retrieveReady && acknowledgeReady;
            var reason = !storeReady
                ? storeReason
                : !retrieveReady
                    ? commonReason
                    : !acknowledgeReady
                        ? acknowledgeReason
                        : "ready";
            return new(
                enabled,
                true,
                authorizerConfigured,
                storeFanoutConfigured,
                ready,
                reason)
            {
                DurableAtomicReplay = true,
                DurableCanonicalOutcomes = true,
                TombstoneFanoutConfigured = tombstoneFanoutConfigured,
                StoreReady = storeReady,
                RetrieveReady = retrieveReady,
                AcknowledgeReady = acknowledgeReady,
                StoreReason = storeReason,
                RetrieveReason = commonReason,
                AcknowledgeReason = acknowledgeReason
            };
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        RetainInitialization();
        try
        {
            if (_options.Enabled)
            {
                await _ledger.InitializeAsync(cancellationToken).ConfigureAwait(false);
                await CleanupTombstonesAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            ReleaseInitialization();
        }
    }

    public async Task<MailboxClientStoreResult> StoreVerifiedAsync(
        MailboxAuthenticatedRuntimeReservation authenticated,
        MailboxEncryptedEnvelope request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticated);
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var status = Status;
        if (!status.Enabled)
        {
            return Failure(MailboxClientStoreStatus.Disabled, status.Reason);
        }

        if (!status.StoreReady)
        {
            return Failure(MailboxClientStoreStatus.NotReady, status.StoreReason);
        }

        if (authenticated.Verified.Binding.Operation
                != MailboxAuthenticatedOperation.Store
            || !MailboxClientCodec.EncodeEncryptedEnvelope(request)
                .AsSpan()
                .SequenceEqual(
                    authenticated.Verified.Binding.CanonicalRequest.Span))
        {
            return Failure(MailboxClientStoreStatus.Malformed, "non-canonical-meo1");
        }

        var placementCommitment = MailboxPlacementCommitment.Compute(
            request.PlacementId);
        var membershipCommitment = _options.GetMembershipCommitment(request.Epoch);
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds;
        try
        {
            expectedReplicaIds = NormalizeReplicaAuthority(
                await _replicaAuthorizer.SelectReplicaIdsAsync(
                        request.Epoch,
                        membershipCommitment.ToArray(),
                        placementCommitment.ToArray(),
                        request.PlacementId.Bytes.ToArray(),
                        ProductionMailboxReplicaSelection.ComputeSelectionInputCommitment(
                            request.PlacementId),
                        cancellationToken).ConfigureAwait(false));
        }
        catch (ArgumentException)
        {
            return Failure(MailboxClientStoreStatus.Unauthorized, "replica-authority-invalid");
        }

        if (expectedReplicaIds.Count < 2
            || !expectedReplicaIds.Take(2).Any(
                id => id.Span.SequenceEqual(_crypto.LocalRouterId)))
        {
            return Failure(MailboxClientStoreStatus.Unauthorized, "local-replica-not-authorized");
        }

        var canonicalEnvelope = authenticated.Verified.Binding.CanonicalRequest.ToArray();
        if (!TryCreateAndPreflightBlob(
                request,
                canonicalEnvelope,
                out var blob,
                out var preflightError))
        {
            return Failure(MailboxClientStoreStatus.Rejected, preflightError);
        }

        var operationKey = MailboxClientOperationLedger.BuildOperationKey(
            request.Epoch,
            request.MailboxId.Bytes.Span,
            request.OperationId.Span);
        var singleFlight = TryRetainSingleFlight(operationKey);
        if (singleFlight is null)
        {
            return Failure(
                MailboxClientStoreStatus.Rejected,
                "single-flight-capacity");
        }

        var entered = false;
        try
        {
            await singleFlight.Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            return await StoreSingleFlightAsync(
                authenticated,
                authenticated.Verified.Binding.RequestDigest.ToArray(),
                request,
                canonicalEnvelope,
                blob!,
                placementCommitment,
                membershipCommitment,
                expectedReplicaIds,
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

    private async Task<MailboxClientStoreResult> StoreSingleFlightAsync(
        MailboxAuthenticatedRuntimeReservation authenticated,
        byte[] requestDigest,
        MailboxEncryptedEnvelope request,
        byte[] canonicalEnvelope,
        EncryptedMailboxBlob blob,
        byte[] placementCommitment,
        byte[] membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        CancellationToken cancellationToken)
    {
        MailboxClientStoreReservation reservation;
        try
        {
            authenticated.MarkSideEffectsStarted();
            Observe(
                MailboxClientOperation.Store,
                MailboxClientObservedAccess.LedgerMutation);
            reservation = await _ledger.ReserveStoreAsync(
                request.Epoch,
                request.OperationId,
                requestDigest,
                request.MailboxId.Bytes,
                request.DeduplicationDigest,
                Convert.FromHexString(blob.BlobId),
                placementCommitment,
                membershipCommitment,
                expectedReplicaIds,
                request.ExpiresAtUnixSeconds,
                cancellationToken).ConfigureAwait(false);
        }
        catch (MailboxClientOperationConflictException)
        {
            return Failure(MailboxClientStoreStatus.Conflict, "operation-id-conflict");
        }
        catch (MailboxClientLedgerCapacityException)
        {
            return Failure(MailboxClientStoreStatus.Rejected, "operation-ledger-capacity");
        }

        if (!ReplicaSetsEqual(reservation.ExpectedReplicaIds, expectedReplicaIds))
        {
            return Failure(MailboxClientStoreStatus.Unauthorized, "replica-authority-rotated");
        }

        var context = CreateContext(
            reservation,
            request,
            canonicalEnvelope,
            placementCommitment,
            membershipCommitment,
            expectedReplicaIds);
        if (reservation.State == MailboxClientLedgerState.Terminal)
        {
            return Failure(MailboxClientStoreStatus.Rejected, reservation.Error);
        }

        if (reservation.State == MailboxClientLedgerState.Durable)
        {
            if (!VerifyCached(reservation, context, expectedReplicaIds))
            {
                return Failure(MailboxClientStoreStatus.Rejected, "cached-quorum-invalid");
            }

            return new(
                MailboxClientStoreStatus.Durable,
                reservation.CachedReceipt.ToArray(),
                "");
        }

        if (reservation.State == MailboxClientLedgerState.Completing)
        {
            return await ResumeCompletionAsync(
                reservation,
                context,
                expectedReplicaIds,
                cancellationToken).ConfigureAwait(false);
        }

        if (reservation.Disposition is null)
        {
            Observe(
                MailboxClientOperation.Store,
                MailboxClientObservedAccess.BlobMutation);
            var localStore = await _store.PutAsync(blob, cancellationToken).ConfigureAwait(false);
            if (localStore.Disposition == MailboxPutDisposition.Rejected)
            {
                await _ledger.MarkTerminalAsync(
                    reservation.OperationKey,
                    localStore.Error,
                    cancellationToken).ConfigureAwait(false);
                return Failure(MailboxClientStoreStatus.Rejected, localStore.Error);
            }

            var disposition = localStore.Disposition == MailboxPutDisposition.Stored
                ? MailboxReplicaDisposition.Stored
                : MailboxReplicaDisposition.Duplicate;
            reservation = await _ledger.SetDispositionAsync(
                reservation.OperationKey,
                disposition,
                NowUnixSeconds(),
                cancellationToken).ConfigureAwait(false);
            context = CreateContext(
                reservation,
                request,
                canonicalEnvelope,
                placementCommitment,
                membershipCommitment,
                expectedReplicaIds);
        }

        var localReceipt = CreateLocalReceipt(context);
        IReadOnlyList<ReadOnlyMemory<byte>> remoteReceipts;
        try
        {
            Observe(
                MailboxClientOperation.Store,
                MailboxClientObservedAccess.PeerMutation);
            remoteReceipts = await _fanout.StoreAsync(
                CopyContext(context),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or OperationCanceledException)
        {
            if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            await _ledger.MarkRetryableAsync(
                reservation.OperationKey,
                "replica-fanout-unavailable",
                cancellationToken).ConfigureAwait(false);
            return Failure(
                MailboxClientStoreStatus.QuorumUnavailable,
                "replica-fanout-unavailable");
        }

        if (remoteReceipts is null || remoteReceipts.Count > 9)
        {
            await _ledger.MarkRetryableAsync(
                reservation.OperationKey,
                "replica-fanout-invalid",
                cancellationToken).ConfigureAwait(false);
            return Failure(
                MailboxClientStoreStatus.QuorumUnavailable,
                "replica-fanout-invalid");
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
                    && VerifyReplica(receipt, context))
                {
                    receiptsById.Add(id, receipt);
                }
            }
            catch (MailboxReceiptException)
            {
                // An unauthenticated, malformed or context-mismatched receipt never counts.
            }
        }

        var required = expectedReplicaIds.Take(2)
            .Select(id => Convert.ToHexString(id.Span).ToLowerInvariant())
            .ToArray();
        if (!required.All(receiptsById.ContainsKey))
        {
            await _ledger.MarkRetryableAsync(
                reservation.OperationKey,
                "durable-quorum-not-reached",
                cancellationToken).ConfigureAwait(false);
            return Failure(
                MailboxClientStoreStatus.QuorumUnavailable,
                "durable-quorum-not-reached");
        }

        var firstBytes = MailboxReceiptV2Codec.EncodeReplica(receiptsById[required[0]]);
        var secondBytes = MailboxReceiptV2Codec.EncodeReplica(receiptsById[required[1]]);
        Observe(
            MailboxClientOperation.Store,
            MailboxClientObservedAccess.LedgerMutation);
        reservation = await _ledger.BeginCompletionAsync(
            reservation.OperationKey,
            firstBytes,
            secondBytes,
            cancellationToken).ConfigureAwait(false);
        return await ResumeCompletionAsync(
            reservation,
            context,
            expectedReplicaIds,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<MailboxClientStoreResult> ResumeCompletionAsync(
        MailboxClientStoreReservation reservation,
        MailboxReplicaStoreContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        CancellationToken cancellationToken)
    {
        if (reservation.Completion is null)
        {
            return Failure(MailboxClientStoreStatus.Rejected, "completion-reservation-invalid");
        }

        MailboxReplicaReceiptV2 first;
        MailboxReplicaReceiptV2 second;
        try
        {
            first = MailboxReceiptV2Codec.DecodeReplica(
                reservation.Completion.FirstReplicaReceipt.Span);
            second = MailboxReceiptV2Codec.DecodeReplica(
                reservation.Completion.SecondReplicaReceipt.Span);
        }
        catch (MailboxReceiptException)
        {
            return Failure(MailboxClientStoreStatus.Rejected, "completion-receipt-invalid");
        }

        var expected = expectedReplicaIds.Take(2)
            .Select(id => Convert.ToHexString(id.Span).ToLowerInvariant())
            .Order(StringComparer.Ordinal)
            .ToArray();
        var actual = new[] { first, second }
            .Select(receipt => Convert.ToHexString(receipt.ReplicaId.Span).ToLowerInvariant())
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!expected.SequenceEqual(actual, StringComparer.Ordinal)
            || !VerifyReplica(first, context)
            || !VerifyReplica(second, context))
        {
            return Failure(MailboxClientStoreStatus.Rejected, "completion-authority-stale");
        }

        var quorum = SignQuorum(
            first,
            second,
            reservation.Completion.CoordinatorSequence);
        var encoded = MailboxReceiptV3Codec.EncodeDurableQuorum(quorum);
        if (!VerifyQuorum(
                encoded,
                context,
                expectedReplicaIds,
                reservation.Completion.CoordinatorSequence))
        {
            return Failure(MailboxClientStoreStatus.Rejected, "completion-quorum-invalid");
        }

        Observe(
            MailboxClientOperation.Store,
            MailboxClientObservedAccess.LedgerMutation);
        await _ledger.CompleteStoreAsync(
            reservation.OperationKey,
            reservation.Completion.CoordinatorSequence,
            encoded,
            cancellationToken).ConfigureAwait(false);
        return new(MailboxClientStoreStatus.Durable, encoded, "");
    }

    private bool VerifyCached(
        MailboxClientStoreReservation reservation,
        MailboxReplicaStoreContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds) =>
        reservation.Completion is not null
        && !reservation.CachedReceipt.IsEmpty
        && VerifyQuorum(
            reservation.CachedReceipt.Span,
            context,
            expectedReplicaIds,
            reservation.Completion.CoordinatorSequence);

    private bool VerifyQuorum(
        ReadOnlySpan<byte> encoded,
        MailboxReplicaStoreContext context,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds,
        ulong coordinatorSequence)
    {
        try
        {
            var coordinator = MailboxReceiptV3Codec.DecodeDurableQuorum(encoded);
            if (!VerifyReplica(coordinator.FirstReplica, context)
                || !VerifyReplica(coordinator.SecondReplica, context)
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
                && coordinator.CoordinatorId.Span.SequenceEqual(_crypto.LocalRouterId)
                && actualIds.SequenceEqual(expectedIds, StringComparer.Ordinal);
        }
        catch (MailboxReceiptException)
        {
            return false;
        }
    }

    private bool VerifyReplica(
        MailboxReplicaReceiptV2 receipt,
        MailboxReplicaStoreContext context)
    {
        var valid = receipt.Status == MailboxReceiptStatus.Durable
            && receipt.Disposition == context.Disposition
            && receipt.OperationId.Span.SequenceEqual(context.OperationId.Span)
            && receipt.Epoch == context.Epoch
            && receipt.Cursor == context.Cursor
            && receipt.AcceptedAtUnixSeconds >= context.AcceptedAtUnixSeconds
            && receipt.DurableAtUnixSeconds >= receipt.AcceptedAtUnixSeconds
            && receipt.DurableAtUnixSeconds < context.ExpiresAtUnixSeconds
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

    private MailboxReplicaReceiptV2 CreateLocalReceipt(MailboxReplicaStoreContext context)
    {
        var unsigned = new MailboxReplicaReceiptV2
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = context.Disposition,
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

    private MailboxDurableQuorumReceiptV3 SignQuorum(
        MailboxReplicaReceiptV2 first,
        MailboxReplicaReceiptV2 second,
        ulong sequence)
    {
        var unsigned = new MailboxDurableQuorumReceiptV3
        {
            CoordinatorId = _crypto.LocalRouterId,
            CoordinatorSequence = sequence,
            FirstReplica = first,
            SecondReplica = second,
            Signature = new byte[64]
        };
        return unsigned with
        {
            Signature = _crypto.SignLocal(
                MailboxReceiptV3Codec.GetQuorumSigningBytes(unsigned))
        };
    }

    private MailboxReplicaStoreContext CreateContext(
        MailboxClientStoreReservation reservation,
        MailboxEncryptedEnvelope request,
        byte[] canonicalEnvelope,
        byte[] placementCommitment,
        byte[] membershipCommitment,
        IReadOnlyList<ReadOnlyMemory<byte>> expectedReplicaIds) =>
        new(
            reservation.Cursor,
            request.Epoch,
            request.OperationId.ToArray(),
            request.MailboxId.Bytes.ToArray(),
            placementCommitment.ToArray(),
            membershipCommitment.ToArray(),
            request.DeduplicationDigest.ToArray(),
            request.ExpiresAtUnixSeconds,
            canonicalEnvelope.ToArray(),
            reservation.Disposition ?? MailboxReplicaDisposition.Stored,
            reservation.AcceptedAtUnixSeconds,
            expectedReplicaIds.Select(static id => (ReadOnlyMemory<byte>)id.ToArray()).ToArray())
        {
            BlindedPlacementId = request.PlacementId.Bytes.ToArray()
        };

    private static MailboxReplicaStoreContext CopyContext(MailboxReplicaStoreContext context) =>
        context with
        {
            OperationId = context.OperationId.ToArray(),
            BlindedMailboxId = context.BlindedMailboxId.ToArray(),
            PlacementCommitment = context.PlacementCommitment.ToArray(),
            MembershipCommitment = context.MembershipCommitment.ToArray(),
            BlindedPlacementId = context.BlindedPlacementId.ToArray(),
            EnvelopeDigest = context.EnvelopeDigest.ToArray(),
            CanonicalEnvelope = context.CanonicalEnvelope.ToArray(),
            ExpectedReplicaIds = context.ExpectedReplicaIds
                .Select(static id => (ReadOnlyMemory<byte>)id.ToArray())
                .ToArray()
        };

    private bool TryCreateAndPreflightBlob(
        MailboxEncryptedEnvelope request,
        byte[] canonicalEnvelope,
        out EncryptedMailboxBlob? blob,
        out string error)
    {
        blob = null;
        error = "mailbox-envelope-preflight-rejected";
        long expiresAtUnixMs;
        try
        {
            expiresAtUnixMs = checked((long)request.ExpiresAtUnixSeconds * 1000L);
        }
        catch (OverflowException)
        {
            error = "ttl-conversion-overflow";
            return false;
        }

        blob = new(
            Convert.ToHexString(request.MailboxId.Bytes.Span).ToLowerInvariant(),
            Convert.ToHexString(SHA256.HashData(canonicalEnvelope)).ToLowerInvariant(),
            expiresAtUnixMs,
            Convert.ToBase64String(canonicalEnvelope));
        return EncryptedMailboxBlobValidator.TryValidate(
            blob,
            _clock.UtcNow,
            _storeOptions,
            out _,
            out error);
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> NormalizeReplicaAuthority(
        IReadOnlyList<ReadOnlyMemory<byte>> replicaIds)
    {
        ArgumentNullException.ThrowIfNull(replicaIds);
        if (replicaIds.Count is < 2 or > 9)
        {
            throw new ArgumentException("Replica authority must select 2..9 replicas.");
        }

        var result = new List<ReadOnlyMemory<byte>>(replicaIds.Count);
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var replicaId in replicaIds)
        {
            var owned = replicaId.ToArray();
            if (owned.Length != RouterId.ByteLength || owned.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException("Replica ids must be 32 nonzero bytes.");
            }

            var key = Convert.ToHexString(owned).ToLowerInvariant();
            if (!unique.Add(key))
            {
                throw new ArgumentException("Replica authority selected a duplicate.");
            }

            result.Add(owned);
        }

        return result;
    }

    private static bool ReplicaSetsEqual(
        IReadOnlyList<ReadOnlyMemory<byte>> left,
        IReadOnlyList<ReadOnlyMemory<byte>> right) =>
        left.Count == right.Count
        && left.Zip(right).All(pair =>
            pair.First.Span.SequenceEqual(pair.Second.Span));

    private static MailboxDurableQuorumExpectationV2 Expectation(
        MailboxReplicaStoreContext context) =>
        new()
        {
            OperationId = context.OperationId,
            Epoch = context.Epoch,
            Cursor = context.Cursor,
            Disposition = context.Disposition,
            BlindedMailboxId = context.BlindedMailboxId,
            PlacementCommitment = context.PlacementCommitment,
            MembershipCommitment = context.MembershipCommitment,
            EnvelopeDigest = context.EnvelopeDigest,
            ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds
        };

    private ulong NowUnixSeconds() => checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static MailboxClientStoreResult Failure(
        MailboxClientStoreStatus status,
        string error) =>
        MailboxClientStoreResult.Failure(status, error);

    private void Observe(
        MailboxClientOperation operation,
        MailboxClientObservedAccess access) =>
        RequestObserver.OnAccess(operation, access);

    private SingleFlightEntry? TryRetainSingleFlight(string operationKey)
    {
        lock (_singleFlightsGate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (_singleFlights.TryGetValue(operationKey, out var existing))
            {
                existing.Users++;
                return existing;
            }

            if (_singleFlights.Count >= _maxSingleFlights)
            {
                return null;
            }

            var created = new SingleFlightEntry { Users = 1 };
            _singleFlights.Add(operationKey, created);
            return created;
        }
    }

    private void ReleaseSingleFlight(string operationKey, SingleFlightEntry entry)
    {
        lock (_singleFlightsGate)
        {
            entry.Users--;
            if (entry.Users == 0)
            {
                if (!_singleFlights.Remove(operationKey, out var removed)
                    || !ReferenceEquals(removed, entry))
                {
                    throw new InvalidOperationException(
                        "Mailbox single-flight ownership is corrupt.");
                }

                entry.Gate.Dispose();
            }
        }
    }

    private void RetainInitialization()
    {
        lock (_singleFlightsGate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            _activeInitializations++;
        }
    }

    private void ReleaseInitialization()
    {
        lock (_singleFlightsGate)
        {
            _activeInitializations--;
        }
    }

    public void Dispose()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        lock (_singleFlightsGate)
        {
            if (_singleFlights.Count != 0
                || _activeInitializations != 0
                || _activeDeliveryOperations != 0)
            {
                throw new InvalidOperationException(
                    "Cannot release a mailbox adapter while operations are active.");
            }

            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _adapterClaim.Dispose();
            }
        }

        GC.SuppressFinalize(this);
    }

    private sealed class SingleFlightEntry
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);
        public int Users { get; set; }
    }

}
