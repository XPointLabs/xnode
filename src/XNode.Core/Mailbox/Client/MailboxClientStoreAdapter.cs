using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed class MailboxClientStoreAdapter
{
    private readonly MailboxClientAdapterOptions _options;
    private readonly ReplicatedMailboxStore _store;
    private readonly MailboxClientOperationLedger _ledger;
    private readonly IMailboxClientCapabilityVerifier _verifier;
    private readonly IMailboxClientReplicaFanout _fanout;
    private readonly MailboxClientReceiptCrypto _crypto;
    private readonly IClock _clock;

    public MailboxClientStoreAdapter(
        MailboxClientAdapterOptions options,
        ReplicatedMailboxStore store,
        MailboxClientOperationLedger ledger,
        IMailboxClientCapabilityVerifier verifier,
        IMailboxClientReplicaFanout fanout,
        MailboxClientReceiptCrypto crypto,
        IClock? clock = null)
    {
        options.Validate();
        _options = options;
        _store = store;
        _ledger = ledger;
        _verifier = verifier;
        _fanout = fanout;
        _crypto = crypto;
        _clock = clock ?? new SystemClock();
    }

    public MailboxClientAdapterStatus Status
    {
        get
        {
            var ready = _options.Enabled && _verifier.IsConfigured && _fanout.IsConfigured;
            var reason = !_options.Enabled
                ? "disabled"
                : !_verifier.IsConfigured
                    ? "capability-verifier-missing"
                    : !_fanout.IsConfigured
                        ? "replica-fanout-missing"
                        : "ready";
            return new(
                _options.Enabled,
                _verifier.IsConfigured,
                _fanout.IsConfigured,
                ready,
                reason);
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_options.Enabled)
        {
            await _ledger.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<MailboxClientStoreResult> StoreAsync(
        ReadOnlyMemory<byte> canonicalStoreRequest,
        CancellationToken cancellationToken = default)
    {
        var status = Status;
        if (!status.Enabled)
        {
            return MailboxClientStoreResult.Failure(MailboxClientStoreStatus.Disabled, status.Reason);
        }

        if (!status.Ready)
        {
            return MailboxClientStoreResult.Failure(MailboxClientStoreStatus.NotReady, status.Reason);
        }

        MailboxStoreRequest request;
        try
        {
            request = MailboxClientCodec.DecodeStore(
                canonicalStoreRequest.Span,
                CreateDecodePolicy(),
                new DeferredReplayGuard());
        }
        catch (Exception exception) when (
            exception is MailboxClientException or MailboxCapabilityException)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Malformed,
                "non-canonical-mst1");
        }

        var placementCommitment = SHA256.HashData(request.Envelope.PlacementId.Bytes.Span);
        var verified = await _verifier.VerifyAsync(
            canonicalStoreRequest,
            MailboxClientOperation.Store,
            cancellationToken).ConfigureAwait(false);
        if (verified is null
            || verified.AllowedOperation != MailboxClientOperation.Store
            || verified.Epoch != request.Epoch
            || !FixedEquals(verified.BlindedMailboxId.Span, request.Envelope.MailboxId.Bytes.Span)
            || !FixedEquals(verified.PlacementCommitment.Span, placementCommitment))
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Unauthorized,
                "capability-binding-rejected");
        }

        var canonicalEnvelope = MailboxClientCodec.EncodeEncryptedEnvelope(request.Envelope);
        if (canonicalEnvelope.Length > MailboxClientLimits.MaximumEncryptedEnvelopeLength)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Rejected,
                "envelope-too-large");
        }

        var requestDigest = SHA256.HashData(canonicalStoreRequest.Span);
        MailboxClientStoreReservation reservation;
        try
        {
            reservation = await _ledger.ReserveStoreAsync(
                request.OperationId,
                requestDigest,
                request.Envelope.MailboxId.Bytes,
                request.Envelope.DeduplicationDigest,
                cancellationToken).ConfigureAwait(false);
        }
        catch (MailboxClientOperationConflictException)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Conflict,
                "operation-id-conflict");
        }
        catch (MailboxClientLedgerCapacityException)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Rejected,
                "operation-ledger-capacity");
        }

        if (!reservation.CachedReceipt.IsEmpty)
        {
            return new(
                MailboxClientStoreStatus.Durable,
                reservation.CachedReceipt,
                "");
        }

        long expiresAtUnixMs;
        try
        {
            expiresAtUnixMs = checked((long)request.Envelope.ExpiresAtUnixSeconds * 1000L);
        }
        catch (OverflowException)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Rejected,
                "ttl-conversion-overflow");
        }

        var mailboxId = Convert.ToHexString(request.Envelope.MailboxId.Bytes.Span).ToLowerInvariant();
        var blobId = Convert.ToHexString(SHA256.HashData(canonicalEnvelope)).ToLowerInvariant();
        var blob = new EncryptedMailboxBlob(
            mailboxId,
            blobId,
            expiresAtUnixMs,
            Convert.ToBase64String(canonicalEnvelope));
        var localStore = await _store.PutAsync(blob, cancellationToken).ConfigureAwait(false);
        if (localStore.Disposition == MailboxPutDisposition.Rejected)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.Rejected,
                localStore.Error);
        }

        var now = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
        var context = new MailboxReplicaStoreContext(
            reservation.Cursor,
            request.Epoch,
            request.OperationId,
            request.Envelope.MailboxId.Bytes,
            placementCommitment,
            _options.GetMembershipCommitment(),
            request.Envelope.DeduplicationDigest,
            request.Envelope.ExpiresAtUnixSeconds,
            canonicalEnvelope);
        var localReceipt = CreateLocalReceipt(
            context,
            now,
            localStore.Disposition == MailboxPutDisposition.Stored
                ? MailboxReplicaDisposition.Stored
                : MailboxReplicaDisposition.Duplicate);
        IReadOnlyList<ReadOnlyMemory<byte>> remoteReceipts;
        try
        {
            remoteReceipts = await _fanout.StoreAsync(context, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or OperationCanceledException)
        {
            if (exception is OperationCanceledException && cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.QuorumUnavailable,
                "replica-fanout-unavailable");
        }

        var expectation = new MailboxDurableQuorumExpectationV2
        {
            OperationId = context.OperationId,
            Epoch = context.Epoch,
            Cursor = context.Cursor,
            Disposition = localReceipt.Disposition,
            BlindedMailboxId = context.BlindedMailboxId,
            PlacementCommitment = context.PlacementCommitment,
            MembershipCommitment = context.MembershipCommitment,
            EnvelopeDigest = context.EnvelopeDigest,
            ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds
        };
        var valid = new List<MailboxReplicaReceiptV2> { localReceipt };
        foreach (var encoded in remoteReceipts)
        {
            try
            {
                var receipt = MailboxReceiptV2Codec.DecodeReplica(encoded.Span);
                if (receipt.ReplicaId.Span.SequenceEqual(localReceipt.ReplicaId.Span)
                    || valid.Any(existing => existing.ReplicaId.Span.SequenceEqual(receipt.ReplicaId.Span)))
                {
                    continue;
                }

                var candidateQuorum = SignQuorum(localReceipt, receipt, reservation.Cursor);
                _ = MailboxReceiptV2Codec.VerifyDurableQuorum(
                    MailboxReceiptV2Codec.EncodeDurableQuorum(candidateQuorum),
                    _crypto,
                    expectation);
                valid.Add(receipt);
            }
            catch (MailboxReceiptException)
            {
                // Malformed, unauthenticated or context-mismatched replica receipts never count.
            }
        }

        if (valid.Count < 2)
        {
            return MailboxClientStoreResult.Failure(
                MailboxClientStoreStatus.QuorumUnavailable,
                "durable-quorum-not-reached");
        }

        var quorum = SignQuorum(localReceipt, valid[1], reservation.Cursor);
        var encodedQuorum = MailboxReceiptV2Codec.EncodeDurableQuorum(quorum);
        _ = MailboxReceiptV2Codec.VerifyDurableQuorum(encodedQuorum, _crypto, expectation);
        await _ledger.CompleteStoreAsync(
            request.OperationId,
            encodedQuorum,
            cancellationToken).ConfigureAwait(false);
        return new(MailboxClientStoreStatus.Durable, encodedQuorum, "");
    }

    private MailboxReplicaReceiptV2 CreateLocalReceipt(
        MailboxReplicaStoreContext context,
        ulong now,
        MailboxReplicaDisposition disposition)
    {
        var unsigned = new MailboxReplicaReceiptV2
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = disposition,
            ReplicaId = _crypto.LocalRouterId,
            OperationId = context.OperationId,
            Epoch = context.Epoch,
            Cursor = context.Cursor,
            AcceptedAtUnixSeconds = now,
            DurableAtUnixSeconds = now,
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

    private MailboxDurableQuorumReceiptV2 SignQuorum(
        MailboxReplicaReceiptV2 first,
        MailboxReplicaReceiptV2 second,
        ulong sequence)
    {
        var unsigned = new MailboxDurableQuorumReceiptV2
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
                MailboxReceiptV2Codec.GetQuorumSigningBytes(unsigned, _crypto))
        };
    }

    private MailboxClientDecodePolicy CreateDecodePolicy()
    {
        var now = checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());
        return new()
        {
            NowUnixSeconds = now,
            EpochWindow = _options.EpochWindow(),
            CapabilityPolicy = new MailboxCapabilityDecodePolicy
            {
                CurrentBucket = checked((uint)now),
                MinimumGeneration = _options.CurrentEpoch,
                AllowLegacyMirrorOverlap = false,
                AllowRevoked = false,
                AllowRecovery = false
            },
            AllowLegacyMirrorOverlap = false
        };
    }

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed class DeferredReplayGuard : IMailboxCapabilityReplayGuard
    {
        public MailboxCapabilityReplayEvaluation Evaluate(MailboxCapabilityReplayScope scope) =>
            new()
            {
                Decision = MailboxCapabilityReplayDecision.AcceptedNew,
                CachedOutcome = ReadOnlyMemory<byte>.Empty
            };
    }
}
