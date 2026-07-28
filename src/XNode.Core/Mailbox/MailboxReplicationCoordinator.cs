using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox;

public sealed record MailboxReplicaPeer(RouterId RouterId, string Endpoint);

public interface IMailboxReplicaPeerClient
{
    Task<ReadOnlyMemory<byte>?> SendAsync(
        MailboxReplicaPeer peer,
        MailboxPeerReplicationOperation operation,
        ReadOnlyMemory<byte> canonicalPrq2,
        CancellationToken cancellationToken);
}

public enum MailboxPeerQuorumStatus
{
    Durable,
    Disabled,
    Unauthorized,
    Conflict,
    PartialFailure,
    Rejected
}

public sealed record MailboxPeerQuorumResult(
    MailboxPeerQuorumStatus Status,
    ReadOnlyMemory<byte> CanonicalMqr3,
    int DurableReplicaCount);

public sealed record MailboxReplicationMetricsSnapshot(
    long Attempts,
    long DurableQuorums,
    long PartialFailures,
    long InvalidReceipts,
    long Rejected);

/// <summary>
/// Sender-side PRQ2 coordinator. A successful result is exactly the local and recipient MRR2
/// verified into the native PRQ2-only MQR3 domain; one-replica progress is never success.
/// </summary>
public sealed class MailboxReplicationCoordinator
{
    private readonly byte[] _localRouterId;
    private readonly byte[] _privateKeySeed;
    private readonly ReplicatedMailboxOptions _options;
    private readonly MailboxPeerMutationStore _mutations;
    private readonly IMailboxReplicaPeerClient _peerClient;
    private readonly IMailboxReplicaMembershipProofVerifier _membershipVerifier;
    private readonly IMailboxPeerReplayJournal _journal;
    private readonly SodiumMailboxPeerReplicationCrypto _crypto = new();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _attempts;
    private long _durableQuorums;
    private long _partialFailures;
    private long _invalidReceipts;
    private long _rejected;

    public MailboxReplicationCoordinator(
        RouterId localRouterId,
        string privateKeySeedHex,
        ReplicatedMailboxOptions options,
        MailboxPeerMutationStore mutations,
        IMailboxReplicaPeerClient peerClient,
        IMailboxReplicaMembershipProofVerifier membershipVerifier,
        IMailboxPeerReplayJournal journal)
    {
        options.Validate();
        _localRouterId = localRouterId.ToBytes();
        _privateKeySeed = Convert.FromHexString(privateKeySeedHex);
        if (_privateKeySeed.Length != 32
            || !CryptographicOperations.FixedTimeEquals(
                _crypto.GetPublicKey(_privateKeySeed),
                _localRouterId))
        {
            throw new InvalidOperationException(
                "The mailbox coordinator identity does not match its Ed25519 seed.");
        }

        _options = options;
        _mutations = mutations;
        _peerClient = peerClient;
        _membershipVerifier = membershipVerifier;
        _journal = journal;
    }

    public MailboxReplicationMetricsSnapshot Metrics => new(
        Interlocked.Read(ref _attempts),
        Interlocked.Read(ref _durableQuorums),
        Interlocked.Read(ref _partialFailures),
        Interlocked.Read(ref _invalidReceipts),
        Interlocked.Read(ref _rejected));

    public async Task<MailboxPeerQuorumResult> ReplicateAsync(
        MailboxReplicaPeer recipient,
        ReadOnlyMemory<byte> canonicalPrq2,
        MailboxPeerWireVerificationPolicyV2 exactPolicy,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _attempts);
        if (!_options.Enabled)
        {
            return Failure(MailboxPeerQuorumStatus.Disabled);
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            VerifiedMailboxPeerWireRequestV2 verified;
            try
            {
                var decoded = MailboxPeerWireV2Codec.Decode(canonicalPrq2.Span);
                if (!CryptographicOperations.FixedTimeEquals(
                        decoded.SenderRouterId.Span,
                        _localRouterId)
                    || !decoded.RecipientRouterId.Span.SequenceEqual(
                        recipient.RouterId.ToBytes()))
                {
                    Interlocked.Increment(ref _rejected);
                    return Failure(MailboxPeerQuorumStatus.Unauthorized);
                }

                verified = MailboxPeerWireV2Codec.VerifyAndReserve(
                    canonicalPrq2.Span,
                    exactPolicy,
                    _crypto,
                    _membershipVerifier,
                    _journal);
            }
            catch (MailboxPeerReplicationException exception)
            {
                Interlocked.Increment(ref _rejected);
                return Failure(exception.Error == MailboxPeerReplicationError.ReplayConflict
                    ? MailboxPeerQuorumStatus.Conflict
                    : MailboxPeerQuorumStatus.Unauthorized);
            }
            catch (MailboxPeerReplayCapacityException)
            {
                Interlocked.Increment(ref _rejected);
                return Failure(MailboxPeerQuorumStatus.Rejected);
            }

            MailboxPeerMutationResult mutation;
            try
            {
                mutation = await _mutations.ApplyAsync(
                    verified,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (
                exception is IOException or InvalidDataException
                    or UnauthorizedAccessException or MailboxPeerMutationCapacityException)
            {
                Interlocked.Increment(ref _partialFailures);
                return Failure(MailboxPeerQuorumStatus.PartialFailure);
            }

            if (!string.IsNullOrEmpty(mutation.Error))
            {
                Interlocked.Increment(ref _rejected);
                return Failure(MailboxPeerQuorumStatus.Rejected);
            }

            var acceptedAt = verified.ReplayClaim.ReservedAtUnixSeconds;
            var localUnsigned =
                MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(
                    verified,
                    MailboxPeerWireResponseReplicaV2.Sender,
                    mutation.Disposition,
                    acceptedAt,
                    acceptedAt);
            var local = _crypto.SignReplicaResponse(localUnsigned, _privateKeySeed);
            var localBytes = MailboxReceiptV2Codec.EncodeReplica(local);

            ReadOnlyMemory<byte>? remoteBytes = null;
            if (verified.ReplayDisposition == MailboxPeerReplayDisposition.IdempotentCompleted)
            {
                remoteBytes = verified.CachedResponse.ToArray();
            }
            else
            {
                try
                {
                    using var timeout =
                        CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    timeout.CancelAfter(_options.PeerTimeout);
                    remoteBytes = await _peerClient.SendAsync(
                        recipient,
                        verified.Request.Operation,
                        canonicalPrq2,
                        timeout.Token).ConfigureAwait(false);
                }
                catch (Exception exception) when (
                    exception is HttpRequestException or IOException
                        or OperationCanceledException
                        && !cancellationToken.IsCancellationRequested)
                {
                    remoteBytes = null;
                }
            }

            if (remoteBytes is null)
            {
                Interlocked.Increment(ref _partialFailures);
                return new(
                    MailboxPeerQuorumStatus.PartialFailure,
                    ReadOnlyMemory<byte>.Empty,
                    DurableReplicaCount: 1);
            }

            try
            {
                _ = MailboxPeerWireV2Codec.VerifyReplicaResponse(
                    remoteBytes.Value.Span,
                    verified,
                    _crypto);
                if (verified.ReplayDisposition == MailboxPeerReplayDisposition.NewReserved)
                {
                    MailboxPeerWireV2Codec.CompleteAtomically(
                        verified,
                        remoteBytes.Value,
                        _crypto,
                        _journal);
                }
                else if (verified.ReplayDisposition == MailboxPeerReplayDisposition.InFlight)
                {
                    _journal.CompleteAtomically(verified.ReplayClaim, remoteBytes.Value);
                }

                var unsignedQuorum =
                    MailboxPeerWireV2Codec.CreateUnsignedDurableQuorumResponse(
                        verified,
                        localBytes,
                        remoteBytes.Value.Span,
                        _localRouterId,
                        _crypto);
                var signedQuorum = _crypto.SignQuorumResponse(
                    unsignedQuorum,
                    _privateKeySeed);
                var encodedQuorum =
                    MailboxReceiptV3Codec.EncodeDurableQuorum(signedQuorum);
                _ = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
                    encodedQuorum,
                    verified,
                    _crypto);
                Interlocked.Increment(ref _durableQuorums);
                return new(
                    MailboxPeerQuorumStatus.Durable,
                    encodedQuorum,
                    DurableReplicaCount: 2);
            }
            catch (Exception exception) when (
                exception is MailboxPeerReplicationException or MailboxReceiptException)
            {
                Interlocked.Increment(ref _invalidReceipts);
                Interlocked.Increment(ref _partialFailures);
                return new(
                    MailboxPeerQuorumStatus.PartialFailure,
                    ReadOnlyMemory<byte>.Empty,
                    DurableReplicaCount: 1);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException
                    or InvalidDataException)
            {
                Interlocked.Increment(ref _partialFailures);
                return new(
                    MailboxPeerQuorumStatus.PartialFailure,
                    ReadOnlyMemory<byte>.Empty,
                    DurableReplicaCount: 1);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static MailboxPeerQuorumResult Failure(MailboxPeerQuorumStatus status) =>
        new(status, ReadOnlyMemory<byte>.Empty, DurableReplicaCount: 0);
}
