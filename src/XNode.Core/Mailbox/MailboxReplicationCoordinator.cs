namespace XNode.Core.Mailbox;

public sealed record MailboxReplicaPeer(RouterId RouterId, string Endpoint);

public interface IMailboxReplicaPeerClient
{
    Task<MailboxWriteReceipt?> PutAsync(
        MailboxReplicaPeer peer,
        SignedMailboxReplicaRequest request,
        CancellationToken cancellationToken);
}

public sealed record MailboxQuorumWriteResult(
    bool QuorumAchieved,
    int RequiredReceipts,
    IReadOnlyList<MailboxWriteReceipt> Receipts,
    int FailedReplicas,
    string Error);

public sealed record MailboxReplicationMetricsSnapshot(
    long WriteAttempts,
    long QuorumWrites,
    long QuorumFailures,
    long ReplicaFailures,
    long InvalidReceipts,
    long Stored,
    long Duplicates);

public sealed class MailboxReplicationCoordinator
{
    private readonly RouterId _localRouterId;
    private readonly string _privateKeySeedHex;
    private readonly ReplicatedMailboxOptions _options;
    private readonly ReplicatedMailboxStore _store;
    private readonly IMailboxReplicaPeerClient _peerClient;
    private readonly IClock _clock;
    private long _writeAttempts;
    private long _quorumWrites;
    private long _quorumFailures;
    private long _replicaFailures;
    private long _invalidReceipts;
    private long _stored;
    private long _duplicates;

    public MailboxReplicationCoordinator(
        RouterId localRouterId,
        string privateKeySeedHex,
        ReplicatedMailboxOptions options,
        ReplicatedMailboxStore store,
        IMailboxReplicaPeerClient peerClient,
        IClock? clock = null)
    {
        options.Validate();
        _localRouterId = localRouterId;
        _privateKeySeedHex = privateKeySeedHex;
        _options = options;
        _store = store;
        _peerClient = peerClient;
        _clock = clock ?? new SystemClock();
    }

    public MailboxReplicationMetricsSnapshot Metrics => new(
        Interlocked.Read(ref _writeAttempts),
        Interlocked.Read(ref _quorumWrites),
        Interlocked.Read(ref _quorumFailures),
        Interlocked.Read(ref _replicaFailures),
        Interlocked.Read(ref _invalidReceipts),
        Interlocked.Read(ref _stored),
        Interlocked.Read(ref _duplicates));

    public async Task<MailboxQuorumWriteResult> PutAsync(
        EncryptedMailboxBlob blob,
        IReadOnlyList<MailboxReplicaPeer> orderedPeers,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _writeAttempts);
        if (!_options.Enabled)
        {
            return Failed("mailbox-disabled", 0);
        }

        var localResult = await _store.PutAsync(blob, cancellationToken).ConfigureAwait(false);
        if (localResult.Disposition == MailboxPutDisposition.Rejected)
        {
            return Failed(localResult.Error, 0);
        }

        IncrementDisposition(localResult.Disposition);
        var receipts = new List<MailboxWriteReceipt>
        {
            MailboxReplicationProtocol.SignReceipt(
                _localRouterId,
                _privateKeySeedHex,
                blob,
                _clock.UtcNow,
                localResult.Disposition)
        };

        var peers = orderedPeers
            .Where(peer => peer.RouterId != _localRouterId)
            .GroupBy(peer => peer.RouterId)
            .Select(group => group.First())
            .Take(_options.ReplicationFactor - 1)
            .ToArray();

        var tasks = peers.Select(peer => ReplicateOneAsync(peer, blob, cancellationToken)).ToArray();
        foreach (var outcome in await Task.WhenAll(tasks).ConfigureAwait(false))
        {
            if (outcome.Receipt is not null)
            {
                receipts.Add(outcome.Receipt);
            }
        }

        var achieved = receipts.Count >= _options.WriteQuorum;
        if (achieved)
        {
            Interlocked.Increment(ref _quorumWrites);
        }
        else
        {
            Interlocked.Increment(ref _quorumFailures);
        }
        return new MailboxQuorumWriteResult(
            achieved,
            _options.WriteQuorum,
            receipts,
            (_options.ReplicationFactor - 1) - (receipts.Count - 1),
            achieved ? "" : "mailbox-write-quorum-not-reached");
    }

    private async Task<(MailboxWriteReceipt? Receipt, string Error)> ReplicateOneAsync(
        MailboxReplicaPeer peer,
        EncryptedMailboxBlob blob,
        CancellationToken cancellationToken)
    {
        var request = MailboxReplicationProtocol.SignRequest(
            _localRouterId,
            peer.RouterId,
            _privateKeySeedHex,
            blob,
            _clock.UtcNow);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_options.PeerTimeout);
            var receipt = await _peerClient.PutAsync(peer, request, timeout.Token).ConfigureAwait(false);
            if (receipt is null)
            {
                Interlocked.Increment(ref _replicaFailures);
                return (null, "mailbox-peer-rejected");
            }

            if (!MailboxReplicationProtocol.VerifyReceipt(receipt, peer.RouterId, blob, _clock.UtcNow))
            {
                Interlocked.Increment(ref _invalidReceipts);
                Interlocked.Increment(ref _replicaFailures);
                return (null, "invalid-mailbox-receipt");
            }

            return (receipt, "");
        }
        catch (Exception exception) when (
            (exception is HttpRequestException
                or IOException
                or System.Text.Json.JsonException
                or OperationCanceledException)
            && (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested))
        {
            Interlocked.Increment(ref _replicaFailures);
            return (null, "mailbox-peer-unavailable");
        }
    }

    private MailboxQuorumWriteResult Failed(string error, int failedReplicas)
    {
        Interlocked.Increment(ref _quorumFailures);
        return new MailboxQuorumWriteResult(
            false,
            _options.WriteQuorum,
            [],
            failedReplicas,
            error);
    }

    private void IncrementDisposition(MailboxPutDisposition disposition)
    {
        if (disposition == MailboxPutDisposition.Stored)
        {
            Interlocked.Increment(ref _stored);
        }
        else if (disposition == MailboxPutDisposition.Duplicate)
        {
            Interlocked.Increment(ref _duplicates);
        }
    }
}
