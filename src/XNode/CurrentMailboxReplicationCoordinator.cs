using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.Mailbox;

namespace XNode;

internal interface ICurrentMailboxReplicaPeerClient
{
    ValueTask<ReadOnlyMemory<byte>?> SendAsync(VerifiedOnionNextHopTransport recipient,
        MailboxPeerReplicationOperation operation, ReadOnlyMemory<byte> exactRequest, CancellationToken token);
}

/// <summary>Same current admission/replay/storage owner as the recipient. A
/// remote failure leaves real local custody and peer Pending, never quorum.</summary>
internal sealed class CurrentMailboxReplicationCoordinator(CurrentMailboxReplicaReceiver local,
    ICurrentMailboxReplicaPeerClient peer, ReplicatedMailboxOptions options)
{
    private readonly TimeSpan timeout = CaptureTimeout(options);
    internal ValueTask<MailboxPeerQuorumResult> ReplicateAsync(ReadOnlyMemory<byte> exactRequest,
        MailboxPeerReplicationOperation operation, CancellationToken token = default) =>
        local.WithPeerAsync<MailboxPeerQuorumResult>(exactRequest, operation, MailboxPeerWireResponseReplicaV2.Sender,
            async (current, ct) =>
            {
                var localReceipt = await current.ApplyAndSignLocalAsync(ct).ConfigureAwait(false);
                // ReadOnlyMemory's implicit array conversion makes a mixed
                // memory/null conditional produce empty memory, not null.
                // Pending must contact the peer, never verify an empty receipt.
                ReadOnlyMemory<byte>? remote = null;
                if (current.Verified.ReplayDisposition == MailboxPeerReplayDisposition.IdempotentCompleted)
                    remote = current.Verified.CachedResponse;
                if (remote is null)
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    deadline.CancelAfter(timeout);
                    try { remote = await peer.SendAsync(current.RecipientTransport, operation,
                        current.CanonicalRequest, deadline.Token).ConfigureAwait(false); }
                    catch (Exception error) when (error is HttpRequestException or IOException ||
                        error is OperationCanceledException && !ct.IsCancellationRequested) { remote = null; }
                }
                await current.EnsureCurrentAsync(ct).ConfigureAwait(false);
                if (remote is null) return new(MailboxPeerQuorumStatus.PartialFailure, ReadOnlyMemory<byte>.Empty, 1);
                ReadOnlyMemory<byte> quorum;
                try { quorum = await current.CreateQuorumAsync(localReceipt, remote.Value, ct).ConfigureAwait(false); }
                catch (MailboxPeerReplicationException) { return new(MailboxPeerQuorumStatus.PartialFailure, ReadOnlyMemory<byte>.Empty, 1); }
                if (current.Verified.ReplayDisposition != MailboxPeerReplayDisposition.IdempotentCompleted)
                    await current.CommitRecipientAsync(remote.Value, ct).ConfigureAwait(false);
                return new(MailboxPeerQuorumStatus.Durable, quorum, 2);
            }, token);
    private static TimeSpan CaptureTimeout(ReplicatedMailboxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options); options.Validate();
        if (!options.Enabled) throw new InvalidOperationException("Current mailbox replication is disabled.");
        return options.PeerTimeout;
    }
}
