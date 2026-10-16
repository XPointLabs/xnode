using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode;

internal sealed partial class CurrentMailboxReplicaReceiver
{
    internal ValueTask<MailboxClientStoreReservation?> ReadPendingStoreAsync(uint turn, CancellationToken token) =>
        WithInitializedHostAsync(async (scope, ct) =>
            await operationLedger.ReadPendingCurrentStoreAsync(turn, scope.Lease, ct).ConfigureAwait(false), token);

    internal ValueTask<T> WithOriginalStoreIntentAsync<T>(MailboxClientStoreReservation intent,
        Func<PeerOperation, CancellationToken, ValueTask<T>> action, CancellationToken token) =>
        WithPeerAsync(intent.CanonicalPeerRequest, MailboxPeerReplicationOperation.Store,
            MailboxPeerWireResponseReplicaV2.Sender, action, token,
            (scope, ct) => operationLedger.RequireExactCurrentStoreIntentAsync(
                intent.OperationKey, intent.CanonicalPeerRequest, scope.Lease, ct));
}
