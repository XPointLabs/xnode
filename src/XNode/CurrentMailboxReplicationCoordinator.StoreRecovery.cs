using XNode.Core.Mailbox;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode;

internal enum CurrentMailboxStoreRecoveryResult { Idle, Incomplete, Settled }

internal sealed partial class CurrentMailboxReplicationCoordinator
{
    // One bounded original intent, no client request/grant/nonce authoring.
    // Readiness remains read-only. Original current grant, both MGR owners,
    // peer replay/mutation checks and two independent receipts still apply.
    internal async ValueTask<CurrentMailboxStoreRecoveryResult> RecoverOneStoreAsync(uint turn,
        CancellationToken token = default)
    {
        var intent = await local.ReadPendingStoreAsync(turn, token).ConfigureAwait(false);
        if (intent is null) return CurrentMailboxStoreRecoveryResult.Idle;
        return await local.WithOriginalStoreIntentAsync(intent, async (current, ct) =>
        {
            var result = await ReplicateAdmittedAsync(current, MailboxPeerReplicationOperation.Store, ct).ConfigureAwait(false);
            if (result.Status != MailboxPeerQuorumStatus.Durable) return CurrentMailboxStoreRecoveryResult.Incomplete;
            await current.SaveStoreSettlementAsync(intent.OperationKey, result.CanonicalMqr3, ct).ConfigureAwait(false);
            return CurrentMailboxStoreRecoveryResult.Settled;
        }, token).ConfigureAwait(false);
    }
}
