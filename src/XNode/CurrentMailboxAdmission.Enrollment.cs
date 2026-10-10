using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

internal sealed partial class CurrentMailboxAdmission
{
    private readonly SemaphoreSlim enrollmentGate = new(1, 1);

    // Explicit operator command only. Ordinary startup/readiness never calls
    // this path. Partial writes are retained/unready, not retried or repaired.
    internal async ValueTask EnrollNewHostAsync(CurrentMailboxReplicaReceiver receiver,
        ReadOnlyMemory<byte> depositInitialSnapshot, ReadOnlyMemory<byte> retrieveInitialSnapshot, CancellationToken token)
    {
        // Own both bounded canonical inputs before source/clock callbacks.
        var depositBytes = MailboxGrantRevocationV1Codec.Decode(depositInitialSnapshot.Span).CanonicalBytes.ToArray();
        var retrieveBytes = MailboxGrantRevocationV1Codec.Decode(retrieveInitialSnapshot.Span).CanonicalBytes.ToArray();
        await enrollmentGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await receiver.ValidateNewNativeScopeAsync(this, token).ConfigureAwait(false);
            var authority = await source.ReadPublicationAuthorityAsync(token).ConfigureAwait(false);
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(authority.Network, authority.Authority,
                authority.MailboxAuthority.ExactPma2, authority.TrustedTime, token).ConfigureAwait(false);
            byte[] policyReference = [.. "PMA2"u8, 0, 1, .. authority.MailboxAuthority.CoreHash.Span];
            deposit.RequireScope(node, host.NetworkId.Span, policyReference, MailboxCapabilityDomain.Deposit);
            retrieve.RequireScope(node, host.NetworkId.Span, policyReference, MailboxCapabilityDomain.Retrieve);
            await receiver.ValidateEnrollmentSigningCustodyAsync(this, host, token).ConfigureAwait(false);
            await receiver.OperationLedger.ValidateNewCurrentScopeAsync(node, host, token).ConfigureAwait(false);
            await deposit.ValidateNewEnrollmentAsync(host, depositBytes, token).ConfigureAwait(false);
            await retrieve.ValidateNewEnrollmentAsync(host, retrieveBytes, token).ConfigureAwait(false);

            await receiver.ValidateEnrollmentSigningCustodyAsync(this, host, token).ConfigureAwait(false);
            await receiver.ValidateNewNativeScopeAsync(this, token).ConfigureAwait(false);
            await deposit.EnrollAsync(host, depositBytes, token).ConfigureAwait(false);
            await retrieve.EnrollAsync(host, retrieveBytes, token).ConfigureAwait(false);
            _ = await EnrollNewOperationsAsync(receiver.OperationLedger, token).ConfigureAwait(false);
            await receiver.InitializeHostAsync(token).ConfigureAwait(false);
        }
        finally { enrollmentGate.Release(); }
    }
}
