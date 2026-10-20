using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox.Client;

namespace XNode;

internal sealed partial class CurrentMailboxReplicaReceiver
{
    internal ValueTask<ReadOnlyMemory<byte>> ExportHistoricalStoreRecoveryAsync(ReadOnlyMemory<byte> exact,
        CancellationToken token = default)
    {
        var owned = MailboxPeerWireV2Codec.Encode(MailboxPeerWireV2Codec.Decode(exact.Span));
        return WithInitializedHostAsync<ReadOnlyMemory<byte>>(async (scope, ct) =>
        {
            var plan = await scope.Host.PrepareHistoricalStoreSourceAsync(owned, replay, ct).ConfigureAwait(false);
            if (!Fixed(plan.Request.SenderRouterId.Span, LocalNodeId.Span))
                throw new CryptographicException("Only the actual first replica may export its retained Store evidence.");
            await admission.InitializeHostOperationsAsync(operationLedger, scope, ct, async (floors, checkToken) =>
            {
                var snapshot = plan.Snapshot;
                var key = Convert.ToHexString(snapshot.ScopeKey.Span).ToLowerInvariant();
                if (!floors.TryGetValue(key, out var floor) || !floor.MutationCompleted || floor.TombstoneDigest.Length != 0 ||
                    floor.ReplayDigest != MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot))
                    throw new InvalidDataException("Source Store evidence has no independent completed original fact.");
                await ValidatePeerCustodyAsync(floors, scope.Lease, checkToken).ConfigureAwait(false);
            }).ConfigureAwait(false);
            await mutations.RequireCompletedPreparedStoreAsync(plan, scope.Lease, ct).ConfigureAwait(false);
            var verified = MailboxPeerWireV2Codec.CommitPreparedReservation(plan, replay, crypto); // Existing only; no write.
            var durableAt = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            var receipt = MailboxPeerWireV2Codec.CreateUnsignedDurableReplicaResponseAfterPersistence(verified,
                MailboxPeerWireResponseReplicaV2.Sender, MailboxReplicaDisposition.Stored,
                verified.ReplayClaim.ReservedAtUnixSeconds, durableAt);
            var encoded = MailboxReceiptV2Codec.EncodeReplica(crypto.SignReplicaResponse(receipt, seed));
            var proof = MailboxPeerWireV2Codec.CreateDurableStoreForwarding(verified, encoded, seed);
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            return proof;
        }, token);
    }

    internal ValueTask ReconcileHistoricalStoreCustodyAsync(ReadOnlyMemory<byte> forwarding,
        CancellationToken token = default)
    {
        var owned = forwarding.ToArray();
        _ = MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(owned);
        return new ValueTask(admission.WithHostAsync(async (scope, ct) =>
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
            if (!ReferenceEquals(scope.Owner, admission)) throw new CryptographicException("Historical recovery owner differs.");
            var local = await scope.Host.ResolveReplicaAsync(LocalNodeId, ct).ConfigureAwait(false);
            if (!Fixed(crypto.GetPublicKey(seed), local.SigningPublicKey.Span))
                throw new CryptographicException("Historical recovery signing custody differs from current descriptor.");
            var plan = await scope.Host.PrepareHistoricalStoreRecoveryAsync(owned, ct).ConfigureAwait(false);
            if (!Fixed(plan.Request.RecipientRouterId.Span, LocalNodeId.Span))
                throw new CryptographicException("Historical recovery names another recipient.");
            var snapshot = plan.Snapshot;
            var key = Convert.ToHexString(snapshot.ScopeKey.Span).ToLowerInvariant();
            MailboxCurrentPeerReplayFloor? prior = null;
            await admission.InitializeHostOperationsAsync(operationLedger, scope, ct, async (floors, checkToken) =>
            {
                prior = floors.GetValueOrDefault(key);
                if (prior is not null && (prior.ReplayDigest != MailboxCurrentPeerReplayFloor.ReplayIdentity(snapshot) ||
                    prior.MutationCompleted || prior.ResponseDigest.Length != 0 || prior.TombstoneDigest.Length != 0))
                    throw new InvalidDataException("Historical repair cannot replace independent completed or different custody.");
                replay.RequireExistingPreparedPending(plan);
                await mutations.RequirePreparedStoreTargetAbsentAsync(plan, scope.Lease, checkToken).ConfigureAwait(false);
                replay.ValidateCurrentFloors(floors, checkToken, prior is null ? snapshot : null);
                await mutations.ValidateCurrentRecoveryAsync(scope.Lease, checkToken, floors).ConfigureAwait(false);
            }).ConfigureAwait(false);
            var fact = await mutations.CapturePreparedPeerFactAsync(plan, scope.Lease, ct).ConfigureAwait(false);
            await operationLedger.RecordCurrentPeerFloorAsync(snapshot.ScopeKey, fact, prior is not null,
                scope.Lease, ct).ConfigureAwait(false);
            replay.ReconcileUnpairedCurrentPending(plan, fact);
            replay.RequireExistingPreparedPending(plan);
            await admission.InitializeHostOperationsAsync(operationLedger, scope, ct,
                (floors, checkToken) => ValidatePeerCustodyAsync(floors, scope.Lease, checkToken)).ConfigureAwait(false);
            _ = await scope.Lease.CheckAsync(ct).ConfigureAwait(false);
            return true; // Metadata only: deliberately no Apply, Complete, receipt or client outcome.
        }, token).AsTask());
    }
}
