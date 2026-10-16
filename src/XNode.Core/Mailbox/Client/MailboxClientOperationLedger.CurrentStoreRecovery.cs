using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientOperationLedger
{
    // Scheduling snapshot only, never admission authority. The selected exact
    // intent is checked again under its original grant before native effects.
    internal async Task<MailboxClientStoreReservation?> ReadPendingCurrentStoreAsync(
        uint turn, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        if (_currentCustody is null) throw new InvalidOperationException("Current operation custody is required.");
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            var pending = document.Operations.Where(pair => (pair.Value.State is "reserved" or "retryable" or "completing") && pair.Value.PeerRequest.Length != 0)
                .OrderBy(pair => pair.Key, StringComparer.Ordinal).ToArray();
            var selected = pending.Length == 0 ? null : ToReservation(pending[turn % (uint)pending.Length].Key,
                pending[turn % (uint)pending.Length].Value);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            return selected;
        }
        finally { _gate.Release(); }
    }

    internal async Task RequireExactCurrentStoreIntentAsync(string key, ReadOnlyMemory<byte> exact,
        MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        if (_currentCustody is null) throw new InvalidOperationException("Current operation custody is required.");
        var owned = MailboxPeerWireV2Codec.Encode(MailboxPeerWireV2Codec.Decode(exact.Span));
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var document = await LoadAsync(token, lease).ConfigureAwait(false);
            var operation = GetOperation(document, key);
            if (operation.State is not ("reserved" or "retryable" or "completing") ||
                operation.PeerRequest.Length == 0 || !CryptographicOperations.FixedTimeEquals(
                    Convert.FromBase64String(operation.PeerRequest), owned))
                throw new InvalidDataException("Store recovery lost its original exact intent.");
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
}
