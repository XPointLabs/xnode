using Deep.Protocol.XPointNetworkV1;

namespace XNode.Core.Mailbox.Client;

public sealed partial class MailboxClientOperationLedger
{
    internal async Task EnrollNewCurrentAsync(ReadOnlyMemory<byte> localNode,
        VerifiedMailboxHostAuthorityV2 host, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        var custody = _currentCustody ?? throw new InvalidOperationException("Current operation custody is required.");
        custody.RequireScope(localNode.Span, host.NetworkId.Span);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
            custody.RequireNewScope(_path);
            if (File.Exists(_path) || Directory.EnumerateFiles(_directory, "*.tmp").Any())
                throw new InvalidDataException("Only a genuinely new operation scope can be explicitly enrolled.");
            var empty = new MailboxClientLedgerDocument(SchemaVersion, 0, 0,
                new(StringComparer.Ordinal), new(StringComparer.Ordinal), new(StringComparer.Ordinal));
            // The actual empty document precedes protected enrollment. Readers
            // cannot retry interrupted provisioning or install a fresh root.
            await SaveAsync(empty, token, lease, enrolling: true).ConfigureAwait(false);
            await custody.EnrollAsync(_path, lease, token).ConfigureAwait(false);
            _ = await LoadAsync(token, lease).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    internal async Task InitializeCurrentAsync(ReadOnlyMemory<byte> localNode,
        VerifiedMailboxHostAuthorityV2 host, MailboxCurrentOperationLease lease, CancellationToken token)
    {
        ThrowIfDisposed(); lease.RequireActive();
        (_currentCustody ?? throw new InvalidOperationException("Current operation custody is required."))
            .RequireScope(localNode.Span, host.NetworkId.Span);
        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            _ = await LoadAsync(token, lease).ConfigureAwait(false);
            _ = await lease.CheckAsync(token).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }
}
