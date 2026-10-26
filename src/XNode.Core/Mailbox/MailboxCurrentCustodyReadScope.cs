namespace XNode.Core.Mailbox;

// A private denial-only segment of one ledger fence. It owns no admission
// result: actual ledger/root authentication precedes it and the actual lease
// callback follows ALL native reads and diagnostics. It cannot span an effect,
// recovery, network callback or return from CheckCurrentOperationAsync.
internal sealed class MailboxCurrentCustodyReadScope(MailboxCurrentOperationLease lease) : IDisposable
{
    private bool closed;
    private ulong missingCompletedBlobExpiry;
    private SemaphoreSlim? mutationOwner;

    internal void RequireActive()
    {
        ObjectDisposedException.ThrowIf(closed, this);
        lease.RequireActive();
    }

    internal void RequireMissingCompletedBlobExpired(ulong expiresAt)
    {
        RequireActive();
        missingCompletedBlobExpiry = Math.Max(missingCompletedBlobExpiry, expiresAt);
    }

    internal void HoldMutationOwner(SemaphoreSlim gate)
    {
        RequireActive();
        if (mutationOwner is not null) throw new InvalidOperationException("The native read segment already owns its mutation inventory.");
        mutationOwner = gate;
    }

    internal async ValueTask<ulong> CompleteAsync(CancellationToken token)
    {
        RequireActive();
        var upper = await lease.CheckAsync(token).ConfigureAwait(false);
        RequireActive();
        token.ThrowIfCancellationRequested();
        if (missingCompletedBlobExpiry > upper)
            throw new InvalidDataException("Mailbox recovery live completed Store has lost its blob.");
        closed = true;
        return upper;
    }

    public void Dispose()
    {
        closed = true;
        Interlocked.Exchange(ref mutationOwner, null)?.Release();
    }
}
