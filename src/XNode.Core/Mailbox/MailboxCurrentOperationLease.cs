namespace XNode.Core.Mailbox;

/// <summary>Internal native composition seam. The owner binds this to its actual
/// closed authority and both protected MGR leases; no public time/trust input.</summary>
internal sealed class MailboxCurrentOperationLease(
    Func<CancellationToken, ValueTask<ulong>> check, Action requireActive)
{
    internal void RequireActive() => requireActive();
    internal async ValueTask<ulong> CheckAsync(CancellationToken token)
    {
        requireActive(); token.ThrowIfCancellationRequested();
        var upper = await check(token).ConfigureAwait(false);
        requireActive(); token.ThrowIfCancellationRequested();
        return upper;
    }
}
