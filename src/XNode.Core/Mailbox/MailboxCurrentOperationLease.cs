namespace XNode.Core.Mailbox;

using System.Security.Cryptography;

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

    internal async ValueTask<ulong> RequireOriginTimeAsync(ulong minimumCreatedAt, CancellationToken token)
    {
        var upper = await CheckAsync(token).ConfigureAwait(false);
        if (upper >= minimumCreatedAt) return upper;
        var lead = minimumCreatedAt - upper;
        // Scheduling only, before an immutable peer intent or any peer effect.
        // Match the existing bounded durable-origin convergence (at most5s).
        if (lead > 4) throw new CryptographicException("The envelope origin is outside the current native time bound.");
        await Task.Delay(TimeSpan.FromSeconds(lead + 1), token).ConfigureAwait(false);
        upper = await CheckAsync(token).ConfigureAwait(false);
        if (upper < minimumCreatedAt)
            throw new CryptographicException("The envelope origin did not converge under authenticated native time.");
        return upper;
    }
}
