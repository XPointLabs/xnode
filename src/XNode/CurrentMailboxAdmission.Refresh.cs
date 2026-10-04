using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

internal sealed partial class CurrentMailboxAdmission
{
    internal const int MaximumRefreshStepsPerRole = 64;

    // Restore first, then independently current host. Never WithHostAsync to
    // bootstrap expired floors: that path requires fresh MGR admission already.
    internal async ValueTask RefreshRevocationsAsync(IMailboxGrantRevocationArtifactSource artifacts, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(artifacts); token.ThrowIfCancellationRequested();
        if (!await enrollmentGate.WaitAsync(0, token).ConfigureAwait(false)) throw new IOException("Mailbox floor refresh is busy.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30)); var ct = deadline.Token;
        try
        {
            // Both missing/partial roots reject before even a remote control read.
            _ = await deposit.ReadProtectedAsync(ct).ConfigureAwait(false);
            _ = await retrieve.ReadProtectedAsync(ct).ConfigureAwait(false);
            var authority = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
            var host = await MailboxHostAuthorityV2Verifier.VerifyAsync(authority.Network, authority.Authority,
                authority.MailboxAuthority.ExactPma2, authority.TrustedTime, ct).ConfigureAwait(false);
            _ = await host.ResolveReplicaAsync(node, ct).ConfigureAwait(false);
            byte[] policy = [.. "PMA2"u8, 0, 1, .. authority.MailboxAuthority.CoreHash.Span];
            deposit.RequireScope(node, host.NetworkId.Span, policy, MailboxCapabilityDomain.Deposit);
            retrieve.RequireScope(node, host.NetworkId.Span, policy, MailboxCapabilityDomain.Retrieve);
            var protectedHistory = OnionNetworkProtectedHistoryCodec.Encode(authority.Network);
            async ValueTask RequireSourcesAsync()
            {
                ct.ThrowIfCancellationRequested();
                var current = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
                if (!Fixed(OnionNetworkProtectedHistoryCodec.Encode(current.Network), protectedHistory) ||
                    !Fixed(current.Authority.AuthorityCoreReference.Span, authority.Authority.AuthorityCoreReference.Span) ||
                    !Fixed(current.Authority.Dts1PolicyCoreReference.Span, authority.Authority.Dts1PolicyCoreReference.Span) ||
                    !Fixed(current.Authority.TimeSourcePolicyHash.Span, authority.Authority.TimeSourcePolicyHash.Span) ||
                    !Fixed(current.MailboxAuthority.ExactPma2.Span, authority.MailboxAuthority.ExactPma2.Span))
                    throw new CryptographicException("Mailbox control source changed during refresh.");
                var currentHost = await MailboxHostAuthorityV2Verifier.VerifyAsync(current.Network, current.Authority,
                    current.MailboxAuthority.ExactPma2, current.TrustedTime, ct).ConfigureAwait(false);
                await currentHost.EnsureCurrentAsync(ct).ConfigureAwait(false);
                await host.EnsureCurrentAsync(ct).ConfigureAwait(false);
            }
            foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
            {
                var store = role == MailboxCapabilityDomain.Deposit ? deposit : retrieve;
                var before = MailboxGrantRevocationV1Codec.Decode((await store.ReadProtectedAsync(ct).ConfigureAwait(false)).Span);
                var bytes = (await artifacts.FetchAsync(host.NetworkId, policy, role, null, ct).ConfigureAwait(false)).ToArray();
                await RequireSourcesAsync().ConfigureAwait(false);
                var latest = MailboxGrantRevocationV1Codec.Decode(bytes);
                if (latest.Generation > 1_048_576 || latest.Domain != role || !Fixed(latest.Field(1).Span, host.NetworkId.Span) ||
                    !Fixed(latest.Field(2).Span, policy) || latest.Generation < before.Generation)
                    throw new CryptographicException("Mailbox control target is foreign or rolled back.");
                // Fresh-target signature/time verification only; the unused plan
                // cannot enroll or replace the existing native predecessor.
                _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, bytes, ct).ConfigureAwait(false);
                var generation = before.Generation;
                if (generation == latest.Generation)
                    await store.CatchUpAsync(host, bytes, ct).ConfigureAwait(false); // exact replay or authenticated fork latch
                for (var step = 0; generation < latest.Generation && step < MaximumRefreshStepsPerRole; step++)
                {
                    var nextGeneration = checked(generation + 1);
                    var next = nextGeneration == latest.Generation ? bytes :
                        (await artifacts.FetchAsync(host.NetworkId, policy, role, nextGeneration, ct).ConfigureAwait(false)).ToArray();
                    await RequireSourcesAsync().ConfigureAwait(false);
                    if (MailboxGrantRevocationV1Codec.Decode(next).Generation != nextGeneration)
                        throw new CryptographicException("Mailbox control step differs from the requested successor.");
                    await store.CatchUpAsync(host, next, ct).ConfigureAwait(false);
                    await RequireSourcesAsync().ConfigureAwait(false);
                    generation = MailboxGrantRevocationV1Codec.Decode((await store.ReadProtectedAsync(ct).ConfigureAwait(false)).Span).Generation;
                    if (generation != nextGeneration) throw new IOException("Mailbox control native read-back changed.");
                }
                if (generation != latest.Generation) throw new IOException("Mailbox control catch-up has more retained steps.");
                _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, bytes, ct).ConfigureAwait(false);
            }
            await RequireSourcesAsync().ConfigureAwait(false);
            _ = await WithHostAsync(async (scope, checkToken) =>
            { _ = await scope.Lease.CheckAsync(checkToken).ConfigureAwait(false); return true; }, ct).ConfigureAwait(false);
        }
        finally { enrollmentGate.Release(); }
    }
}

internal sealed class CurrentMailboxRevocationRefreshWorker(CurrentMailboxAdmission admission,
    IMailboxGrantRevocationArtifactSource artifacts, ILogger<CurrentMailboxRevocationRefreshWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await admission.RefreshRevocationsAsync(artifacts, stoppingToken).ConfigureAwait(false); failures = 0; }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception error) when (error is HttpRequestException or IOException or InvalidDataException or CryptographicException or UnauthorizedAccessException or
                InvalidOperationException or ArgumentException or FormatException or OverflowException or OnionBoundaryException or
                OperationCanceledException or TimeoutException)
            { failures = Math.Min(failures + 1, 4); logger.LogWarning("Mailbox control refresh unavailable ({Category}).", error.GetType().Name); }
            var seconds = failures == 0 ? 15 : Math.Min(60, 5 * (1 << failures));
            await Task.Delay(TimeSpan.FromSeconds(seconds + Random.Shared.Next(0, 3)), stoppingToken).ConfigureAwait(false);
        }
    }
}
