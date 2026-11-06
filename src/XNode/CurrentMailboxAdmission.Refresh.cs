using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

internal sealed partial class CurrentMailboxAdmission
{
    internal const int MaximumRefreshStepsPerRole = 64;
    // Scheduling only, serialized by enrollmentGate. Advance before callbacks
    // so an unavailable first role cannot starve the other role's next flight.
    private MailboxCapabilityDomain nextRevocationRefreshRole = MailboxCapabilityDomain.Deposit;

    // Restore first, then independently current host. Never WithHostAsync to
    // bootstrap expired floors: that path requires fresh MGR admission already.
    internal async ValueTask<MailboxRevocationRefreshResult> RefreshRevocationsAsync(IMailboxGrantRevocationArtifactSource artifacts, CancellationToken token,
        MailboxRevocationRefreshDiagnostics? diagnostics = null)
    {
        ArgumentNullException.ThrowIfNull(artifacts); token.ThrowIfCancellationRequested();
        if (!await enrollmentGate.WaitAsync(0, token).ConfigureAwait(false)) throw new IOException("Mailbox floor refresh is busy.");
        var firstRole = nextRevocationRefreshRole;
        var secondRole = firstRole == MailboxCapabilityDomain.Deposit ? MailboxCapabilityDomain.Retrieve : MailboxCapabilityDomain.Deposit;
        nextRevocationRefreshRole = secondRole;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(30)); var ct = deadline.Token;
        var verifiedSteps = 0;
        var nativeStepInFlight = false;
        try
        {
            // Both missing/partial roots reject before even a remote control read.
            if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Restore;
            var restoredDeposit = await deposit.ReadProtectedAsync(ct).ConfigureAwait(false);
            if (diagnostics is not null) diagnostics.DepositGeneration = MailboxGrantRevocationV1Codec.Decode(restoredDeposit.Span).Generation;
            var restoredRetrieve = await retrieve.ReadProtectedAsync(ct).ConfigureAwait(false);
            if (diagnostics is not null) diagnostics.RetrieveGeneration = MailboxGrantRevocationV1Codec.Decode(restoredRetrieve.Span).Generation;
            if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Authority;
            var authority = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
            if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Host;
            var host = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(authority.Network, authority.Authority,
                authority.MailboxAuthority, authority.TrustedTime, ct).ConfigureAwait(false);
            _ = await host.ResolveReplicaAsync(node, ct).ConfigureAwait(false);
            byte[] policy = [.. "PMA2"u8, 0, 1, .. authority.MailboxAuthority.CoreHash.Span];
            deposit.RequireScope(node, host.NetworkId.Span, policy, MailboxCapabilityDomain.Deposit);
            retrieve.RequireScope(node, host.NetworkId.Span, policy, MailboxCapabilityDomain.Retrieve);
            var protectedHistory = OnionNetworkProtectedHistoryCodec.Encode(authority.Network);
            async ValueTask RequireSourcesAsync()
            {
                if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Sources;
                ct.ThrowIfCancellationRequested();
                var current = await source.ReadPublicationAuthorityAsync(ct).ConfigureAwait(false);
                if (!Fixed(OnionNetworkProtectedHistoryCodec.Encode(current.Network), protectedHistory) ||
                    !Fixed(current.Authority.AuthorityCoreReference.Span, authority.Authority.AuthorityCoreReference.Span) ||
                    !Fixed(current.Authority.Dts1PolicyCoreReference.Span, authority.Authority.Dts1PolicyCoreReference.Span) ||
                    !Fixed(current.Authority.TimeSourcePolicyHash.Span, authority.Authority.TimeSourcePolicyHash.Span) ||
                    !Fixed(current.MailboxAuthority.ExactPma2.Span, authority.MailboxAuthority.ExactPma2.Span))
                    throw new CryptographicException("Mailbox control source changed during refresh.");
                var currentHost = await MailboxHostAuthorityV2Verifier.VerifyPolicyAsync(current.Network, current.Authority,
                    current.MailboxAuthority, current.TrustedTime, ct).ConfigureAwait(false);
                await currentHost.EnsureCurrentAsync(ct).ConfigureAwait(false);
                await host.EnsureCurrentAsync(ct).ConfigureAwait(false);
            }
            var moreRetainedSteps = false;
            foreach (var role in new[] { firstRole, secondRole })
            {
                if (diagnostics is not null)
                { diagnostics.Role = role; diagnostics.TargetGeneration = null; diagnostics.Phase = MailboxRevocationRefreshPhase.Restore; }
                var store = role == MailboxCapabilityDomain.Deposit ? deposit : retrieve;
                var before = MailboxGrantRevocationV1Codec.Decode((await store.ReadProtectedAsync(ct).ConfigureAwait(false)).Span);
                if (diagnostics is not null)
                {
                    if (role == MailboxCapabilityDomain.Deposit) diagnostics.DepositGeneration = before.Generation;
                    else diagnostics.RetrieveGeneration = before.Generation;
                }
                if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.TargetRead;
                var bytes = (await FetchControlAsync(role, null).ConfigureAwait(false)).ToArray();
                await RequireSourcesAsync().ConfigureAwait(false);
                if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.TargetVerify;
                var latest = MailboxGrantRevocationV1Codec.Decode(bytes);
                if (latest.Generation > 1_048_576 || latest.Domain != role || !Fixed(latest.Field(1).Span, host.NetworkId.Span) ||
                    !Fixed(latest.Field(2).Span, policy) || latest.Generation < before.Generation)
                    throw new CryptographicException("Mailbox control target is foreign or rolled back.");
                // Fresh-target signature/time verification only; the unused plan
                // cannot enroll or replace the existing native predecessor.
                _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, bytes, ct).ConfigureAwait(false);
                if (diagnostics is not null) diagnostics.TargetGeneration = latest.Generation;
                var generation = before.Generation;
                if (generation == latest.Generation)
                {
                    if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Advance;
                    nativeStepInFlight = true;
                    await store.CatchUpAsync(host, bytes, ct).ConfigureAwait(false); // exact replay or authenticated fork latch
                    nativeStepInFlight = false;
                }
                for (var step = 0; generation < latest.Generation && step < MaximumRefreshStepsPerRole; step++)
                {
                    var nextGeneration = checked(generation + 1);
                    if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.HistoryRead;
                    var next = nextGeneration == latest.Generation ? bytes :
                        (await FetchControlAsync(role, nextGeneration).ConfigureAwait(false)).ToArray();
                    await RequireSourcesAsync().ConfigureAwait(false);
                    if (MailboxGrantRevocationV1Codec.Decode(next).Generation != nextGeneration)
                        throw new CryptographicException("Mailbox control step differs from the requested successor.");
                    if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Advance;
                    nativeStepInFlight = true;
                    await store.CatchUpAsync(host, next, ct).ConfigureAwait(false);
                    nativeStepInFlight = false;
                    await RequireSourcesAsync().ConfigureAwait(false);
                    if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.ReadBack;
                    var readback = await store.ReadProtectedAsync(ct).ConfigureAwait(false);
                    generation = MailboxGrantRevocationV1Codec.Decode(readback.Span).Generation;
                    if (generation != nextGeneration || !Fixed(readback.Span, next)) throw new IOException("Mailbox control native read-back changed.");
                    verifiedSteps++;
                    if (diagnostics is not null)
                    {
                        if (role == MailboxCapabilityDomain.Deposit) diagnostics.DepositGeneration = generation;
                        else diagnostics.RetrieveGeneration = generation;
                    }
                }
                // Exhausting one role's step budget must not suppress the
                // other role's bounded batch. This flag is not admission or
                // a resume cursor: every next flight restores actual floors.
                moreRetainedSteps |= generation != latest.Generation;
                if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.TargetVerify;
                _ = await MailboxGrantRevocationV1Verifier.PlanInitialEnrollmentAsync(host, bytes, ct).ConfigureAwait(false);
            }
            await RequireSourcesAsync().ConfigureAwait(false);
            if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Completion;
            if (moreRetainedSteps) return new(false, verifiedSteps);
            if (diagnostics is not null) diagnostics.Phase = MailboxRevocationRefreshPhase.Admission;
            _ = await WithHostAsync(async (scope, checkToken) =>
            { _ = await scope.Lease.CheckAsync(checkToken).ConfigureAwait(false); return true; }, ct).ConfigureAwait(false);
            return new(true, verifiedSteps);

            async ValueTask<ReadOnlyMemory<byte>> FetchControlAsync(MailboxCapabilityDomain role, ulong? generation)
            {
                try { return await artifacts.FetchAsync(host.NetworkId, policy, role, generation, ct).ConfigureAwait(false); }
                catch (Exception error) when (verifiedSteps > 0 && !token.IsCancellationRequested &&
                    error is HttpRequestException or TimeoutException or OperationCanceledException or IOException)
                {
                    // Read-only transport interruption after independently
                    // verified native progress. This carries scheduling facts,
                    // never current revocation/admission authority.
                    throw new MailboxRevocationRefreshProgressException(verifiedSteps, error);
                }
            }
        }
        catch (OperationCanceledException error) when (!token.IsCancellationRequested && deadline.IsCancellationRequested &&
            verifiedSteps > 0 && !nativeStepInFlight)
        { throw new MailboxRevocationRefreshProgressException(verifiedSteps, error); }
        finally { enrollmentGate.Release(); }
    }
}

internal readonly record struct MailboxRevocationRefreshResult(bool CaughtUp, int VerifiedSteps);

// Only actual expected-next protected readbacks contribute to this count.
// It changes retry scheduling; it cannot activate a stale or partial floor.
internal sealed class MailboxRevocationRefreshProgressException(int verifiedSteps, Exception inner)
    : IOException("Mailbox control catch-up retains verified sequential progress.", inner)
{
    internal int VerifiedSteps { get; } = verifiedSteps > 0 ? verifiedSteps : throw new ArgumentOutOfRangeException(nameof(verifiedSteps));
}

internal enum MailboxRevocationRefreshPhase { Starting, Restore, Authority, Host, Sources, TargetRead, TargetVerify, HistoryRead, Advance, ReadBack, Completion, Admission }

// Per-flight log metadata only. Never read by authority, scheduling or persistence.
// Generations describe completed protected reads, not a current floor capability.
internal sealed class MailboxRevocationRefreshDiagnostics
{
    internal MailboxRevocationRefreshPhase Phase;
    internal MailboxCapabilityDomain? Role;
    internal ulong? DepositGeneration, RetrieveGeneration, TargetGeneration;
    internal string RoleLabel => Role switch
    { MailboxCapabilityDomain.Deposit => "deposit", MailboxCapabilityDomain.Retrieve => "retrieve", _ => "none" };
    internal string PhaseLabel => Phase switch
    {
        MailboxRevocationRefreshPhase.Starting => "starting", MailboxRevocationRefreshPhase.Restore => "restore",
        MailboxRevocationRefreshPhase.Authority => "authority", MailboxRevocationRefreshPhase.Host => "host",
        MailboxRevocationRefreshPhase.Sources => "sources", MailboxRevocationRefreshPhase.TargetRead => "target-read",
        MailboxRevocationRefreshPhase.TargetVerify => "target-verify", MailboxRevocationRefreshPhase.HistoryRead => "history-read",
        MailboxRevocationRefreshPhase.Advance => "advance", MailboxRevocationRefreshPhase.ReadBack => "read-back",
        MailboxRevocationRefreshPhase.Completion => "completion", MailboxRevocationRefreshPhase.Admission => "admission", _ => "unknown"
    };
    internal static string FailureReason(Exception error) => error.Message switch
    {
        "Mailbox control source changed during refresh." => "source-changed",
        "Mailbox control target is foreign or rolled back." => "target-scope",
        "Mailbox control step differs from the requested successor." => "history-step",
        "Mailbox control native read-back changed." => "read-back",
        "Mailbox control catch-up has more retained steps." => "more-steps",
        _ => error switch
        {
            HttpRequestException => "transport", OperationCanceledException => "cancelled", TimeoutException => "deadline",
            _ => CurrentMailboxHostRecovery.FailureReason(error)
        }
    };
}

internal sealed class CurrentMailboxRevocationRefreshWorker(CurrentMailboxAdmission admission,
    IMailboxGrantRevocationArtifactSource artifacts, ILogger<CurrentMailboxRevocationRefreshWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var diagnostics = new MailboxRevocationRefreshDiagnostics();
            var continueProgress = false;
            try
            {
                var result = await admission.RefreshRevocationsAsync(artifacts, stoppingToken, diagnostics).ConfigureAwait(false);
                failures = 0;
                continueProgress = !result.CaughtUp && result.VerifiedSteps > 0;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (MailboxRevocationRefreshProgressException progress)
            {
                failures = 0; continueProgress = true;
                ReportFailure(progress.InnerException!);
                logger.LogInformation("Mailbox control refresh retained {Steps} verified sequential steps; continuing bounded recovery.", progress.VerifiedSteps);
            }
            catch (Exception error) when (error is HttpRequestException or IOException or InvalidDataException or CryptographicException or UnauthorizedAccessException or
                InvalidOperationException or ArgumentException or FormatException or OverflowException or OnionBoundaryException or
                OperationCanceledException or TimeoutException)
            {
                failures = Math.Min(failures + 1, 4);
                ReportFailure(error);
            }
            var seconds = RetryDelaySeconds(continueProgress, failures);
            await Task.Delay(TimeSpan.FromSeconds(seconds + Random.Shared.Next(0, 3)), stoppingToken).ConfigureAwait(false);

            void ReportFailure(Exception error) => logger.LogWarning(
                "Mailbox control refresh unavailable ({Category}; phase={Phase}; reason={Reason}; role={Role}; deposit={Deposit}; retrieve={Retrieve}; target={Target}).",
                error.GetType().Name, diagnostics.PhaseLabel, MailboxRevocationRefreshDiagnostics.FailureReason(error), diagnostics.RoleLabel,
                diagnostics.DepositGeneration, diagnostics.RetrieveGeneration, diagnostics.TargetGeneration);
        }
    }
    internal static int RetryDelaySeconds(bool verifiedProgress, int failures) =>
        verifiedProgress ? 1 : failures == 0 ? 15 : Math.Min(60, 5 * (1 << Math.Clamp(failures, 1, 4)));
}
