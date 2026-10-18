using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

// Host-owned retry of already admitted exact intent. No new signing input,
// custody generation, endpoint, authority cache or readiness-triggered effect.
internal sealed class CurrentMailboxStoreRecoveryWorker(CurrentMailboxReplicationCoordinator coordinator,
    ILogger<CurrentMailboxStoreRecoveryWorker> logger) : BackgroundService
{
    private uint turn;
    private string? lastState;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var failures = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var state = await RunOnceAsync(stoppingToken).ConfigureAwait(false);
            failures = state is "idle" or "settled" ? 0 : Math.Min(failures + 1, 4);
            var seconds = failures == 0 ? 30 : Math.Min(60, 5 * (1 << failures));
            try { await Task.Delay(TimeSpan.FromSeconds(seconds + Random.Shared.Next(0, 3)), stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }

    internal async Task<string> RunOnceAsync(CancellationToken stoppingToken)
    {
        stoppingToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(MailboxWireHttpContract.Store.RequestTimeoutSeconds));
        string state;
        Exception? failure = null;
        try
        {
            state = await coordinator.RecoverOneStoreAsync(unchecked(turn++), deadline.Token).ConfigureAwait(false) switch
            {
                CurrentMailboxStoreRecoveryResult.Idle => "idle",
                CurrentMailboxStoreRecoveryResult.Settled => "settled",
                _ => "incomplete"
            };
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException error) when (deadline.IsCancellationRequested) { state = "deadline"; failure = error; }
        catch (OperationCanceledException error) { state = "unavailable"; failure = error; }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or OverflowException or CryptographicException
            or HttpRequestException or TimeoutException
            or OnionBoundaryException
            or MailboxPeerReplicationException or MailboxGrantRevocationFloorException
            or MailboxPeerReplayCapacityException or MailboxPeerMutationCapacityException or MailboxClientLedgerCapacityException
            or MailboxClientOperationConflictException or MailboxClientException
            or MailboxClientCanonicalOutcomePersistenceException or MailboxClientCanonicalOutcomeCapacityException
            or MailboxClientCanonicalOutcomeConflictException or MailboxClientCanonicalOutcomeMissingException)
        { state = "unavailable"; failure = error; }
        var diagnosticKey = state;
        try
        {
            var location = CurrentMailboxDiagnostics.FailureLocation(failure);
            var check = CurrentMailboxDiagnostics.AuthorityFailureCheck(failure);
            diagnosticKey = state + "|" + location.Method + "|" + location.Il.ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + check;
            if (lastState != diagnosticKey)
            {
                if (failure is null) logger.Log(state is "idle" or "settled" ? LogLevel.Information : LogLevel.Warning,
                    "Current mailbox Store recovery: state={State}; original custody retained.", state);
                else logger.LogWarning("Current mailbox Store recovery: state={State}; method={CodeMethod}; il={Il}; check={Check}; original custody retained.",
                    state, location.Method, location.Il, check);
            }
        }
        catch { /* Diagnostics cannot alter recovery or shut down the host. */ }
        lastState = diagnosticKey;
        return state;
    }
}
