using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;

namespace XNode;

// Observability of a completed fresh recovery check, never a dispatch capability.
internal sealed record CurrentMailboxHostRecoveryStatus(bool Recovered, string State);

internal sealed class CurrentMailboxHostRecovery(IServiceProvider services, ReplicatedMailboxOptions options,
    ILogger<CurrentMailboxHostRecovery> logger)
    : IHostedService
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private int running;
    private string? lastFailure;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Volatile.Write(ref running, 1);
        _ = await CheckAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Volatile.Write(ref running, 0);
        return Task.CompletedTask;
    }

    internal async ValueTask<CurrentMailboxHostRecoveryStatus> CheckAsync(CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        if (Volatile.Read(ref running) == 0) return new(false, "not-running");
        if (!options.Enabled) return new(true, "disabled");
        // A public health request cannot build an unbounded queue of protected
        // operations. Busy is unavailable, not cached successful authority.
        if (!await gate.WaitAsync(0, token).ConfigureAwait(false)) return new(false, "checking");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            var receiver = services.GetService<CurrentMailboxReplicaReceiver>();
            var coordinator = services.GetService<CurrentMailboxReplicationCoordinator>();
            if (receiver is null || coordinator is null) return new(false, "unconfigured");
            coordinator.RequireReceiver(receiver);
            await receiver.InitializeHostAsync(deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            lastFailure = null;
            return Volatile.Read(ref running) == 0 ? new(false, "not-running") : new(true, "recovered");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            ReportFailure("check-deadline");
            return new(false, "unavailable");
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException
            or CryptographicException or InvalidOperationException or ArgumentException or FormatException or OverflowException
            or MailboxGrantRevocationFloorException)
        {
            // Keep exact files and independent roots. The public response stays
            // unchanged; private logs receive only a closed denial reason.
            ReportFailure(FailureReason(error));
            return new(false, "unavailable");
        }
        finally { gate.Release(); }
    }

    private void ReportFailure(string reason)
    {
        if (lastFailure != reason)
            logger.LogWarning("Current mailbox host recovery unavailable ({Reason}); retained custody is unchanged.", reason);
        lastFailure = reason;
    }

    internal static string FailureReason(Exception error) => error.Message switch
    {
        "No acquired DID2 network observation is available." => "observation-missing",
        "The observed DID2 network floor changed." => "observation-floor-changed",
        "The observed DID2 proof no longer closes the protected floor." => "observation-head-changed",
        "The observed DID2 proof is no longer current." => "observation-expired",
        "The observed DID2 authority changed." => "observation-authority-changed",
        "MGR1 is outside current PMA2 role/network/protected-time authority." => "revocation-context",
        "Current host signing custody differs from its descriptor." => "descriptor-key",
        "Current mailbox authority changed during the operation." => "authority-changed",
        "Current mailbox trusted interval is unavailable." => "trusted-interval",
        _ => error switch
        {
            MailboxGrantRevocationFloorException => "revocation-floor",
            CryptographicException => "cryptographic-rejection",
            IOException => "custody-or-io",
            UnauthorizedAccessException => "custody-access",
            _ => "configuration-or-state"
        }
    };
}

internal static class CurrentMailboxHostRecoveryComposition
{
    internal static IServiceCollection AddCurrentMailboxHostRecovery(this IServiceCollection services)
    {
        services.AddSingleton<CurrentMailboxHostRecovery>();
        services.AddHostedService(provider => provider.GetRequiredService<CurrentMailboxHostRecovery>());
        return services;
    }
}
