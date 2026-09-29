using System.Security.Cryptography;
using System.Diagnostics;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using XNode.Core;
using XNode.Core.PrivacyRouting;

namespace XNode;

internal sealed class VerifiedOnionHostReceiveBindingSource(
    IDeepIdV2ReceiveNetworkSource networks,
    RouterNodeOptions node,
    PrivacyRoutingConfiguration configuration)
    : IOnionHostReceiveBindingSource
{
    private readonly IDeepIdV2ReceiveNetworkSource networks = networks
        ?? throw new ArgumentNullException(nameof(networks));
    private readonly byte[] localOwnerId = (node
        ?? throw new ArgumentNullException(nameof(node))).GetRouterId().ToBytes();
    private readonly PrivacyRoutingConfiguration configuration = configuration
        ?? throw new ArgumentNullException(nameof(configuration));

    public async ValueTask<OnionHostReceiveBinding> GetCurrentAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!configuration.Enabled)
        {
            throw new InvalidOperationException(
                "The verified ONION receive binding is dormant while privacy routing is disabled.");
        }

        var network = await networks.ReadCurrentAsync(localOwnerId, configuration.PublicKey, configuration.NextPublicKey, cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "The ONION authority source returned no current verified snapshot.");
        network.EnsureCurrent();
        var candidates = OnionPathCandidateSnapshotFactory.Create(network)
            .Candidates
            .Where(candidate => Fixed(candidate.RouterOwnerId.Span, localOwnerId))
            .ToArray();
        if (candidates.Length != 1)
        {
            throw new InvalidOperationException(
                "The current verified XND1 view must contain exactly one node for the local router owner.");
        }

        var local = candidates[0];
        if ((local.VerifiedRoleMask & 0x0007) == 0)
        {
            throw new InvalidOperationException(
                "The local node lacks a receive role in the current verified XND1 view.");
        }

        return new OnionHostReceiveBinding(
            network,
            local.NodeId.Span,
            configuration.SelectVerifiedHandle(network, local.NodeId).Span);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class PrivacyRoutingProductionCapability : IHostedService, IAsyncDisposable
{
    private readonly PrivacyRoutingConfiguration configuration;
    private readonly IOnionHostReceiveBindingSource receiveBindings;
    private readonly TimeSpan refreshInterval;
    private readonly CancellationTokenSource lifetime = new();
    private readonly SemaphoreSlim refreshGate = new(1, 1);
    private Task? refreshTask;
    private OnionHostReceiveBinding? verifiedBinding;
    private long bindingCreatedTimestamp;
    private Exception? proofBackoff;
    private long proofBackoffTimestamp;
    private int stopped;
    private int started;
    private int disposed;
    private readonly ILogger<PrivacyRoutingProductionCapability>? logger;
    private string? lastFailure;

    public PrivacyRoutingProductionCapability(PrivacyRoutingConfiguration configuration,
        IOnionHostReceiveBindingSource receiveBindings, ILogger<PrivacyRoutingProductionCapability>? logger = null)
        : this(configuration, receiveBindings, TimeSpan.FromSeconds(10), logger) { }

    internal PrivacyRoutingProductionCapability(PrivacyRoutingConfiguration configuration,
        IOnionHostReceiveBindingSource receiveBindings, TimeSpan refreshInterval,
        ILogger<PrivacyRoutingProductionCapability>? logger = null)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.receiveBindings = receiveBindings ?? throw new ArgumentNullException(nameof(receiveBindings));
        if (refreshInterval <= TimeSpan.Zero || refreshInterval > TimeSpan.FromSeconds(10))
            throw new ArgumentOutOfRangeException(nameof(refreshInterval));
        this.refreshInterval = refreshInterval;
        this.logger = logger;
    }

    internal bool IsVerified
    {
        get
        {
            var network = Volatile.Read(ref verifiedBinding)?.Network;
            if (Volatile.Read(ref stopped) != 0 || !configuration.Enabled || network is null) return false;
            try { network.EnsureCurrent(); return true; }
            catch (OnionBoundaryException) { return false; }
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref started, 1) != 0 || Volatile.Read(ref stopped) != 0)
            throw new InvalidOperationException("The ONION capability cannot be restarted in-place.");
        if (!configuration.Enabled)
        {
            return;
        }
        try
        {
            _ = await ReadCurrentAsync(forceRefresh: true, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or TimeoutException or
            CryptographicException or OnionBoundaryException or OperationCanceledException)
        {
            // Dependency loss or expired authority is an unavailable capability,
            // not a fatal host startup. Keep mutations closed and let the same
            // bounded fresh-proof loop recover; never revive a retained binding.
            Volatile.Write(ref verifiedBinding, null);
        }
        refreshTask = RefreshUntilStoppedAsync();
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Interlocked.Exchange(ref stopped, 1);
        await lifetime.CancelAsync().ConfigureAwait(false);
        Volatile.Write(ref verifiedBinding, null);
        if (refreshTask is not null)
            await refreshTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        await refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { Volatile.Write(ref verifiedBinding, null); }
        finally { refreshGate.Release(); }
    }

    internal ValueTask<OnionHostReceiveBinding> GetCurrentAsync(
        CancellationToken cancellationToken) => ReadCurrentAsync(false, cancellationToken);

    private async ValueTask<OnionHostReceiveBinding> ReadCurrentAsync(
        bool forceRefresh, CancellationToken cancellationToken)
    {
        using var request = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token);
        await refreshGate.WaitAsync(request.Token).ConfigureAwait(false);
        try
        {
            request.Token.ThrowIfCancellationRequested();
            if (proofBackoff is { } unavailable &&
                Stopwatch.GetElapsedTime(proofBackoffTimestamp) <
                    (unavailable is DeepIdV2DirectoryProofUnavailableException { RetryAfter: { } retryAfter }
                        && retryAfter > refreshInterval
                        ? retryAfter : refreshInterval))
                throw unavailable;
            var retained = Volatile.Read(ref verifiedBinding);
            if (!forceRefresh && retained is not null &&
                Stopwatch.GetElapsedTime(bindingCreatedTimestamp) < refreshInterval)
            {
                try { retained.Network.EnsureCurrent(); }
                catch (OnionBoundaryException) { retained = null; Volatile.Write(ref verifiedBinding, null); }
                if (retained is not null)
                {
                    request.Token.ThrowIfCancellationRequested();
                    if (Volatile.Read(ref stopped) != 0)
                        throw new OperationCanceledException(lifetime.Token);
                    return retained;
                }
            }
            var binding = await receiveBindings.GetCurrentAsync(request.Token)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    "The ONION receive binding source returned no capability.");
            binding.Network.EnsureCurrent();
            if (!configuration.OwnsHandle(binding.KeyHandleId.Span))
            {
                throw new InvalidOperationException(
                    "The current ONION binding does not match the configured opaque key handle.");
            }
            request.Token.ThrowIfCancellationRequested();
            if (Volatile.Read(ref stopped) != 0)
                throw new OperationCanceledException(lifetime.Token);
            bindingCreatedTimestamp = Stopwatch.GetTimestamp();
            proofBackoff = null;
            lastFailure = null;
            Volatile.Write(ref verifiedBinding, binding);
            return binding;
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException or TimeoutException ||
            exception is OperationCanceledException && !request.IsCancellationRequested)
        {
            ReportFailure(exception);
            // Repeated local callers must not renew or bypass the same delay.
            // It is a scheduling hint only; no authority survives the failure.
            if (!ReferenceEquals(proofBackoff, exception))
            {
                proofBackoff = exception;
                proofBackoffTimestamp = Stopwatch.GetTimestamp();
            }
            Volatile.Write(ref verifiedBinding, null);
            throw;
        }
        catch (Exception exception)
        {
            ReportFailure(exception);
            Volatile.Write(ref verifiedBinding, null);
            throw;
        }
        finally { refreshGate.Release(); }
    }

    private void ReportFailure(Exception exception)
    {
        // Closed diagnostic categories only: never log exception messages,
        // inner exceptions, recipient ids, proof bytes, capabilities or paths.
        var category = exception switch {
            DeepIdV2DirectoryProofUnavailableException { StatusCode: System.Net.HttpStatusCode.TooManyRequests } => "proof-rate-limit",
            DeepIdV2DirectoryProofUnavailableException => "proof-unavailable",
            HttpRequestException { HttpRequestError: System.Net.Http.HttpRequestError.NameResolutionError } => "http-dns",
            HttpRequestException { HttpRequestError: System.Net.Http.HttpRequestError.ConnectionError } => "http-connect",
            HttpRequestException { HttpRequestError: System.Net.Http.HttpRequestError.SecureConnectionError } => "http-tls",
            HttpRequestException { HttpRequestError: System.Net.Http.HttpRequestError.ResponseEnded } => "http-response-ended",
            HttpRequestException => "http-transport",
            TimeoutException or OperationCanceledException => "request-timeout",
            CryptographicException => "cryptographic-rejection",
            OnionBoundaryException => "onion-boundary-rejection",
            InvalidDataException => "malformed-input",
            IOException => "custody-or-io",
            _ => "configuration-or-state"
        };
        if (lastFailure != category) logger?.LogWarning("ONION current capability unavailable ({Category}); retained custody and floors are unchanged.", category);
        lastFailure = category;
    }

    private async Task RefreshUntilStoppedAsync()
    {
        using var timer = new PeriodicTimer(refreshInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(lifetime.Token).ConfigureAwait(false))
            {
                try { _ = await ReadCurrentAsync(forceRefresh: true, lifetime.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { break; }
                catch (Exception exception) when (exception is IOException or InvalidOperationException or
                    HttpRequestException or TimeoutException or UnauthorizedAccessException or CryptographicException or
                    FormatException or OnionBoundaryException or OperationCanceledException)
                {
                    // Never retain stale authority after a failed refresh. The
                    // next bounded tick may recover only through fresh proof.
                    Volatile.Write(ref verifiedBinding, null);
                }
            }
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally { Volatile.Write(ref verifiedBinding, null); }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        lifetime.Dispose();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class PrivacyRoutingProductionComposition
{
    internal static void AddProductionPrivacyRoutingBoundary(
        this IServiceCollection services,
        PrivacyRoutingConfiguration configuration,
        RouterNodeOptions node)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(node);

        if (!configuration.Enabled)
        {
            services.TryAddSingleton<PrivacyRoutingRuntime>();
            return;
        }
        RequireRegistered<IDeepIdV2ReceiveNetworkSource>(services);
        RequirePath(configuration.StateProtectionKeyPath, "state protection key");
        RequirePath(configuration.ReplayStatePath, "replay state");
        RequirePath(configuration.EntropyStatePath, "entropy state");
        RequirePath(configuration.KeyVaultDirectory, "key vault");

        services.TryAddSingleton<IOnionHostReceiveBindingSource>(provider =>
            new VerifiedOnionHostReceiveBindingSource(
                provider.GetRequiredService<IDeepIdV2ReceiveNetworkSource>(),
                node,
                configuration));
        services.TryAddSingleton(provider => new DurableOnionReplayStore(
            configuration.ReplayStatePath,
            configuration.StateProtectionKeyPath,
            new DurableOnionReplayStoreOptions
            {
                MaximumEntries = configuration.ReplayCapacity
            }));
        services.TryAddSingleton(provider => new DurableOnionEntropyUniquenessLedger(
            configuration.EntropyStatePath,
            configuration.StateProtectionKeyPath,
            new DurableOnionEntropyLedgerOptions
            {
                MaximumCommitments = configuration.ReplayCapacity,
                MaximumBatchCommitments = 8
            }));
        services.TryAddSingleton(provider =>
        {
            FileOnionKeyAgreementVault.EnsureSlot(
                configuration.KeyVaultDirectory,
                configuration.KeyHandleId.Span,
                configuration.PrivateKeySpan,
                configuration.StateProtectionKeyPath);
            if (!configuration.NextPublicKey.IsEmpty)
                FileOnionKeyAgreementVault.EnsureSlot(configuration.KeyVaultDirectory,
                    configuration.NextKeyHandleId.Span, configuration.NextPrivateKeySpan,
                    configuration.StateProtectionKeyPath);
            return new FileOnionKeyAgreementVault(
                configuration.KeyVaultDirectory,
                configuration.StateProtectionKeyPath);
        });
        services.TryAddSingleton(provider => new OnionKeyAgreementAuthority(
            provider.GetRequiredService<FileOnionKeyAgreementVault>()));
        services.TryAddSingleton(provider => new OnionReplayAuthority(
            provider.GetRequiredService<DurableOnionReplayStore>()));
        services.TryAddSingleton(provider => new OnionEntropyAuthority(
            provider.GetRequiredService<DurableOnionEntropyUniquenessLedger>()));
        services.TryAddSingleton(provider => new PrivacyRoutingCodec(
            provider.GetRequiredService<OnionEntropyAuthority>(),
            provider.GetRequiredService<OnionKeyAgreementAuthority>()));
        services.TryAddSingleton<PrivacyRoutingProductionCapability>();
        services.AddHostedService(provider =>
            provider.GetRequiredService<PrivacyRoutingProductionCapability>());
        services.TryAddSingleton(provider => new PrivacyRoutingRuntime(
            configuration,
            provider.GetRequiredService<IPrivacyPeerClient>(),
            provider.GetRequiredService<INativeMailboxExitDispatcher>(),
            provider.GetRequiredService<PrivacyRoutingProductionCapability>(),
            provider.GetRequiredService<OnionKeyAgreementAuthority>(),
            provider.GetRequiredService<OnionReplayAuthority>(),
            provider.GetRequiredService<PrivacyRoutingCodec>()));
    }

    internal static byte[] DeriveKeyHandle(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length != 32 || publicKey.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The ONION public key must be exactly 32 nonzero bytes.",
                nameof(publicKey));
        }
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes("Deep/XPoint/V1/xnode-key-handle\0"));
        hash.AppendData(publicKey);
        return hash.GetHashAndReset();
    }

    private static void RequireRegistered<T>(IServiceCollection services)
    {
        if (!services.Any(static descriptor => descriptor.ServiceType == typeof(T)))
        {
            throw new InvalidOperationException(
                $"PrivacyRouting production activation requires a registered {typeof(T).Name}.");
        }
    }

    private static void RequirePath(string path, string name)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new InvalidOperationException(
                $"PrivacyRouting production activation requires a validated {name} path.");
        }
    }
}
