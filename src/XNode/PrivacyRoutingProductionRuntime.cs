using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using XNode.Core;
using XNode.Core.PrivacyRouting;

namespace XNode;

internal sealed class VerifiedOnionHostReceiveBindingSource(
    IContactVerifiedAuthoritySnapshotSource snapshots,
    RouterNodeOptions node,
    PrivacyRoutingConfiguration configuration)
    : IOnionHostReceiveBindingSource
{
    private readonly IContactVerifiedAuthoritySnapshotSource snapshots = snapshots
        ?? throw new ArgumentNullException(nameof(snapshots));
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

        var snapshot = await snapshots.ReadCurrentAsync(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                "The ONION authority source returned no current verified snapshot.");
        snapshot.EnsureConsistent();
        var candidates = OnionPathCandidateSnapshotFactory.Create(snapshot.Network)
            .Candidates
            .Where(candidate => Fixed(candidate.RouterOwnerId.Span, localOwnerId))
            .ToArray();
        if (candidates.Length != 1)
        {
            throw new InvalidOperationException(
                "The current verified XND1 view must contain exactly one node for the local router owner.");
        }

        var local = candidates[0];
        var requiredRoleBit = configuration.ReceivePosition switch
        {
            OnionReceivePosition.Ingress => 0,
            OnionReceivePosition.Core => 1,
            OnionReceivePosition.Exit => 2,
            _ => throw new InvalidOperationException(
                "The configured ONION receive position is invalid.")
        };
        if ((local.VerifiedRoleMask & (1 << requiredRoleBit)) == 0)
        {
            throw new InvalidOperationException(
                "The local node lacks the configured role in the current verified XND1 view.");
        }

        return new OnionHostReceiveBinding(
            snapshot.Network,
            configuration.ReceivePosition,
            local.NodeId.Span,
            configuration.KeyHandleId.Span);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class PrivacyRoutingProductionCapability(
    PrivacyRoutingConfiguration configuration,
    IOnionHostReceiveBindingSource receiveBindings) : IHostedService
{
    private readonly PrivacyRoutingConfiguration configuration = configuration
        ?? throw new ArgumentNullException(nameof(configuration));
    private readonly IOnionHostReceiveBindingSource receiveBindings = receiveBindings
        ?? throw new ArgumentNullException(nameof(receiveBindings));
    private int verified;

    internal bool IsVerified => configuration.Enabled && Volatile.Read(ref verified) == 1;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!configuration.Enabled)
        {
            return;
        }
        _ = await GetCurrentAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Volatile.Write(ref verified, 0);
        return Task.CompletedTask;
    }

    internal async ValueTask<OnionHostReceiveBinding> GetCurrentAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var binding = await receiveBindings.GetCurrentAsync(cancellationToken)
                .ConfigureAwait(false)
                ?? throw new InvalidOperationException(
                    "The ONION receive binding source returned no capability.");
            binding.Network.EnsureCurrent();
            if (binding.Position != configuration.ReceivePosition
                || !Fixed(binding.KeyHandleId.Span, configuration.KeyHandleId.Span))
            {
                throw new InvalidOperationException(
                    "The current ONION binding does not match the configured role or opaque key handle.");
            }
            Volatile.Write(ref verified, 1);
            return binding;
        }
        catch
        {
            Volatile.Write(ref verified, 0);
            throw;
        }
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
        RequireRegistered<IContactVerifiedAuthoritySnapshotSource>(services);
        RequirePath(configuration.StateProtectionKeyPath, "state protection key");
        RequirePath(configuration.ReplayStatePath, "replay state");
        RequirePath(configuration.EntropyStatePath, "entropy state");
        RequirePath(configuration.KeyVaultDirectory, "key vault");

        services.TryAddSingleton<IOnionHostReceiveBindingSource>(provider =>
            new VerifiedOnionHostReceiveBindingSource(
                provider.GetRequiredService<IContactVerifiedAuthoritySnapshotSource>(),
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
        if (services.Any(static descriptor => descriptor.ServiceType
            == typeof(IPrivacyRoutedContactRecipientResolveEvidenceIngestion)))
        {
            services.TryAddSingleton<IPrivacyRoutedContactRecipientResolveClient,
                PrivacyRoutedContactRecipientResolveClient>();
        }
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
