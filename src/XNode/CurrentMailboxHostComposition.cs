using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode;

// These are local custody bindings, never issuer, membership or time authority.
internal sealed class CurrentMailboxCustodyOptions
{
    public string NetworkIdHex { get; set; } = "";
    public string MailboxAuthorityCoreHashHex { get; set; } = "";
    public string IndependentCustodyDirectory { get; set; } = "";
    public string DataProtectionKeysDirectory { get; set; } = "";

    internal CurrentMailboxCustodyConfiguration? Validate(RouterNodeOptions node, ReplicatedMailboxOptions mailbox)
    {
        ArgumentNullException.ThrowIfNull(node); ArgumentNullException.ThrowIfNull(mailbox);
        if (!mailbox.Enabled)
        {
            if (NetworkIdHex != "" || MailboxAuthorityCoreHashHex != "" ||
                IndependentCustodyDirectory != "" || DataProtectionKeysDirectory != "")
                throw new InvalidOperationException("Current mailbox custody cannot be partially configured while disabled.");
            return null;
        }
        var network = FixedHex(NetworkIdHex, 16); var policyHash = FixedHex(MailboxAuthorityCoreHashHex, 32);
        var data = AbsoluteDirectory(node.DataDirectory);
        var custody = AbsoluteDirectory(IndependentCustodyDirectory);
        var keys = AbsoluteDirectory(DataProtectionKeysDirectory);
        if (Overlaps(data, custody) || Overlaps(data, keys) || Overlaps(custody, keys))
            throw new InvalidOperationException("Mailbox data, independent custody and key ring must be disjoint directories.");
        mailbox.Validate();
        if (mailbox.AllowInsecureHttpPeerTransport)
            throw new InvalidOperationException("Current mailbox peer transport requires descriptor-bound TLS.");
        return new(network, [.. "PMA2"u8, 0, 1, .. policyHash], custody, keys);
    }

    private static byte[] FixedHex(string? value, int size)
    {
        if (value is null || value.Length != size * 2 ||
            value.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidOperationException("Current mailbox scope requires canonical fixed-width public bindings.");
        var bytes = Convert.FromHexString(value);
        if (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException("Current mailbox scope cannot contain an absent public binding.");
        return bytes;
    }

    private static string AbsoluteDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException("Current mailbox custody requires absolute non-root directories.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (string.Equals(full, Path.TrimEndingDirectorySeparator(Path.GetPathRoot(full)!), PathComparison))
            throw new InvalidOperationException("A filesystem root cannot be mailbox custody.");
        return full;
    }
    private static StringComparison PathComparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static bool Overlaps(string left, string right) =>
        string.Equals(left, right, PathComparison) || left.StartsWith(right + Path.DirectorySeparatorChar, PathComparison) ||
        right.StartsWith(left + Path.DirectorySeparatorChar, PathComparison);
}

internal sealed record CurrentMailboxCustodyConfiguration(byte[] NetworkId, byte[] PolicyReference,
    string IndependentCustodyDirectory, string DataProtectionKeysDirectory);

internal static class CurrentMailboxHostComposition
{
    internal const string ProtectionApplication = "XPoint.XNode.Mailbox.Custody.v1";
    internal const string OperationDirectory = "mailbox-client-intent";

    internal static IServiceCollection AddCurrentMailboxHost(this IServiceCollection services,
        CurrentMailboxCustodyConfiguration? configuration, RouterNodeOptions node, ReplicatedMailboxOptions mailbox)
    {
        if (configuration is null) return services;
        if (!mailbox.Enabled || !services.Any(d => d.ServiceType == typeof(IDeepIdV2ContactStoreAuthoritySource)) ||
            !services.Any(d => d.ServiceType == typeof(IOnionMonotonicClock)))
            throw new InvalidOperationException("Current mailbox requires the real current network/time source.");
        Type[] ownedServices = [typeof(CurrentMailboxReplicaReceiver), typeof(CurrentMailboxReplicationCoordinator),
            typeof(MailboxClientOperationLedger), typeof(FileMailboxOperationCustody), typeof(FileMailboxGrantRevocationStore),
            typeof(ReplicatedMailboxStore), typeof(MailboxPeerMutationStore), typeof(DurableMailboxPeerReplayJournal),
            typeof(DurableMailboxCapabilityReplayJournal), typeof(MailboxClientCanonicalOutcomeStore),
            typeof(MailboxAuthenticatedCapabilityRuntime), typeof(CurrentMailboxAdmission),
            typeof(ICurrentMailboxReplicaPeerClient), typeof(CurrentMailboxPeerHttpEndpoint)];
        if (services.Any(d => ownedServices.Contains(d.ServiceType) ||
            d.ServiceType == typeof(IDataProtectionProvider) && d.IsKeyedService &&
            Equals(d.ServiceKey, typeof(CurrentMailboxHostComposition))))
            throw new InvalidOperationException("Current mailbox cannot share or replace another native owner graph.");

        // Capture local bindings before deferred DI callbacks; mutable options
        // must not redirect a native owner after registration.
        configuration = configuration with { NetworkId = configuration.NetworkId.ToArray(), PolicyReference = configuration.PolicyReference.ToArray() };
        var dataDirectory = Path.GetFullPath(node.DataDirectory);
        var id = Convert.FromHexString(node.GetRouterId().Value);
        services.AddKeyedSingleton<IDataProtectionProvider>(typeof(CurrentMailboxHostComposition), (provider, _) =>
            OpenProtection(configuration, provider.GetRequiredService<IMailboxStorageSecurity>()));
        foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
            services.AddKeyedSingleton<FileMailboxGrantRevocationStore>(role, (provider, key) => new(
                dataDirectory, configuration.IndependentCustodyDirectory, id, configuration.NetworkId,
                configuration.PolicyReference, (MailboxCapabilityDomain)key!, Protection(provider),
                provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new FileMailboxOperationCustody(dataDirectory,
            configuration.IndependentCustodyDirectory, OperationDirectory, id, configuration.NetworkId, Protection(provider),
            provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new MailboxClientOperationLedger(dataDirectory,
            new MailboxClientAdapterOptions { DirectoryName = OperationDirectory },
            provider.GetRequiredService<FileMailboxOperationCustody>(), new NoWallClock(),
            provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new ReplicatedMailboxStore(dataDirectory, mailbox, new NoWallClock(),
            provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new MailboxPeerMutationStore(dataDirectory, mailbox,
            provider.GetRequiredService<ReplicatedMailboxStore>(), new NoWallClock(),
            provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new DurableMailboxPeerReplayJournal(dataDirectory, mailbox, new NoWallClock(),
            provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new DurableMailboxCapabilityReplayJournal(dataDirectory,
            security: provider.GetRequiredService<IMailboxStorageSecurity>(), durability: provider.GetRequiredService<IMailboxDurabilityBarrier>(), clock: new NoWallClock()));
        services.AddSingleton(provider => new MailboxClientCanonicalOutcomeStore(dataDirectory,
            security: provider.GetRequiredService<IMailboxStorageSecurity>(), durability: provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new MailboxAuthenticatedCapabilityRuntime(new RejectAllMailboxCapabilityAuthoritySource(),
            new RejectAllMailboxCapabilityRevocationPolicy(), provider.GetRequiredService<DurableMailboxCapabilityReplayJournal>(),
            provider.GetRequiredService<MailboxClientCanonicalOutcomeStore>(), new NoWallClock()));
        services.AddSingleton(provider => new CurrentMailboxAdmission(provider.GetRequiredService<IDeepIdV2ContactStoreAuthoritySource>(),
            provider.GetRequiredService<IOnionMonotonicClock>(), id,
            provider.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit),
            provider.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Retrieve),
            provider.GetRequiredService<MailboxAuthenticatedCapabilityRuntime>()));
        services.AddSingleton(provider =>
        {
            var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
            try { return new CurrentMailboxReplicaReceiver(provider.GetRequiredService<CurrentMailboxAdmission>(),
                provider.GetRequiredService<MailboxPeerMutationStore>(), provider.GetRequiredService<DurableMailboxPeerReplayJournal>(),
                seed, provider.GetRequiredService<MailboxClientOperationLedger>()); }
            finally { CryptographicOperations.ZeroMemory(seed); }
        });
        services.AddSingleton<ICurrentMailboxReplicaPeerClient, CurrentMailboxReplicaPeerClient>();
        services.AddSingleton<CurrentMailboxReplicationCoordinator>();
        services.AddSingleton(provider => new CurrentMailboxPeerHttpEndpoint(provider.GetRequiredService<CurrentMailboxReplicaReceiver>(),
            NodeListenerConfiguration.Create(node).PrivacyPeerPort));
        // Only the already reviewed configured DID2 source graph has an actual
        // Registry origin/strict TLS handler. Fixture-owned sources do not activate a worker.
        if (services.Any(d => d.ServiceType == typeof(DeepIdV2DirectoryProofConfiguration)))
        {
            services.AddSingleton<IMailboxGrantRevocationArtifactSource>(provider =>
                new HttpsMailboxGrantRevocationArtifactSource(provider.GetRequiredService<IHttpClientFactory>()
                    .CreateClient("did2-directory-proof"), provider.GetRequiredService<DeepIdV2DirectoryProofConfiguration>().RegistryOrigin));
            services.AddHostedService<CurrentMailboxRevocationRefreshWorker>();
        }
        return services;
    }

    private static IDataProtectionProvider Protection(IServiceProvider services) =>
        services.GetRequiredKeyedService<IDataProtectionProvider>(typeof(CurrentMailboxHostComposition));

    private static IDataProtectionProvider OpenProtection(CurrentMailboxCustodyConfiguration configuration, IMailboxStorageSecurity security)
    {
        var directory = new DirectoryInfo(configuration.DataProtectionKeysDirectory);
        for (var parent = directory; parent is not null; parent = parent.Parent)
            if (!parent.Exists || (parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Current mailbox key ring is absent or linked; provisioning is explicit.");
        var keys = directory.GetFiles("key-*.xml");
        if (keys.Length == 0) throw new InvalidDataException("Current mailbox key ring is absent; no generation is allowed by a reader.");
        foreach (var key in keys)
        {
            if ((key.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new InvalidDataException("Current mailbox key ring requires regular files.");
            security.ValidateSecureFile(key.FullName);
        }
        return DataProtectionProvider.Create(directory, builder => builder.SetApplicationName(ProtectionApplication).DisableAutomaticKeyGeneration());
    }

    private sealed class NoWallClock : IClock
    { public DateTimeOffset UtcNow => throw new InvalidOperationException("Current mailbox requires its held protected time interval."); }
}
