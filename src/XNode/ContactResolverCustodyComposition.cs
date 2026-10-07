using Microsoft.AspNetCore.DataProtection;
using XNode.Core;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode;

// Configuration binds local custody, never membership, publication or time authority.
internal sealed class ContactResolverCustodyOptions
{
    public string NetworkIdHex { get; set; } = "";
    public string IndependentCustodyDirectory { get; set; } = "";
    public string DataProtectionKeysDirectory { get; set; } = "";

    internal ContactResolverCustodyConfiguration? Validate(RouterNodeOptions node, bool enabled)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (!enabled)
        {
            if (NetworkIdHex != "" || IndependentCustodyDirectory != "" || DataProtectionKeysDirectory != "")
                throw new InvalidOperationException("Resolver custody cannot be configured while the DID2 resolver is disabled.");
            return null;
        }
        if (NetworkIdHex is not { Length: 32 } || NetworkIdHex.Any(c => c is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidOperationException("Resolver custody requires an exact canonical public network binding.");
        var network = Convert.FromHexString(NetworkIdHex);
        if (network.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException("Resolver custody network binding cannot be absent.");
        var data = Absolute(node.DataDirectory); var custody = Absolute(IndependentCustodyDirectory);
        var keys = Absolute(DataProtectionKeysDirectory);
        if (Overlaps(data, custody) || Overlaps(data, keys) || Overlaps(custody, keys))
            throw new InvalidOperationException("Resolver data, independent custody and key ring must be disjoint.");
        return new(network, data, custody, keys, node.GetRouterId().ToBytes());
    }

    private static StringComparison Comparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    private static string Absolute(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException("Resolver custody requires absolute non-root directories.");
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        if (string.Equals(full, Path.TrimEndingDirectorySeparator(Path.GetPathRoot(full)!), Comparison))
            throw new InvalidOperationException("Resolver custody cannot use a filesystem root.");
        return full;
    }
    private static bool Overlaps(string a, string b) => string.Equals(a, b, Comparison) ||
        a.StartsWith(b + Path.DirectorySeparatorChar, Comparison) || b.StartsWith(a + Path.DirectorySeparatorChar, Comparison);
}

internal sealed record ContactResolverCustodyConfiguration(byte[] Network, string DataDirectory,
    string IndependentCustodyDirectory, string DataProtectionKeysDirectory, byte[] NodeId);

internal static class ContactResolverCustodyComposition
{
    internal const string ProtectionApplication = "XPoint.XNode.ContactResolver.Custody.v1";

    internal static void AddContactResolverCustody(this IServiceCollection services,
        ContactResolverCustodyConfiguration? configuration)
    {
        if (configuration is null) return;
        if (services.Any(d => d.ServiceType == typeof(FileContactResolverStateCustody) ||
            d.ServiceType == typeof(IDataProtectionProvider) && d.IsKeyedService &&
            Equals(d.ServiceKey, typeof(ContactResolverCustodyComposition))))
            throw new InvalidOperationException("Resolver custody cannot replace another native owner graph.");
        configuration = configuration with { Network = configuration.Network.ToArray(), NodeId = configuration.NodeId.ToArray() };
        services.AddKeyedSingleton<IDataProtectionProvider>(typeof(ContactResolverCustodyComposition), (provider, _) =>
            NativeCustodyKeyRing.OpenExisting(configuration.DataProtectionKeysDirectory, ProtectionApplication,
                provider.GetRequiredService<IMailboxStorageSecurity>()));
        services.AddSingleton(provider =>
        {
            var node = provider.GetRequiredService<RouterNodeOptions>();
            var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(node.DataDirectory)), configuration.DataDirectory, comparison) ||
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(node.GetRouterId().ToBytes(), configuration.NodeId))
                throw new InvalidOperationException("Deferred resolver composition cannot change its captured node/data binding.");
            return new FileContactResolverStateCustody(configuration.DataDirectory,
                configuration.IndependentCustodyDirectory, configuration.NodeId, configuration.Network,
                provider.GetRequiredKeyedService<IDataProtectionProvider>(typeof(ContactResolverCustodyComposition)),
                new ContactResolverOpaqueStoreOptions().MaximumPersistedBytes,
                provider.GetRequiredService<IMailboxStorageSecurity>(), provider.GetRequiredService<IMailboxDurabilityBarrier>());
        });
    }
}
