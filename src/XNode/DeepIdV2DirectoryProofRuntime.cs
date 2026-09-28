using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>
/// Explicit UAT-only DID2 proof boundary. It does not activate contact
/// publication, pre-key claim or messaging by itself.
/// </summary>
public sealed class DeepIdV2DirectoryProofOptions
{
    public bool Enabled { get; set; }
    public string RegistryOrigin { get; set; } = string.Empty;
    public string NetworkIdHex { get; set; } = string.Empty;
    public string GenesisAuthorityCoreHashHex { get; set; } = string.Empty;
    public List<string> ExactAuthorityPaths { get; set; } = [];
    public List<string> ExactTimePolicyPaths { get; set; } = [];
    public string GenesisHeadPath { get; set; } = string.Empty;
    public string GenesisHeadCoreHashHex { get; set; } = string.Empty;
    public string StateRelativeDirectory { get; set; } = string.Empty;
    public string DataProtectionKeysRelativeDirectory { get; set; } = string.Empty;
    public ushort DeploymentProfileId { get; set; }
    public int RequestTimeoutSeconds { get; set; }

    internal DeepIdV2DirectoryProofConfiguration? ValidateAndLoad(
        RouterNodeOptions node, bool developmentOrUat,
        bool v1ContactAuthorityEnabled)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (RegistryOrigin is null || NetworkIdHex is null ||
            GenesisAuthorityCoreHashHex is null ||
            ExactAuthorityPaths is null || ExactTimePolicyPaths is null ||
            GenesisHeadPath is null || GenesisHeadCoreHashHex is null ||
            StateRelativeDirectory is null ||
            DataProtectionKeysRelativeDirectory is null)
            throw new InvalidOperationException(
                "DID2 proof configuration must not contain null fields.");
        var any = Enabled || RegistryOrigin.Length != 0 ||
            NetworkIdHex.Length != 0 || GenesisAuthorityCoreHashHex.Length != 0 ||
            ExactAuthorityPaths.Count != 0 || ExactTimePolicyPaths.Count != 0 ||
            GenesisHeadPath.Length != 0 || GenesisHeadCoreHashHex.Length != 0 ||
            StateRelativeDirectory.Length != 0 ||
            DataProtectionKeysRelativeDirectory.Length != 0 ||
            DeploymentProfileId != 0 || RequestTimeoutSeconds != 0;
        if (!Enabled)
        {
            if (any) throw new InvalidOperationException(
                "DID2 directory proof configuration is partial while disabled.");
            return null;
        }
        if (!developmentOrUat || v1ContactAuthorityEnabled)
            throw new InvalidOperationException(
                "DID2 proof UAT must not reuse the V1 contact authority or activate as production.");
        if (string.IsNullOrWhiteSpace(RegistryOrigin) ||
            string.IsNullOrWhiteSpace(GenesisHeadPath) ||
            !Path.IsPathFullyQualified(GenesisHeadPath) ||
            DeploymentProfileId == 0 || RequestTimeoutSeconds is < 1 or > 30)
            throw new InvalidOperationException(
                "DID2 proof requires exact Registry, genesis and bounded timeout settings.");

        var network = ParseHex(NetworkIdHex, 16, nameof(NetworkIdHex));
        var authorityHash = ParseHex(GenesisAuthorityCoreHashHex, 32,
            nameof(GenesisAuthorityCoreHashHex));
        var headHash = ParseHex(GenesisHeadCoreHashHex, 32,
            nameof(GenesisHeadCoreHashHex));
        try
        {
            var pin = new XPointNetworkGenesisPin(network, authorityHash);
            var source = new DeepIdV2NetworkAuthorityFileSource(pin,
                ExactAuthorityPaths, ExactTimePolicyPaths);
            var root = Path.GetFullPath(node.DataDirectory);
            var state = ResolveDirectory(root, StateRelativeDirectory);
            var keys = ResolveDirectory(root, DataProtectionKeysRelativeDirectory);
            if (state == keys || IsWithin(state, keys) || IsWithin(keys, state))
                throw new InvalidOperationException(
                    "DID2 protected head journal and key ring must be separate.");
            foreach (var reserved in new[] { "did2-head-anchor", "did2-network-state", "did2-network-anchor" })
            {
                var anchor = Path.Combine(root, reserved);
                if (IsWithin(state, anchor) || IsWithin(anchor, state) ||
                    IsWithin(keys, anchor) || IsWithin(anchor, keys))
                    throw new InvalidOperationException(
                        "DID2 proof custody must not overlap a reserved protected floor.");
            }
            var genesis = Path.GetFullPath(GenesisHeadPath);
            if (IsWithin(genesis, state) || IsWithin(genesis, keys))
                throw new InvalidOperationException(
                    "DID2 signed genesis must be outside mutable proof custody.");
            _ = HttpsDeepIdV2DirectoryProofArtifactSource.CreateEndpoint(
                RegistryOrigin);
            return new DeepIdV2DirectoryProofConfiguration(source, genesis,
                headHash, root, state, keys, RegistryOrigin,
                DeploymentProfileId,
                TimeSpan.FromSeconds(RequestTimeoutSeconds));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(authorityHash);
        }
    }

    private static byte[] ParseHex(string value, int length, string name)
    {
        if (value.Length != length * 2)
            throw new InvalidOperationException(
                $"DID2 proof {name} requires {length * 2} uppercase hex characters.");
        byte[] bytes;
        try { bytes = Convert.FromHexString(value); }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"DID2 proof {name} is not hexadecimal.", exception);
        }
        if (Convert.ToHexString(bytes) != value ||
            bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            throw new InvalidOperationException(
                $"DID2 proof {name} must be canonical and nonzero.");
        return bytes;
    }

    private static string ResolveDirectory(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) ||
            relative != relative.Trim() ||
            Path.IsPathFullyQualified(relative))
            throw new InvalidOperationException(
                "DID2 proof state directories must be clean relative paths.");
        var path = Path.GetFullPath(Path.Combine(root, relative));
        if (!IsWithin(path, root) || path == root)
            throw new InvalidOperationException(
                "DID2 proof state directories must stay under Node:DataDirectory.");
        return path;
    }

    private static bool IsWithin(string path, string directory)
    {
        var relative = Path.GetRelativePath(directory, path);
        return relative == "." ||
            (relative != ".." &&
             !relative.StartsWith($"..{Path.DirectorySeparatorChar}",
                 StringComparison.Ordinal) &&
             !Path.IsPathFullyQualified(relative));
    }
}

internal sealed record DeepIdV2DirectoryProofConfiguration(
    DeepIdV2NetworkAuthorityFileSource Authority,
    string ExactGenesisPath, byte[] PinnedGenesisCoreHash,
    string NodeDataDirectory, string StateDirectory, string KeyDirectory,
    string RegistryOrigin, ushort DeploymentProfileId,
    TimeSpan RequestTimeout);

internal interface IDeepIdV2CurrentDirectoryProofSource
{
    ValueTask<VerifiedDeepIdV2DirectoryFreshness> ReadCurrentAsync(
        ParsedDid2 did2, CancellationToken cancellationToken);
}

internal sealed class DeepIdV2DirectoryProofRuntime :
    IDeepIdV2CurrentDirectoryProofSource, IDisposable
{
    private readonly DeepIdV2DirectoryProofConfiguration configuration;
    private readonly DeepIdV2DirectoryCurrentProofReader reader;
    private readonly FileDeepIdV2DirectoryProtectedHeadStore store;
    private readonly IDeepMlDsa65VerifierLease verifier;
    private readonly IDisposable? protection;
    private readonly IDataProtectionProvider networkProtection;

    internal DeepIdV2DirectoryProofRuntime(
        DeepIdV2DirectoryProofConfiguration configuration,
        HttpClient client, IOnionMonotonicClock clock,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        this.configuration = configuration ??
            throw new ArgumentNullException(nameof(configuration));
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(clock);
        ArgumentNullException.ThrowIfNull(security);
        ArgumentNullException.ThrowIfNull(durability);
        var authority = configuration.Authority.ReadCurrent();
        var genesis = DeepIdV2NetworkAuthorityFileSource.ReadExact(
            configuration.ExactGenesisPath);
        IDataProtectionProvider? provider = null;
        FileDeepIdV2DirectoryProtectedHeadStore? opened = null;
        IDeepMlDsa65VerifierLease? lease = null;
        try
        {
            _ = DeepIdV2DirectoryBootstrapVerifier.RestoreGenesis(authority,
                genesis, configuration.PinnedGenesisCoreHash);
            security.SecureDirectory(configuration.KeyDirectory);
            provider = DataProtectionProvider.Create(
                new DirectoryInfo(configuration.KeyDirectory),
                builder => builder.SetApplicationName(
                    "XPoint.XNode.DID2.DirectoryProof.v2"));
            opened = new FileDeepIdV2DirectoryProtectedHeadStore(
                configuration.StateDirectory,
                configuration.NodeDataDirectory, genesis,
                configuration.PinnedGenesisCoreHash,
                provider, security, durability);
            lease = DeepMlDsa65CandidateVerifierFactory.OpenForCurrentProcess();
            var artifacts = new HttpsDeepIdV2DirectoryProofArtifactSource(
                client, configuration.RegistryOrigin, configuration.RequestTimeout);
            reader = new DeepIdV2DirectoryCurrentProofReader(
                artifacts, opened, clock, lease);
            store = opened;
            verifier = lease;
            protection = provider as IDisposable;
            networkProtection = provider;
        }
        catch
        {
            lease?.Dispose();
            opened?.Dispose();
            (provider as IDisposable)?.Dispose();
            throw;
        }
        finally { CryptographicOperations.ZeroMemory(genesis); }
    }

    public ValueTask<VerifiedDeepIdV2DirectoryFreshness> ReadCurrentAsync(
        ParsedDid2 did2, CancellationToken cancellationToken)
    {
        var authority = configuration.Authority.ReadCurrent();
        return reader.ReadCurrentAsync(did2, authority,
            configuration.DeploymentProfileId, supportedReader: 2,
            cancellationToken);
    }

    internal ValueTask<AccountDirectoryProtectedLkg> RestoreHeadAsync(
        CancellationToken cancellationToken) =>
        store.RestoreAsync(configuration.Authority.ReadCurrent(),
            cancellationToken);

    internal VerifiedXPointNetworkAuthority ReadCurrentNetworkAuthority() =>
        configuration.Authority.ReadCurrent();

    internal FileDeepIdV2NetworkFloorStore OpenNetworkFloor(RouterNodeOptions node,
        IMailboxStorageSecurity security, IMailboxDurabilityBarrier durability) =>
        new(configuration.NodeDataDirectory,
            networkProtection.CreateProtector("Deep.XNode.DID2.NetworkFloor.v2",
                Convert.ToHexString(configuration.PinnedGenesisCoreHash),
                Convert.ToHexString(node.GetRouterId().ToBytes())), security, durability);

    public void Dispose()
    {
        store.Dispose();
        verifier.Dispose();
        protection?.Dispose();
    }
}

internal sealed class DeepIdV2DirectoryProofHostedService(
    DeepIdV2DirectoryProofRuntime runtime) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _ = await runtime.RestoreHeadAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}

internal static class DeepIdV2DirectoryProofHostComposition
{
    internal static IServiceCollection AddDeepIdV2DirectoryProof(
        this IServiceCollection services,
        DeepIdV2DirectoryProofConfiguration configuration)
    {
        services.AddSingleton(configuration);
        services.AddSingleton(configuration.Authority);
        services.AddHttpClient("did2-directory-proof")
            .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None
            });
        services.AddSingleton(provider => new DeepIdV2DirectoryProofRuntime(
            configuration,
            provider.GetRequiredService<IHttpClientFactory>()
                .CreateClient("did2-directory-proof"),
            provider.GetRequiredService<IOnionMonotonicClock>(),
            provider.GetRequiredService<IMailboxStorageSecurity>(),
            provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton<IDeepIdV2CurrentDirectoryProofSource>(provider =>
            provider.GetRequiredService<DeepIdV2DirectoryProofRuntime>());
        services.AddSingleton<DeepIdV2PublicationCandidateAuthority>();
        services.AddHostedService<DeepIdV2DirectoryProofHostedService>();
        return services;
    }
}
