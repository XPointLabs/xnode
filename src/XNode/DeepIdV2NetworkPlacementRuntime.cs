using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

/// <summary>
/// UAT-only exact network closure for DID2 contact placement. No V1 ADP1
/// snapshot or caller-projected placement can enter this source.
/// </summary>
public sealed class DeepIdV2NetworkPlacementOptions
{
    public bool Enabled { get; set; }
    public List<string> ExactPolicyPaths { get; set; } = [];
    public List<string> ExactViewPaths { get; set; } = [];
    public List<string> ExactHeadPaths { get; set; } = [];
    public List<string> ExactActiveNodePaths { get; set; } = [];
    public List<string> ExactMailboxProjectionPaths { get; set; } = [];

    internal DeepIdV2NetworkClosureFileSource? ValidateAndLoad(
        bool did2ProofEnabled, bool developmentOrUat)
    {
        if (ExactPolicyPaths is null || ExactViewPaths is null ||
            ExactHeadPaths is null || ExactActiveNodePaths is null ||
            ExactMailboxProjectionPaths is null)
            throw new InvalidOperationException(
                "DID2 network placement configuration has null paths.");
        var any = Enabled || ExactPolicyPaths.Count != 0 ||
            ExactViewPaths.Count != 0 || ExactHeadPaths.Count != 0 ||
            ExactActiveNodePaths.Count != 0 ||
            ExactMailboxProjectionPaths.Count != 0;
        if (!Enabled)
        {
            if (any) throw new InvalidOperationException(
                "DID2 network placement configuration is partial while disabled.");
            return null;
        }
        if (!did2ProofEnabled || !developmentOrUat)
            throw new InvalidOperationException(
                "DID2 UAT placement requires the independent DID2 proof boundary.");
        return new DeepIdV2NetworkClosureFileSource(ExactPolicyPaths,
            ExactViewPaths, ExactHeadPaths, ExactActiveNodePaths,
            ExactMailboxProjectionPaths);
    }
}

internal sealed class DeepIdV2NetworkClosureFileSource
{
    private const int MaximumChainCount = 4_096;
    private const long MaximumClosureBytes = 64L * 1024 * 1024;
    private readonly string[][] paths;

    internal DeepIdV2NetworkClosureFileSource(
        IReadOnlyList<string> policies, IReadOnlyList<string> views,
        IReadOnlyList<string> heads, IReadOnlyList<string> nodes,
        IReadOnlyList<string> projections)
    {
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(views);
        ArgumentNullException.ThrowIfNull(heads);
        ArgumentNullException.ThrowIfNull(nodes);
        ArgumentNullException.ThrowIfNull(projections);
        if (policies.Count is < 1 or > MaximumChainCount ||
            views.Count is < 1 or > MaximumChainCount ||
            heads.Count != views.Count ||
            nodes.Count is < 1 or > MaximumChainCount ||
            projections.Count is < 1 or > MaximumChainCount)
            throw new ArgumentException(
                "DID2 network closure requires bounded complete ordered chains.");
        paths = [Copy(policies), Copy(views), Copy(heads), Copy(nodes),
            Copy(projections)];
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (paths.SelectMany(static group => group).Distinct(comparer).Count() !=
            paths.Sum(static group => group.Length))
            throw new ArgumentException(
                "DID2 network closure paths must be distinct.");
    }

    internal DeepIdV2NetworkClosureArtifacts ReadCurrent()
    {
        var groups = new byte[paths.Length][][];
        long total = 0;
        try
        {
            for (var group = 0; group < paths.Length; group++)
            {
                groups[group] = new byte[paths[group].Length][];
                for (var index = 0; index < paths[group].Length; index++)
                {
                    var exact = DeepIdV2NetworkAuthorityFileSource.ReadExact(
                        paths[group][index]);
                    groups[group][index] = exact;
                    total = checked(total + exact.Length);
                    if (total > MaximumClosureBytes)
                        throw new InvalidDataException(
                            "DID2 network closure exceeds its total byte bound.");
                }
            }
            return new DeepIdV2NetworkClosureArtifacts(groups);
        }
        catch
        {
            foreach (var exact in groups.Where(static group => group is not null)
                         .SelectMany(static group => group))
                if (exact is not null) CryptographicOperations.ZeroMemory(exact);
            throw;
        }
    }

    private static string[] Copy(IReadOnlyList<string> candidates)
    {
        var output = new string[candidates.Count];
        for (var index = 0; index < output.Length; index++)
        {
            var path = candidates[index];
            if (string.IsNullOrWhiteSpace(path) || path != path.Trim() ||
                !Path.IsPathFullyQualified(path))
                throw new ArgumentException(
                    "DID2 network artifacts require clean absolute paths.");
            output[index] = Path.GetFullPath(path);
        }
        return output;
    }
}

internal sealed class DeepIdV2NetworkClosureArtifacts(byte[][][] groups) :
    IDisposable
{
    internal IReadOnlyList<ReadOnlyMemory<byte>> Policies => Copy(groups[0]);
    internal IReadOnlyList<ReadOnlyMemory<byte>> Views => Copy(groups[1]);
    internal IReadOnlyList<ReadOnlyMemory<byte>> Heads => Copy(groups[2]);
    internal IReadOnlyList<ReadOnlyMemory<byte>> Nodes => Copy(groups[3]);
    internal IReadOnlyList<ReadOnlyMemory<byte>> Projections => Copy(groups[4]);

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(byte[][] group) =>
        Array.AsReadOnly(group.Select(static exact =>
            (ReadOnlyMemory<byte>)exact).ToArray());

    public void Dispose()
    {
        foreach (var exact in groups.SelectMany(static group => group))
            CryptographicOperations.ZeroMemory(exact);
    }
}

internal sealed class DeepIdV2NetworkPlacementRuntime(
    DeepIdV2DirectoryProofRuntime proofs,
    DeepIdV2NetworkClosureFileSource artifacts,
    IOnionMonotonicClock clock)
{
    internal async ValueTask<ContactServicePlacementCapability>
        MintPreKeyPublicationAsync(ParsedDid2 publisher,
            ReadOnlyMemory<byte> serviceCapability,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        if (serviceCapability.Length != 32 ||
            serviceCapability.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "DID2 pre-key publication needs a nonzero service capability.",
                nameof(serviceCapability));
        var freshness = await proofs.ReadCurrentAsync(publisher,
            cancellationToken).ConfigureAwait(false);
        if (freshness.CurrentCheckpoint is null)
            throw new CryptographicException(
                "DID2 publication placement requires a current account checkpoint.");
        var authority = proofs.ReadCurrentNetworkAuthority();
        using var exact = artifacts.ReadCurrent();
        var network = await OnionNetworkContextVerifier.VerifyAsync(
            authority, freshness, exact.Policies, exact.Views, exact.Heads,
            exact.Nodes, exact.Projections, protectedPrevious: null,
            new OnionTrustedTimeAuthority(clock), cancellationToken)
            .ConfigureAwait(false);
        network.EnsureCurrent();
        var placement = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.PublishPreKeyInventory,
            serviceCapability);
        return ContactServicePlacementCapability.FromNetcodec(placement,
            ContactServiceRequestKind.PublishPreKeyInventory,
            serviceCapability, freshness.TrustedUpperUnixSeconds);
    }
}

internal static class DeepIdV2NetworkPlacementHostComposition
{
    internal static IServiceCollection AddDeepIdV2NetworkPlacement(
        this IServiceCollection services,
        DeepIdV2NetworkClosureFileSource artifacts)
    {
        services.AddSingleton(artifacts);
        services.AddSingleton<DeepIdV2NetworkPlacementRuntime>();
        services.AddHostedService<DeepIdV2NetworkPlacementHostedService>();
        return services;
    }
}

internal sealed class DeepIdV2NetworkPlacementHostedService(
    DeepIdV2NetworkClosureFileSource artifacts) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var exact = artifacts.ReadCurrent();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
