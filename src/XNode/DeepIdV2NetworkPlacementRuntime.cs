using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
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
    public List<string> ExactMailboxAuthorityPaths { get; set; } = [];
    public string PublicObservationDid2Path { get; set; } = string.Empty;
    public string PublicBundlePath { get; set; } = string.Empty;

    internal DeepIdV2NetworkClosureFileSource? ValidateAndLoad(
        bool did2ProofEnabled, bool developmentOrUat)
    {
        if (ExactPolicyPaths is null || ExactViewPaths is null ||
            ExactHeadPaths is null || ExactActiveNodePaths is null ||
            ExactMailboxProjectionPaths is null || ExactMailboxAuthorityPaths is null || PublicObservationDid2Path is null || PublicBundlePath is null)
            throw new InvalidOperationException(
                "DID2 network placement configuration has null paths.");
        var any = Enabled || ExactPolicyPaths.Count != 0 ||
            ExactViewPaths.Count != 0 || ExactHeadPaths.Count != 0 ||
            ExactActiveNodePaths.Count != 0 ||
            ExactMailboxProjectionPaths.Count != 0 || ExactMailboxAuthorityPaths.Count != 0 || PublicObservationDid2Path.Length != 0 || PublicBundlePath.Length != 0;
        if (!Enabled)
        {
            if (any) throw new InvalidOperationException(
                "DID2 network placement configuration is partial while disabled.");
            return null;
        }
        if (!did2ProofEnabled || !developmentOrUat)
            throw new InvalidOperationException(
                "DID2 UAT placement requires the independent DID2 proof boundary.");
        if (PublicBundlePath.Length != 0)
        {
            if (ExactPolicyPaths.Count + ExactViewPaths.Count + ExactHeadPaths.Count +
                ExactActiveNodePaths.Count + ExactMailboxProjectionPaths.Count + ExactMailboxAuthorityPaths.Count != 0)
                throw new InvalidOperationException("A mutable closure must use one atomic bundle, not mixed file generations.");
            return new DeepIdV2NetworkClosureFileSource(PublicBundlePath, PublicObservationDid2Path);
        }
        return new DeepIdV2NetworkClosureFileSource(ExactPolicyPaths,
            ExactViewPaths, ExactHeadPaths, ExactActiveNodePaths,
            ExactMailboxProjectionPaths, ExactMailboxAuthorityPaths, PublicObservationDid2Path);
    }
}

internal sealed class DeepIdV2NetworkClosureFileSource
{
    private const int MaximumChainCount = 4_096;
    private const long MaximumClosureBytes = 64L * 1024 * 1024;
    private readonly string[][] paths;
    private readonly string? publicBundlePath;
    internal ParsedDid2? Observer { get; }

    internal DeepIdV2NetworkClosureFileSource(string bundlePath, string publicObservationDid2Path)
    {
        publicBundlePath = Copy([bundlePath])[0];
        paths = [];
        var observer = DeepIdV2NetworkAuthorityFileSource.ReadExact(Copy([publicObservationDid2Path])[0]);
        Observer = DeepIdV2Codec.DecodeDid2(observer);
        using var initial = ReadCurrent(); // Validate the bounded frame without promoting authority.
    }

    internal DeepIdV2NetworkClosureFileSource(
        IReadOnlyList<string> policies, IReadOnlyList<string> views,
        IReadOnlyList<string> heads, IReadOnlyList<string> nodes,
        IReadOnlyList<string> projections, IReadOnlyList<string> mailboxAuthorities,
        string publicObservationDid2Path = "")
    {
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(views);
        ArgumentNullException.ThrowIfNull(heads);
        ArgumentNullException.ThrowIfNull(nodes);
        ArgumentNullException.ThrowIfNull(projections);
        ArgumentNullException.ThrowIfNull(mailboxAuthorities);
        if (policies.Count is < 1 or > MaximumChainCount ||
            views.Count is < 1 or > MaximumChainCount ||
            heads.Count != views.Count ||
            nodes.Count is < 1 or > MaximumChainCount ||
            projections.Count is < 1 or > MaximumChainCount ||
            mailboxAuthorities.Count is < 1 or > MaximumChainCount)
            throw new ArgumentException(
                "DID2 network closure requires bounded complete ordered chains.");
        paths = [Copy(policies), Copy(views), Copy(heads), Copy(nodes),
            Copy(projections), Copy(mailboxAuthorities)];
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        if (paths.SelectMany(static group => group).Distinct(comparer).Count() !=
            paths.Sum(static group => group.Length))
            throw new ArgumentException(
                "DID2 network closure paths must be distinct.");
        if (publicObservationDid2Path.Length != 0)
        {
            var observerPath = Copy([publicObservationDid2Path])[0];
            if (paths.SelectMany(static group => group).Contains(observerPath, comparer))
                throw new ArgumentException("The public DID2 observer must be distinct from network records.");
            var bytes = DeepIdV2NetworkAuthorityFileSource.ReadExact(observerPath);
            try { Observer = DeepIdV2Codec.DecodeDid2(bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }

    internal DeepIdV2NetworkClosureArtifacts ReadCurrent()
    {
        if (publicBundlePath is not null)
        {
            using var stream = new FileStream(publicBundlePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length is < 1 || stream.Length > XPointNetworkClosureWireCodec.MaximumResponseLength)
                throw new InvalidDataException("The atomic network closure is unbounded.");
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw new IOException("The network closure changed while reading.");
            var raw = XPointNetworkClosureWireCodec.DecodeResponse(bytes);
            return new DeepIdV2NetworkClosureArtifacts(new[] {
                raw.ExactNetworkPolicyChain.Select(static b => b.ToArray()).ToArray(),
                raw.ExactViewChain.Select(static b => b.ToArray()).ToArray(),
                raw.ExactHeadChain.Select(static b => b.ToArray()).ToArray(),
                raw.ExactActiveNodeDescriptors.Select(static b => b.ToArray()).ToArray(),
                raw.ExactPlacementTopologyChain.Select(static b => b.ToArray()).ToArray(),
                raw.ExactMailboxAuthorityChain.Select(static b => b.ToArray()).ToArray()
            });
        }
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
    internal IReadOnlyList<ReadOnlyMemory<byte>> MailboxAuthorities => Copy(groups[5]);

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(byte[][] group) =>
        Array.AsReadOnly(group.Select(static exact =>
            (ReadOnlyMemory<byte>)exact).ToArray());

    public void Dispose()
    {
        foreach (var exact in groups.SelectMany(static group => group))
            CryptographicOperations.ZeroMemory(exact);
    }
}

internal interface IDeepIdV2PreKeyPlacementSource
{
    ValueTask<ContactServicePlacementCapability> MintPreKeyPublicationAsync(
        ParsedDid2 publisher, ReadOnlyMemory<byte> serviceCapability,
        CancellationToken cancellationToken);
}

internal interface IDeepIdV2ReceiveNetworkSource
{
    ValueTask<VerifiedOnionNetworkContext> ReadCurrentAsync(
        ReadOnlyMemory<byte> localOwnerId, ReadOnlyMemory<byte> localOnionPublicKey, ReadOnlyMemory<byte> nextInstalledPublicKey,
        CancellationToken cancellationToken);
}

internal interface IDeepIdV2PreKeyClaimPlacementSource
{
    ValueTask<ContactServicePlacementCapability> MintPreKeyClaimAsync(
        ReadOnlyMemory<byte> serviceCapability, CancellationToken cancellationToken);
}

internal sealed record DeepIdV2ContactStoreAuthority(
    VerifiedOnionNetworkContext Network, VerifiedXPointNetworkAuthority Authority,
    Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness Freshness,
    OnionTrustedTimeAuthority TrustedTime, VerifiedMailboxAuthorityV2 MailboxAuthority);

internal interface IDeepIdV2ContactStoreAuthoritySource
{
    ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken cancellationToken);
}

internal sealed class DeepIdV2NetworkPlacementRuntime(
    IDeepIdV2CurrentDirectoryProofSource proofs,
    DeepIdV2NetworkAuthorityFileSource authoritySource,
    DeepIdV2NetworkClosureFileSource artifacts,
    FileDeepIdV2NetworkFloorStore floor,
    IOnionMonotonicClock clock) : IDeepIdV2PreKeyPlacementSource, IDeepIdV2ReceiveNetworkSource,
    IDeepIdV2PreKeyClaimPlacementSource, IDeepIdV2ContactStoreAuthoritySource
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private sealed record Observation(VerifiedDeepIdV2DirectoryFreshness Freshness,
        VerifiedXPointNetworkAuthority Authority, DeepIdV2NetworkFloor Floor, OnionMonotonicReading Reading);
    private Observation? observation;
    private int stopped;

    internal void StopObservations()
    {
        Volatile.Write(ref stopped, 1);
        Volatile.Write(ref observation, null);
    }

    // Explicit operator acquisition for a non-listening enrollment command.
    // Ordinary admission/readiness never calls this operation.
    internal async ValueTask AcquireObservationAsync(CancellationToken cancellationToken)
    {
        var observer = artifacts.Observer ?? throw new InvalidOperationException(
            "DID2 acquisition requires the configured public observation credential.");
        _ = await ReadNetworkAsync(observer, default, default, default, cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask<DeepIdV2ContactStoreAuthority> ReadPublicationAuthorityAsync(CancellationToken cancellationToken)
    {
        var observer = artifacts.Observer ?? throw new InvalidOperationException(
            "DID2 publication needs the configured public observation credential.");
        var current = await ReadNetworkAsync(observer, default, default, default, cancellationToken,
            observational: true).ConfigureAwait(false);
        return new(current.Network, current.Authority, current.Freshness, new OnionTrustedTimeAuthority(clock), current.MailboxAuthority);
    }

    public async ValueTask<ContactServicePlacementCapability> MintPreKeyClaimAsync(
        ReadOnlyMemory<byte> serviceCapability, CancellationToken cancellationToken)
    {
        if (serviceCapability.Length != 32 || serviceCapability.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 claim needs a nonzero service capability.", nameof(serviceCapability));
        // Account-independent placement must precede capability-indexed lookup.
        // Only the configured public observer, never the requester, selects this proof.
        var observer = artifacts.Observer ?? throw new InvalidOperationException(
            "DID2 claim placement requires the configured public observation credential.");
        var (network, freshness, _, _) = await ReadNetworkAsync(observer, default, default, default,
            cancellationToken, observational: true).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.ClaimPreKey, serviceCapability);
        return ContactServicePlacementCapability.FromNetcodec(placement,
            ContactServiceRequestKind.ClaimPreKey, serviceCapability, freshness.TrustedUpperUnixSeconds);
    }

    public async ValueTask<ContactServicePlacementCapability>
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
        var (network, freshness, _, _) = await ReadNetworkAsync(publisher, default, default, default,
            cancellationToken).ConfigureAwait(false);
        var placement = ContactServicePlacementFactory.Create(network,
            ContactServiceRequestKind.PublishPreKeyInventory,
            serviceCapability);
        return ContactServicePlacementCapability.FromNetcodec(placement,
            ContactServiceRequestKind.PublishPreKeyInventory,
            serviceCapability, freshness.TrustedUpperUnixSeconds);
    }

    public async ValueTask<VerifiedOnionNetworkContext> ReadCurrentAsync(
        ReadOnlyMemory<byte> localOwnerId, ReadOnlyMemory<byte> localOnionPublicKey, ReadOnlyMemory<byte> nextInstalledPublicKey,
        CancellationToken cancellationToken)
    {
        if (localOwnerId.Length != 32 || localOnionPublicKey.Length != 32 ||
            localOwnerId.Span.IndexOfAnyExcept((byte)0) < 0 || localOnionPublicKey.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The receive host needs its exact independent local node/key binding.");
        var observer = artifacts.Observer ?? throw new InvalidOperationException(
            "DID2 receive authority requires an operator-configured public observation credential.");
        if (!nextInstalledPublicKey.IsEmpty && (nextInstalledPublicKey.Length != 32 || nextInstalledPublicKey.Span.IndexOfAnyExcept((byte)0) < 0))
            throw new ArgumentException("Staged installed public key is invalid.");
        var result = await ReadNetworkAsync(observer, localOwnerId, localOnionPublicKey, nextInstalledPublicKey,
            cancellationToken).ConfigureAwait(false);
        return result.Network;
    }

    private async ValueTask<(VerifiedOnionNetworkContext Network,
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness Freshness,
        VerifiedXPointNetworkAuthority Authority, VerifiedMailboxAuthorityV2 MailboxAuthority)> ReadNetworkAsync(
        ParsedDid2 did2, ReadOnlyMemory<byte> localOwnerId, ReadOnlyMemory<byte> localKey, ReadOnlyMemory<byte> nextInstalledKey,
        CancellationToken cancellationToken, bool observational = false)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var observesConfiguredAccount = artifacts.Observer is { } configuredObserver &&
            CryptographicOperations.FixedTimeEquals(configuredObserver.CanonicalBytes.Span, did2.CanonicalBytes.Span);
        try
        {
            if (Volatile.Read(ref stopped) != 0)
                throw new InvalidOperationException("The DID2 network source is stopped.");
            var observed = observational ? Volatile.Read(ref observation) ??
                throw new CryptographicException("No acquired DID2 network observation is available.") : null;
            if (!observational && observesConfiguredAccount) Volatile.Write(ref observation, null);
            var previous = await floor.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (observed is not null && !FileDeepIdV2NetworkFloorStore.Same(observed.Floor, previous))
                throw new CryptographicException("The observed DID2 network floor changed.");
            var freshness = observed?.Freshness ?? await proofs.ReadCurrentAsync(did2, cancellationToken).ConfigureAwait(false);
            if (freshness.CurrentCheckpoint is null)
                throw new CryptographicException("DID2 network authority requires a current account checkpoint.");
            var authority = authoritySource.ReadCurrent();
            if (observed is not null)
            {
                if (!SameAuthority(observed.Authority, authority))
                    throw new CryptographicException("The observed DID2 authority changed.");
                await proofs.ValidateObservedAsync(freshness, cancellationToken).ConfigureAwait(false);
            }
            using var exact = artifacts.ReadCurrent();
            var time = new OnionTrustedTimeAuthority(clock);
            var network = previous is null
                ? await OnionNetworkContextVerifier.VerifyAsync(authority, freshness, exact.Policies,
                    exact.Views, exact.Heads, exact.Nodes, exact.Projections, null, time, cancellationToken).ConfigureAwait(false)
                : await OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(authority, freshness,
                    exact.Policies, exact.Views, exact.Heads, exact.Nodes, exact.Projections,
                    previous.History, time, cancellationToken).ConfigureAwait(false);
            network.EnsureCurrent();
            var issuer = await VerifyMailboxAuthorityAsync(network, authority, freshness, exact,
                cancellationToken).ConfigureAwait(false);
            if (observed is not null && (!CryptographicOperations.FixedTimeEquals(
                    observed.Reading.BootId.Span, issuer.Reading.BootId.Span) ||
                    issuer.Reading.SampleSeconds < observed.Reading.SampleSeconds))
                throw new CryptographicException("DID2 observation crossed a clock discontinuity.");
            if (!localOwnerId.IsEmpty)
            {
                var local = OnionPathCandidateSnapshotFactory.Create(network).Candidates
                    .Where(node => node.RouterOwnerId.Span.SequenceEqual(localOwnerId.Span)).ToArray();
                if (local.Length != 1)
                    throw new CryptographicException("The signed view does not contain one exact local node.");
                try { OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(network, local[0].NodeId, localKey); }
                catch (OnionBoundaryException exception) when (exception.Code == "local-node-key-mismatch" && !nextInstalledKey.IsEmpty) {
                    OnionLocalNodeKeyFactory.EnsureInstalledPublicKey(network, local[0].NodeId, nextInstalledKey);
                }
            }
            DeepIdV2NetworkFloor committed;
            if (observed is not null)
            {
                if (!CryptographicOperations.FixedTimeEquals(OnionNetworkProtectedHistoryCodec.Encode(network), observed.Floor.History))
                    throw new CryptographicException("Observation cannot advance the DID2 network floor.");
                committed = observed.Floor;
            }
            else committed = await floor.CommitVerifiedAsync(previous, network, cancellationToken).ConfigureAwait(false);
            var retained = await floor.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!FileDeepIdV2NetworkFloorStore.Same(committed, retained))
                throw new IOException("The DID2 network floor changed before capability release.");
            network.EnsureCurrent();
            var retainedAuthority = authoritySource.ReadCurrent();
            using var retainedArtifacts = artifacts.ReadCurrent();
            if (!CryptographicOperations.FixedTimeEquals(authority.AuthorityCoreReference.Span, retainedAuthority.AuthorityCoreReference.Span) ||
                !CryptographicOperations.FixedTimeEquals(authority.Dts1PolicyCoreReference.Span, retainedAuthority.Dts1PolicyCoreReference.Span) ||
                !CryptographicOperations.FixedTimeEquals(authority.TimeSourcePolicyHash.Span, retainedAuthority.TimeSourcePolicyHash.Span) ||
                !SameSeries(exact.Policies, retainedArtifacts.Policies) || !SameSeries(exact.Views, retainedArtifacts.Views) ||
                !SameSeries(exact.Heads, retainedArtifacts.Heads) || !SameSeries(exact.Nodes, retainedArtifacts.Nodes) ||
                !SameSeries(exact.Projections, retainedArtifacts.Projections) ||
                !SameSeries(exact.MailboxAuthorities, retainedArtifacts.MailboxAuthorities))
                throw new CryptographicException("DID2 network authority changed before capability release.");
            var finalIssuer = await VerifyMailboxAuthorityAsync(network, authority, freshness,
                retainedArtifacts, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(issuer.Policy.ExactPma2.Span,
                    finalIssuer.Policy.ExactPma2.Span) ||
                !CryptographicOperations.FixedTimeEquals(issuer.Reading.BootId.Span, finalIssuer.Reading.BootId.Span) ||
                finalIssuer.Reading.SampleSeconds < issuer.Reading.SampleSeconds)
                throw new CryptographicException("DID2 mailbox issuer changed or crossed a clock discontinuity before release.");
            cancellationToken.ThrowIfCancellationRequested();
            if (observed is not null)
                await proofs.ValidateObservedAsync(freshness, cancellationToken).ConfigureAwait(false);
            if (Volatile.Read(ref stopped) != 0)
                throw new InvalidOperationException("The DID2 network source stopped before capability release.");
            if (!observational && observesConfiguredAccount)
                Volatile.Write(ref observation, new(freshness, authority, committed, finalIssuer.Reading));
            else if (observed is not null)
                Volatile.Write(ref observation, observed with { Reading = finalIssuer.Reading });
            return (network, freshness, authority, finalIssuer.Policy);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Caller cancellation is not evidence that the observation changed.
            // An acquisition has already cleared its own observer above.
            throw;
        }
        catch
        {
            // A recipient-specific rejection must not invalidate the independent
            // observer. Any changed floor/source is still rejected on its next
            // read; failed observer refresh and failed observation do clear it.
            if (observational || observesConfiguredAccount) Volatile.Write(ref observation, null);
            throw;
        }
        finally { gate.Release(); }
    }

    private static bool SameAuthority(VerifiedXPointNetworkAuthority left, VerifiedXPointNetworkAuthority right) =>
        CryptographicOperations.FixedTimeEquals(left.AuthorityCoreReference.Span, right.AuthorityCoreReference.Span) &&
        CryptographicOperations.FixedTimeEquals(left.Dts1PolicyCoreReference.Span, right.Dts1PolicyCoreReference.Span) &&
        CryptographicOperations.FixedTimeEquals(left.TimeSourcePolicyHash.Span, right.TimeSourcePolicyHash.Span);

    private async ValueTask<(VerifiedMailboxAuthorityV2 Policy, OnionMonotonicReading Reading)>
        VerifyMailboxAuthorityAsync(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority,
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness freshness,
        DeepIdV2NetworkClosureArtifacts exact, CancellationToken ct)
    {
        network.EnsureCurrent();
        var projection = ContactCodec.Decode(ProtocolMagic.PMT2, exact.Projections[^1].Span);
        if (!network.BindsProjection(ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes))
            throw new CryptographicException("DID2 mailbox policy requires the exact current PMT2.");
        var records = exact.MailboxAuthorities.Select(bytes => ContactCodec.Decode(ProtocolMagic.PMA2, bytes.Span)).ToArray();
        var matches = records.Where(record => CryptographicOperations.FixedTimeEquals(
            record.CoreHash.Span, projection.Field(4).Span[6..])).ToArray();
        if (matches.Length != 1)
            throw new CryptographicException("DID2 current PMT2 must name exactly one distributed PMA2.");
        var reading = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("DID2 mailbox issuer time is unavailable.");
        if (!freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("DID2 mailbox issuer needs the current independent proof.");
        var elapsed = checked(reading.SampleSeconds - freshness.MonotonicSample);
        var policy = MailboxAuthorityV2Verifier.Verify(authority, matches[0].CanonicalBytes.Span,
            checked(freshness.TrustedLowerUnixSeconds + elapsed), checked(freshness.TrustedUpperUnixSeconds + elapsed));
        if (!policy.BindsProjection(projection.CanonicalBytes.Span))
            throw new CryptographicException("DID2 mailbox issuer does not bind the current projection.");
        network.EnsureCurrent(); ct.ThrowIfCancellationRequested();
        return (policy, reading);
    }

    private static bool SameSeries(IReadOnlyList<ReadOnlyMemory<byte>> left, IReadOnlyList<ReadOnlyMemory<byte>> right)
    {
        if (left.Count != right.Count) return false;
        for (var i = 0; i < left.Count; i++)
            if (!CryptographicOperations.FixedTimeEquals(left[i].Span, right[i].Span)) return false;
        return true;
    }
}

internal static class DeepIdV2NetworkPlacementHostComposition
{
    internal static IServiceCollection AddDeepIdV2NetworkPlacement(
        this IServiceCollection services,
        DeepIdV2NetworkClosureFileSource artifacts)
    {
        services.AddSingleton(artifacts);
        services.AddSingleton(provider => provider.GetRequiredService<DeepIdV2DirectoryProofRuntime>()
            .OpenNetworkFloor(provider.GetRequiredService<XNode.Core.RouterNodeOptions>(),
                provider.GetRequiredService<XNode.Core.Mailbox.IMailboxStorageSecurity>(),
                provider.GetRequiredService<XNode.Core.Mailbox.IMailboxDurabilityBarrier>()));
        services.AddSingleton<DeepIdV2NetworkPlacementRuntime>();
        services.AddSingleton<IDeepIdV2PreKeyPlacementSource>(provider =>
            provider.GetRequiredService<DeepIdV2NetworkPlacementRuntime>());
        services.AddSingleton<IDeepIdV2ReceiveNetworkSource>(provider =>
            provider.GetRequiredService<DeepIdV2NetworkPlacementRuntime>());
        services.AddSingleton<IDeepIdV2PreKeyClaimPlacementSource>(provider =>
            provider.GetRequiredService<DeepIdV2NetworkPlacementRuntime>());
        services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(provider =>
            provider.GetRequiredService<DeepIdV2NetworkPlacementRuntime>());
        services.AddHostedService<DeepIdV2NetworkPlacementHostedService>();
        return services;
    }
}

internal sealed class DeepIdV2NetworkPlacementHostedService(
    DeepIdV2NetworkClosureFileSource artifacts, DeepIdV2NetworkPlacementRuntime runtime) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var exact = artifacts.ReadCurrent();
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        runtime.StopObservations();
        return Task.CompletedTask;
    }
}
