using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
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
    // Pure framing of one exact PUBLIC frame, not signatures/currentness.
    // Every call still reads the actual file/EOF. Each consumer gets its own
    // buffers, so disposing a read cannot mutate a later observation.
    private readonly object bundleGrammarGate = new();
    private byte[]? bundleGrammarBytes;
    private byte[][][]? bundleGrammarGroups;
    internal long BundleGrammarDecodes { get; private set; }
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
        using var measurement = CurrentMailboxDiagnostics.Measure("network-source-files");
        if (publicBundlePath is not null)
        {
            using var stream = new FileStream(publicBundlePath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            if (stream.Length is < 1 || stream.Length > XPointNetworkClosureWireCodec.MaximumResponseLength)
                throw new InvalidDataException("The atomic network closure is unbounded.");
            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw new IOException("The network closure changed while reading.");
            lock (bundleGrammarGate)
            {
                if (bundleGrammarBytes is not null && bundleGrammarGroups is not null && bytes.AsSpan().SequenceEqual(bundleGrammarBytes))
                    return new(CloneGroups(bundleGrammarGroups));
                BundleGrammarDecodes++;
                var raw = XPointNetworkClosureWireCodec.DecodeResponse(bytes);
                var framedGroups = new[] {
                    raw.ExactNetworkPolicyChain, raw.ExactViewChain, raw.ExactHeadChain,
                    raw.ExactActiveNodeDescriptors, raw.ExactPlacementTopologyChain, raw.ExactMailboxAuthorityChain
                }.Select(static group => group.Select(static b => b.ToArray()).ToArray()).ToArray();
                // Resource bound only: larger valid frames keep the full path.
                if (bytes.Length <= 4 * 1024 * 1024)
                {
                    bundleGrammarBytes = bytes; bundleGrammarGroups = framedGroups;
                    return new(CloneGroups(framedGroups));
                }
                bundleGrammarBytes = null; bundleGrammarGroups = null;
                return new(framedGroups);
            }
        }
        var groups = new byte[paths.Length][][];
        var budget = new BoundedFileRead.ByteBudget(MaximumClosureBytes,
            "DID2 network closure exceeds its total byte bound.");
        byte[][]? records = null;
        try
        {
            records = DeepIdV2NetworkAuthorityFileSource.ReadExactMany(paths.SelectMany(static group => group).ToArray(), budget);
            var offset = 0;
            for (var group = 0; group < paths.Length; group++)
            {
                groups[group] = records.AsSpan(offset, paths[group].Length).ToArray();
                offset += paths[group].Length;
            }
            return new DeepIdV2NetworkClosureArtifacts(groups);
        }
        catch
        {
            if (records is not null)
                foreach (var exact in records) CryptographicOperations.ZeroMemory(exact);
            throw;
        }
    }

    private static byte[][][] CloneGroups(byte[][][] groups) =>
        groups.Select(static group => group.Select(static bytes => bytes.ToArray()).ToArray()).ToArray();

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

internal interface IObservedDeepIdV2ReceiveNetworkSource
{
    ValueTask<bool> ObserveReceiveNetworkAsync(VerifiedOnionNetworkContext retained, CancellationToken cancellationToken);
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
    // Only the initial, pre-effect admission may ask the acquisition owner to
    // join a changed public closure. All in-operation fences remain observers.
    ValueTask<DeepIdV2ContactStoreAuthority> ReadAdmissionAuthorityAsync(CancellationToken cancellationToken) =>
        ReadPublicationAuthorityAsync(cancellationToken);
    // Scheduling input from the actual decoded request, never permission. The
    // returned host must still verify the complete original grant independently.
    ValueTask<DeepIdV2ContactStoreAuthority> ReadGrantAdmissionAuthorityAsync(MailboxAuthenticatedGrant grant,
        CancellationToken cancellationToken) => ReadAdmissionAuthorityAsync(cancellationToken);
}

internal sealed class DeepIdV2NetworkObservationChangedException() : CryptographicException(
    "The acquired DID2 observation no longer binds the current public source.");

internal sealed class DeepIdV2NetworkObservationMissingException() : CryptographicException(
    "No acquired DID2 network observation is available.");

internal sealed class DeepIdV2NetworkPlacementRuntime(
    IDeepIdV2CurrentDirectoryProofSource proofs,
    DeepIdV2NetworkAuthorityFileSource authoritySource,
    DeepIdV2NetworkClosureFileSource artifacts,
    FileDeepIdV2NetworkFloorStore floor,
    IOnionMonotonicClock clock, TimeProvider? resourceTimeProvider = null,
    ILogger<DeepIdV2NetworkPlacementRuntime>? logger = null) : IDeepIdV2PreKeyPlacementSource, IDeepIdV2ReceiveNetworkSource,
    IDeepIdV2PreKeyClaimPlacementSource, IDeepIdV2ContactStoreAuthoritySource, IObservedDeepIdV2ReceiveNetworkSource
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly TimeProvider resourceClock = resourceTimeProvider ?? TimeProvider.System;
    private sealed record Observation(VerifiedDeepIdV2DirectoryFreshness Freshness,
        VerifiedXPointNetworkAuthority Authority, DeepIdV2NetworkFloor Floor, OnionMonotonicReading Reading,
        VerifiedOnionNetworkContext Network, byte[] SourceDigest, long NetworkVerifiedAt);
    private Observation? observation;
    // Pure verifier result keyed by ALL its inputs, including the actual
    // trusted interval. No clock, floor, currentness decision or TTL is cached.
    // Access is serialized by the real network-source gate.
    private sealed record MailboxPolicyMemo(VerifiedXPointNetworkAuthority Authority,
        byte[] Exact, ulong Lower, ulong Upper, VerifiedMailboxAuthorityV2 Policy);
    private MailboxPolicyMemo? mailboxPolicyMemo;
    internal long MailboxPolicySignatureVerifications { get; private set; }
    private byte[]? parsedMailboxProjection;
    private byte[][] parsedMailboxPolicies = [];
    private (ContactRecord Projection, ContactRecord[] Policies)? parsedMailboxInputs;
    internal long MailboxInputDecodes { get; private set; }
    private int stopped;
    private long lastTimingReport;

    private void ReportReadTiming(CurrentMailboxNetworkReadTiming.Result work)
    {
        if (logger is null || work.TotalMs < 1000) return;
        var stamp = System.Diagnostics.Stopwatch.GetTimestamp();
        var previous = Interlocked.Read(ref lastTimingReport);
        if (previous != 0 && System.Diagnostics.Stopwatch.GetElapsedTime(previous) < TimeSpan.FromSeconds(10)) return;
        if (Interlocked.CompareExchange(ref lastTimingReport, stamp, previous) != previous) return;
        logger.LogWarning("DID2 network read work totalMs={TotalMs}; slowest={Phase}; slowestMs={SlowestMs}; gateWaitMs={GateWaitMs}; proofAcquireMs={ProofAcquireMs}; networkVerifyMs={NetworkVerifyMs}.",
            work.TotalMs, work.Slowest, work.SlowestMs, work.GateWaitMs, work.ProofAcquireMs, work.NetworkVerifyMs);
    }

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

    public async ValueTask<DeepIdV2ContactStoreAuthority> ReadAdmissionAuthorityAsync(CancellationToken cancellationToken)
    {
        try { return await ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false); }
        catch (DeepIdV2NetworkObservationChangedException)
        {
            // No mailbox/native effect or grant has been admitted. Reacquire
            // once under the existing owner gate/budget; never replay an effect
            // or revive a captured proof. Invalid new input still fails closed.
            cancellationToken.ThrowIfCancellationRequested();
            var observer = artifacts.Observer ?? throw new InvalidOperationException("DID2 admission requires the configured observer.");
            var current = await ReadNetworkAsync(observer, default, default, default, cancellationToken).ConfigureAwait(false);
            return new(current.Network, current.Authority, current.Freshness,
                new OnionTrustedTimeAuthority(clock), current.MailboxAuthority);
        }
    }

    public async ValueTask<DeepIdV2ContactStoreAuthority> ReadGrantAdmissionAuthorityAsync(MailboxAuthenticatedGrant grant,
        CancellationToken cancellationToken)
    {
        var candidate = await ReadAdmissionAuthorityAsync(cancellationToken).ConfigureAwait(false);
        if (grant.ExpiresAtUnixSeconds <= candidate.Network.MaximumRecordExpiryUnixSeconds) return candidate;
        // Invalid caller signatures must not schedule an additional proof.
        // This pure check is not grant admission: the host still checks every
        // lifecycle/serial/assignment/time/revocation/holder constraint below.
        var issuer = candidate.MailboxAuthority.ResolveIssuer(grant.Domain);
        if (!CryptographicOperations.FixedTimeEquals(grant.NetworkId.Span, candidate.Network.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(grant.IssuerPublicKey.Span, issuer.PublicKey.Span) ||
            !Sodium.PublicKeyAuth.VerifyDetached(grant.IssuerSignature.ToArray(),
                MailboxAuthenticatedCapabilityCodec.GetGrantSigningBytes(grant), issuer.PublicKey.ToArray())) return candidate;
        // An independently issued grant can end after the ADH1 carried by this
        // still-live cached proof. Before any effect, acquire one NEW actual proof;
        // never extend the old loan or remove the host's NetworkExpiry bound.
        // A current-issuer signed expiry schedules at most one acquisition, not acceptance.
        var observer = artifacts.Observer ?? throw new InvalidOperationException("DID2 grant admission requires the configured observer.");
        var current = await ReadNetworkAsync(observer, default, default, default, cancellationToken).ConfigureAwait(false);
        return new(current.Network, current.Authority, current.Freshness,
            new OnionTrustedTimeAuthority(clock), current.MailboxAuthority);
    }

    public async ValueTask<bool> ObserveReceiveNetworkAsync(VerifiedOnionNetworkContext retained, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(retained);
        try { retained.EnsureCurrent(); }
        catch (OnionBoundaryException error) when (error.Code == "trusted-time-expired") { return false; }
        DeepIdV2ContactStoreAuthority current;
        try { current = await ReadPublicationAuthorityAsync(cancellationToken).ConfigureAwait(false); }
        catch (DeepIdV2NetworkObservationChangedException) { return false; }
        // Negative scheduling only. The receive-binding owner must perform a
        // genuine acquisition BEFORE dispatch; observation itself cannot mint.
        catch (DeepIdV2NetworkObservationMissingException) { return false; }
        var observed = Volatile.Read(ref observation);
        if (observed is null || !ReferenceEquals(observed.Freshness, current.Freshness) ||
            !CryptographicOperations.FixedTimeEquals(OnionNetworkProtectedHistoryCodec.Encode(retained),
                OnionNetworkProtectedHistoryCodec.Encode(current.Network))) return false;
        // Scheduling only; all actual source/floor/clock/issuer checks above
        // remain mandatory, including for bindings younger than ten seconds.
        var sample = observed.Reading.SampleSeconds;
        var fresh = current.Freshness;
        if (!fresh.IsCurrentAtMonotonic(observed.Reading.BootId.Span, sample)) return false;
        var upper = checked(fresh.TrustedUpperUnixSeconds + (sample - fresh.MonotonicSample));
        var end = retained.MaximumRecordExpiryUnixSeconds;
        var due = fresh.FreshnessDeadlineMonotonicSeconds - sample <= 30 || end <= upper || end - upper <= 30;
        retained.EnsureCurrent(); cancellationToken.ThrowIfCancellationRequested(); return !due;
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
        using var timing = new CurrentMailboxNetworkReadTiming(ReportReadTiming);
        using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.GateWait))
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var observesConfiguredAccount = artifacts.Observer is { } configuredObserver &&
            CryptographicOperations.FixedTimeEquals(configuredObserver.CanonicalBytes.Span, did2.CanonicalBytes.Span);
        try
        {
            if (Volatile.Read(ref stopped) != 0)
                throw new InvalidOperationException("The DID2 network source is stopped.");
            var observed = observational ? Volatile.Read(ref observation) ??
                throw new DeepIdV2NetworkObservationMissingException() : null;
            if (!observational && observesConfiguredAccount) Volatile.Write(ref observation, null);
            DeepIdV2NetworkFloor? previous;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.FloorRead))
            using (CurrentMailboxDiagnostics.Measure("network-floor-read"))
                previous = await floor.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (observed is not null && !FileDeepIdV2NetworkFloorStore.Same(observed.Floor, previous))
                throw new CryptographicException("The observed DID2 network floor changed.");
            VerifiedDeepIdV2DirectoryFreshness freshness;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.ProofAcquire))
                freshness = observed?.Freshness ?? await proofs.ReadCurrentAsync(did2, cancellationToken).ConfigureAwait(false);
            if (freshness.CurrentCheckpoint is null)
                throw new CryptographicException("DID2 network authority requires a current account checkpoint.");
            VerifiedXPointNetworkAuthority authority;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.AuthorityRead))
            using (CurrentMailboxDiagnostics.Measure("authority-lineage"))
                authority = authoritySource.ReadCurrent();
            if (observed is not null)
            {
                if (!SameAuthority(observed.Authority, authority))
                    throw new CryptographicException("The observed DID2 authority changed.");
                // Observational work below is denial-only: no floor commit or
                // capability escapes. Rejoin the actual protected proof once
                // at the existing final fence AFTER all source/clock callbacks.
            }
            DeepIdV2NetworkClosureArtifacts exactSource;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.SourceRead))
                exactSource = artifacts.ReadCurrent();
            using var exact = exactSource;
            var sourceDigest = ComputeSourceDigest(exact);
            if (observed is not null && !CryptographicOperations.FixedTimeEquals(sourceDigest, observed.SourceDigest))
                throw new DeepIdV2NetworkObservationChangedException();
            var time = new OnionTrustedTimeAuthority(clock);
            VerifiedOnionNetworkContext network;
            var verifiedAt = observed?.NetworkVerifiedAt ?? 0;
            var cacheElapsed = observed is null ? TimeSpan.MaxValue : resourceClock.GetElapsedTime(observed.NetworkVerifiedAt);
            if (observed is not null && CryptographicOperations.FixedTimeEquals(sourceDigest, observed.SourceDigest) &&
                cacheElapsed >= TimeSpan.Zero)
            {
                // Reuse only a previously minted immutable context, not a
                // trust boolean. Both protected floors, current proof, raw
                // authority/sources, clock, issuer and release fencing are
                // still checked by this operation. Its original lease must
                // remain live; cache hits never refresh either lifetime.
                // Resource age alone does not invalidate an exact immutable
                // signature result. Signed expiry and actual source/floor
                // changes, not a second ten-second TTL, bound its reuse.
                using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.ContextReuse))
                using (CurrentMailboxDiagnostics.Measure("network-context-reuse"))
                    network = observed.Network;
            }
            else
            {
                using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.NetworkVerify))
                using (CurrentMailboxDiagnostics.Measure("network-verify"))
                    network = previous is null
                        ? await OnionNetworkContextVerifier.VerifyAsync(authority, freshness, exact.Policies,
                            exact.Views, exact.Heads, exact.Nodes, exact.Projections, null, time, cancellationToken).ConfigureAwait(false)
                        : await OnionNetworkContextVerifier.VerifyFromProtectedHistoryAsync(authority, freshness,
                            exact.Policies, exact.Views, exact.Heads, exact.Nodes, exact.Projections,
                            previous.History, time, cancellationToken).ConfigureAwait(false);
                verifiedAt = resourceClock.GetTimestamp();
            }
            network.EnsureCurrent();
            (VerifiedMailboxAuthorityV2 Policy, OnionMonotonicReading Reading) issuer;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.MailboxVerify))
                issuer = await VerifyMailboxAuthorityAsync(network, authority, freshness, exact,
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
            else
            {
                using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.FloorCommit))
                    committed = await floor.CommitVerifiedAsync(previous, network, cancellationToken).ConfigureAwait(false);
            }
            DeepIdV2NetworkFloor? retained;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.FloorReadback))
            using (CurrentMailboxDiagnostics.Measure("network-floor-readback"))
                retained = await floor.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (!FileDeepIdV2NetworkFloorStore.Same(committed, retained))
                throw new IOException("The DID2 network floor changed before capability release.");
            network.EnsureCurrent();
            VerifiedXPointNetworkAuthority retainedAuthority;
            DeepIdV2NetworkClosureArtifacts retainedSource;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.SourceReadback))
            {
                using (CurrentMailboxDiagnostics.Measure("authority-lineage"))
                    retainedAuthority = authoritySource.ReadCurrent();
                retainedSource = artifacts.ReadCurrent();
            }
            using var retainedArtifacts = retainedSource;
            if (!CryptographicOperations.FixedTimeEquals(authority.AuthorityCoreReference.Span, retainedAuthority.AuthorityCoreReference.Span) ||
                !CryptographicOperations.FixedTimeEquals(authority.Dts1PolicyCoreReference.Span, retainedAuthority.Dts1PolicyCoreReference.Span) ||
                !CryptographicOperations.FixedTimeEquals(authority.TimeSourcePolicyHash.Span, retainedAuthority.TimeSourcePolicyHash.Span) ||
                !SameSeries(exact.Policies, retainedArtifacts.Policies) || !SameSeries(exact.Views, retainedArtifacts.Views) ||
                !SameSeries(exact.Heads, retainedArtifacts.Heads) || !SameSeries(exact.Nodes, retainedArtifacts.Nodes) ||
                !SameSeries(exact.Projections, retainedArtifacts.Projections) ||
                !SameSeries(exact.MailboxAuthorities, retainedArtifacts.MailboxAuthorities))
                throw new CryptographicException("DID2 network authority changed before capability release.");
            (VerifiedMailboxAuthorityV2 Policy, OnionMonotonicReading Reading) finalIssuer;
            using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.MailboxReadback))
                finalIssuer = await VerifyMailboxAuthorityAsync(network, authority, freshness,
                    retainedArtifacts, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(issuer.Policy.ExactPma2.Span,
                    finalIssuer.Policy.ExactPma2.Span) ||
                !CryptographicOperations.FixedTimeEquals(issuer.Reading.BootId.Span, finalIssuer.Reading.BootId.Span) ||
                finalIssuer.Reading.SampleSeconds < issuer.Reading.SampleSeconds)
                throw new CryptographicException("DID2 mailbox issuer changed or crossed a clock discontinuity before release.");
            cancellationToken.ThrowIfCancellationRequested();
            if (observed is not null)
            {
                using (timing.Measure(CurrentMailboxNetworkReadTiming.Phase.ProofReadback))
                using (CurrentMailboxDiagnostics.Measure("proof-observe"))
                    await proofs.ValidateObservedAsync(freshness, cancellationToken).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref stopped) != 0)
                throw new InvalidOperationException("The DID2 network source stopped before capability release.");
            if (!observational && observesConfiguredAccount)
                Volatile.Write(ref observation, new(freshness, authority, committed, finalIssuer.Reading, network, sourceDigest, verifiedAt));
            else if (observed is not null)
                Volatile.Write(ref observation, observed with { Reading = finalIssuer.Reading, Network = network, SourceDigest = sourceDigest, NetworkVerifiedAt = verifiedAt });
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

    // Private resource-cache key only, never a wire hash or authority. Closed
    // group/count/length framing prevents series or record-boundary ambiguity.
    private static byte[] ComputeSourceDigest(DeepIdV2NetworkClosureArtifacts exact)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (var group in new[] { exact.Policies, exact.Views, exact.Heads, exact.Nodes, exact.Projections, exact.MailboxAuthorities })
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)group.Count)); hash.AppendData(length);
            foreach (var bytes in group)
            {
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
                hash.AppendData(length); hash.AppendData(bytes.Span);
            }
        }
        return hash.GetHashAndReset();
    }

    private async ValueTask<(VerifiedMailboxAuthorityV2 Policy, OnionMonotonicReading Reading)>
        VerifyMailboxAuthorityAsync(VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority authority,
        Deep.Protocol.AccountDirectoryV1.VerifiedDeepIdV2DirectoryFreshness freshness,
        DeepIdV2NetworkClosureArtifacts exact, CancellationToken ct)
    {
        network.EnsureCurrent();
        var parsed = ParseMailboxInputs(exact);
        var projection = parsed.Projection;
        if (!network.BindsProjection(ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes))
            throw new CryptographicException("DID2 mailbox policy requires the exact current PMT2.");
        var records = parsed.Policies;
        var matches = records.Where(record => CryptographicOperations.FixedTimeEquals(
            record.CoreHash.Span, projection.Field(4).Span[6..])).ToArray();
        if (matches.Length != 1)
            throw new CryptographicException("DID2 current PMT2 must name exactly one distributed PMA2.");
        var reading = await clock.ReadAsync(ct).ConfigureAwait(false) ??
            throw new CryptographicException("DID2 mailbox issuer time is unavailable.");
        if (!freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("DID2 mailbox issuer needs the current independent proof.");
        var elapsed = checked(reading.SampleSeconds - freshness.MonotonicSample);
        var lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
        var upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
        var memo = mailboxPolicyMemo;
        VerifiedMailboxAuthorityV2 policy;
        if (memo is not null && ReferenceEquals(memo.Authority, authority) &&
            memo.Lower == lower && memo.Upper == upper &&
            CryptographicOperations.FixedTimeEquals(memo.Exact, matches[0].CanonicalBytes.Span))
            policy = memo.Policy;
        else
        {
            policy = MailboxAuthorityV2Verifier.Verify(authority, matches[0].CanonicalBytes.Span, lower, upper);
            MailboxPolicySignatureVerifications++;
            mailboxPolicyMemo = new(authority, matches[0].CanonicalBytes.ToArray(), lower, upper, policy);
        }
        if (!policy.BindsProjection(projection.CanonicalBytes.Span))
            throw new CryptographicException("DID2 mailbox issuer does not bind the current projection.");
        network.EnsureCurrent(); ct.ThrowIfCancellationRequested();
        return (policy, reading);
    }

    // Canonical grammar of identical PUBLIC bytes is immutable. This one-frame
    // memo does not cache selection, signatures, time or any native floor.
    // Actual files are still read twice by ReadNetworkAsync and compared after
    // callbacks; every use below independently checks projection/currentness.
    private (ContactRecord Projection, ContactRecord[] Policies) ParseMailboxInputs(DeepIdV2NetworkClosureArtifacts exact)
    {
        var projection = exact.Projections[^1];
        if (parsedMailboxInputs is { } memo && parsedMailboxProjection is not null &&
            projection.Span.SequenceEqual(parsedMailboxProjection) && parsedMailboxPolicies.Length == exact.MailboxAuthorities.Count &&
            !exact.MailboxAuthorities.Where((bytes, index) => !bytes.Span.SequenceEqual(parsedMailboxPolicies[index])).Any())
            return memo;
        var parsed = (Projection: ContactCodec.Decode(ProtocolMagic.PMT2, projection.Span),
            Policies: exact.MailboxAuthorities.Select(bytes => ContactCodec.Decode(ProtocolMagic.PMA2, bytes.Span)).ToArray());
        MailboxInputDecodes++;
        // Resource-only bound; larger valid closures retain full parsing, not
        // a new rejection threshold or permission to omit an issuer record.
        if (projection.Length + exact.MailboxAuthorities.Sum(bytes => (long)bytes.Length) <= 4 * 1024 * 1024)
        {
            parsedMailboxProjection = projection.ToArray();
            parsedMailboxPolicies = exact.MailboxAuthorities.Select(bytes => bytes.ToArray()).ToArray();
            parsedMailboxInputs = parsed;
        }
        else { parsedMailboxProjection = null; parsedMailboxPolicies = []; parsedMailboxInputs = null; }
        return parsed;
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
