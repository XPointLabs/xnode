using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Microsoft.AspNetCore.DataProtection;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode;

public sealed class ProductionGroupControlAuthorityOptions
{
    public bool Enabled { get; set; }
    public string ArtifactDirectoryRelativePath { get; set; } = string.Empty;
    public string StateRelativePath { get; set; } = string.Empty;
    public int MaximumDcr1Bytes { get; set; }
    public int MaximumProtectedStateBytes { get; set; }
    public int MaximumLineageDepth { get; set; }

    internal ProductionGroupControlAuthorityConfiguration? ValidateAndLoad(
        RouterNodeOptions node,
        GroupControlServiceOptions service,
        bool verifiedNetworkAuthorityConfigured)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(service);
        service.Validate();

        var any = Enabled
            || !string.IsNullOrEmpty(ArtifactDirectoryRelativePath)
            || !string.IsNullOrEmpty(StateRelativePath)
            || MaximumDcr1Bytes != 0
            || MaximumProtectedStateBytes != 0
            || MaximumLineageDepth != 0;
        if (!Enabled)
        {
            if (any)
            {
                throw new InvalidOperationException(
                    "GroupControlAuthority configuration is partial: Enabled=false requires every production field to be absent.");
            }
            if (service.RuntimeActivation || service.MapReplicaEndpoint)
            {
                throw new InvalidOperationException(
                    "GroupControlService cannot activate without a complete explicit GroupControlAuthority configuration.");
            }
            return null;
        }

        if (!verifiedNetworkAuthorityConfigured)
        {
            throw new InvalidOperationException(
                "GroupControlAuthority requires the production verified XPoint network authority.");
        }
        if (!service.RuntimeActivation || !service.MapReplicaEndpoint)
        {
            throw new InvalidOperationException(
                "GroupControlAuthority activation requires both GroupControlService runtime and replica endpoint activation.");
        }
        if (string.IsNullOrEmpty(ArtifactDirectoryRelativePath)
            || string.IsNullOrEmpty(StateRelativePath)
            || MaximumDcr1Bytes == 0
            || MaximumProtectedStateBytes == 0
            || MaximumLineageDepth == 0)
        {
            throw new InvalidOperationException(
                "GroupControlAuthority activation requires every production field to be configured explicitly.");
        }
        if (MaximumDcr1Bytes is < 1_024 or > 16 * 1024 * 1024
            || MaximumProtectedStateBytes is < 4_096 or > 16 * 1024 * 1024
            || MaximumLineageDepth is < 1 or > 4_096)
        {
            throw new InvalidOperationException(
                "GroupControlAuthority resource bounds are invalid.");
        }

        var root = ResolveInside(node.DataDirectory, ArtifactDirectoryRelativePath, file: false);
        var state = ResolveInside(node.DataDirectory, StateRelativePath, file: true);
        if (Path.GetRelativePath(root, state) is ".")
        {
            throw new InvalidOperationException(
                "GroupControlAuthority artifact directory and state path must be distinct.");
        }
        return new ProductionGroupControlAuthorityConfiguration(
            root,
            state,
            MaximumDcr1Bytes,
            MaximumProtectedStateBytes,
            MaximumLineageDepth);
    }

    private static string ResolveInside(string dataDirectory, string relativePath, bool file)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory)
            || relativePath != relativePath.Trim()
            || Path.IsPathFullyQualified(relativePath)
            || relativePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            throw new InvalidOperationException(
                "GroupControlAuthority paths must be clean relative paths inside Node:DataDirectory.");
        }
        var dataRoot = Path.GetFullPath(dataDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var resolved = Path.GetFullPath(Path.Combine(dataRoot, relativePath));
        var relation = Path.GetRelativePath(dataRoot, resolved);
        if (relation is "." or ".."
            || relation.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relation)
            || file && string.IsNullOrEmpty(Path.GetFileName(resolved)))
        {
            throw new InvalidOperationException(
                "GroupControlAuthority paths must remain inside Node:DataDirectory.");
        }
        return resolved;
    }
}

internal sealed record ProductionGroupControlAuthorityConfiguration(
    string ArtifactDirectory,
    string StatePath,
    int MaximumDcr1Bytes,
    int MaximumProtectedStateBytes,
    int MaximumLineageDepth);

internal sealed record GroupControlAuthorityArtifact(
    ReadOnlyMemory<byte> ExactGsr1,
    ReadOnlyMemory<byte> ExactDcr1);

internal interface IGroupControlAuthorityArtifactSource
{
    ValueTask<GroupControlAuthorityArtifact> ReadAsync(
        ReadOnlyMemory<byte> exactGsr1Hash,
        CancellationToken cancellationToken);

    ValueTask<ReadOnlyMemory<byte>> ReadGsr1Async(
        ReadOnlyMemory<byte> exactGsr1Hash,
        CancellationToken cancellationToken);
}

internal sealed class FileGroupControlAuthorityArtifactSource
    : IGroupControlAuthorityArtifactSource
{
    private const int ExactGsr1Bytes = 528;
    private readonly ProductionGroupControlAuthorityConfiguration configuration;

    internal FileGroupControlAuthorityArtifactSource(
        ProductionGroupControlAuthorityConfiguration configuration,
        IMailboxStorageSecurity security)
    {
        this.configuration = configuration
            ?? throw new ArgumentNullException(nameof(configuration));
        ArgumentNullException.ThrowIfNull(security);
        security.SecureDirectory(configuration.ArtifactDirectory);
        EnsureSafe(configuration.ArtifactDirectory, expectDirectory: true);
    }

    public async ValueTask<GroupControlAuthorityArtifact> ReadAsync(
        ReadOnlyMemory<byte> exactGsr1Hash,
        CancellationToken cancellationToken)
    {
        var stem = Stem(exactGsr1Hash.Span);
        var gsr = await ReadExactAsync(
            Path.Combine(configuration.ArtifactDirectory, $"{stem}.gsr1"),
            ExactGsr1Bytes,
            ExactGsr1Bytes,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var dcr = await ReadExactAsync(
                Path.Combine(configuration.ArtifactDirectory, $"{stem}.dcr1"),
                1,
                configuration.MaximumDcr1Bytes,
                cancellationToken).ConfigureAwait(false);
            return new GroupControlAuthorityArtifact(gsr, dcr);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(gsr);
            throw;
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>> ReadGsr1Async(
        ReadOnlyMemory<byte> exactGsr1Hash,
        CancellationToken cancellationToken) => await ReadExactAsync(
            Path.Combine(configuration.ArtifactDirectory, $"{Stem(exactGsr1Hash.Span)}.gsr1"),
            ExactGsr1Bytes,
            ExactGsr1Bytes,
            cancellationToken).ConfigureAwait(false);

    private static string Stem(ReadOnlySpan<byte> hash)
    {
        if (hash.Length != 32 || hash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The exact GSR1 hash must be 32 nonzero bytes.", nameof(hash));
        }
        return Convert.ToHexStringLower(hash);
    }

    private async ValueTask<byte[]> ReadExactAsync(
        string path,
        int minimum,
        int maximum,
        CancellationToken cancellationToken)
    {
        EnsureInsideRoot(path);
        EnsureSafe(path, expectDirectory: false);
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        if (stream.Length < minimum || stream.Length > maximum)
        {
            throw new InvalidDataException("A GroupControl authority artifact length is invalid.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        if (stream.Position != stream.Length)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new InvalidDataException("A GroupControl authority artifact changed while being read.");
        }
        EnsureSafe(path, expectDirectory: false);
        return bytes;
    }

    private void EnsureInsideRoot(string candidate)
    {
        var root = Path.GetFullPath(configuration.ArtifactDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = Path.GetFullPath(candidate);
        var relative = Path.GetRelativePath(root, path);
        if (relative is "." or ".."
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relative))
        {
            throw new InvalidDataException("A GroupControl authority artifact escaped its trust root.");
        }
    }

    private static void EnsureSafe(string path, bool expectDirectory)
    {
        var attributes = File.GetAttributes(path);
        var isDirectory = (attributes & FileAttributes.Directory) != 0;
        if ((attributes & FileAttributes.ReparsePoint) != 0
            || expectDirectory != isDirectory)
        {
            throw new InvalidDataException("A GroupControl authority artifact path is not a regular trusted path.");
        }
    }
}

internal sealed class ProductionGroupControlAuthoritySource : IGroupControlAuthoritySource
{
    private readonly IContactVerifiedAuthoritySnapshotSource snapshots;
    private readonly IGroupControlAuthorityArtifactSource artifacts;
    private readonly IOnionMonotonicClock monotonicClock;
    private readonly IGroupControlAuthorityLineageStore lineage;
    private readonly RouterNodeOptions node;
    private readonly int maximumLineageDepth;
    private readonly SemaphoreSlim gate = new(1, 1);

    internal ProductionGroupControlAuthoritySource(
        IContactVerifiedAuthoritySnapshotSource snapshots,
        IGroupControlAuthorityArtifactSource artifacts,
        IOnionMonotonicClock monotonicClock,
        IGroupControlAuthorityLineageStore lineage,
        RouterNodeOptions node,
        ProductionGroupControlAuthorityConfiguration configuration)
    {
        this.snapshots = snapshots ?? throw new ArgumentNullException(nameof(snapshots));
        this.artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        this.monotonicClock = monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));
        this.lineage = lineage ?? throw new ArgumentNullException(nameof(lineage));
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        maximumLineageDepth = (configuration
            ?? throw new ArgumentNullException(nameof(configuration))).MaximumLineageDepth;
    }

    public async ValueTask<VerifiedGroupControlRequestAuthority> AuthorizeAsync(
        GroupControlOperation operation,
        GroupRecord exactRequest,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(exactRequest);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(operation)
            || exactRequest is not (GroupControlWriteRecord or GroupControlQueryRecord))
        {
            throw new ArgumentException("The GroupControl operation is invalid.", nameof(operation));
        }

        var requestedHash = exactRequest.Field(17).ToArray();
        GroupControlAuthorityArtifact package = await artifacts.ReadAsync(
            requestedHash,
            cancellationToken).ConfigureAwait(false);
        try
        {
            var snapshot = await snapshots.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            snapshot.EnsureConsistent();
            var reading = await monotonicClock.ReadAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new GroupControlAuthorityUnavailableException();
            var rendezvous = VerifyRendezvous(package, snapshot, reading);
            var gsr = rendezvous.Record;
            if (!Fixed(gsr.ArtifactHash.Span, requestedHash))
            {
                throw new GroupControlAuthorityUnavailableException();
            }
            var placement = GroupControlPlacementVerifier.Verify(snapshot.Network, rendezvous);
            var candidates = OnionPathCandidateSnapshotFactory.Create(snapshot.Network);
            var replicas = placement.ReplicaNodeIds;
            EnsureProductionReplicaSet(candidates, replicas, node.GetRouterId().ToBytes());
            var placementHash = PlacementHash(
                candidates.ViewHash.Span,
                gsr,
                replicas);
            var routeHash = RouteClosureHash(
                candidates.ViewHash.Span,
                gsr,
                replicas);
            var ancestry = await ReadAndValidateAncestryAsync(
                gsr,
                cancellationToken).ConfigureAwait(false);

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await lineage.ObserveAsync(ancestry, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }

            return new VerifiedGroupControlRequestAuthority(
                operation,
                snapshot.Network.NetworkId.Span,
                candidates.ViewHash.Span,
                placementHash,
                gsr.Field(2).Span,
                gsr.ArtifactHash.Span,
                routeHash,
                BinaryPrimitives.ReadUInt64BigEndian(gsr.Field(13).Span),
                replicas);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (GroupControlAuthorityUnavailableException)
        {
            throw;
        }
        catch (Exception exception) when (exception is FormatException
            or CryptographicException
            or ArgumentException
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException
            or OverflowException)
        {
            throw new GroupControlAuthorityUnavailableException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestedHash);
            Zero(package.ExactGsr1);
            Zero(package.ExactDcr1);
        }
    }

    private static VerifiedGroupControlRendezvous VerifyRendezvous(
        GroupControlAuthorityArtifact package,
        ContactVerifiedAuthoritySnapshot snapshot,
        OnionMonotonicReading reading)
    {
        var freshness = snapshot.DirectoryFreshness;
        var checkpoint = freshness.CurrentCheckpoint
            ?? throw new InvalidOperationException("The GroupControl owner directory is not current.");
        if (!freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
        {
            throw new InvalidOperationException("The GroupControl owner directory freshness expired.");
        }
        var dcr = ContactCodec.Decode("DCR1", package.ExactDcr1.Span);
        var bundle = ContactCodec.Decode("DCB1", dcr.Field(2).Span);
        var dca = ApplicationCoreCodec.DecodeDca1(bundle.Field(6).Span);
        var verifiedDca = ApplicationCoreVerifier.VerifyDca1(
            dca,
            checkpoint.Binding,
            checkpoint.Directory);
        var authoritative = ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
            verifiedDca,
            freshness.TrustedUpperUnixSeconds);
        var owner = ContactCodec.VerifyDcr1Closure(
            dcr,
            authoritative,
            freshness,
            reading.BootId.Span,
            reading.SampleSeconds);
        var gsr = AssertGsr1(package.ExactGsr1.Span);
        EnsureRendezvousBindings(
            gsr,
            snapshot.Network.NetworkId.Span,
            freshness.TrustedLowerUnixSeconds,
            freshness.TrustedUpperUnixSeconds);
        var signer = owner.Directory.Identity.ActiveDevices.SingleOrDefault(device =>
            Fixed(device.Certificate.DeviceId.Span, gsr.Field(10).Span))
            ?? throw new CryptographicException("The GSR1 signer is not a current owner device.");
        EnsureRendezvousSignature(gsr, signer.Certificate.DeviceEd25519PublicKey.Span);
        return GroupCodec.VerifyControlRendezvous(
            gsr,
            owner,
            reading.BootId.Span,
            reading.SampleSeconds);
    }

    private async ValueTask<GroupControlLineageObservation> ReadAndValidateAncestryAsync(
        GroupControlRendezvousRecord current,
        CancellationToken cancellationToken)
    {
        var chain = new List<(ulong Generation, byte[] Hash)>();
        var cursor = current;
        byte[]? root = null;
        for (var depth = 0; depth < maximumLineageDepth; depth++)
        {
            var generation = BinaryPrimitives.ReadUInt64BigEndian(cursor.Field(4).Span);
            var hash = cursor.ArtifactHash.ToArray();
            chain.Add((generation, hash));
            var predecessor = cursor.Field(5).ToArray();
            if (generation == 0)
            {
                if (predecessor.AsSpan().IndexOfAnyExcept((byte)0) >= 0)
                {
                    throw new InvalidDataException("A generation-zero GSR1 has a predecessor.");
                }
                root = hash.ToArray();
                CryptographicOperations.ZeroMemory(predecessor);
                break;
            }
            if (predecessor.AsSpan().IndexOfAnyExcept((byte)0) < 0)
            {
                throw new InvalidDataException("A successor GSR1 omits its predecessor.");
            }
            var priorBytes = await artifacts.ReadGsr1Async(predecessor, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                var prior = AssertGsr1(priorBytes.Span);
                if (!Fixed(prior.ArtifactHash.Span, predecessor)
                    || BinaryPrimitives.ReadUInt64BigEndian(prior.Field(4).Span) + 1 != generation
                    || !Fixed(prior.Field(1).Span, current.Field(1).Span))
                {
                    throw new InvalidDataException("The GSR1 predecessor lineage is invalid.");
                }
                cursor = prior;
            }
            finally
            {
                Zero(priorBytes);
                CryptographicOperations.ZeroMemory(predecessor);
            }
        }
        if (root is null)
        {
            throw new InvalidDataException("The GSR1 lineage exceeds its configured bound.");
        }
        chain.Reverse();
        return new GroupControlLineageObservation(
            root,
            chain[^1].Generation,
            chain[^1].Hash,
            chain.Select(static value => (ReadOnlyMemory<byte>)value.Hash).ToArray());
    }

    private static GroupControlRendezvousRecord AssertGsr1(ReadOnlySpan<byte> exact)
    {
        var record = GroupCodec.Decode(exact);
        if (record is not GroupControlRendezvousRecord gsr
            || !gsr.CanonicalBytes.Span.SequenceEqual(exact))
        {
            throw new InvalidDataException("The GroupControl authority artifact is not exact canonical GSR1.");
        }
        return gsr;
    }

    private static void EnsureProductionReplicaSet(
        VerifiedOnionPathCandidateSnapshot candidates,
        IReadOnlyList<ReadOnlyMemory<byte>> replicas,
        ReadOnlySpan<byte> localNodeId)
    {
        var roles = candidates.Candidates.ToDictionary(
            static value => Convert.ToHexString(value.NodeId.Span),
            static value => value.VerifiedRoleMask,
            StringComparer.Ordinal);
        EnsureProductionReplicaSet(roles, replicas, localNodeId);
    }

    internal static void EnsureProductionReplicaSet(
        IReadOnlyDictionary<string, ushort> verifiedRoleMasks,
        IReadOnlyList<ReadOnlyMemory<byte>> replicas,
        ReadOnlySpan<byte> localNodeId)
    {
        ArgumentNullException.ThrowIfNull(verifiedRoleMasks);
        ArgumentNullException.ThrowIfNull(replicas);
        var local = localNodeId.ToArray();
        if (replicas.Count != 2
            || Fixed(replicas[0].Span, replicas[1].Span)
            || !replicas.Any(value => Fixed(value.Span, local)))
        {
            throw new GroupControlAuthorityUnavailableException();
        }
        foreach (var replica in replicas)
        {
            if (!verifiedRoleMasks.TryGetValue(Convert.ToHexString(replica.Span), out var roleMask)
                || (roleMask & (1 << 2)) == 0)
            {
                throw new GroupControlAuthorityUnavailableException();
            }
        }
    }

    internal static void EnsureRendezvousBindings(
        GroupControlRendezvousRecord gsr,
        ReadOnlySpan<byte> expectedNetworkId,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(gsr);
        if (expectedNetworkId.Length != 16
            || !Fixed(gsr.Field(1).Span, expectedNetworkId)
            || BinaryPrimitives.ReadUInt64BigEndian(gsr.Field(12).Span) > trustedLowerUnixSeconds
            || BinaryPrimitives.ReadUInt64BigEndian(gsr.Field(13).Span) <= trustedUpperUnixSeconds)
        {
            throw new GroupControlAuthorityUnavailableException();
        }
    }

    internal static void EnsureRendezvousSignature(
        GroupControlRendezvousRecord gsr,
        ReadOnlySpan<byte> currentDevicePublicKey)
    {
        ArgumentNullException.ThrowIfNull(gsr);
        if (currentDevicePublicKey.Length != 32
            || currentDevicePublicKey.IndexOfAnyExcept((byte)0) < 0
            || !PublicKeyAuth.VerifyDetached(
                gsr.Field(14).ToArray(),
                gsr.SignatureInput.ToArray(),
                currentDevicePublicKey.ToArray()))
        {
            throw new CryptographicException("The exact GSR1 signature is invalid.");
        }
    }

    internal static byte[] PlacementHash(
        ReadOnlySpan<byte> viewHash,
        GroupControlRendezvousRecord gsr,
        IReadOnlyList<ReadOnlyMemory<byte>> replicas) => Commitment(
            "Deep/Group/V1/control-placement/v1",
            viewHash,
            gsr,
            replicas);

    private static byte[] RouteClosureHash(
        ReadOnlySpan<byte> viewHash,
        GroupControlRendezvousRecord gsr,
        IReadOnlyList<ReadOnlyMemory<byte>> replicas) => Commitment(
            "Deep/Group/V1/control-route-closure/v1",
            viewHash,
            gsr,
            replicas);

    private static byte[] Commitment(
        string domain,
        ReadOnlySpan<byte> viewHash,
        GroupControlRendezvousRecord gsr,
        IReadOnlyList<ReadOnlyMemory<byte>> replicas)
    {
        if (viewHash.Length != 32 || replicas.Count != 2)
        {
            throw new ArgumentException("The verified GroupControl placement is incomplete.");
        }
        var payload = new byte[32 + 32 + 38 + 32 + 64];
        var offset = 0;
        viewHash.CopyTo(payload.AsSpan(offset)); offset += 32;
        gsr.ArtifactHash.Span.CopyTo(payload.AsSpan(offset)); offset += 32;
        gsr.Field(6).Span.CopyTo(payload.AsSpan(offset)); offset += 38;
        gsr.Field(7).Span.CopyTo(payload.AsSpan(offset)); offset += 32;
        foreach (var replica in replicas)
        {
            replica.Span.CopyTo(payload.AsSpan(offset));
            offset += 32;
        }
        try
        {
            return GroupControlRequestProjection.HashDomain(domain, payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Zero(ReadOnlyMemory<byte> memory)
    {
        if (MemoryMarshal.TryGetArray(memory, out ArraySegment<byte> segment))
        {
            CryptographicOperations.ZeroMemory(segment.AsSpan());
        }
    }
}

internal sealed record GroupControlLineageObservation(
    ReadOnlyMemory<byte> RootHash,
    ulong Generation,
    ReadOnlyMemory<byte> HeadHash,
    IReadOnlyList<ReadOnlyMemory<byte>> OrderedHashes);

internal interface IGroupControlAuthorityLineageStore
{
    ValueTask InitializeAsync(CancellationToken cancellationToken);
    ValueTask ObserveAsync(
        GroupControlLineageObservation observation,
        CancellationToken cancellationToken);
}

internal sealed class FileGroupControlAuthorityLineageStore
    : IGroupControlAuthorityLineageStore
{
    private const ushort Version = 1;
    private readonly string path;
    private readonly int maximumBytes;
    private readonly IDataProtector protector;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly Dictionary<string, State> states = new(StringComparer.Ordinal);
    private bool initialized;

    internal FileGroupControlAuthorityLineageStore(
        ProductionGroupControlAuthorityConfiguration configuration,
        IDataProtectionProvider protection,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        path = configuration.StatePath;
        maximumBytes = configuration.MaximumProtectedStateBytes;
        protector = (protection ?? throw new ArgumentNullException(nameof(protection)))
            .CreateProtector("Deep.XNode.GroupControlAuthorityLineage.V1");
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        security.SecureDirectory(Path.GetDirectoryName(path)!);
    }

    public ValueTask InitializeAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (initialized)
        {
            return ValueTask.CompletedTask;
        }
        if (File.Exists(path))
        {
            EnsureRegular(path);
            var protectedBytes = File.ReadAllBytes(path);
            if (protectedBytes.Length is <= 0 || protectedBytes.Length > maximumBytes)
            {
                throw new InvalidDataException("The GroupControl authority state length is invalid.");
            }
            var plaintext = protector.Unprotect(protectedBytes);
            try
            {
                Decode(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
        }
        initialized = true;
        return ValueTask.CompletedTask;
    }

    public async ValueTask ObserveAsync(
        GroupControlLineageObservation observation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ValidateObservation(observation);
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        var key = Convert.ToHexString(observation.RootHash.Span);
        if (states.TryGetValue(key, out var prior))
        {
            if (prior.Forked)
            {
                throw new InvalidDataException("The GSR1 lineage is permanently fork-latched.");
            }
            if (observation.Generation < prior.Generation)
            {
                throw new InvalidDataException("The GSR1 lineage rolls back the durable head.");
            }
            if (observation.Generation == prior.Generation)
            {
                if (Fixed(prior.HeadHash, observation.HeadHash.Span))
                {
                    return;
                }
                prior = prior with { Forked = true };
                states[key] = prior;
                await CommitAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidDataException("The GSR1 lineage forked at the durable generation.");
            }
            if (prior.Generation >= (ulong)observation.OrderedHashes.Count
                || !Fixed(prior.HeadHash, observation.OrderedHashes[checked((int)prior.Generation)].Span))
            {
                prior = prior with { Forked = true };
                states[key] = prior;
                await CommitAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidDataException("The GSR1 successor does not descend from the durable head.");
            }
        }
        states[key] = new State(
            observation.RootHash.ToArray(),
            observation.Generation,
            observation.HeadHash.ToArray(),
            false);
        await CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateObservation(GroupControlLineageObservation observation)
    {
        if (observation.RootHash.Length != 32
            || observation.RootHash.Span.IndexOfAnyExcept((byte)0) < 0
            || observation.HeadHash.Length != 32
            || observation.HeadHash.Span.IndexOfAnyExcept((byte)0) < 0
            || observation.Generation > int.MaxValue
            || observation.OrderedHashes.Count != checked((int)observation.Generation + 1)
            || !Fixed(observation.RootHash.Span, observation.OrderedHashes[0].Span)
            || !Fixed(observation.HeadHash.Span, observation.OrderedHashes[^1].Span)
            || observation.OrderedHashes.Any(static value =>
                value.Length != 32 || value.Span.IndexOfAnyExcept((byte)0) < 0)
            || observation.OrderedHashes
                .Select(static value => Convert.ToHexString(value.Span))
                .Distinct(StringComparer.Ordinal).Count() != observation.OrderedHashes.Count)
        {
            throw new InvalidDataException("The GSR1 lineage observation is invalid.");
        }
    }

    private async ValueTask CommitAsync(CancellationToken cancellationToken)
    {
        var plaintext = Encode();
        byte[] protectedBytes;
        try
        {
            protectedBytes = protector.Protect(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
        if (protectedBytes.Length > maximumBytes)
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            throw new InvalidDataException("The GroupControl authority state exceeds its configured bound.");
        }
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(protectedBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            EnsureRegular(temporary);
            if (File.Exists(path))
            {
                EnsureRegular(path);
            }
            durability.ReplaceFile(temporary, path);
            security.SecureFile(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private byte[] Encode()
    {
        var ordered = states.Values.OrderBy(static value => value.RootHash, ByteComparer.Instance).ToArray();
        var bytes = new byte[12 + ordered.Length * 73];
        "GCL1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), Version);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), checked((uint)ordered.Length));
        var offset = 12;
        foreach (var value in ordered)
        {
            value.RootHash.CopyTo(bytes, offset); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), value.Generation); offset += 8;
            value.HeadHash.CopyTo(bytes, offset); offset += 32;
            bytes[offset++] = value.Forked ? (byte)1 : (byte)0;
        }
        return bytes;
    }

    private void Decode(ReadOnlySpan<byte> exact)
    {
        if (exact.Length < 12
            || !exact[..4].SequenceEqual("GCL1"u8)
            || BinaryPrimitives.ReadUInt16BigEndian(exact[4..]) != Version
            || BinaryPrimitives.ReadUInt16BigEndian(exact[6..]) != 0)
        {
            throw new InvalidDataException("The GroupControl authority state header is invalid.");
        }
        var count = BinaryPrimitives.ReadUInt32BigEndian(exact[8..]);
        if (count > 100_000 || exact.Length != 12 + checked((int)count) * 73)
        {
            throw new InvalidDataException("The GroupControl authority state shape is invalid.");
        }
        var offset = 12;
        byte[]? previous = null;
        for (var index = 0; index < count; index++)
        {
            var root = exact.Slice(offset, 32).ToArray(); offset += 32;
            var generation = BinaryPrimitives.ReadUInt64BigEndian(exact[offset..]); offset += 8;
            var head = exact.Slice(offset, 32).ToArray(); offset += 32;
            var forked = exact[offset++] switch
            {
                0 => false,
                1 => true,
                _ => throw new InvalidDataException("The GroupControl fork marker is invalid.")
            };
            if (root.AsSpan().IndexOfAnyExcept((byte)0) < 0
                || head.AsSpan().IndexOfAnyExcept((byte)0) < 0
                || previous is not null && previous.AsSpan().SequenceCompareTo(root) >= 0
                || !states.TryAdd(Convert.ToHexString(root), new State(root, generation, head, forked)))
            {
                throw new InvalidDataException("The GroupControl authority state is non-canonical.");
            }
            previous = root;
        }
    }

    private static void EnsureRegular(string candidate)
    {
        if ((File.GetAttributes(candidate) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException("The GroupControl authority state path is not a regular file.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed record State(byte[] RootHash, ulong Generation, byte[] HeadHash, bool Forked);

    private sealed class ByteComparer : IComparer<byte[]>
    {
        internal static ByteComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) => (x ?? []).AsSpan().SequenceCompareTo(y ?? []);
    }
}

internal sealed class ProductionGroupControlAuthorityHostedService(
    IGroupControlAuthorityLineageStore lineage,
    GroupControlLocalReplicaRuntime local,
    IOnionMonotonicClock monotonicClock) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _ = local.Binding;
        _ = await monotonicClock.ReadAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The GroupControl monotonic clock is unavailable.");
        await lineage.InitializeAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
