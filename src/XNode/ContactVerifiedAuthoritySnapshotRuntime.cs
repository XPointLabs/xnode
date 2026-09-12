using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>
/// One locally measured request for a fresh, nonce-bound Contact authority package.
/// The package source must not substitute its own clock samples or nonce.
/// </summary>
public sealed class ContactAuthorityArtifactRequest
{
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[] directoryLeafKey;
    private readonly byte[]? directoryCoreHash;

    internal ContactAuthorityArtifactRequest(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId,
        ulong nonceCreatedAt,
        ReadOnlySpan<byte> directoryLeafKey)
    {
        this.nonce = Required(nonce, 32, nameof(nonce));
        this.bootId = Required(bootId, 16, nameof(bootId));
        this.directoryLeafKey = Required(directoryLeafKey, 32, nameof(directoryLeafKey));
        NonceCreatedAt = nonceCreatedAt;
    }

    internal ContactAuthorityArtifactRequest(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId,
        ulong nonceCreatedAt,
        ReadOnlySpan<byte> directoryLeafKey,
        ulong directoryTreeSize,
        ReadOnlySpan<byte> directoryCoreHash)
        : this(nonce, bootId, nonceCreatedAt, directoryLeafKey)
    {
        DirectoryTreeSize = directoryTreeSize;
        this.directoryCoreHash = Required(
            directoryCoreHash, 32, nameof(directoryCoreHash));
    }

    public ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ulong NonceCreatedAt { get; }
    public ReadOnlyMemory<byte> DirectoryLeafKey => directoryLeafKey.ToArray();
    internal ulong? DirectoryTreeSize { get; }
    internal ReadOnlyMemory<byte> DirectoryCoreHash =>
        directoryCoreHash?.ToArray() ?? ReadOnlyMemory<byte>.Empty;

    internal bool NonceMatches(ReadOnlySpan<byte> value) => Fixed(nonce, value);
    internal bool BootIdMatches(ReadOnlySpan<byte> value) => Fixed(bootId, value);
    internal bool DirectoryLeafKeyMatches(ReadOnlySpan<byte> value) =>
        Fixed(directoryLeafKey, value);

    internal void CopyNonceTo(Span<byte> destination) => nonce.CopyTo(destination);
    internal void CopyBootIdTo(Span<byte> destination) => bootId.CopyTo(destination);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
        }
        return value.ToArray();
    }
}

public sealed class ContactAuthorityForwardCheckpointPackage
{
    private readonly byte[][] exactXna1AuthorityChain;
    private readonly byte[][] exactOrderedXnf1Chain;
    private readonly byte[] exactNfp1;
    private readonly byte[] exactTargetXnv1;
    private readonly byte[] exactTargetXnh1;

    public ContactAuthorityForwardCheckpointPackage(
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnf1Chain,
        ReadOnlyMemory<byte> exactNfp1,
        ReadOnlyMemory<byte> exactTargetXnv1,
        ReadOnlyMemory<byte> exactTargetXnh1)
    {
        this.exactXna1AuthorityChain = Own(exactXna1AuthorityChain, nameof(exactXna1AuthorityChain));
        this.exactOrderedXnf1Chain = Own(exactOrderedXnf1Chain, nameof(exactOrderedXnf1Chain));
        this.exactNfp1 = exactNfp1.ToArray();
        this.exactTargetXnv1 = exactTargetXnv1.ToArray();
        this.exactTargetXnh1 = exactTargetXnh1.ToArray();
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactXna1AuthorityChain => Copy(exactXna1AuthorityChain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnf1Chain => Copy(exactOrderedXnf1Chain);
    public ReadOnlyMemory<byte> ExactNfp1 => exactNfp1.ToArray();
    public ReadOnlyMemory<byte> ExactTargetXnv1 => exactTargetXnv1.ToArray();
    public ReadOnlyMemory<byte> ExactTargetXnh1 => exactTargetXnh1.ToArray();

    private static byte[][] Own(IReadOnlyList<ReadOnlyMemory<byte>> values, string name)
    {
        ArgumentNullException.ThrowIfNull(values, name);
        return values.Select(static value => value.ToArray()).ToArray();
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(byte[][] values) =>
        Array.AsReadOnly(values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
}

/// <summary>
/// Exact canonical artifacts returned by a network-owned package source. Ordinary
/// XNA1/DTS1/XVP1/XNV1/XNH1/PMT2 chains are complete from generation zero so a
/// protected prefix can be re-established after process restart.
/// </summary>
public sealed class ContactAuthorityArtifactPackage
{
    private readonly byte[][] exactXna1AuthorityChain;
    private readonly byte[][] exactDts1PolicyChain;
    private readonly byte[][] exactOrderedXvp1Chain;
    private readonly byte[][] exactOrderedXnv1Chain;
    private readonly byte[][] exactOrderedXnh1Chain;
    private readonly byte[][] exactActiveXnd1;
    private readonly byte[][] exactOrderedPmt2Chain;
    private readonly byte[] exactAdh1;
    private readonly byte[] exactDtt1;
    private readonly byte[] exactAdp1;

    public ContactAuthorityArtifactPackage(
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDts1PolicyChain,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        ContactAuthorityForwardCheckpointPackage? forwardCheckpoint = null)
    {
        this.exactXna1AuthorityChain = Own(exactXna1AuthorityChain, nameof(exactXna1AuthorityChain));
        this.exactDts1PolicyChain = Own(exactDts1PolicyChain, nameof(exactDts1PolicyChain));
        this.exactAdh1 = exactAdh1.ToArray();
        this.exactDtt1 = exactDtt1.ToArray();
        this.exactAdp1 = exactAdp1.ToArray();
        this.exactOrderedXvp1Chain = Own(exactOrderedXvp1Chain, nameof(exactOrderedXvp1Chain));
        this.exactOrderedXnv1Chain = Own(exactOrderedXnv1Chain, nameof(exactOrderedXnv1Chain));
        this.exactOrderedXnh1Chain = Own(exactOrderedXnh1Chain, nameof(exactOrderedXnh1Chain));
        this.exactActiveXnd1 = Own(exactActiveXnd1, nameof(exactActiveXnd1));
        this.exactOrderedPmt2Chain = Own(exactOrderedPmt2Chain, nameof(exactOrderedPmt2Chain));
        ForwardCheckpoint = forwardCheckpoint;
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExactXna1AuthorityChain => Copy(exactXna1AuthorityChain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactDts1PolicyChain => Copy(exactDts1PolicyChain);
    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public ReadOnlyMemory<byte> ExactDtt1 => exactDtt1.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1 => exactAdp1.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXvp1Chain => Copy(exactOrderedXvp1Chain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnv1Chain => Copy(exactOrderedXnv1Chain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnh1Chain => Copy(exactOrderedXnh1Chain);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactActiveXnd1 => Copy(exactActiveXnd1);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedPmt2Chain => Copy(exactOrderedPmt2Chain);
    public ContactAuthorityForwardCheckpointPackage? ForwardCheckpoint { get; }

    private static byte[][] Own(IReadOnlyList<ReadOnlyMemory<byte>> values, string name)
    {
        ArgumentNullException.ThrowIfNull(values, name);
        return values.Select(static value => value.ToArray()).ToArray();
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(byte[][] values) =>
        Array.AsReadOnly(values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
}

/// <summary>
/// Production network boundary. Implementations fetch raw canonical artifacts;
/// they must never return verifier-minted capabilities.
/// </summary>
public interface IContactAuthorityArtifactPackageSource
{
    XPointNetworkGenesisPin GenesisPin { get; }
    ReadOnlyMemory<byte> DirectoryLeafKey { get; }

    ValueTask<ContactAuthorityArtifactPackage?> FetchAsync(
        ContactAuthorityArtifactRequest request,
        CancellationToken cancellationToken);
}

public sealed class ContactAuthoritySnapshotPersistenceOptions
{
    public string StatePath { get; set; } = string.Empty;
    public ushort SupportedDirectoryReader { get; set; } = 1;
    public int MaximumProtectedStateBytes { get; set; } = 80 * 1024 * 1024;

    internal string ValidateAndGetStatePath(RouterNodeOptions node)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (SupportedDirectoryReader == 0 || MaximumProtectedStateBytes is < 4_096 or > 128 * 1024 * 1024)
        {
            throw new InvalidOperationException("Contact authority persistence bounds are invalid.");
        }
        if (string.IsNullOrWhiteSpace(StatePath) || !Path.IsPathFullyQualified(StatePath))
        {
            throw new InvalidOperationException("Contact authority LKG path must be absolute.");
        }
        var root = Path.GetFullPath(node.DataDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = Path.GetFullPath(StatePath);
        var relative = Path.GetRelativePath(root, path);
        if (relative == ".." || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relative))
        {
            throw new InvalidOperationException("Contact authority LKG must be inside Node:DataDirectory.");
        }
        return path;
    }
}

internal interface IContactAuthorityPackageVerifier
{
    ValueTask<ContactAuthorityVerificationResult> VerifyAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactAuthorityArtifactRequest request,
        ContactAuthorityArtifactPackage package,
        AccountDirectoryMonotonicRequestWindow monotonic,
        ContactAuthorityDurableState? previous,
        ushort supportedDirectoryReader,
        CancellationToken cancellationToken);
}

internal sealed class ProtocolContactAuthorityPackageVerifier(IOnionMonotonicClock monotonicClock)
    : IContactAuthorityPackageVerifier
{
    private readonly OnionTrustedTimeAuthority trustedTime = new(
        monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock)));

    public async ValueTask<ContactAuthorityVerificationResult> VerifyAsync(
        XPointNetworkGenesisPin genesisPin,
        ContactAuthorityArtifactRequest request,
        ContactAuthorityArtifactPackage package,
        AccountDirectoryMonotonicRequestWindow monotonic,
        ContactAuthorityDurableState? previous,
        ushort supportedDirectoryReader,
        CancellationToken cancellationToken)
    {
        var authority = XPointNetworkAuthorityVerifier.Verify(
            genesisPin,
            package.ExactXna1AuthorityChain,
            package.ExactDts1PolicyChain);
        AccountDirectoryProtectedLkg? directoryLkg = previous is null
            ? null
            : AccountDirectoryProtectedLkgFactory.Restore(
                authority,
                previous.ExactAdh1,
                previous.Adh1CoreHash);
        var freshness = AccountDirectoryCurrentProofVerifier.Verify(
            authority,
            package.ExactAdh1,
            package.ExactDtt1,
            package.ExactAdp1,
            request.Nonce.Span,
            request.DirectoryLeafKey.Span,
            monotonic,
            directoryLkg,
            currentCheckpoint: null,
            supportedDirectoryReader);

        VerifiedOnionNetworkContext network;
        if (package.ForwardCheckpoint is null)
        {
            network = await OnionNetworkContextVerifier.VerifyAsync(
                authority,
                freshness,
                package.ExactOrderedXvp1Chain,
                package.ExactOrderedXnv1Chain,
                package.ExactOrderedXnh1Chain,
                package.ExactActiveXnd1,
                package.ExactOrderedPmt2Chain,
                protectedPrevious: null,
                trustedTime,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            if (previous is null)
            {
                throw new InvalidOperationException(
                    "A Contact network forward checkpoint requires a protected predecessor.");
            }
            var recovery = package.ForwardCheckpoint;
            var checkpoint = await XPointNetworkForwardCheckpointVerifier.VerifyAsync(
                authority,
                freshness,
                previous.ToNetworkLkg(),
                recovery.ExactXna1AuthorityChain,
                recovery.ExactOrderedXnf1Chain,
                recovery.ExactNfp1,
                recovery.ExactTargetXnv1,
                recovery.ExactTargetXnh1,
                trustedTime,
                cancellationToken).ConfigureAwait(false);
            network = await OnionNetworkContextVerifier.VerifyFromForwardCheckpointAsync(
                authority,
                freshness,
                checkpoint,
                package.ExactOrderedXvp1Chain[^1],
                package.ExactActiveXnd1,
                package.ExactOrderedPmt2Chain[^1],
                trustedTime,
                cancellationToken).ConfigureAwait(false);
        }

        network.EnsureCurrent();
        var networkLkg = network.ProtectedLkg
            ?? throw new InvalidOperationException("The verified Contact network omitted its protected LKG.");
        if (package.ForwardCheckpoint is null && previous?.LastForwardCheckpointGeneration is not null)
        {
            networkLkg = new XPointNetworkProtectedLkg(
                networkLkg.NetworkId,
                networkLkg.HeadCoreReference,
                networkLkg.HeadTreeSize,
                networkLkg.HeadRoot,
                networkLkg.ViewCoreReference,
                networkLkg.ViewGeneration,
                networkLkg.AuthorityCoreReference,
                previous.LastForwardCheckpointCoreReference,
                previous.LastForwardCheckpointGeneration);
        }
        var snapshot = new ContactVerifiedAuthoritySnapshot(network, authority, freshness, trustedTime);
        snapshot.EnsureConsistent();
        return new ContactAuthorityVerificationResult(
            snapshot,
            ContactAuthorityDurableState.FromVerified(
                genesisPin,
                freshness,
                networkLkg,
                package));
    }
}

internal sealed record ContactAuthorityVerificationResult(
    ContactVerifiedAuthoritySnapshot Snapshot,
    ContactAuthorityDurableState State);

internal sealed class ProductionContactVerifiedAuthoritySnapshotSource
    : IContactVerifiedAuthoritySnapshotSource,
      IContactRouteCurrentNetworkAuthoritySource,
      IDisposable
{
    private readonly IContactAuthorityArtifactPackageSource packageSource;
    private readonly IOnionMonotonicClock monotonicClock;
    private readonly IContactAuthorityPackageVerifier verifier;
    private readonly IContactAuthorityDurableStateStore stateStore;
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly byte[] directoryLeafKey;
    private readonly ushort supportedDirectoryReader;
    private readonly SemaphoreSlim readGate = new(1, 1);
    private bool disposed;

    internal ProductionContactVerifiedAuthoritySnapshotSource(
        IContactAuthorityArtifactPackageSource packageSource,
        IOnionMonotonicClock monotonicClock,
        ContactAuthoritySnapshotPersistenceOptions options,
        RouterNodeOptions node,
        IDataProtectionProvider dataProtectionProvider,
        IMailboxStorageSecurity storageSecurity,
        IMailboxDurabilityBarrier durability)
        : this(
            packageSource,
            monotonicClock,
            new ProtocolContactAuthorityPackageVerifier(monotonicClock),
            CreateStateStore(
                options,
                node,
                dataProtectionProvider,
                storageSecurity,
                durability),
            options?.SupportedDirectoryReader
                ?? throw new ArgumentNullException(nameof(options)))
    {
    }

    internal ProductionContactVerifiedAuthoritySnapshotSource(
        IContactAuthorityArtifactPackageSource packageSource,
        IOnionMonotonicClock monotonicClock,
        IContactAuthorityPackageVerifier verifier,
        IContactAuthorityDurableStateStore stateStore,
        ushort supportedDirectoryReader)
    {
        this.packageSource = packageSource ?? throw new ArgumentNullException(nameof(packageSource));
        this.monotonicClock = monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        if (supportedDirectoryReader == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(supportedDirectoryReader));
        }
        var suppliedPin = packageSource.GenesisPin
            ?? throw new InvalidOperationException("The Contact package source has no genesis pin.");
        genesisPin = new XPointNetworkGenesisPin(
            suppliedPin.NetworkId.Span,
            suppliedPin.AuthorityCoreHash.Span);
        directoryLeafKey = Required(packageSource.DirectoryLeafKey.Span, 32, "directory leaf key");
        this.supportedDirectoryReader = supportedDirectoryReader;
    }

    public async ValueTask<ContactVerifiedAuthoritySnapshot> ReadCurrentAsync(
        CancellationToken cancellationToken) =>
        (await ReadCurrentVerificationAsync(cancellationToken).ConfigureAwait(false)).Snapshot;

    async ValueTask<ContactRouteCurrentNetworkAuthorityMaterial>
        IContactRouteCurrentNetworkAuthoritySource.ReadCurrentRouteAuthorityAsync(
            CancellationToken cancellationToken) =>
        ContactRouteCurrentNetworkAuthorityMaterial.FromVerified(
            await ReadCurrentVerificationAsync(cancellationToken).ConfigureAwait(false));

    private async ValueTask<ContactAuthorityVerificationResult> ReadCurrentVerificationAsync(
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        await readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var previous = await stateStore.ReadAsync(cancellationToken).ConfigureAwait(false);
            previous?.EnsurePin(genesisPin);
            var started = await monotonicClock.ReadAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("The Contact monotonic clock returned no reading.");
            var nonce = RandomNumberGenerator.GetBytes(32);
            var request = previous is null
                ? new ContactAuthorityArtifactRequest(
                    nonce,
                    started.BootId.Span,
                    started.SampleSeconds,
                    directoryLeafKey)
                : new ContactAuthorityArtifactRequest(
                    nonce,
                    started.BootId.Span,
                    started.SampleSeconds,
                    directoryLeafKey,
                    previous.AdhTreeSize,
                    previous.Adh1CoreHash);
            ContactAuthorityArtifactPackage package;
            try
            {
                package = await packageSource.FetchAsync(request, cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException(
                        "The Contact authority artifact package is unavailable.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonce);
            }
            var received = await monotonicClock.ReadAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("The Contact monotonic clock returned no response reading.");
            if (!Fixed(started.BootId.Span, received.BootId.Span)
                || received.SampleSeconds < started.SampleSeconds)
            {
                throw new InvalidOperationException(
                    "The Contact monotonic boot changed while fetching authority artifacts.");
            }
            var monotonic = new AccountDirectoryMonotonicRequestWindow(
                started.BootId.Span,
                started.SampleSeconds,
                received.SampleSeconds,
                received.SampleSeconds);
            ContactAuthorityDurableState.EnsureCompletePrefix(previous, package);
            var verified = await verifier.VerifyAsync(
                genesisPin,
                request,
                package,
                monotonic,
                previous,
                supportedDirectoryReader,
                cancellationToken).ConfigureAwait(false);
            verified.State.EnsurePin(genesisPin);
            var progress = ContactAuthorityDurableState.Compare(previous, verified.State);
            if (progress == ContactAuthorityProgress.Stale)
            {
                throw new InvalidOperationException("The Contact authority package rolls protected LKG backward.");
            }
            if (progress == ContactAuthorityProgress.Fork)
            {
                throw new InvalidOperationException("The Contact authority package forks protected LKG.");
            }
            if (progress == ContactAuthorityProgress.Advanced || previous is null)
            {
                await stateStore.CommitAsync(verified.State, cancellationToken).ConfigureAwait(false);
            }
            return verified;
        }
        finally
        {
            readGate.Release();
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        readGate.Dispose();
    }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidOperationException($"The Contact package source {name} is invalid.");
        }
        return value.ToArray();
    }

    private static IContactAuthorityDurableStateStore CreateStateStore(
        ContactAuthoritySnapshotPersistenceOptions options,
        RouterNodeOptions node,
        IDataProtectionProvider dataProtectionProvider,
        IMailboxStorageSecurity storageSecurity,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(node);
        var path = options.ValidateAndGetStatePath(node);
        return new FileContactAuthorityDurableStateStore(
            path,
            Path.GetFullPath(node.DataDirectory),
            options.MaximumProtectedStateBytes,
            new DataProtectionContactAuthorityStateProtector(dataProtectionProvider),
            storageSecurity,
            durability);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal enum ContactAuthorityProgress
{
    Replay,
    Advanced,
    Stale,
    Fork
}

internal sealed class ContactAuthorityDurableState
{
    internal required byte[] NetworkId { get; init; }
    internal required byte[] GenesisAuthorityCoreHash { get; init; }
    internal required byte[] ExactAdh1 { get; init; }
    internal required byte[] Adh1CoreHash { get; init; }
    internal required ulong AdhGeneration { get; init; }
    internal required ulong AdhTreeSize { get; init; }
    internal required byte[] HeadCoreReference { get; init; }
    internal required ulong HeadTreeSize { get; init; }
    internal required byte[] HeadRoot { get; init; }
    internal required byte[] ViewCoreReference { get; init; }
    internal required ulong ViewGeneration { get; init; }
    internal required byte[] AuthorityCoreReference { get; init; }
    internal required byte[] LastForwardCheckpointCoreReference { get; init; }
    internal ulong? LastForwardCheckpointGeneration { get; init; }
    internal required byte[][] Xna1Chain { get; init; }
    internal required byte[][] Dts1Chain { get; init; }
    internal required byte[][] Xvp1Chain { get; init; }
    internal required byte[][] Xnv1Chain { get; init; }
    internal required byte[][] Xnh1Chain { get; init; }
    internal required byte[][] Pmt2Chain { get; init; }

    internal static ContactAuthorityDurableState FromVerified(
        XPointNetworkGenesisPin pin,
        VerifiedAccountDirectoryFreshness freshness,
        XPointNetworkProtectedLkg network,
        ContactAuthorityArtifactPackage package) => new()
        {
            NetworkId = pin.NetworkId.ToArray(),
            GenesisAuthorityCoreHash = pin.AuthorityCoreHash.ToArray(),
            ExactAdh1 = freshness.NextProtectedLkg.ExactAdh1.ToArray(),
            Adh1CoreHash = freshness.NextProtectedLkg.CoreHash.ToArray(),
            AdhGeneration = freshness.NextProtectedLkg.LogGeneration,
            AdhTreeSize = freshness.NextProtectedLkg.TreeSize,
            HeadCoreReference = network.HeadCoreReference.ToArray(),
            HeadTreeSize = network.HeadTreeSize,
            HeadRoot = network.HeadRoot.ToArray(),
            ViewCoreReference = network.ViewCoreReference.ToArray(),
            ViewGeneration = network.ViewGeneration,
            AuthorityCoreReference = network.AuthorityCoreReference.ToArray(),
            LastForwardCheckpointCoreReference = network.LastForwardCheckpointCoreReference.ToArray(),
            LastForwardCheckpointGeneration = network.LastForwardCheckpointGeneration,
            Xna1Chain = Own(package.ExactXna1AuthorityChain),
            Dts1Chain = Own(package.ExactDts1PolicyChain),
            Xvp1Chain = Own(package.ExactOrderedXvp1Chain),
            Xnv1Chain = Own(package.ExactOrderedXnv1Chain),
            Xnh1Chain = Own(package.ExactOrderedXnh1Chain),
            Pmt2Chain = Own(package.ExactOrderedPmt2Chain)
        };

    internal XPointNetworkProtectedLkg ToNetworkLkg() => new(
        NetworkId,
        HeadCoreReference,
        HeadTreeSize,
        HeadRoot,
        ViewCoreReference,
        ViewGeneration,
        AuthorityCoreReference,
        LastForwardCheckpointCoreReference,
        LastForwardCheckpointGeneration);

    internal void EnsurePin(XPointNetworkGenesisPin pin)
    {
        if (!Fixed(NetworkId, pin.NetworkId.Span)
            || !Fixed(GenesisAuthorityCoreHash, pin.AuthorityCoreHash.Span))
        {
            throw new InvalidDataException("The protected Contact LKG belongs to another network genesis.");
        }
    }

    internal static void EnsureCompletePrefix(
        ContactAuthorityDurableState? previous,
        ContactAuthorityArtifactPackage package)
    {
        if (previous is null)
        {
            return;
        }
        RequirePrefix(previous.Xna1Chain, package.ExactXna1AuthorityChain, "XNA1");
        RequirePrefix(previous.Dts1Chain, package.ExactDts1PolicyChain, "DTS1");
        RequirePrefix(previous.Xvp1Chain, package.ExactOrderedXvp1Chain, "XVP1");
        RequirePrefix(previous.Xnv1Chain, package.ExactOrderedXnv1Chain, "XNV1");
        RequirePrefix(previous.Xnh1Chain, package.ExactOrderedXnh1Chain, "XNH1");
        RequirePrefix(previous.Pmt2Chain, package.ExactOrderedPmt2Chain, "PMT2");
    }

    internal static ContactAuthorityProgress Compare(
        ContactAuthorityDurableState? previous,
        ContactAuthorityDurableState candidate)
    {
        if (previous is null)
        {
            return ContactAuthorityProgress.Advanced;
        }
        if (!Fixed(previous.NetworkId, candidate.NetworkId)
            || !Fixed(previous.GenesisAuthorityCoreHash, candidate.GenesisAuthorityCoreHash))
        {
            return ContactAuthorityProgress.Fork;
        }
        if (candidate.AdhGeneration < previous.AdhGeneration
            || candidate.AdhTreeSize < previous.AdhTreeSize
            || candidate.ViewGeneration < previous.ViewGeneration
            || candidate.HeadTreeSize < previous.HeadTreeSize
            || previous.LastForwardCheckpointGeneration.HasValue
                && (!candidate.LastForwardCheckpointGeneration.HasValue
                    || candidate.LastForwardCheckpointGeneration.Value
                        < previous.LastForwardCheckpointGeneration.Value))
        {
            return ContactAuthorityProgress.Stale;
        }
        if (candidate.AdhGeneration == previous.AdhGeneration
            && candidate.AdhTreeSize == previous.AdhTreeSize
            && (!Fixed(previous.Adh1CoreHash, candidate.Adh1CoreHash)
                || !Fixed(previous.ExactAdh1, candidate.ExactAdh1)))
        {
            return ContactAuthorityProgress.Fork;
        }
        if (candidate.LastForwardCheckpointGeneration
                == previous.LastForwardCheckpointGeneration
            && candidate.LastForwardCheckpointGeneration.HasValue
            && !Fixed(
                previous.LastForwardCheckpointCoreReference,
                candidate.LastForwardCheckpointCoreReference))
        {
            return ContactAuthorityProgress.Fork;
        }
        if (candidate.ViewGeneration == previous.ViewGeneration
            && candidate.HeadTreeSize == previous.HeadTreeSize
            && (!Fixed(previous.ViewCoreReference, candidate.ViewCoreReference)
                || !Fixed(previous.HeadCoreReference, candidate.HeadCoreReference)
                || !Fixed(previous.HeadRoot, candidate.HeadRoot)))
        {
            return ContactAuthorityProgress.Fork;
        }
        var same = candidate.AdhGeneration == previous.AdhGeneration
            && candidate.AdhTreeSize == previous.AdhTreeSize
            && candidate.ViewGeneration == previous.ViewGeneration
            && candidate.HeadTreeSize == previous.HeadTreeSize
            && candidate.LastForwardCheckpointGeneration
                == previous.LastForwardCheckpointGeneration
            && Fixed(
                previous.LastForwardCheckpointCoreReference,
                candidate.LastForwardCheckpointCoreReference)
            && Fixed(previous.AuthorityCoreReference, candidate.AuthorityCoreReference)
            && Same(previous.Xna1Chain, candidate.Xna1Chain)
            && Same(previous.Dts1Chain, candidate.Dts1Chain)
            && Same(previous.Xvp1Chain, candidate.Xvp1Chain)
            && Same(previous.Xnv1Chain, candidate.Xnv1Chain)
            && Same(previous.Xnh1Chain, candidate.Xnh1Chain)
            && Same(previous.Pmt2Chain, candidate.Pmt2Chain);
        return same ? ContactAuthorityProgress.Replay : ContactAuthorityProgress.Advanced;
    }

    private static void RequirePrefix(
        byte[][] protectedChain,
        IReadOnlyList<ReadOnlyMemory<byte>> candidate,
        string magic)
    {
        if (candidate.Count < protectedChain.Length)
        {
            throw new InvalidDataException($"The Contact {magic} chain rolls protected LKG backward.");
        }
        for (var index = 0; index < protectedChain.Length; index++)
        {
            if (!Fixed(protectedChain[index], candidate[index].Span))
            {
                throw new InvalidDataException($"The Contact {magic} chain forks protected LKG.");
            }
        }
    }

    private static byte[][] Own(IReadOnlyList<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => value.ToArray()).ToArray();

    private static bool Same(byte[][] left, byte[][] right) =>
        left.Length == right.Length
        && left.Select((value, index) => Fixed(value, right[index])).All(static value => value);

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal interface IContactAuthorityDurableStateStore
{
    ValueTask<ContactAuthorityDurableState?> ReadAsync(CancellationToken cancellationToken);
    ValueTask CommitAsync(ContactAuthorityDurableState state, CancellationToken cancellationToken);
}

internal interface IContactAuthorityStateProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext);
    byte[] Unprotect(ReadOnlySpan<byte> protectedBytes);
}

internal sealed class DataProtectionContactAuthorityStateProtector : IContactAuthorityStateProtector
{
    private readonly IDataProtector protector;

    internal DataProtectionContactAuthorityStateProtector(IDataProtectionProvider provider) =>
        protector = (provider ?? throw new ArgumentNullException(nameof(provider)))
            .CreateProtector("Deep.XNode.ContactAuthorityLkg.V1");

    public byte[] Protect(ReadOnlySpan<byte> plaintext)
    {
        var copy = plaintext.ToArray();
        try
        {
            return protector.Protect(copy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    public byte[] Unprotect(ReadOnlySpan<byte> protectedBytes)
    {
        var copy = protectedBytes.ToArray();
        try
        {
            return protector.Unprotect(copy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }
}

internal sealed class FileContactAuthorityDurableStateStore : IContactAuthorityDurableStateStore
{
    private readonly string path;
    private readonly string trustRoot;
    private readonly int maximumProtectedBytes;
    private readonly IContactAuthorityStateProtector protector;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;

    internal FileContactAuthorityDurableStateStore(
        string path,
        string trustRoot,
        int maximumProtectedBytes,
        IContactAuthorityStateProtector protector,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        this.path = Path.GetFullPath(path ?? throw new ArgumentNullException(nameof(path)));
        this.trustRoot = Path.GetFullPath(
            trustRoot ?? throw new ArgumentNullException(nameof(trustRoot)))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        this.maximumProtectedBytes = maximumProtectedBytes;
        this.protector = protector ?? throw new ArgumentNullException(nameof(protector));
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        var directory = Path.GetDirectoryName(this.path)
            ?? throw new ArgumentException("Contact authority LKG has no parent directory.", nameof(path));
        security.SecureDirectory(directory);
        ValidatePath(directory, expectFile: false);
    }

    public ValueTask<ContactAuthorityDurableState?> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!File.Exists(path))
        {
            return ValueTask.FromResult<ContactAuthorityDurableState?>(null);
        }
        ValidatePath(path, expectFile: true);
        security.SecureFile(path);
        var info = new FileInfo(path);
        if (info.Length is <= 0 || info.Length > maximumProtectedBytes)
        {
            throw new InvalidDataException("The protected Contact authority LKG length is invalid.");
        }
        var protectedBytes = File.ReadAllBytes(path);
        var plaintext = protector.Unprotect(protectedBytes);
        try
        {
            return ValueTask.FromResult<ContactAuthorityDurableState?>(
                ContactAuthorityDurableStateCodec.Decode(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public ValueTask CommitAsync(
        ContactAuthorityDurableState state,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        cancellationToken.ThrowIfCancellationRequested();
        var plaintext = ContactAuthorityDurableStateCodec.Encode(state);
        byte[] protectedBytes;
        try
        {
            protectedBytes = protector.Protect(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
        if (protectedBytes.Length > maximumProtectedBytes)
        {
            throw new InvalidDataException("The protected Contact authority LKG exceeds its bound.");
        }
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(protectedBytes);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            ValidatePath(temporary, expectFile: true);
            if (File.Exists(path))
            {
                ValidatePath(path, expectFile: true);
            }
            durability.ReplaceFile(temporary, path);
            security.SecureFile(path);
            durability.FlushFileAndParentDirectory(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
        return ValueTask.CompletedTask;
    }

    private void ValidatePath(string candidate, bool expectFile)
    {
        var full = Path.GetFullPath(candidate);
        var relative = Path.GetRelativePath(trustRoot, full);
        if (relative == ".." || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relative))
        {
            throw new UnauthorizedAccessException("The Contact authority LKG path escaped its trust root.");
        }
        FileSystemInfo current = expectFile
            ? new FileInfo(full)
            : new DirectoryInfo(full);
        while (true)
        {
            if (!current.Exists)
            {
                throw new InvalidDataException("The Contact authority LKG path is missing.");
            }
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0 || current.LinkTarget is not null)
            {
                throw new InvalidDataException("The Contact authority LKG path contains a link or reparse point.");
            }
            if (string.Equals(
                    Path.GetFullPath(current.FullName).TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar),
                    trustRoot,
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
            {
                return;
            }
            current = current switch
            {
                FileInfo file => file.Directory
                    ?? throw new InvalidDataException("The Contact authority LKG file has no parent."),
                DirectoryInfo directory => directory.Parent
                    ?? throw new InvalidDataException("The Contact authority LKG directory escaped its root."),
                _ => throw new InvalidDataException("The Contact authority LKG path kind is invalid.")
            };
        }
    }
}

internal static class ContactAuthorityDurableStateCodec
{
    private static ReadOnlySpan<byte> Magic => "CAL1"u8;
    private const ushort Version = 1;
    private const int MaximumChainCount = 4_096;
    private const int MaximumRecordBytes = 1_048_576;

    internal static byte[] Encode(ContactAuthorityDurableState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        using var stream = new MemoryStream();
        stream.Write(Magic);
        WriteUInt16(stream, Version);
        WriteBytes(stream, state.NetworkId);
        WriteBytes(stream, state.GenesisAuthorityCoreHash);
        WriteBytes(stream, state.ExactAdh1);
        WriteBytes(stream, state.Adh1CoreHash);
        WriteUInt64(stream, state.AdhGeneration);
        WriteUInt64(stream, state.AdhTreeSize);
        WriteBytes(stream, state.HeadCoreReference);
        WriteUInt64(stream, state.HeadTreeSize);
        WriteBytes(stream, state.HeadRoot);
        WriteBytes(stream, state.ViewCoreReference);
        WriteUInt64(stream, state.ViewGeneration);
        WriteBytes(stream, state.AuthorityCoreReference);
        stream.WriteByte(state.LastForwardCheckpointGeneration.HasValue ? (byte)1 : (byte)0);
        if (state.LastForwardCheckpointGeneration.HasValue)
        {
            WriteBytes(stream, state.LastForwardCheckpointCoreReference);
            WriteUInt64(stream, state.LastForwardCheckpointGeneration.Value);
        }
        WriteChain(stream, state.Xna1Chain);
        WriteChain(stream, state.Dts1Chain);
        WriteChain(stream, state.Xvp1Chain);
        WriteChain(stream, state.Xnv1Chain);
        WriteChain(stream, state.Xnh1Chain);
        WriteChain(stream, state.Pmt2Chain);
        return stream.ToArray();
    }

    internal static ContactAuthorityDurableState Decode(ReadOnlySpan<byte> exact)
    {
        var reader = new StateReader(exact);
        if (!reader.ReadExact(4).SequenceEqual(Magic) || reader.ReadUInt16() != Version)
        {
            throw new InvalidDataException("The protected Contact authority LKG framing is invalid.");
        }
        var networkId = reader.ReadBytes(16, 16);
        var genesis = reader.ReadBytes(32, 32);
        var adh = reader.ReadBytes(1, MaximumRecordBytes);
        var adhHash = reader.ReadBytes(32, 32);
        var adhGeneration = reader.ReadUInt64();
        var adhTreeSize = reader.ReadUInt64();
        var headReference = reader.ReadBytes(38, 38);
        var headTreeSize = reader.ReadUInt64();
        var headRoot = reader.ReadBytes(32, 32);
        var viewReference = reader.ReadBytes(38, 38);
        var viewGeneration = reader.ReadUInt64();
        var authorityReference = reader.ReadBytes(38, 38);
        var hasCheckpoint = reader.ReadByte();
        if (hasCheckpoint > 1)
        {
            throw new InvalidDataException("The protected Contact checkpoint marker is invalid.");
        }
        var checkpointReference = hasCheckpoint == 1 ? reader.ReadBytes(38, 38) : [];
        ulong? checkpointGeneration = hasCheckpoint == 1 ? reader.ReadUInt64() : null;
        var state = new ContactAuthorityDurableState
        {
            NetworkId = networkId,
            GenesisAuthorityCoreHash = genesis,
            ExactAdh1 = adh,
            Adh1CoreHash = adhHash,
            AdhGeneration = adhGeneration,
            AdhTreeSize = adhTreeSize,
            HeadCoreReference = headReference,
            HeadTreeSize = headTreeSize,
            HeadRoot = headRoot,
            ViewCoreReference = viewReference,
            ViewGeneration = viewGeneration,
            AuthorityCoreReference = authorityReference,
            LastForwardCheckpointCoreReference = checkpointReference,
            LastForwardCheckpointGeneration = checkpointGeneration,
            Xna1Chain = reader.ReadChain(MaximumChainCount, MaximumRecordBytes),
            Dts1Chain = reader.ReadChain(MaximumChainCount, MaximumRecordBytes),
            Xvp1Chain = reader.ReadChain(MaximumChainCount, MaximumRecordBytes),
            Xnv1Chain = reader.ReadChain(MaximumChainCount, MaximumRecordBytes),
            Xnh1Chain = reader.ReadChain(MaximumChainCount, MaximumRecordBytes),
            Pmt2Chain = reader.ReadChain(MaximumChainCount, MaximumRecordBytes)
        };
        reader.EnsureEnd();
        _ = state.ToNetworkLkg();
        if (state.ExactAdh1.Length == 0
            || state.Adh1CoreHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidDataException("The protected Contact directory LKG is invalid.");
        }
        return state;
    }

    private static void WriteChain(Stream stream, byte[][] values)
    {
        if (values.Length is < 1 or > MaximumChainCount)
        {
            throw new InvalidDataException("A protected Contact lineage count is invalid.");
        }
        WriteUInt32(stream, checked((uint)values.Length));
        foreach (var value in values)
        {
            WriteBytes(stream, value);
        }
    }

    private static void WriteBytes(Stream stream, ReadOnlySpan<byte> value)
    {
        if (value.Length > MaximumRecordBytes)
        {
            throw new InvalidDataException("A protected Contact LKG field exceeds its bound.");
        }
        WriteUInt32(stream, checked((uint)value.Length));
        stream.Write(value);
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteUInt64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private ref struct StateReader(ReadOnlySpan<byte> exact)
    {
        private readonly ReadOnlySpan<byte> exact = exact;
        private int offset;

        internal byte ReadByte() => ReadExact(1)[0];
        internal ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(ReadExact(2));
        internal uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(ReadExact(4));
        internal ulong ReadUInt64() => BinaryPrimitives.ReadUInt64BigEndian(ReadExact(8));

        internal byte[] ReadBytes(int minimum, int maximum)
        {
            var length = checked((int)ReadUInt32());
            if (length < minimum || length > maximum)
            {
                throw new InvalidDataException("A protected Contact LKG field length is invalid.");
            }
            return ReadExact(length).ToArray();
        }

        internal byte[][] ReadChain(int maximumCount, int maximumRecordBytes)
        {
            var count = checked((int)ReadUInt32());
            if (count is < 1 || count > maximumCount)
            {
                throw new InvalidDataException("A protected Contact lineage count is invalid.");
            }
            var output = new byte[count][];
            for (var index = 0; index < count; index++)
            {
                output[index] = ReadBytes(1, maximumRecordBytes);
            }
            return output;
        }

        internal ReadOnlySpan<byte> ReadExact(int length)
        {
            if (length < 0 || offset > exact.Length - length)
            {
                throw new InvalidDataException("The protected Contact authority LKG is truncated.");
            }
            var value = exact.Slice(offset, length);
            offset += length;
            return value;
        }

        internal void EnsureEnd()
        {
            if (offset != exact.Length)
            {
                throw new InvalidDataException("The protected Contact authority LKG has trailing bytes.");
            }
        }
    }
}
