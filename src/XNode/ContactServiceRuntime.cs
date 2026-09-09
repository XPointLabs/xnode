using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Buffers.Binary;
using System.Security.Cryptography;
using XNode.Core;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode;

public enum ContactServiceOperation
{
    PublishDcr = 1,
    ResolveDcr = 2,
    ClaimPreKey = 3,
    WriteContactUpdate = 4,
    FetchContactUpdates = 5,
    PublishPreKeyInventory = 6
}

public interface IContactServiceOpaqueDispatcher
{
    ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        ContactServiceOperation operation,
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken);
}

public sealed class ContactServicePersistenceOptions
{
    public bool RuntimeActivation { get; set; }
    public bool MapReplicaEndpoint { get; set; }
    public int ReplicaTimeoutSeconds { get; set; } = 5;
    public int ReplayCapacity { get; set; } = 100_000;
    public int ReplayTtlSeconds { get; set; } = 300;

    internal TimeSpan ReplicaTimeout => TimeSpan.FromSeconds(ReplicaTimeoutSeconds);
    internal TimeSpan ReplayTtl => TimeSpan.FromSeconds(ReplayTtlSeconds);

    public void Validate()
    {
        if (ReplicaTimeoutSeconds is < 1 or > 30
            || ReplayCapacity is < 1_000 or > 10_000_000
            || ReplayTtlSeconds is < 120 or > 3_600)
        {
            throw new InvalidOperationException("ContactService transport resource bounds are invalid.");
        }
        if (MapReplicaEndpoint != RuntimeActivation)
        {
            throw new InvalidOperationException(
                "ContactService runtime activation and replica endpoint mapping must change together.");
        }
    }
}

internal interface IContactServicePlacementAuthoritySource
{
    ValueTask<ContactServicePlacementCapability> MintAsync(
        ContactServiceRequestKind requestKind,
        ReadOnlyMemory<byte> shardKey,
        CancellationToken cancellationToken);
}

internal sealed class ContactServiceAuthoritySources
{
    internal ContactServiceAuthoritySources(
        IContactServicePlacementAuthoritySource placements,
        IContactRouteClosureSource routeClosures,
        IContactPublicationAuthorizationVerifier publicationAuthorizations,
        IContactPreKeyRecipientAuthoritySource? preKeyRecipients = null,
        IContactVerifiedAuthoritySnapshotSource? snapshots = null)
    {
        Placements = placements ?? throw new ArgumentNullException(nameof(placements));
        RouteClosures = routeClosures ?? throw new ArgumentNullException(nameof(routeClosures));
        PublicationAuthorizations = publicationAuthorizations
            ?? throw new ArgumentNullException(nameof(publicationAuthorizations));
        PreKeyRecipients = preKeyRecipients;
        Snapshots = snapshots;
    }

    internal IContactServicePlacementAuthoritySource Placements { get; }
    internal IContactRouteClosureSource RouteClosures { get; }
    internal IContactPublicationAuthorizationVerifier PublicationAuthorizations { get; }
    internal IContactPreKeyRecipientAuthoritySource? PreKeyRecipients { get; }
    internal IContactVerifiedAuthoritySnapshotSource? Snapshots { get; }

    internal static ContactServiceAuthoritySources ForTransportTests(
        IContactServicePlacementAuthoritySource placements) => new(
            placements,
            new RejectingRouteClosureSource(),
            new RejectAllContactPublicationAuthorizationVerifier());

    private sealed class RejectingRouteClosureSource : IContactRouteClosureSource
    {
        public ValueTask<ReadOnlyMemory<byte>?> ReadAsync(
            ReadOnlyMemory<byte> networkId,
            ReadOnlyMemory<byte> locatorHash,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<ReadOnlyMemory<byte>?>(null);
    }

}

internal sealed class ContactServiceHostCompositionPlan
{
    private ContactServiceHostCompositionPlan(
        bool runtimeActivation,
        bool mapReplicaEndpoint,
        ContactServiceAuthoritySources? authorities)
    {
        RuntimeActivation = runtimeActivation;
        MapReplicaEndpoint = mapReplicaEndpoint;
        Authorities = authorities;
    }

    internal bool RuntimeActivation { get; }
    internal bool MapReplicaEndpoint { get; }
    internal ContactServiceAuthoritySources? Authorities { get; }

    internal static ContactServiceHostCompositionPlan Create(
        ContactServicePersistenceOptions options,
        ContactServiceAuthoritySources? authorities)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if ((options.RuntimeActivation || options.MapReplicaEndpoint)
            && authorities is null)
        {
            throw new InvalidOperationException(
                "ContactService activation remains blocked until the verified XNV/PMT, route-closure, and XPA authority sources are composed.");
        }
        return new ContactServiceHostCompositionPlan(
            options.RuntimeActivation,
            options.MapReplicaEndpoint,
            authorities);
    }

    internal static ContactServiceHostCompositionPlan CreateForDeferredAuthorities(
        ContactServicePersistenceOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (!options.RuntimeActivation || !options.MapReplicaEndpoint)
        {
            throw new InvalidOperationException(
                "Deferred Contact authority composition is valid only for an activated runtime.");
        }
        return new ContactServiceHostCompositionPlan(
            runtimeActivation: true,
            mapReplicaEndpoint: true,
            authorities: null);
    }
}

internal sealed class ContactServiceLocalReplicaRuntime : IDisposable
{
    private readonly ContactResolverOpaqueStore resolverStore;
    private readonly ContactPreKeyOpaqueStore preKeyStore;
    private readonly LocalContactServiceReplicaReceiptAuthority receiptAuthority;
    private bool disposed;

    public ContactServiceLocalReplicaRuntime(
        RouterNodeOptions node,
        IClock clock,
        IMailboxStorageSecurity storageSecurity,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(clock);
        var root = Path.Combine(Path.GetFullPath(node.DataDirectory), "contact-service-v1");
        Directory.CreateDirectory(root);
        var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
        try
        {
            receiptAuthority = new LocalContactServiceReplicaReceiptAuthority(seed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
        if (!CryptographicOperations.FixedTimeEquals(
                receiptAuthority.ReplicaId.Span,
                node.GetRouterId().ToBytes()))
        {
            receiptAuthority.Dispose();
            throw new InvalidOperationException(
                "The local contact receipt authority must be the local NETCODEC node identity.");
        }

        resolverStore = new ContactResolverOpaqueStore(
            Path.Combine(root, "resolver.state"),
            clock: clock,
            storageSecurity: storageSecurity,
            durability: durability);
        preKeyStore = new ContactPreKeyOpaqueStore(
            Path.Combine(root, "prekey.state"),
            clock: clock,
            storageSecurity: storageSecurity,
            durability: durability);
        AuthorizationSaga = new ContactPublicationAuthorizationSaga(
            Path.Combine(root, "xpa1-saga.state"),
            Path.Combine(root, "xpa1-saga.key"),
            security: storageSecurity,
            durability: durability);
        Binding = new ContactServiceReplicaBinding(
            new ContactResolverStoreReplica(receiptAuthority.ReplicaId.Span, resolverStore),
            new ContactPreKeyStoreReplica(receiptAuthority.ReplicaId.Span, preKeyStore),
            receiptAuthority);
    }

    internal ContactServiceReplicaBinding Binding { get; }
    internal ContactPublicationAuthorizationSaga AuthorizationSaga { get; }

    internal ReadOnlyMemory<byte> ResolvePublicationServiceCapability(
        Xpp1BoundedRequest request) => preKeyStore.ResolvePublicationServiceCapability(request);

    internal async ValueTask<ReadOnlyMemory<byte>> ApplyPublicationAsync(
        Xpp1BoundedRequest request,
        ContactServicePlacementCapability placement,
        IReadOnlyList<ContactPreKeyRecipientAuthorityCandidate> candidates,
        OnionTrustedTimeAuthority trustedTime,
        ulong receiptAtUnixSeconds,
        CancellationToken cancellationToken)
    {
        var staged = preKeyStore.ApplyPublicationStage(
            request,
            receiptAuthority.ReplicaId.Span,
            receiptAtUnixSeconds,
            receiptAuthority.SignBoundedPreKeyReceipt);
        if (staged.StoredReceipt is not null)
        {
            return staged.StoredReceipt.CanonicalBytes;
        }
        if (staged.UnsignedReceipt is not null)
        {
            return receiptAuthority.SignBoundedPreKeyReceipt(staged.UnsignedReceipt);
        }
        if (request is not Xpp1CommitRequest commit)
        {
            throw new InvalidOperationException("Only a complete XPP1 commit may enter candidate verification.");
        }

        var context = preKeyStore.ReadPublicationCommit(commit);
        VerifiedPreKeyInventoryCandidate? verified = null;
        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                VerifiedPreKeyInventoryCandidate current;
                if (context.PredecessorExactXpi1.IsEmpty)
                {
                    current = await PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
                        context.Transition,
                        placement.VerifiedPlacement,
                        candidate.Authority,
                        candidate.Bundle,
                        trustedTime,
                        predecessor: null,
                        cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    var lineage = PreKeyInventoryPublicationVerifier.RestoreReplicaLineage(
                        context.PredecessorExactXpi1.Span,
                        context.PredecessorXpi1Hash.Span,
                        candidate.Authority,
                        candidate.Bundle);
                    current = await PreKeyInventoryPublicationVerifier.VerifyCandidateAsync(
                        context.Transition,
                        lineage,
                        placement.VerifiedPlacement,
                        candidate.Authority,
                        candidate.Bundle,
                        trustedTime,
                        cancellationToken).ConfigureAwait(false);
                }
                if (verified is not null)
                {
                    throw new InvalidDataException(
                        "Multiple current recipient authorities verified the same bounded XPP1 publication.");
                }
                verified = current;
            }
            catch (PreKeyInventoryPublicationVerificationException)
            {
                // A capability-keyed bounded scan deliberately lets Protocol reject
                // non-matching recipient evidence; raw cache metadata never selects it.
            }
        }
        if (verified is null)
        {
            throw new InvalidOperationException(
                "No current verified recipient authority closes the bounded XPP1 publication.");
        }
        var plan = PreKeyPublicationReplicaState.PrepareActivation(context.Transition, verified);
        var unsigned = preKeyStore.ActivatePublication(
            commit,
            plan,
            placement.ReplicaIds,
            receiptAuthority.ReplicaId.Span,
            receiptAtUnixSeconds);
        var exactReceipt = receiptAuthority.SignBoundedPreKeyReceipt(unsigned);
        return preKeyStore.StoreActivatedPublicationReceipt(commit, exactReceipt).CanonicalBytes;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        AuthorizationSaga.Dispose();
        preKeyStore.Dispose();
        resolverStore.Dispose();
        receiptAuthority.Dispose();
    }
}

internal sealed class ExactContactRequestContextVerifier : IContactRequestContextVerifier
{
    private readonly ContactServicePlacementCapability placement;

    internal ExactContactRequestContextVerifier(ContactServicePlacementCapability placement) =>
        this.placement = placement ?? throw new ArgumentNullException(nameof(placement));

    public ValueTask<ContactRequestContextResult> VerifyAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> viewHash,
        ReadOnlyMemory<byte> placementHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = !Fixed(networkId.Span, placement.NetworkId.Span)
            ? new ContactRequestContextResult(
                ContactRequestContextStatus.Unavailable,
                ReadOnlyMemory<byte>.Empty)
            : !Fixed(viewHash.Span, placement.ViewHash.Span)
                ? new ContactRequestContextResult(
                    ContactRequestContextStatus.StaleView,
                    placement.ViewHash)
                : !Fixed(placementHash.Span, placement.PlacementHash.Span)
                    ? new ContactRequestContextResult(
                        ContactRequestContextStatus.PlacementUnavailable,
                        ReadOnlyMemory<byte>.Empty)
                    : new ContactRequestContextResult(
                        ContactRequestContextStatus.Accepted,
                        ReadOnlyMemory<byte>.Empty);
        return ValueTask.FromResult(result);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed class ProductionContactServiceOpaqueDispatcher :
    IContactServiceOpaqueDispatcher,
    IDisposable
{
    private readonly RouterNodeOptions node;
    private readonly ContactServiceAuthoritySources authorities;
    private readonly ContactServiceLocalReplicaRuntime local;
    private readonly IContactReplicaPeerClient peerClient;
    private readonly IClock clock;
    private readonly SemaphoreSlim[] executionGates = Enumerable.Range(0, 64)
        .Select(static _ => new SemaphoreSlim(1, 1))
        .ToArray();
    private bool disposed;

    public ProductionContactServiceOpaqueDispatcher(
        RouterNodeOptions node,
        ContactServiceAuthoritySources authorities,
        ContactServiceLocalReplicaRuntime local,
        IContactReplicaPeerClient peerClient,
        IClock clock)
    {
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.authorities = authorities ?? throw new ArgumentNullException(nameof(authorities));
        this.local = local ?? throw new ArgumentNullException(nameof(local));
        this.peerClient = peerClient ?? throw new ArgumentNullException(nameof(peerClient));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    public async ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        ContactServiceOperation operation,
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (operation == ContactServiceOperation.PublishPreKeyInventory)
        {
            return await DispatchPreKeyPublicationAsync(
                canonicalRequest,
                cancellationToken).ConfigureAwait(false);
        }
        var request = Decode(operation, canonicalRequest.Span);
        var requestKind = ContactReplicaRequestBinding.RequestKind(operation);
        var shardKey = ContactReplicaRequestBinding.ShardKey(request);
        var gate = executionGates[BinaryPrimitives.ReadUInt16BigEndian(
            SHA256.HashData(shardKey.Span)) % executionGates.Length];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var placement = await authorities.Placements
                .MintAsync(requestKind, shardKey, cancellationToken)
                .ConfigureAwait(false);
            placement.EnsureUsable(checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
            if (placement.RequestKind != requestKind
                || !Fixed(placement.ShardKey.Span, shardKey.Span)
                || !placement.ContainsReplica(node.GetRouterId().ToBytes()))
            {
                throw new InvalidOperationException(
                    "The local node is not selected by the exact contact placement capability.");
            }

            var remote = new AuthenticatedRemoteContactServiceReplica(
                placement,
                node.GetRouterId().ToBytes(),
                peerClient,
                canonicalRequest);
            using var facade = new ContactServiceOpaqueFacade(
                [
                    local.Binding,
                    new ContactServiceReplicaBinding(remote, remote, remote)
                ],
                authorities.RouteClosures,
                new ExactContactRequestContextVerifier(placement),
                authorities.PublicationAuthorizations,
                local.AuthorizationSaga,
                clock);
            return await facade.DispatchAsync(
                (ContactServiceFacadeOperation)operation,
                canonicalRequest,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private async ValueTask<ReadOnlyMemory<byte>> DispatchPreKeyPublicationAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        if (canonicalRequest.Length > Xpp1BoundedCodec.MaximumCanonicalRequestBytes)
        {
            throw new InvalidDataException("The bounded XPP1 request exceeds its canonical transport limit.");
        }
        var request = Xpp1BoundedCodec.Decode(canonicalRequest.Span);
        var shardKey = local.ResolvePublicationServiceCapability(request);
        var gate = executionGates[BinaryPrimitives.ReadUInt16BigEndian(
            SHA256.HashData(shardKey.Span)) % executionGates.Length];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var placement = await authorities.Placements.MintAsync(
                    ContactServiceRequestKind.PublishPreKeyInventory,
                    shardKey,
                    cancellationToken)
                .ConfigureAwait(false);
            var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            placement.EnsureUsable(now);
            if (placement.RequestKind != ContactServiceRequestKind.PublishPreKeyInventory
                || !Fixed(placement.ShardKey.Span, shardKey.Span)
                || !placement.ContainsReplica(node.GetRouterId().ToBytes())
                || !Fixed(request.NetworkId.Span, placement.NetworkId.Span)
                || !Fixed(request.ViewHash.Span, placement.ViewHash.Span)
                || !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span))
            {
                throw new InvalidOperationException(
                    "The local node or exact bounded XPP1 envelope is outside the NETCODEC placement capability.");
            }
            var recipients = authorities.PreKeyRecipients
                ?? throw new InvalidOperationException(
                    "Bounded XPP1 activation requires the verified recipient evidence source.");
            var snapshots = authorities.Snapshots
                ?? throw new InvalidOperationException(
                    "Bounded XPP1 activation requires the current verified authority snapshot.");
            var candidates = await recipients.ReadCurrentCandidatesAsync(
                    request.NetworkId,
                    cancellationToken)
                .ConfigureAwait(false);
            var snapshot = await snapshots.ReadCurrentAsync(cancellationToken)
                .ConfigureAwait(false);
            snapshot.EnsureConsistent();
            if (!Fixed(snapshot.Network.NetworkId.Span, request.NetworkId.Span))
            {
                throw new InvalidOperationException(
                    "The current trusted-time snapshot does not bind the bounded XPP1 network.");
            }
            return await local.ApplyPublicationAsync(
                    request,
                    placement,
                    candidates,
                    snapshot.TrustedTimeAuthority,
                    now,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        foreach (var gate in executionGates)
        {
            gate.Dispose();
        }
    }

    private static ContactServiceRequestRecord Decode(
        ContactServiceOperation operation,
        ReadOnlySpan<byte> exact) => operation switch
        {
            ContactServiceOperation.PublishDcr => Xpu1Codec.Decode(exact),
            ContactServiceOperation.ResolveDcr => Xiq1Codec.Decode(exact),
            ContactServiceOperation.ClaimPreKey => Xpk1Codec.Decode(exact),
            ContactServiceOperation.WriteContactUpdate => Xuw1Codec.Decode(exact),
            ContactServiceOperation.FetchContactUpdates => Xuq1Codec.Decode(exact),
            ContactServiceOperation.PublishPreKeyInventory =>
                throw new InvalidOperationException("Bounded XPP1 uses its sealed publication dispatcher."),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class ContactServiceHostComposition
{
    internal static ContactServiceHostCompositionPlan AddContactServiceBoundary(
        this IServiceCollection services,
        ContactServicePersistenceOptions options,
        ContactServiceAuthoritySources? authorities = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var plan = ContactServiceHostCompositionPlan.Create(options, authorities);
        services.TryAddSingleton(options);
        services.TryAddSingleton(plan);
        services.TryAddSingleton<ContactReplicaReplayGuard>();
        services.TryAddSingleton<IContactReplicaPeerClient, HttpContactReplicaPeerClient>();
        if (!plan.RuntimeActivation)
        {
            services.TryAddSingleton<IContactServiceOpaqueDispatcher,
                UnavailableContactServiceOpaqueDispatcher>();
            return plan;
        }

        services.AddSingleton(authorities!);
        services.AddSingleton<ContactServiceLocalReplicaRuntime>();
        services.AddSingleton<ProductionContactServiceOpaqueDispatcher>();
        services.AddSingleton<IContactServiceOpaqueDispatcher>(provider =>
            provider.GetRequiredService<ProductionContactServiceOpaqueDispatcher>());
        services.AddSingleton<ContactReplicaRequestReceiver>();
        return plan;
    }

    /// <summary>
    /// Explicit production activation path. Merely configuring ContactService is
    /// insufficient: raw artifact, protected monotonic clock, data-protection and
    /// verified route sources must already be registered in DI.
    /// </summary>
    internal static ContactServiceHostCompositionPlan AddProductionContactServiceBoundary(
        this IServiceCollection services,
        ContactServicePersistenceOptions options,
        ContactAuthoritySnapshotPersistenceOptions authorityOptions)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authorityOptions);
        RequireRegistered<IContactAuthorityArtifactPackageSource>(services);
        RequireRegistered<IOnionMonotonicClock>(services);
        RequireRegistered<IDataProtectionProvider>(services);
        RequireRegistered<IVerifiedContactRouteClosureSource>(services);

        var plan = ContactServiceHostCompositionPlan.CreateForDeferredAuthorities(options);
        services.TryAddSingleton(authorityOptions);
        services.TryAddSingleton<ProductionContactVerifiedAuthoritySnapshotSource>(provider => new(
            provider.GetRequiredService<IContactAuthorityArtifactPackageSource>(),
            provider.GetRequiredService<IOnionMonotonicClock>(),
            provider.GetRequiredService<ContactAuthoritySnapshotPersistenceOptions>(),
            provider.GetRequiredService<RouterNodeOptions>(),
            provider.GetRequiredService<IDataProtectionProvider>(),
            provider.GetRequiredService<IMailboxStorageSecurity>(),
            provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.TryAddSingleton<IContactVerifiedAuthoritySnapshotSource>(provider =>
            provider.GetRequiredService<ProductionContactVerifiedAuthoritySnapshotSource>());
        services.TryAddSingleton<IContactRouteCurrentNetworkAuthoritySource>(provider =>
            provider.GetRequiredService<ProductionContactVerifiedAuthoritySnapshotSource>());
        services.TryAddSingleton<VerifiedContactServicePlacementAuthoritySource>(provider => new(
            provider.GetRequiredService<IContactVerifiedAuthoritySnapshotSource>(),
            provider.GetRequiredService<IClock>()));
        services.TryAddSingleton<IContactServicePlacementAuthoritySource>(provider =>
            provider.GetRequiredService<VerifiedContactServicePlacementAuthoritySource>());
        services.TryAddSingleton<VerifiedContactPublicationAuthorizationVerifier>(provider => new(
            provider.GetRequiredService<IContactVerifiedAuthoritySnapshotSource>()));
        services.TryAddSingleton<IContactPublicationAuthorizationVerifier>(provider =>
            provider.GetRequiredService<VerifiedContactPublicationAuthorizationVerifier>());
        services.TryAddSingleton<VerifiedContactRouteClosureSource>(provider => new(
            provider.GetRequiredService<IVerifiedContactRouteClosureSource>(),
            provider.GetRequiredService<IClock>()));
        services.TryAddSingleton<IContactRouteClosureSource>(provider =>
            provider.GetRequiredService<VerifiedContactRouteClosureSource>());
        services.TryAddSingleton<ContactServiceAuthoritySources>(provider => new(
            provider.GetRequiredService<IContactServicePlacementAuthoritySource>(),
            provider.GetRequiredService<IContactRouteClosureSource>(),
            provider.GetRequiredService<IContactPublicationAuthorizationVerifier>(),
            provider.GetRequiredService<IContactPreKeyRecipientAuthoritySource>(),
            provider.GetRequiredService<IContactVerifiedAuthoritySnapshotSource>()));
        services.TryAddSingleton(options);
        services.TryAddSingleton(plan);
        services.TryAddSingleton<ContactReplicaReplayGuard>();
        services.TryAddSingleton<IContactReplicaPeerClient, HttpContactReplicaPeerClient>();
        services.TryAddSingleton<ContactServiceLocalReplicaRuntime>();
        services.TryAddSingleton<ProductionContactServiceOpaqueDispatcher>();
        services.TryAddSingleton<IContactServiceOpaqueDispatcher>(provider =>
            provider.GetRequiredService<ProductionContactServiceOpaqueDispatcher>());
        services.TryAddSingleton<ContactReplicaRequestReceiver>();
        return plan;
    }

    private static void RequireRegistered<T>(IServiceCollection services)
    {
        if (!services.Any(static descriptor => descriptor.ServiceType == typeof(T)))
        {
            throw new InvalidOperationException(
                $"ContactService production activation requires a registered {typeof(T).Name}.");
        }
    }
}

/// <summary>
/// Explicit dependency-unavailable boundary. It keeps ContactResolve closed at
/// the authenticated ONION terminal while production quorum dependencies are
/// not yet implemented.
/// </summary>
public sealed class UnavailableContactServiceOpaqueDispatcher
    : IContactServiceOpaqueDispatcher
{
    public ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        ContactServiceOperation operation,
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        _ = operation;
        _ = canonicalRequest;
        cancellationToken.ThrowIfCancellationRequested();
        throw new ContactServiceUnavailableException(
            "Contact service production dependencies are unavailable.");
    }
}

internal sealed class ContactServiceUnavailableException(string message)
    : InvalidOperationException(message);

/// <summary>
/// Closed terminal multiplexer. Contact and GroupV1 bytes are accepted only
/// after Deep.Protocol has produced a verified ONION exit request; every other
/// payload remains on the existing mailbox path.
/// </summary>
public sealed class PrivacyTerminalExitDispatcher : INativeMailboxExitDispatcher
{
    private readonly RoutedNativeMailboxExitDispatcher mailbox;
    private readonly IContactServiceOpaqueDispatcher contact;
    private readonly GroupControlOnionTerminalAdapter groupControl;

    public PrivacyTerminalExitDispatcher(
        RoutedNativeMailboxExitDispatcher mailbox,
        IContactServiceOpaqueDispatcher contact,
        GroupControlOnionTerminalAdapter groupControl)
    {
        this.mailbox = mailbox ?? throw new ArgumentNullException(nameof(mailbox));
        this.contact = contact ?? throw new ArgumentNullException(nameof(contact));
        this.groupControl = groupControl ?? throw new ArgumentNullException(nameof(groupControl));
    }

    // Keeps focused tests and non-hosted callers fail-closed while Program uses
    // the full three-way production composition above.
    public PrivacyTerminalExitDispatcher(
        RoutedNativeMailboxExitDispatcher mailbox,
        IContactServiceOpaqueDispatcher contact)
        : this(
            mailbox,
            contact,
            new GroupControlOnionTerminalAdapter(
                new UnavailableGroupControlTerminalDispatcher()))
    {
    }

    public async Task<NativeMailboxDispatchResult> DispatchAsync(
        VerifiedCanonicalOnionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var privacyOperation = request.Operation;
        var canonicalBody = request.CanonicalBytes;
        if (TryGroupControlOperation(canonicalBody.Span))
        {
            if (!OuterOperationMatchesGroupControl(privacyOperation))
            {
                return new NativeMailboxDispatchResult(
                    StatusCodes.Status400BadRequest,
                    ReadOnlyMemory<byte>.Empty,
                    NativeMailboxDispatchCertainty.RejectedBeforeForward);
            }
            // The request object is a non-forgeable Deep.Protocol result: raw
            // callers cannot reach this branch. GroupV1 performs a second exact
            // canonical/type check before authority resolution or mutation.
            return await groupControl.DispatchAsync(
                canonicalBody,
                cancellationToken).ConfigureAwait(false);
        }
        if (!TryContactOperation(canonicalBody.Span, out var contactOperation))
        {
            if (privacyOperation == OnionOperation.ContactResolve)
            {
                return new NativeMailboxDispatchResult(
                    StatusCodes.Status400BadRequest, ReadOnlyMemory<byte>.Empty);
            }
            return await mailbox.DispatchAsync(
                request, cancellationToken).ConfigureAwait(false);
        }

        if (!OuterOperationMatches(privacyOperation, contactOperation))
        {
            return new NativeMailboxDispatchResult(
                StatusCodes.Status400BadRequest, ReadOnlyMemory<byte>.Empty);
        }

        try
        {
            var response = await contact.DispatchAsync(
                contactOperation, canonicalBody, cancellationToken).ConfigureAwait(false);
            return new NativeMailboxDispatchResult(StatusCodes.Status200OK, response);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is ContactFormatException
            or ArgumentException
            or InvalidDataException
            or OverflowException)
        {
            return new NativeMailboxDispatchResult(
                StatusCodes.Status400BadRequest, ReadOnlyMemory<byte>.Empty);
        }
        catch (ContactServiceUnavailableException)
        {
            return new NativeMailboxDispatchResult(
                StatusCodes.Status503ServiceUnavailable,
                ReadOnlyMemory<byte>.Empty,
                NativeMailboxDispatchCertainty.RejectedBeforeForward);
        }
        catch (Exception exception) when (exception is IOException
            or InvalidOperationException
            or UnauthorizedAccessException)
        {
            return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
        }
    }

    internal static bool TryContactOperation(
        ReadOnlySpan<byte> body,
        out ContactServiceOperation operation)
    {
        operation = default;
        if (body.Length < 4)
        {
            return false;
        }
        operation = body[..4] switch
        {
            var magic when magic.SequenceEqual("XPU1"u8) => ContactServiceOperation.PublishDcr,
            var magic when magic.SequenceEqual("XIQ1"u8) => ContactServiceOperation.ResolveDcr,
            var magic when magic.SequenceEqual("XPK1"u8) => ContactServiceOperation.ClaimPreKey,
            var magic when magic.SequenceEqual("XUW1"u8) => ContactServiceOperation.WriteContactUpdate,
            var magic when magic.SequenceEqual("XUQ1"u8) => ContactServiceOperation.FetchContactUpdates,
            var magic when magic.SequenceEqual("XPP1"u8) => ContactServiceOperation.PublishPreKeyInventory,
            _ => default
        };
        return operation != default;
    }

    internal static bool TryGroupControlOperation(ReadOnlySpan<byte> body) =>
        body.Length >= 4
        && (body[..4].SequenceEqual("GSW1"u8)
            || body[..4].SequenceEqual("GSQ1"u8));

    internal static bool OuterOperationMatchesGroupControl(OnionOperation outer) =>
        Convert.ToByte(outer) == 5
        && string.Equals(
            Enum.GetName(outer),
            "GroupControl",
            StringComparison.Ordinal);

    internal static bool OuterOperationMatches(
        OnionOperation outer,
        ContactServiceOperation inner) =>
        Enum.IsDefined(inner) && outer == OnionOperation.ContactResolve;
}
