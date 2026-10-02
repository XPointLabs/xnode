using Deep.Protocol.ContactV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Diagnostics;
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
    PublishPreKeyInventory = 6,
    AcquireMailboxGrant = 7
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
        IContactPublicationAuthorizationVerifier publicationAuthorizations)
    {
        Placements = placements ?? throw new ArgumentNullException(nameof(placements));
        PublicationAuthorizations = publicationAuthorizations
            ?? throw new ArgumentNullException(nameof(publicationAuthorizations));
    }

    internal IContactServicePlacementAuthoritySource Placements { get; }
    internal IContactPublicationAuthorizationVerifier PublicationAuthorizations { get; }

    internal static ContactServiceAuthoritySources ForTransportTests(
        IContactServicePlacementAuthoritySource placements) => new(
            placements,
            new RejectAllContactPublicationAuthorizationVerifier());

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
    private readonly IMailboxGrantAuthorityClient mailboxGrantAuthority;
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
        IMailboxGrantAuthorityClient mailboxGrantAuthority,
        IClock clock)
    {
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.authorities = authorities ?? throw new ArgumentNullException(nameof(authorities));
        this.local = local ?? throw new ArgumentNullException(nameof(local));
        this.peerClient = peerClient ?? throw new ArgumentNullException(nameof(peerClient));
        this.mailboxGrantAuthority = mailboxGrantAuthority
            ?? throw new ArgumentNullException(nameof(mailboxGrantAuthority));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    public async ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        ContactServiceOperation operation,
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (operation == ContactServiceOperation.AcquireMailboxGrant)
        {
            return await DispatchMailboxGrantAsync(
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

    private async ValueTask<ReadOnlyMemory<byte>> DispatchMailboxGrantAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken)
    {
        var request = ContactCodec.Decode(ProtocolMagic.XMG1, canonicalRequest.Span);
        ContactCodec.VerifyMailboxGrantHolderSignature(request);
        var locatorHash = request.Field(3);
        var capability = request.Field(4);
        var role = request.Field(6).Span[0] switch
        {
            (byte)Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Deposit =>
                ContactMailboxGrantRole.Deposit,
            (byte)Deep.Protocol.DeepExtension.MailboxCapabilities.MailboxCapabilityDomain.Retrieve =>
                ContactMailboxGrantRole.Retrieve,
            _ => throw new InvalidDataException("The XMG1 mailbox grant role is invalid.")
        };
        var gate = executionGates[BinaryPrimitives.ReadUInt16BigEndian(
            SHA256.HashData(locatorHash.Span)) % executionGates.Length];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var placement = await authorities.Placements.MintAsync(
                    ContactServiceRequestKind.ResolveInvite,
                    locatorHash,
                    cancellationToken)
                .ConfigureAwait(false);
            var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            placement.EnsureUsable(now);
            if (!Fixed(request.Field(1).Span, placement.NetworkId.Span) ||
                !Fixed(locatorHash.Span, placement.ShardKey.Span) ||
                !placement.ContainsReplica(node.GetRouterId().ToBytes()))
                throw new InvalidOperationException(
                    "The XMG1 request is outside the exact resolver placement.");

            var remote = new AuthenticatedRemoteContactServiceReplica(
                placement,
                node.GetRouterId().ToBytes(),
                peerClient,
                canonicalRequest);
            using var coordinator = new ContactResolverTwoReplicaCoordinator(
                local.Binding.ResolverReplica,
                remote);
            var route = await coordinator.ReadMailboxGrantRouteAsync(
                    locatorHash,
                    capability,
                    role,
                    cancellationToken)
                .ConfigureAwait(false);
            var resultCode = route.Disposition switch
            {
                ContactResolverReadDisposition.Current => MailboxGrantAcquisitionResultCode.Success,
                ContactResolverReadDisposition.NotFound or ContactResolverReadDisposition.Expired =>
                    MailboxGrantAcquisitionResultCode.UnknownOrExpired,
                ContactResolverReadDisposition.Conflict => MailboxGrantAcquisitionResultCode.Conflict,
                _ => MailboxGrantAcquisitionResultCode.Unavailable
            };

            ParsedContactRouteClosure? exactRoute = null;
            if (resultCode == MailboxGrantAcquisitionResultCode.Success)
            {
                exactRoute = ContactRouteClosureCodec.Decode(route.CanonicalRouteClosure);
                if (role == ContactMailboxGrantRole.Deposit)
                    MailboxGrantRequestVerifier.VerifyDeposit(canonicalRequest.Span, exactRoute, now);
                else
                    MailboxGrantRequestVerifier.VerifyRetrieve(
                        canonicalRequest.Span,
                        exactRoute,
                        capability.Span,
                        now);
            }

            // Exact unknown-outcome retry must not change the issuer's journal
            // scope/deadline each time the node observes another second.
            var responseExpiry = BinaryPrimitives.ReadUInt64BigEndian(request.Field(10).Span);
            var routeHash = route.Disposition == ContactResolverReadDisposition.Current
                ? SHA256.HashData(route.CanonicalRouteClosure)
                : new byte[32];
            var evidenceExpiry = route.Disposition == ContactResolverReadDisposition.Current
                ? route.EffectiveExpiresAtUnixSeconds
                : 0;
            var evidenceTuple = MailboxGrantRouteEvidenceAuthentication.CreateTuple(
                SHA256.HashData(canonicalRequest.Span),
                locatorHash.Span,
                XNode.Core.ContactResolver.MailboxGrantCapabilityDigest.Compute(
                    capability.Span, role),
                checked((byte)role),
                checked((ushort)route.Disposition),
                routeHash,
                evidenceExpiry);
            var evidenceRequest = new ContactServiceReplicaReceiptRequest(
                ContactServiceReceiptKind.MailboxGrantRoute,
                evidenceTuple);
            var localEvidenceTask = local.Binding.ReceiptAuthority
                .IssueAsync(evidenceRequest, cancellationToken).AsTask();
            var remoteEvidenceTask = remote
                .IssueAsync(evidenceRequest, cancellationToken).AsTask();
            await Task.WhenAll(localEvidenceTask, remoteEvidenceTask).ConfigureAwait(false);
            var replicaEvidence = new[]
            {
                ValidateMailboxGrantEvidence(
                    await localEvidenceTask.ConfigureAwait(false),
                    evidenceTuple,
                    node.GetRouterId().ToBytes()),
                ValidateMailboxGrantEvidence(
                    await remoteEvidenceTask.ConfigureAwait(false),
                    evidenceTuple,
                    remote.ReplicaId.Span),
            };
            var exactResponse = await mailboxGrantAuthority.AuthorizeAsync(
                    new MailboxGrantAuthorityRequest(
                        canonicalRequest.ToArray(),
                        resultCode,
                        resultCode == MailboxGrantAcquisitionResultCode.Success
                            ? route.CanonicalRouteClosure
                            : ReadOnlyMemory<byte>.Empty,
                        checked((ushort)route.Disposition),
                        evidenceExpiry,
                        responseExpiry,
                        replicaEvidence),
                    cancellationToken)
                .ConfigureAwait(false);
            var response = ContactCodec.Decode(ProtocolMagic.XMC1, exactResponse.Span);
            ContactCodec.ValidateMailboxGrantResultBinding(request, response);
            if (resultCode == MailboxGrantAcquisitionResultCode.Success)
                ContactCodec.ValidateMailboxGrantResultRouteBinding(response, exactRoute!);
            else if (BinaryPrimitives.ReadUInt16BigEndian(response.Field(3).Span) != (ushort)resultCode)
                throw new InvalidDataException("The mailbox authority changed the requested failure result.");
            return response.CanonicalBytes.ToArray();
        }
        finally
        {
            gate.Release();
        }
    }

    private static MailboxGrantReplicaEvidence ValidateMailboxGrantEvidence(
        ContactServiceReplicaReceipt evidence,
        ReadOnlySpan<byte> tuple,
        ReadOnlySpan<byte> expectedReplicaId)
    {
        if (evidence.ReplicaId.Length != 32
            || evidence.Signature.Length != 64
            || !Fixed(evidence.ReplicaId.Span, expectedReplicaId)
            || !ContactServiceReceiptTranscript.Verify(
                evidence.ReplicaId.Span,
                MailboxGrantRouteEvidenceAuthentication.GetSigningBytes(tuple),
                evidence.Signature.Span))
            throw new ContactServiceReceiptAuthorityException(
                "A resolver replica returned invalid mailbox grant route evidence.");
        return new MailboxGrantReplicaEvidence(
            evidence.ReplicaId.ToArray(),
            evidence.Signature.ToArray());
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
            ContactServiceOperation.AcquireMailboxGrant =>
                throw new InvalidOperationException("XMG1 uses its sealed grant dispatcher."),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal static class ContactServiceHostComposition
{
    internal static ContactServiceHostCompositionPlan AddDid2ContactServiceBoundary(
        this IServiceCollection services, ContactServicePersistenceOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (!options.RuntimeActivation)
            return services.AddContactServiceBoundary(options);
        RequireRegistered<IDeepIdV2ContactStoreAuthoritySource>(services);
        RequireRegistered<IOnionMonotonicClock>(services);
        var plan = ContactServiceHostCompositionPlan.CreateForDeferredAuthorities(options);
        services.TryAddSingleton(options);
        services.TryAddSingleton(plan);
        services.TryAddSingleton<ContactReplicaReplayGuard>();
        services.TryAddSingleton<IContactReplicaPeerClient, HttpContactReplicaPeerClient>();
        services.TryAddSingleton<IMailboxGrantAuthorityClient, UnavailableMailboxGrantAuthorityClient>();
        return plan;
    }

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
        services.TryAddSingleton<IMailboxGrantAuthorityClient,
            UnavailableMailboxGrantAuthorityClient>();
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
    private readonly ContactCoordinationOnionDispatcher? coordination;
    private readonly ILogger<PrivacyTerminalExitDispatcher>? logger;
    private long failureLogTimestamp;

    public PrivacyTerminalExitDispatcher(
        RoutedNativeMailboxExitDispatcher mailbox,
        IContactServiceOpaqueDispatcher contact,
        GroupControlOnionTerminalAdapter groupControl)
    {
        this.mailbox = mailbox ?? throw new ArgumentNullException(nameof(mailbox));
        this.contact = contact ?? throw new ArgumentNullException(nameof(contact));
        this.groupControl = groupControl ?? throw new ArgumentNullException(nameof(groupControl));
    }

    internal PrivacyTerminalExitDispatcher(RoutedNativeMailboxExitDispatcher mailbox,
        IContactServiceOpaqueDispatcher contact, GroupControlOnionTerminalAdapter groupControl,
        ContactCoordinationOnionDispatcher? coordination,
        ILogger<PrivacyTerminalExitDispatcher>? logger = null) : this(mailbox, contact, groupControl)
    {
        this.coordination = coordination;
        this.logger = logger;
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
        if (canonicalBody.Length >= 4 && canonicalBody.Span[..4].SequenceEqual("XCA2"u8))
            return coordination is null ? NativeMailboxDispatchResult.RejectedBeforeForward() :
                await coordination.DispatchAsync(request, cancellationToken).ConfigureAwait(false);
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
            or ApplicationCoreFormatException
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
            or CryptographicException
            or UnauthorizedAccessException)
        {
            ReportUnknownCompletion(exception);
            return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
        }
    }

    private void ReportUnknownCompletion(Exception exception)
    {
        if (logger is null) return;
        var previous = Volatile.Read(ref failureLogTimestamp);
        // A valid anonymous request must not turn dependency failures into
        // unbounded log traffic. This is diagnostic scheduling, not trust/time.
        if (previous != 0 && Stopwatch.GetElapsedTime(previous) < TimeSpan.FromSeconds(10)) return;
        if (Interlocked.CompareExchange(ref failureLogTimestamp, Stopwatch.GetTimestamp(), previous) != previous) return;
        var category = exception switch
        {
            DeepIdV2DirectoryProofUnavailableException { StatusCode: System.Net.HttpStatusCode.TooManyRequests } => "proof-rate-limit",
            DeepIdV2DirectoryProofUnavailableException => "proof-unavailable",
            CryptographicException => "cryptographic-rejection",
            UnauthorizedAccessException => "authorization-rejection",
            IOException => "custody-or-io",
            _ => "configuration-or-state"
        };
        // No exception object/message, payload, identity, capability or origin
        // enters logs. Classification cannot change unknown completion.
        logger.LogWarning("DID2 ContactResolve terminal could not complete ({Category}); completion remains unknown.", category);
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
            var magic when magic.SequenceEqual("XMG1"u8) => ContactServiceOperation.AcquireMailboxGrant,
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
