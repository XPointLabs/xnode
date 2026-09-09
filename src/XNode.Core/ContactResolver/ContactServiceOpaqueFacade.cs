using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using XNode.Core.ContactPreKey;
using XNode.Core.Mailbox;

namespace XNode.Core.ContactResolver;

internal enum ContactServiceFacadeOperation
{
    PublishDcr = 1,
    ResolveDcr = 2,
    ClaimPreKey = 3,
    WriteContactUpdate = 4,
    FetchContactUpdates = 5
}

internal interface IContactRouteClosureSource
{
    // Production implementations must return only the canonical bytes exported
    // from a current Protocol-minted VerifiedContactRouteClosure. The facade's
    // final XIS1 encoding independently rechecks the complete route graph.
    ValueTask<ReadOnlyMemory<byte>?> ReadAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal enum ContactRequestContextStatus
{
    Accepted = 1,
    StaleView = 2,
    PlacementUnavailable = 3,
    Unavailable = 4
}

internal sealed record ContactRequestContextResult(
    ContactRequestContextStatus Status,
    ReadOnlyMemory<byte> RequiredViewHash);

internal interface IContactRequestContextVerifier
{
    ValueTask<ContactRequestContextResult> VerifyAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> viewHash,
        ReadOnlyMemory<byte> placementHash,
        CancellationToken cancellationToken);
}

internal interface IContactPublicationAuthorizationVerifier
{
    ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request,
        CancellationToken cancellationToken);
}

internal sealed class RejectAllContactPublicationAuthorizationVerifier
    : IContactPublicationAuthorizationVerifier
{
    public ValueTask<VerifiedXpa1PublicationAuthorization> VerifyAsync(
        Xpu1Request request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromException<VerifiedXpa1PublicationAuthorization>(
            new InvalidOperationException("No contact publication authority is composed."));
    }
}

internal sealed class ContactPublicationAuthorizationBindingException : CryptographicException
{
    internal ContactPublicationAuthorizationBindingException(string message) : base(message) { }
}

/// <summary>
/// Maps canonical Contact V1 service bytes to an explicitly bound two-replica
/// resolver, pre-key, and receipt-authority set. The path-based constructor is
/// an all-local test fixture only. Production must inject one local and one
/// authenticated remote binding and is not activated by this type.
/// </summary>
internal sealed class ContactServiceOpaqueFacade : IDisposable
{
    private const uint RetryAfterSeconds = 5;
    private readonly ContactResolverTwoReplicaCoordinator resolverCoordinator;
    private readonly ContactPreKeyTwoReplicaCoordinator preKeyCoordinator;
    private readonly ContactResolverApplicationService resolver;
    private readonly ContactPreKeyApplicationService preKeys;
    private readonly ReceiptAuthorityBinding[] receiptAuthorities;
    private readonly IDisposable[] ownedFixtureResources;
    private readonly IContactRouteClosureSource routeClosures;
    private readonly IContactRequestContextVerifier requestContexts;
    private readonly IContactPublicationAuthorizationVerifier publicationAuthorizations;
    private readonly ContactPublicationAuthorizationSaga publicationAuthorizationSaga;
    private readonly SemaphoreSlim[] publicationAuthorizationGates;
    private readonly IClock clock;
    private bool disposed;

    public ContactServiceOpaqueFacade(
        string firstResolverStatePath,
        string secondResolverStatePath,
        string firstPreKeyStatePath,
        string secondPreKeyStatePath,
        IReadOnlyList<LocalContactServiceReplicaReceiptAuthority> localReceiptAuthorities,
        IContactRouteClosureSource routeClosures,
        IContactRequestContextVerifier requestContexts,
        IContactPublicationAuthorizationVerifier publicationAuthorizations,
        IClock? clock = null,
        IMailboxStorageSecurity? storageSecurity = null,
        IMailboxDurabilityBarrier? durability = null,
        ContactPublicationAuthorizationSagaOptions? authorizationSagaOptions = null,
        IContactPublicationAuthorizationSagaFaults? authorizationSagaFaults = null)
    {
        ArgumentNullException.ThrowIfNull(localReceiptAuthorities);
        ArgumentNullException.ThrowIfNull(routeClosures);
        ArgumentNullException.ThrowIfNull(requestContexts);
        ArgumentNullException.ThrowIfNull(publicationAuthorizations);
        if (localReceiptAuthorities.Count != 2
            || localReceiptAuthorities.Any(static authority => authority is null))
        {
            throw new ArgumentException(
                "Exactly two local contact receipt authorities are required by the test fixture.",
                nameof(localReceiptAuthorities));
        }

        var sortedAuthorities = localReceiptAuthorities
            .OrderBy(static item => item.ReplicaId.ToArray(), ByteArrayComparer.Instance)
            .ToArray();
        if (CryptographicOperations.FixedTimeEquals(
                ValidateReplicaId(sortedAuthorities[0].ReplicaId, nameof(localReceiptAuthorities)),
                ValidateReplicaId(sortedAuthorities[1].ReplicaId, nameof(localReceiptAuthorities))))
        {
            throw new ArgumentException(
                "The two local contact receipt authorities must be distinct.",
                nameof(localReceiptAuthorities));
        }
        this.routeClosures = routeClosures;
        this.requestContexts = requestContexts;
        this.publicationAuthorizations = publicationAuthorizations;
        this.clock = clock ?? new SystemClock();
        var security = storageSecurity ?? new MailboxStorageSecurity();
        var barrier = durability ?? new MailboxDurabilityBarrier();
        publicationAuthorizationSaga = new ContactPublicationAuthorizationSaga(
            firstResolverStatePath + ".xpa1-saga",
            firstResolverStatePath + ".xpa1-saga.key",
            authorizationSagaOptions,
            security,
            barrier,
            authorizationSagaFaults);
        publicationAuthorizationGates = CreateAuthorizationGates();

        var firstResolverStore = new ContactResolverOpaqueStore(firstResolverStatePath, clock: this.clock,
            storageSecurity: security, durability: barrier);
        var secondResolverStore = new ContactResolverOpaqueStore(secondResolverStatePath, clock: this.clock,
            storageSecurity: security, durability: barrier);
        var firstPreKeyStore = new ContactPreKeyOpaqueStore(firstPreKeyStatePath, clock: this.clock,
            storageSecurity: security, durability: barrier);
        var secondPreKeyStore = new ContactPreKeyOpaqueStore(secondPreKeyStatePath, clock: this.clock,
            storageSecurity: security, durability: barrier);

        var bindings = PrepareBindings(
        [
            new ContactServiceReplicaBinding(
                new ContactResolverStoreReplica(sortedAuthorities[0].ReplicaId.Span, firstResolverStore),
                new ContactPreKeyStoreReplica(sortedAuthorities[0].ReplicaId.Span, firstPreKeyStore),
                sortedAuthorities[0]),
            new ContactServiceReplicaBinding(
                new ContactResolverStoreReplica(sortedAuthorities[1].ReplicaId.Span, secondResolverStore),
                new ContactPreKeyStoreReplica(sortedAuthorities[1].ReplicaId.Span, secondPreKeyStore),
                sortedAuthorities[1])
        ]);
        receiptAuthorities = bindings
            .Select(static binding => new ReceiptAuthorityBinding(
                binding.ReplicaId,
                binding.Binding.ReceiptAuthority))
            .ToArray();
        resolverCoordinator = new(
            bindings[0].Binding.ResolverReplica,
            bindings[1].Binding.ResolverReplica);
        preKeyCoordinator = new(
            bindings[0].Binding.PreKeyReplica,
            bindings[1].Binding.PreKeyReplica);
        resolver = new(resolverCoordinator);
        preKeys = new(preKeyCoordinator);
        ownedFixtureResources =
        [
            firstResolverStore,
            secondResolverStore,
            firstPreKeyStore,
            secondPreKeyStore,
            publicationAuthorizationSaga,
            .. sortedAuthorities
        ];
    }

    internal ContactServiceOpaqueFacade(
        IReadOnlyList<ContactServiceReplicaBinding> replicaBindings,
        IContactRouteClosureSource routeClosures,
        IContactRequestContextVerifier requestContexts,
        IContactPublicationAuthorizationVerifier publicationAuthorizations,
        ContactPublicationAuthorizationSaga publicationAuthorizationSaga,
        IClock? clock = null)
    {
        ArgumentNullException.ThrowIfNull(routeClosures);
        ArgumentNullException.ThrowIfNull(requestContexts);
        ArgumentNullException.ThrowIfNull(publicationAuthorizations);
        var bindings = PrepareBindings(replicaBindings);

        receiptAuthorities = bindings
            .Select(static binding => new ReceiptAuthorityBinding(
                binding.ReplicaId,
                binding.Binding.ReceiptAuthority))
            .ToArray();
        this.routeClosures = routeClosures;
        this.requestContexts = requestContexts;
        this.publicationAuthorizations = publicationAuthorizations;
        this.publicationAuthorizationSaga = publicationAuthorizationSaga
            ?? throw new ArgumentNullException(nameof(publicationAuthorizationSaga));
        publicationAuthorizationGates = CreateAuthorizationGates();
        this.clock = clock ?? new SystemClock();
        resolverCoordinator = new(
            bindings[0].Binding.ResolverReplica,
            bindings[1].Binding.ResolverReplica);
        preKeyCoordinator = new(
            bindings[0].Binding.PreKeyReplica,
            bindings[1].Binding.PreKeyReplica);
        resolver = new(resolverCoordinator);
        preKeys = new(preKeyCoordinator);
        ownedFixtureResources = [];
    }

    public async ValueTask<ReadOnlyMemory<byte>> DispatchAsync(
        ContactServiceFacadeOperation operation,
        ReadOnlyMemory<byte> canonicalRequest,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return operation switch
        {
            ContactServiceFacadeOperation.PublishDcr =>
                await PublishAsync(Xpu1Codec.Decode(canonicalRequest.Span), canonicalRequest, cancellationToken)
                    .ConfigureAwait(false),
            ContactServiceFacadeOperation.ResolveDcr =>
                await ResolveAsync(Xiq1Codec.Decode(canonicalRequest.Span), canonicalRequest, cancellationToken)
                    .ConfigureAwait(false),
            ContactServiceFacadeOperation.ClaimPreKey =>
                await ClaimAsync(Xpk1Codec.Decode(canonicalRequest.Span), canonicalRequest, cancellationToken)
                    .ConfigureAwait(false),
            ContactServiceFacadeOperation.WriteContactUpdate =>
                await WriteUpdateAsync(Xuw1Codec.Decode(canonicalRequest.Span), canonicalRequest, cancellationToken)
                    .ConfigureAwait(false),
            ContactServiceFacadeOperation.FetchContactUpdates =>
                await FetchUpdatesAsync(Xuq1Codec.Decode(canonicalRequest.Span), canonicalRequest, cancellationToken)
                    .ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        resolverCoordinator.Dispose();
        preKeyCoordinator.Dispose();
        foreach (var resource in ownedFixtureResources)
        {
            resource.Dispose();
        }
        foreach (var gate in publicationAuthorizationGates)
        {
            gate.Dispose();
        }
    }

    private async Task<byte[]> PublishAsync(
        Xpu1Request request,
        ReadOnlyMemory<byte> exact,
        CancellationToken cancellationToken)
    {
        if (Expired(request))
        {
            return Xpo1Codec.Encode(exact.Span, Xpo1Status.Expired,
                ContactServiceMutationOutcome.None, Now(), 0,
                ContactServicePaddingClass.Bytes256, []);
        }

        var context = await VerifyContextAsync(request, cancellationToken).ConfigureAwait(false);
        if (context.Status != ContactRequestContextStatus.Accepted)
        {
            var contextStatus = context.Status == ContactRequestContextStatus.StaleView
                ? Xpo1Status.StaleView
                : Xpo1Status.TemporarilyUnavailable;
            var contextPayload = contextStatus == Xpo1Status.StaleView
                ? new ReadOnlyMemory<byte>[] { context.RequiredViewHash.ToArray() }
                : [];
            return EncodeSmallest((padding) => Xpo1Codec.Encode(
                exact.Span, contextStatus, ContactServiceMutationOutcome.None,
                Now(), 0, padding, contextPayload), maximumClass: 3);
        }
        var authorizationGate = SelectAuthorizationGate(request.ExactXpa1.Span);
        await authorizationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            VerifiedXpa1PublicationAuthorization authorization;
            try
            {
                authorization = await publicationAuthorizations
                    .VerifyAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                ValidatePublicationAuthorization(authorization, request);
            }
            catch (Exception exception) when (exception is Xpa1PublicationAuthorizationException
                or ContactPublicationAuthorizationBindingException)
            {
                return Xpo1Codec.Encode(exact.Span, Xpo1Status.Unauthorized,
                    ContactServiceMutationOutcome.None, Now(), 0,
                    ContactServicePaddingClass.Bytes256, []);
            }

            ContactPublicationAuthorizationSagaDisposition reservation;
            try
            {
                reservation = publicationAuthorizationSaga.Reserve(authorization, request, Now());
            }
            catch (Exception exception) when (exception is IOException
                or InvalidDataException
                or UnauthorizedAccessException
                or InvalidOperationException
                or CryptographicException)
            {
                return Xpo1Codec.Encode(exact.Span, Xpo1Status.OutcomeUnknown,
                    ContactServiceMutationOutcome.OutcomeUnknown, Now(), RetryAfterSeconds,
                    ContactServicePaddingClass.Bytes256, []);
            }
            if (reservation == ContactPublicationAuthorizationSagaDisposition.ConflictLatched)
            {
                return EncodeSmallest((padding) => Xpo1Codec.Encode(
                    exact.Span, Xpo1Status.Conflict, ContactServiceMutationOutcome.None,
                    Now(), 0, padding, [Evidence(request.RequestHash.Span)]), maximumClass: 3);
            }

            return await PublishReservedAsync(request, exact, authorization, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            authorizationGate.Release();
        }
    }

    private async Task<byte[]> PublishReservedAsync(
        Xpu1Request request,
        ReadOnlyMemory<byte> exact,
        VerifiedXpa1PublicationAuthorization authorization,
        CancellationToken cancellationToken)
    {
        var result = await resolver.PublishDcrAsync(new ContactResolverPublishRequest(
            new OpaqueDcrPublishRequest(
                request.LocatorHash.Span,
                request.OperationId.Span,
                request.RequestHash.Span,
                request.Generation,
                request.PredecessorObjectHash.Span,
                request.ObjectCiphertextHash.Span,
                request.ObjectCiphertext.Span,
                request.UsageLimit,
                request.EffectiveExpiresAtUnixSeconds)), cancellationToken).ConfigureAwait(false);

        var status = result.Status switch
        {
            ContactResolverApplicationStatus.Committed => Xpo1Status.Committed,
            ContactResolverApplicationStatus.ExactReplay => Xpo1Status.ExactReplay,
            ContactResolverApplicationStatus.Expired => Xpo1Status.Expired,
            ContactResolverApplicationStatus.StaleGeneration => Xpo1Status.StaleView,
            ContactResolverApplicationStatus.RateLimited => Xpo1Status.RateLimited,
            ContactResolverApplicationStatus.OutcomeUnknown => Xpo1Status.OutcomeUnknown,
            ContactResolverApplicationStatus.TemporarilyUnavailable => Xpo1Status.TemporarilyUnavailable,
            _ => Xpo1Status.Conflict
        };
        var outcome = MutationOutcome(result.MutationOutcome);
        IReadOnlyList<ReadOnlyMemory<byte>> payload;
        if (status is Xpo1Status.Committed or Xpo1Status.ExactReplay)
        {
            try
            {
                if (result.DurableReplicaCount != 2
                    || result.MutationOutcome != ContactResolverApplicationMutationOutcome.DurablyCommitted)
                {
                    throw new InvalidDataException(
                        "A committed XPU1 requires two durable replica outcomes.");
                }
                publicationAuthorizationSaga.Commit(authorization, request, Now());
                payload =
                [
                    U64(result.Generation),
                    result.ObjectHash.ToArray(),
                    U64(result.Generation + 1),
                    await ReceiptsAsync(
                        ContactServiceReceiptKind.PublishCommit,
                        PublishTuple(result),
                        cancellationToken).ConfigureAwait(false)
                ];
            }
            catch (Exception exception) when (exception is ContactServiceReceiptAuthorityException
                or IOException
                or InvalidDataException
                or UnauthorizedAccessException
                or InvalidOperationException
                or CryptographicException)
            {
                status = Xpo1Status.OutcomeUnknown;
                outcome = ContactServiceMutationOutcome.OutcomeUnknown;
                payload = [];
            }
        }
        else
        {
            payload = status switch
            {
                Xpo1Status.StaleView => [request.ViewHash.ToArray()],
                Xpo1Status.Conflict => [Evidence(request.RequestHash.Span)],
                _ => []
            };
        }
        return EncodeSmallest((padding) => Xpo1Codec.Encode(
            exact.Span, status, outcome, Now(), Retry(status), padding, payload), maximumClass: 3);
    }

    private async Task<byte[]> ResolveAsync(
        Xiq1Request request,
        ReadOnlyMemory<byte> exact,
        CancellationToken cancellationToken)
    {
        if (Expired(request))
        {
            return Xis1Codec.Encode(exact.Span, Xis1Status.Expired,
                ContactServiceMutationOutcome.None, Now(), 0,
                ContactServicePaddingClass.Bytes256, []);
        }

        var context = await VerifyContextAsync(request, cancellationToken).ConfigureAwait(false);
        if (context.Status != ContactRequestContextStatus.Accepted)
        {
            var contextStatus = context.Status == ContactRequestContextStatus.StaleView
                ? Xis1Status.StaleView
                : Xis1Status.TemporarilyUnavailable;
            IReadOnlyList<ReadOnlyMemory<byte>> contextPayload =
                contextStatus == Xis1Status.StaleView
                    ? [context.RequiredViewHash.ToArray()]
                    : [];
            return EncodeXis(exact.Span, contextStatus,
                ContactServiceMutationOutcome.None, 0, contextPayload);
        }

        var preflightRequest = new ContactResolverResolveRequest(
            request.OperationId.Span,
            request.RequestHash.Span,
            request.LocatorHash.Span);
        var preflight = await resolver.PreflightDcrClaimAsync(
            preflightRequest, cancellationToken).ConfigureAwait(false);
        var preflightStatus = ResolveStatus(preflight.Status);
        if (preflight.Status == ContactResolverApplicationStatus.ExactReplay)
        {
            return await EncodeCommittedResolveAsync(
                exact, request, preflight, cancellationToken).ConfigureAwait(false);
        }
        if (preflight.DurableReplicaCount == 1)
        {
            if (preflight.CanonicalRouteClosure.IsEmpty
                || preflight.ResponseUnixSeconds == 0)
            {
                return ResolveFailure(exact.Span, request,
                    Xis1Status.OutcomeUnknown,
                    ContactResolverApplicationMutationOutcome.OutcomeUnknown);
            }
            var healed = await resolver.ResolveCurrentDcrAsync(
                new ContactResolverResolveRequest(
                    request.OperationId.Span,
                    request.RequestHash.Span,
                    request.LocatorHash.Span,
                    preflight.CanonicalRouteClosure,
                    preflight.ResponseUnixSeconds),
                cancellationToken).ConfigureAwait(false);
            return ResolveStatus(healed.Status) == Xis1Status.Success
                ? await EncodeCommittedResolveAsync(
                    exact, request, healed, cancellationToken).ConfigureAwait(false)
                : ResolveFailure(exact.Span, request,
                    ResolveStatus(healed.Status), healed.MutationOutcome);
        }
        if (preflightStatus != Xis1Status.Success || preflight.Publication is null)
        {
            return ResolveFailure(exact.Span, request, preflightStatus,
                preflight.MutationOutcome);
        }

        var publication = preflight.Publication;
        if (request.RequestedGeneration != 0
            && request.RequestedGeneration != publication.Generation)
        {
            return ResolveFailure(exact.Span, request, Xis1Status.StaleView,
                ContactResolverApplicationMutationOutcome.None);
        }

        var closure = await routeClosures.ReadAsync(
            request.NetworkId, request.LocatorHash, cancellationToken).ConfigureAwait(false);
        if (closure is null || closure.Value.IsEmpty)
        {
            return ResolveFailure(exact.Span, request,
                Xis1Status.TemporarilyUnavailable,
                ContactResolverApplicationMutationOutcome.None);
        }

        var canonicalClosure = closure.Value.ToArray();
        var preflightPayload = ResolvePayload(publication, canonicalClosure);

        if (publication.UsageLimit == 0)
        {
            return EncodeXis(exact.Span, Xis1Status.Success,
                ContactServiceMutationOutcome.None, 0, preflightPayload);
        }

        var claim = await resolver.ResolveCurrentDcrAsync(
            new ContactResolverResolveRequest(
                request.OperationId.Span,
                request.RequestHash.Span,
                request.LocatorHash.Span,
                canonicalClosure,
                Now()),
            cancellationToken).ConfigureAwait(false);
        var claimStatus = ResolveStatus(claim.Status);
        if (claimStatus != Xis1Status.Success)
        {
            return ResolveFailure(exact.Span, request, claimStatus,
                claim.MutationOutcome);
        }
        if (claim.Publication is null
            || claim.ClaimCommitGeneration == 0
            || claim.ResponseUnixSeconds == 0
            || claim.CanonicalRouteClosure.IsEmpty
            || claim.MutationOutcome !=
                ContactResolverApplicationMutationOutcome.DurablyCommitted)
        {
            return ResolveFailure(exact.Span, request,
                Xis1Status.OutcomeUnknown,
                ContactResolverApplicationMutationOutcome.OutcomeUnknown);
        }

        return await EncodeCommittedResolveAsync(
            exact, request, claim, cancellationToken).ConfigureAwait(false);
    }

    private async Task<byte[]> ClaimAsync(
        Xpk1Request request,
        ReadOnlyMemory<byte> exact,
        CancellationToken cancellationToken)
    {
        if (Expired(request))
        {
            return Xpc1Codec.Encode(exact.Span, Xpc1Status.Expired,
                ContactServiceMutationOutcome.None, Now(), 0,
                ContactServicePaddingClass.Bytes256, []);
        }

        var context = await VerifyContextAsync(request, cancellationToken).ConfigureAwait(false);
        if (context.Status != ContactRequestContextStatus.Accepted)
        {
            return Xpc1Codec.Encode(exact.Span, Xpc1Status.PreKeysUnavailable,
                ContactServiceMutationOutcome.None, Now(), 0,
                ContactServicePaddingClass.Bytes256, []);
        }

        var result = await preKeys.ClaimAsync(new OpaquePreKeyClaimRequest(
            request.NetworkId.Span,
            request.ServiceCapability.Span,
            request.ResponderDeviceId.Span,
            request.RequestedSuite,
            request.OperationId.Span,
            request.RequestHash.Span,
            request.Dcb1Hash.Span,
            request.Xps1Hash.Span,
            request.ExpiresAtUnixSeconds), cancellationToken).ConfigureAwait(false);
        var status = result.Status switch
        {
            ContactPreKeyApplicationStatus.Claimed => Xpc1Status.Claimed,
            // A retry must reproduce the first canonical response byte-for-byte.
            // The durable operation remains a claim; changing only the status to
            // Replay would change the verifier's full exact replay hash.
            ContactPreKeyApplicationStatus.Replay => Xpc1Status.Claimed,
            ContactPreKeyApplicationStatus.PreKeysUnavailable => Xpc1Status.PreKeysUnavailable,
            ContactPreKeyApplicationStatus.Expired => Xpc1Status.Expired,
            ContactPreKeyApplicationStatus.StaleBundle => Xpc1Status.StaleBundle,
            ContactPreKeyApplicationStatus.RateLimited => Xpc1Status.RateLimited,
            ContactPreKeyApplicationStatus.OutcomeUnknown => Xpc1Status.OutcomeUnknown,
            _ => Xpc1Status.Conflict
        };
        var mutationOutcome = MutationOutcome(result.MutationOutcome);
        var claim = result.Claim;
        IReadOnlyList<ReadOnlyMemory<byte>> payload;
        if (status is Xpc1Status.Claimed or Xpc1Status.Replay)
        {
            try
            {
                payload = await ClaimPayloadAsync(request, claim, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is ContactServiceReceiptAuthorityException
                or ContactFormatException
                or FormatException
                or CryptographicException
                or ArgumentException
                or InvalidDataException
                or InvalidOperationException)
            {
                status = Xpc1Status.OutcomeUnknown;
                mutationOutcome = ContactServiceMutationOutcome.OutcomeUnknown;
                payload = [];
            }
        }
        else
        {
            payload = status switch
            {
                Xpc1Status.StaleBundle =>
                    [claim.RequiredDcb1Hash.ToArray(), claim.RequiredXps1Hash.ToArray(),
                        claim.RequiredXpi1Hash.ToArray()],
                Xpc1Status.Conflict => [Evidence(request.RequestHash.Span)],
                _ => []
            };
        }
        return EncodeSmallest((padding) => Xpc1Codec.Encode(
            exact.Span, status, mutationOutcome,
            status == Xpc1Status.Claimed ? claim.ClaimedAtUnixSeconds : Now(),
            Retry(status), padding, payload), maximumClass: 3);
    }

    private async Task<byte[]> WriteUpdateAsync(
        Xuw1Request request,
        ReadOnlyMemory<byte> exact,
        CancellationToken cancellationToken)
    {
        if (Expired(request))
        {
            return Xus1Codec.Encode(exact.Span, Xus1OperationKind.Write, Xus1Status.Expired,
                ContactServiceMutationOutcome.None, Now(), 0,
                ContactServicePaddingClass.Bytes256, []);
        }

        var context = await VerifyContextAsync(request, cancellationToken).ConfigureAwait(false);
        if (context.Status != ContactRequestContextStatus.Accepted)
        {
            return EncodeSmallest((padding) => Xus1Codec.Encode(
                exact.Span, Xus1OperationKind.Write, Xus1Status.Conflict,
                ContactServiceMutationOutcome.None, Now(), 0, padding,
                [Evidence(request.RequestHash.Span)]), maximumClass: 4);
        }

        var result = await resolver.WriteXurAsync(new ContactResolverXurWriteRequest(
            new OpaqueXurWriteRequest(
                request.ServiceCapability.Span,
                request.OperationId.Span,
                request.RequestHash.Span,
                request.Xur1Hash.Span,
                request.EventGeneration,
                request.PredecessorEventHash.Span,
                request.EventHash.Span,
                request.EventCiphertextHash.Span,
                request.SealedUpdate.Span,
                request.EffectiveExpiresAtUnixSeconds)), cancellationToken).ConfigureAwait(false);
        var status = result.Status switch
        {
            ContactResolverApplicationStatus.Committed => Xus1Status.WriteCommitted,
            ContactResolverApplicationStatus.ExactReplay => Xus1Status.ExactReplay,
            ContactResolverApplicationStatus.Expired => Xus1Status.Expired,
            ContactResolverApplicationStatus.StaleGeneration => Xus1Status.StaleGeneration,
            ContactResolverApplicationStatus.RateLimited => Xus1Status.RateLimited,
            ContactResolverApplicationStatus.OutcomeUnknown => Xus1Status.OutcomeUnknown,
            _ => Xus1Status.Conflict
        };
        var mutationOutcome = MutationOutcome(result.MutationOutcome);
        IReadOnlyList<ReadOnlyMemory<byte>> payload;
        if (status is Xus1Status.WriteCommitted or Xus1Status.ExactReplay)
        {
            try
            {
                payload =
                [
                    U64(result.Generation),
                    result.ObjectHash.ToArray(),
                    U64(result.Generation),
                    await ReceiptsAsync(
                        ContactServiceReceiptKind.UpdateCommit,
                        UpdateTuple(result),
                        cancellationToken).ConfigureAwait(false)
                ];
            }
            catch (ContactServiceReceiptAuthorityException)
            {
                status = Xus1Status.OutcomeUnknown;
                mutationOutcome = ContactServiceMutationOutcome.OutcomeUnknown;
                payload = [];
            }
        }
        else
        {
            payload = status switch
            {
                Xus1Status.StaleGeneration => [U64(result.Generation),
                    result.ObjectHash.IsEmpty
                        ? Evidence(request.RequestHash.Span)
                        : result.ObjectHash.ToArray()],
                Xus1Status.Conflict => [Evidence(request.RequestHash.Span)],
                _ => []
            };
        }
        return EncodeSmallest((padding) => Xus1Codec.Encode(
            exact.Span, Xus1OperationKind.Write, status,
            mutationOutcome, Now(), Retry(status), padding, payload),
            maximumClass: 4);
    }

    private async Task<byte[]> FetchUpdatesAsync(
        Xuq1Request request,
        ReadOnlyMemory<byte> exact,
        CancellationToken cancellationToken)
    {
        var padding = request.ResponsePaddingClass;
        if (Expired(request))
        {
            return Xus1Codec.Encode(exact.Span, Xus1OperationKind.Fetch, Xus1Status.Expired,
                ContactServiceMutationOutcome.None, Now(), 0, padding, []);
        }

        var context = await VerifyContextAsync(request, cancellationToken).ConfigureAwait(false);
        if (context.Status != ContactRequestContextStatus.Accepted)
        {
            return Xus1Codec.Encode(exact.Span, Xus1OperationKind.Fetch, Xus1Status.Conflict,
                ContactServiceMutationOutcome.None, Now(), 0, padding,
                [Evidence(request.RequestHash.Span)]);
        }

        var result = await resolver.FetchXurAsync(new ContactResolverXurFetchRequest(
            request.OperationId.Span,
            request.RequestHash.Span,
            request.ServiceCapability.Span,
            request.Xur1Hash.Span,
            request.AfterGeneration,
            request.MaxEvents), cancellationToken).ConfigureAwait(false);
        if (result.Status == ContactResolverApplicationStatus.Events)
        {
            return EncodeEventsPage(exact.Span, request, result);
        }

        var status = result.Status switch
        {
            ContactResolverApplicationStatus.NoChange => Xus1Status.NoChange,
            ContactResolverApplicationStatus.Expired => Xus1Status.Expired,
            ContactResolverApplicationStatus.RateLimited => Xus1Status.RateLimited,
            ContactResolverApplicationStatus.StaleGeneration => Xus1Status.StaleGeneration,
            _ => Xus1Status.Conflict
        };
        IReadOnlyList<ReadOnlyMemory<byte>> payload = status switch
        {
            Xus1Status.StaleGeneration => [U64(result.CurrentGeneration), result.CurrentHash.ToArray()],
            Xus1Status.Conflict => [Evidence(request.RequestHash.Span)],
            _ => []
        };
        return Xus1Codec.Encode(exact.Span, Xus1OperationKind.Fetch, status,
            ContactServiceMutationOutcome.None, Now(), Retry(status), padding, payload);
    }

    private byte[] EncodeEventsPage(
        ReadOnlySpan<byte> exact,
        Xuq1Request request,
        ContactResolverApplicationResult result)
    {
        var encodedEvents = result.Events.Select(EncodeEvent).ToArray();
        var page = new List<byte[]>();
        byte[]? accepted = null;
        foreach (var item in encodedEvents)
        {
            page.Add(item);
            var data = page.SelectMany(static value => value).ToArray();
            var lastGeneration = result.Events[page.Count - 1].Generation;
            var hasMore = page.Count < encodedEvents.Length || result.CurrentGeneration > lastGeneration;
            try
            {
                accepted = Xus1Codec.Encode(exact, Xus1OperationKind.Fetch, Xus1Status.Events,
                    ContactServiceMutationOutcome.None, Now(), 0, request.ResponsePaddingClass,
                    [U16(checked((ushort)page.Count)), data, U64(lastGeneration),
                        new byte[] { hasMore ? (byte)1 : (byte)0 }]);
            }
            catch (ContactFormatException)
            {
                page.RemoveAt(page.Count - 1);
                break;
            }
        }

        if (accepted is not null)
        {
            return accepted;
        }

        var required = RequiredXusPadding(exact, encodedEvents[0], result.Events[0].Generation,
            result.CurrentGeneration > result.Events[0].Generation);
        return Xus1Codec.Encode(exact, Xus1OperationKind.Fetch, Xus1Status.RecordTooLarge,
            ContactServiceMutationOutcome.None, Now(), 0, request.ResponsePaddingClass,
            [U16((ushort)required), U32(checked((uint)encodedEvents[0].Length))]);
    }

    private ContactServicePaddingClass RequiredXusPadding(
        ReadOnlySpan<byte> exact,
        byte[] firstEvent,
        ulong generation,
        bool hasMore)
    {
        for (var value = 0; value <= 4; value++)
        {
            var padding = (ContactServicePaddingClass)value;
            try
            {
                _ = Xus1Codec.Encode(exact, Xus1OperationKind.Fetch, Xus1Status.Events,
                    ContactServiceMutationOutcome.None, Now(), 0, padding,
                    [U16(1), firstEvent, U64(generation), new byte[] { hasMore ? (byte)1 : (byte)0 }]);
                return padding;
            }
            catch (ContactFormatException)
            {
            }
        }
        throw new InvalidDataException("A valid XUR event does not fit the maximum response class.");
    }

    private async Task<IReadOnlyList<ReadOnlyMemory<byte>>> ClaimPayloadAsync(
        Xpk1Request request,
        ContactPreKeyClaimResult claim,
        CancellationToken cancellationToken)
    {
        ValidateClaimBinding(request, claim);
        var tuple = ContactServiceReceiptTranscript.PreKeyClaimTuple(claim);
        return
        [
            claim.ExactDpk2.ToArray(),
            claim.OneTimePreKeyId.ToArray(),
            Xpc1Codec.ComputeClaimReceiptHash(
                request.RequestHash.Span,
                claim.ExactDpk2,
                claim.ExactXpi1,
                claim.OneTimePreKeyId,
                claim.ClaimCommitGeneration,
                claim.LastResortUseCounter),
            claim.ExactCurrentDmd1Hash.ToArray(),
            claim.ExactCurrentDrs1Ref.ToArray(),
            U64(claim.ServiceGeneration),
            U64(claim.PreKeyExpiresAt),
            U16(claim.LastResortUseCounter),
            U64(claim.ClaimCommitGeneration),
            await ReceiptsAsync(
                ContactServiceReceiptKind.PreKeyClaimCommit,
                tuple,
                cancellationToken).ConfigureAwait(false),
            claim.ExactXpi1.ToArray(),
            U16(claim.InventoryIndex),
            claim.InclusionProof.ToArray()
        ];
    }

    private void ValidateClaimBinding(
        Xpk1Request request,
        ContactPreKeyClaimResult claim)
    {
        if (claim.ClaimedAtUnixSeconds == 0
            || !Fixed(request.RequestHash.Span, claim.RequestHash))
        {
            throw new InvalidDataException(
                "The durable pre-key claim does not bind the exact XPK1 request.");
        }

        var dpk2 = Dpk2Codec.Decode(claim.ExactDpk2);
        var manifest = Xpi1Codec.Decode(claim.ExactXpi1);
        var computedXpi1Hash = Xpi1Codec.ComputeHash(claim.ExactXpi1);
        var selectedId = claim.OneTimePreKeyId;
        var selectedIsLastResort = ContactPreKeyOpaqueValue.IsZero32(selectedId);
        try
        {
            if (!Fixed(dpk2.NetworkId.Span, request.NetworkId.Span)
                || !Fixed(dpk2.ResponderDeviceId.Span, request.ResponderDeviceId.Span)
                || dpk2.PrekeyServiceGeneration != claim.ServiceGeneration
                || dpk2.InventoryEpoch != claim.InventoryEpoch
                || dpk2.ExpiresAt != claim.PreKeyExpiresAt
                || !Fixed(dpk2.DeviceDirectoryHeadHash.Span, claim.ExactCurrentDmd1Hash)
                || !Fixed(computedXpi1Hash, claim.Xpi1Hash)
                || !Fixed(manifest.NetworkId.Span, request.NetworkId.Span)
                || !Fixed(manifest.ServiceCapability.Span, request.ServiceCapability.Span)
                || !Fixed(manifest.ResponderDeviceId.Span, request.ResponderDeviceId.Span)
                || manifest.ServiceGeneration != claim.ServiceGeneration
                || manifest.InventoryEpoch != claim.InventoryEpoch
                || !Fixed(manifest.CurrentDmd1Hash.Span, claim.ExactCurrentDmd1Hash)
                || !manifest.CurrentDrs1Reference.Span.SequenceEqual(claim.ExactCurrentDrs1Ref)
                || claim.ReplicaNodeIds.Count != receiptAuthorities.Length
                || claim.ReplicaNodeIds.Where((value, index) =>
                    !value.Span.SequenceEqual(receiptAuthorities[index].ReplicaId)).Any()
                || (dpk2.MlKemKind == Dpk2PrekeyKind.LastResort) != selectedIsLastResort
                || (selectedIsLastResort
                    ? claim.LastResortUseCounter is 0
                        || claim.LastResortUseCounter > dpk2.ReuseLimit
                    : claim.LastResortUseCounter != 0
                        || !Fixed(dpk2.OneTimeX25519PrekeyId.Span, selectedId)))
            {
                throw new InvalidDataException(
                    "The selected DPK2 does not bind the exact XPK1 and durable claim tuple.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedXpi1Hash);
        }
    }

    private async Task<byte[]> ReceiptsAsync(
        ContactServiceReceiptKind kind,
        ReadOnlyMemory<byte> tuple,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ContactServiceReplicaReceiptRequest request;
        try
        {
            request = new ContactServiceReplicaReceiptRequest(kind, tuple.Span);
        }
        catch (Exception exception) when (exception is ArgumentException
            or OverflowException)
        {
            throw new ContactServiceReceiptAuthorityException(
                "The contact receipt transcript is invalid.", exception);
        }

        var statement = ContactServiceReceiptTranscript.SigningInput(request);
        var firstTask = IssueValidatedReceiptAsync(
            receiptAuthorities[0], request, statement, cancellationToken);
        var secondTask = IssueValidatedReceiptAsync(
            receiptAuthorities[1], request, statement, cancellationToken);
        try
        {
            await Task.WhenAll(firstTask, secondTask).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is not ContactServiceReceiptAuthorityException)
        {
            throw new ContactServiceReceiptAuthorityException(
                "A contact receipt authority is unavailable.", exception);
        }

        var firstSignature = await firstTask.ConfigureAwait(false);
        var secondSignature = await secondTask.ConfigureAwait(false);
        var output = new byte[193];
        output[0] = 2;
        receiptAuthorities[0].ReplicaId.CopyTo(output, 1);
        firstSignature.CopyTo(output, 33);
        receiptAuthorities[1].ReplicaId.CopyTo(output, 97);
        secondSignature.CopyTo(output, 129);
        return output;
    }

    private static async Task<byte[]> IssueValidatedReceiptAsync(
        ReceiptAuthorityBinding binding,
        ContactServiceReplicaReceiptRequest request,
        ReadOnlyMemory<byte> statement,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var currentAuthorityId = ValidateReplicaId(
                binding.Authority.ReplicaId,
                nameof(binding.Authority));
            if (!CryptographicOperations.FixedTimeEquals(
                    binding.ReplicaId,
                    currentAuthorityId))
            {
                throw new ContactServiceReceiptAuthorityException(
                    "The receipt authority changed its bound replica ID.");
            }

            var receipt = await binding.Authority.IssueAsync(request, cancellationToken)
                .ConfigureAwait(false);
            if (receipt is null)
            {
                throw new ContactServiceReceiptAuthorityException(
                    "The receipt authority returned no receipt.");
            }

            var returnedId = ValidateReplicaId(receipt.ReplicaId, nameof(receipt));
            if (!CryptographicOperations.FixedTimeEquals(binding.ReplicaId, returnedId))
            {
                throw new ContactServiceReceiptAuthorityException(
                    "The receipt authority returned a receipt for another replica.");
            }
            if (receipt.Signature.Length != 64)
            {
                throw new ContactServiceReceiptAuthorityException(
                    "The receipt authority returned a non-canonical signature size.");
            }
            if (!ContactServiceReceiptTranscript.Verify(
                    binding.ReplicaId,
                    statement.Span,
                    receipt.Signature.Span))
            {
                throw new ContactServiceReceiptAuthorityException(
                    "The receipt authority returned an invalid signature.");
            }

            return receipt.Signature.ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ContactServiceReceiptAuthorityException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new ContactServiceReceiptAuthorityException(
                "The contact receipt authority is unavailable.", exception);
        }
    }

    private static byte[] PublishTuple(ContactResolverApplicationResult result) =>
        Concat(result.RequestHash.ToArray(), result.ObjectHash.ToArray(), U64(result.Generation + 1));

    private static byte[] UpdateTuple(ContactResolverApplicationResult result) =>
        Concat(result.RequestHash.ToArray(), U64(result.Generation), result.ObjectHash.ToArray(),
            U64(result.Generation));

    // Exact CONTACT-RESOLVER-V1 one-time redemption receipt transcript.
    private static byte[] ResolveClaimTuple(
        Xiq1Request request,
        ContactResolverApplicationResult result)
    {
        var publication = result.Publication
            ?? throw new InvalidOperationException("A committed redemption has no publication.");

        return Concat(
            request.RequestHash.ToArray(),
            request.LocatorHash.ToArray(),
            U64(publication.Generation),
            U64(publication.EffectiveExpiresAtUnixSeconds),
            result.ObjectHash.ToArray(),
            SHA256.HashData(result.CanonicalRouteClosure),
            U64(result.ClaimCommitGeneration),
            U64(result.ResponseUnixSeconds));
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> ResolvePayload(
        OpaqueDcrPublication publication,
        ReadOnlySpan<byte> canonicalClosure) =>
    [
        U64(publication.Generation),
        U64(publication.EffectiveExpiresAtUnixSeconds),
        publication.ObjectCiphertextHash,
        publication.Ciphertext,
        SHA256.HashData(canonicalClosure),
        canonicalClosure.ToArray()
    ];

    private async Task<byte[]> EncodeCommittedResolveAsync(
        ReadOnlyMemory<byte> exact,
        Xiq1Request request,
        ContactResolverApplicationResult result,
        CancellationToken cancellationToken)
    {
        if (result.Publication is null
            || result.ClaimCommitGeneration == 0
            || result.ResponseUnixSeconds == 0
            || result.CanonicalRouteClosure.IsEmpty
            || result.MutationOutcome !=
                ContactResolverApplicationMutationOutcome.DurablyCommitted)
        {
            return ResolveFailure(exact.Span, request, Xis1Status.OutcomeUnknown,
                ContactResolverApplicationMutationOutcome.OutcomeUnknown);
        }

        try
        {
            var payload = ResolvePayload(
                result.Publication,
                result.CanonicalRouteClosure).Concat<ReadOnlyMemory<byte>>(
                [
                    U64(result.ClaimCommitGeneration),
                    await ReceiptsAsync(
                        ContactServiceReceiptKind.InviteClaimCommit,
                        ResolveClaimTuple(request, result),
                        cancellationToken).ConfigureAwait(false)
                ]).ToArray();
            return EncodeXis(exact.Span, Xis1Status.Success,
                ContactServiceMutationOutcome.DurablyCommitted, 0,
                payload, result.ResponseUnixSeconds);
        }
        catch (Exception exception) when (exception is CryptographicException
            or ContactFormatException
            or InvalidDataException
            or InvalidOperationException
            or ArgumentException
            or OverflowException
            or ContactServiceReceiptAuthorityException)
        {
            return ResolveFailure(exact.Span, request, Xis1Status.OutcomeUnknown,
                ContactResolverApplicationMutationOutcome.OutcomeUnknown);
        }
    }

    private byte[] ResolveFailure(
        ReadOnlySpan<byte> exact,
        Xiq1Request request,
        Xis1Status status,
        ContactResolverApplicationMutationOutcome mutationOutcome)
    {
        IReadOnlyList<ReadOnlyMemory<byte>> payload = status switch
        {
            Xis1Status.StaleView => [request.ViewHash.ToArray()],
            Xis1Status.Conflict => [Evidence(request.RequestHash.Span)],
            _ => []
        };
        return EncodeXis(
            exact,
            status,
            status == Xis1Status.OutcomeUnknown
                ? MutationOutcome(mutationOutcome)
                : ContactServiceMutationOutcome.None,
            Retry(status),
            payload);
    }

    private static Xis1Status ResolveStatus(
        ContactResolverApplicationStatus status) => status switch
        {
            ContactResolverApplicationStatus.Success or
            ContactResolverApplicationStatus.Committed or
            ContactResolverApplicationStatus.ExactReplay => Xis1Status.Success,
            ContactResolverApplicationStatus.AlreadyClaimed => Xis1Status.AlreadyClaimed,
            ContactResolverApplicationStatus.Expired => Xis1Status.Expired,
            ContactResolverApplicationStatus.NotFound => Xis1Status.NotFound,
            ContactResolverApplicationStatus.StaleGeneration => Xis1Status.StaleView,
            ContactResolverApplicationStatus.RateLimited => Xis1Status.RateLimited,
            ContactResolverApplicationStatus.OutcomeUnknown => Xis1Status.OutcomeUnknown,
            ContactResolverApplicationStatus.TemporarilyUnavailable =>
                Xis1Status.TemporarilyUnavailable,
            _ => Xis1Status.Conflict
        };

    private static byte[] EncodeEvent(OpaqueXurEvent item)
    {
        var output = new byte[84 + item.Ciphertext.Length];
        BinaryPrimitives.WriteUInt64BigEndian(output, item.Generation);
        item.PredecessorEventHash.CopyTo(output, 8);
        item.EventCiphertextHash.CopyTo(output, 40);
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(72), item.EffectiveExpiresAtUnixSeconds);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(80), checked((uint)item.Ciphertext.Length));
        item.Ciphertext.CopyTo(output, 84);
        return output;
    }

    private byte[] EncodeXis(
        ReadOnlySpan<byte> exact,
        Xis1Status status,
        ContactServiceMutationOutcome mutationOutcome,
        uint retryAfter,
        IReadOnlyList<ReadOnlyMemory<byte>> payload,
        ulong? serverUnixSeconds = null)
    {
        var classes = status == Xis1Status.Success
            ? new[] { 0, 1, 2, 3, 5 }
            : new[] { 0, 1, 2, 3 };
        foreach (var value in classes)
        {
            try
            {
                return Xis1Codec.Encode(exact, status, mutationOutcome,
                    serverUnixSeconds ?? Now(), retryAfter,
                    (ContactServicePaddingClass)value, payload);
            }
            catch (ContactFormatException)
            {
            }
        }
        throw new InvalidDataException("The XIS1 result does not fit a registered padding class.");
    }

    private static byte[] EncodeSmallest(
        Func<ContactServicePaddingClass, byte[]> encoder,
        int maximumClass)
    {
        for (var value = 0; value <= maximumClass; value++)
        {
            try
            {
                return encoder((ContactServicePaddingClass)value);
            }
            catch (ContactFormatException)
            {
            }
        }
        throw new InvalidDataException("The contact service result does not fit a registered padding class.");
    }

    private bool Expired(ContactServiceRequestRecord request) =>
        request.ExpiresAtUnixSeconds <= Now() || request.IssuedAtUnixSeconds > Now();

    private ValueTask<ContactRequestContextResult> VerifyContextAsync(
        ContactServiceRequestRecord request,
        CancellationToken cancellationToken) => requestContexts.VerifyAsync(
            request.NetworkId,
            request.ViewHash,
            request.PlacementHash,
            cancellationToken);

    private ulong Now() => checked((ulong)clock.UtcNow.ToUnixTimeSeconds());

    private static uint Retry(Xpo1Status status) => status is Xpo1Status.RateLimited
        or Xpo1Status.OutcomeUnknown ? RetryAfterSeconds : 0;
    private static uint Retry(Xis1Status status) => status is Xis1Status.RateLimited
        or Xis1Status.OutcomeUnknown ? RetryAfterSeconds : 0;
    private static uint Retry(Xpc1Status status) => status is Xpc1Status.RateLimited
        or Xpc1Status.OutcomeUnknown ? RetryAfterSeconds : 0;
    private static uint Retry(Xus1Status status) => status is Xus1Status.RateLimited
        or Xus1Status.OutcomeUnknown ? RetryAfterSeconds : 0;

    private static ContactServiceMutationOutcome MutationOutcome(
        ContactResolverApplicationMutationOutcome value) => value switch
        {
            ContactResolverApplicationMutationOutcome.DurablyCommitted =>
                ContactServiceMutationOutcome.DurablyCommitted,
            ContactResolverApplicationMutationOutcome.OutcomeUnknown =>
                ContactServiceMutationOutcome.OutcomeUnknown,
            _ => ContactServiceMutationOutcome.None
        };

    private static ContactServiceMutationOutcome MutationOutcome(
        ContactPreKeyMutationOutcome value) => value switch
        {
            ContactPreKeyMutationOutcome.DurablyCommitted =>
                ContactServiceMutationOutcome.DurablyCommitted,
            ContactPreKeyMutationOutcome.OutcomeUnknown =>
                ContactServiceMutationOutcome.OutcomeUnknown,
            _ => ContactServiceMutationOutcome.None
        };

    private static byte[] Evidence(ReadOnlySpan<byte> requestHash) =>
        DomainHash("Deep/ContactResolver/V1/sanitized-conflict", requestHash);

    private static byte[] DomainHash(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[label.Length + 5 + value.Length];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(label.Length + 1), checked((uint)value.Length));
        value.CopyTo(input.AsSpan(label.Length + 5));
        return SHA256.HashData(input);
    }

    private static SemaphoreSlim[] CreateAuthorizationGates() =>
        Enumerable.Range(0, 64).Select(static _ => new SemaphoreSlim(1, 1)).ToArray();

    private SemaphoreSlim SelectAuthorizationGate(ReadOnlySpan<byte> exactXpa1)
    {
        var authorizationId = Xpa1AuthorizationId(exactXpa1);
        var digest = SHA256.HashData(authorizationId);
        try
        {
            return publicationAuthorizationGates[
                BinaryPrimitives.ReadUInt16BigEndian(digest) % publicationAuthorizationGates.Length];
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    internal static ReadOnlySpan<byte> Xpa1AuthorizationId(ReadOnlySpan<byte> exactXpa1)
    {
        if (exactXpa1.Length < 12)
        {
            throw new ContactPublicationAuthorizationBindingException(
                "The exact XPA1 authorization is truncated.");
        }
        var count = BinaryPrimitives.ReadUInt16BigEndian(exactXpa1[8..10]);
        var offset = 12;
        for (var index = 0; index < count; index++)
        {
            if (offset > exactXpa1.Length - 8)
            {
                break;
            }
            var tag = BinaryPrimitives.ReadUInt16BigEndian(exactXpa1.Slice(offset, 2));
            var length = BinaryPrimitives.ReadUInt32BigEndian(exactXpa1.Slice(offset + 4, 4));
            offset += 8;
            if (length > int.MaxValue || offset > exactXpa1.Length - (int)length)
            {
                break;
            }
            if (tag == 2 && length == 32)
            {
                return exactXpa1.Slice(offset, 32);
            }
            offset += (int)length;
        }
        throw new ContactPublicationAuthorizationBindingException(
            "The exact XPA1 authorization id is unavailable.");
    }

    internal static void ValidatePublicationAuthorization(
        VerifiedXpa1PublicationAuthorization authorization,
        Xpu1Request request)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        var expectedKind = request.UsageLimit == 0
            ? Xpa1PublicationKind.PermanentAddress
            : Xpa1PublicationKind.OneTimeInvite;
        if (!Fixed(authorization.ExactXpa1.Span, request.ExactXpa1.Span)
            || !Fixed(authorization.NetworkId.Span, request.NetworkId.Span)
            || !Fixed(authorization.OperationId.Span, request.OperationId.Span)
            || !Fixed(authorization.LocatorHash.Span, request.LocatorHash.Span)
            || authorization.PublicationKind != expectedKind
            || !Fixed(authorization.Xir1Hash.Span, request.Xir1Hash.Span)
            || authorization.Generation != request.Generation
            || !Fixed(authorization.PredecessorObjectHash.Span, request.PredecessorObjectHash.Span)
            || !Fixed(authorization.ObjectCiphertextHash.Span, request.ObjectCiphertextHash.Span)
            || authorization.UsageLimit != request.UsageLimit
            || authorization.EffectiveExpiresAtUnixSeconds != request.EffectiveExpiresAtUnixSeconds
            || !Fixed(authorization.AuthorizedBodyHash.Span, request.AuthorizedBodyHash.Span)
            || !Fixed(authorization.RequestHash.Span, request.RequestHash.Span)
            || !Fixed(authorization.ViewHash.Span, request.ViewHash.Span)
            || !Fixed(authorization.PlacementHash.Span, request.PlacementHash.Span)
            || authorization.AuthorizationId.Length != 32
            || authorization.AuthorizationId.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ContactPublicationAuthorizationBindingException(
                "The verified XPA1 capability does not bind the exact XPU1 request.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static PreparedReplicaBinding[] PrepareBindings(
        IReadOnlyList<ContactServiceReplicaBinding> replicaBindings)
    {
        ArgumentNullException.ThrowIfNull(replicaBindings);
        if (replicaBindings.Count != 2)
        {
            throw new ArgumentException(
                "Exactly two contact replica bindings are required.",
                nameof(replicaBindings));
        }

        var prepared = new PreparedReplicaBinding[2];
        for (var index = 0; index < prepared.Length; index++)
        {
            var binding = replicaBindings[index]
                ?? throw new ArgumentException(
                    "A contact replica binding cannot be null.",
                    nameof(replicaBindings));
            if (binding.ResolverReplica is null
                || binding.PreKeyReplica is null
                || binding.ReceiptAuthority is null)
            {
                throw new ArgumentException(
                    "Each contact binding requires resolver, pre-key, and receipt-authority components.",
                    nameof(replicaBindings));
            }

            var resolverId = ValidateReplicaId(
                binding.ResolverReplica.ReplicaId,
                nameof(binding.ResolverReplica));
            var preKeyId = ValidateReplicaId(
                binding.PreKeyReplica.ReplicaId,
                nameof(binding.PreKeyReplica));
            var authorityId = ValidateReplicaId(
                binding.ReceiptAuthority.ReplicaId,
                nameof(binding.ReceiptAuthority));
            if (!CryptographicOperations.FixedTimeEquals(resolverId, preKeyId)
                || !CryptographicOperations.FixedTimeEquals(resolverId, authorityId))
            {
                throw new ArgumentException(
                    "Resolver, pre-key, and receipt authority IDs must align one-to-one.",
                    nameof(replicaBindings));
            }

            prepared[index] = new PreparedReplicaBinding(binding, resolverId);
        }

        if (CryptographicOperations.FixedTimeEquals(
                prepared[0].ReplicaId,
                prepared[1].ReplicaId)
            || ReferenceEquals(
                prepared[0].Binding.ReceiptAuthority,
                prepared[1].Binding.ReceiptAuthority))
        {
            throw new ArgumentException(
                "The two contact replica bindings and receipt authorities must be distinct.",
                nameof(replicaBindings));
        }

        return prepared
            .OrderBy(static item => item.ReplicaId, ByteArrayComparer.Instance)
            .ToArray();
    }

    private static byte[] ValidateReplicaId(
        ReadOnlyMemory<byte> replicaId,
        string parameterName)
    {
        if (replicaId.Length != 32
            || replicaId.Span.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "A non-zero 32-byte contact replica ID is required.",
                parameterName);
        }

        return replicaId.ToArray();
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U32(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Concat(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private sealed record PreparedReplicaBinding(
        ContactServiceReplicaBinding Binding,
        byte[] ReplicaId);

    private sealed record ReceiptAuthorityBinding(
        byte[] ReplicaId,
        IContactServiceReplicaReceiptAuthority Authority);
}
