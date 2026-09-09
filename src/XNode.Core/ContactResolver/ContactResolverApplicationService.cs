namespace XNode.Core.ContactResolver;

internal sealed class ContactResolverApplicationService
{
    private readonly ContactResolverTwoReplicaCoordinator coordinator;

    internal ContactResolverApplicationService(ContactResolverTwoReplicaCoordinator coordinator)
    {
        this.coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
    }

    internal async Task<ContactResolverApplicationResult> PublishDcrAsync(
        ContactResolverPublishRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = await coordinator.PublishDcrAsync(request.StoreRequest, cancellationToken)
            .ConfigureAwait(false);
        return ContactResolverApplicationResult.Mutation(
            request,
            result.Status,
            result.MutationOutcome,
            result.DurableReplicaCount,
            result.Generation,
            result.ObjectHash);
    }

    internal async Task<ContactResolverApplicationResult> ResolveCurrentDcrAsync(
        ContactResolverResolveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = await coordinator.ResolveDcrAsync(
            request.StoreRequest,
            cancellationToken).ConfigureAwait(false);
        return ContactResolverApplicationResult.DcrRead(
            request,
            result.Status,
            result.Publication,
            result.MutationOutcome,
            result.DurableReplicaCount,
            result.ClaimCommitGeneration,
            result.CanonicalRouteClosure,
            result.ResponseUnixSeconds);
    }

    internal async Task<ContactResolverApplicationResult> PreflightCurrentDcrAsync(
        ContactResolverResolveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var pair = await coordinator.ReadDcrAsync(
            request.LocatorHash.ToArray(), cancellationToken).ConfigureAwait(false);
        if (!pair.First.Succeeded || !pair.Second.Succeeded)
        {
            return ContactResolverApplicationResult.DcrRead(
                request,
                ContactResolverApplicationStatus.OutcomeUnknown,
                mutationOutcome: ContactResolverApplicationMutationOutcome.OutcomeUnknown);
        }
        return ReconcileDcrRead(request, pair.First.Value!, pair.Second.Value!);
    }

    internal async Task<ContactResolverApplicationResult> PreflightDcrClaimAsync(
        ContactResolverResolveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = await coordinator.ReadDcrClaimAsync(
            request.StoreRequest, cancellationToken).ConfigureAwait(false);
        return ContactResolverApplicationResult.DcrRead(
            request,
            result.Status,
            result.Publication,
            result.MutationOutcome,
            result.DurableReplicaCount,
            result.ClaimCommitGeneration,
            result.CanonicalRouteClosure,
            result.ResponseUnixSeconds);
    }

    internal async Task<ContactResolverApplicationResult> WriteXurAsync(
        ContactResolverXurWriteRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = await coordinator.WriteXurAsync(request.StoreRequest, cancellationToken)
            .ConfigureAwait(false);
        return ContactResolverApplicationResult.Mutation(
            request,
            result.Status,
            result.MutationOutcome,
            result.DurableReplicaCount,
            result.Generation,
            result.ObjectHash);
    }

    internal async Task<ContactResolverApplicationResult> FetchXurAsync(
        ContactResolverXurFetchRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var pair = await coordinator.ReadXurAsync(
            request.ServiceCapability.ToArray(),
            request.ExactXur1Hash.ToArray(),
            request.AfterGeneration,
            request.MaximumEvents,
            cancellationToken).ConfigureAwait(false);
        if (!pair.First.Succeeded || !pair.Second.Succeeded)
        {
            return ContactResolverApplicationResult.XurRead(
                request,
                ContactResolverApplicationStatus.TemporarilyUnavailable,
                null,
                0,
                default);
        }
        return ReconcileXurRead(request, pair.First.Value!, pair.Second.Value!);
    }

    internal Task<ContactResolverApplicationResult> ReconcileAsync(
        ContactResolverApplicationRequest request,
        CancellationToken cancellationToken = default) =>
        request switch
        {
            ContactResolverPublishRequest publish => PublishDcrAsync(publish, cancellationToken),
            ContactResolverXurWriteRequest write => WriteXurAsync(write, cancellationToken),
            _ => Task.FromResult(ContactResolverApplicationResult.Invalid(request))
        };

    private static ContactResolverApplicationResult ReconcileDcrRead(
        ContactResolverResolveRequest request,
        ContactResolverDcrReadResult left,
        ContactResolverDcrReadResult right)
    {
        if (left.Disposition != right.Disposition)
        {
            return ContactResolverApplicationResult.DcrRead(
                request,
                ContactResolverApplicationStatus.TemporarilyUnavailable);
        }
        if (left.Disposition != ContactResolverReadDisposition.Current)
        {
            return ContactResolverApplicationResult.DcrRead(request, MapRead(left.Disposition));
        }
        if (left.Publication is null
            || right.Publication is null
            || !Same(left.Publication, right.Publication))
        {
            return ContactResolverApplicationResult.DcrRead(
                request,
                ContactResolverApplicationStatus.Conflict);
        }
        return ContactResolverApplicationResult.DcrRead(
            request,
            ContactResolverApplicationStatus.Success,
            left.Publication);
    }

    private static ContactResolverApplicationResult ReconcileXurRead(
        ContactResolverXurFetchRequest request,
        ContactResolverXurReadResult left,
        ContactResolverXurReadResult right)
    {
        if (left.Disposition != right.Disposition)
        {
            return ContactResolverApplicationResult.XurRead(
                request,
                ContactResolverApplicationStatus.TemporarilyUnavailable,
                null,
                0,
                default);
        }
        if (left.Disposition is not (ContactResolverReadDisposition.Current
            or ContactResolverReadDisposition.NoChange))
        {
            if (left.CurrentGeneration != right.CurrentGeneration
                || !OpaqueValue.FixedEquals(left.CurrentEventHash, right.CurrentEventHash))
            {
                return ContactResolverApplicationResult.XurRead(
                    request,
                    ContactResolverApplicationStatus.Conflict,
                    null,
                    0,
                    default);
            }
            return ContactResolverApplicationResult.XurRead(
                request,
                MapRead(left.Disposition),
                null,
                left.CurrentGeneration,
                left.CurrentEventHash);
        }
        if (left.CurrentGeneration != right.CurrentGeneration
            || !OpaqueValue.FixedEquals(left.CurrentEventHash, right.CurrentEventHash)
            || left.Events.Count != right.Events.Count)
        {
            return ContactResolverApplicationResult.XurRead(
                request,
                ContactResolverApplicationStatus.TemporarilyUnavailable,
                null,
                0,
                default);
        }
        for (var index = 0; index < left.Events.Count; index++)
        {
            if (!Same(left.Events[index], right.Events[index]))
            {
                return ContactResolverApplicationResult.XurRead(
                    request,
                    ContactResolverApplicationStatus.Conflict,
                    null,
                    0,
                    default);
            }
        }
        return ContactResolverApplicationResult.XurRead(
            request,
            left.Disposition == ContactResolverReadDisposition.NoChange
                ? ContactResolverApplicationStatus.NoChange
                : ContactResolverApplicationStatus.Events,
            left.Events,
            left.CurrentGeneration,
            left.CurrentEventHash);
    }

    private static ContactResolverApplicationStatus MapRead(ContactResolverReadDisposition value) =>
        value switch
        {
            ContactResolverReadDisposition.NotFound => ContactResolverApplicationStatus.NotFound,
            ContactResolverReadDisposition.Expired => ContactResolverApplicationStatus.Expired,
            ContactResolverReadDisposition.StaleGeneration => ContactResolverApplicationStatus.StaleGeneration,
            ContactResolverReadDisposition.Conflict => ContactResolverApplicationStatus.Conflict,
            ContactResolverReadDisposition.NoChange => ContactResolverApplicationStatus.NoChange,
            _ => ContactResolverApplicationStatus.Conflict
        };

    private static bool Same(OpaqueDcrPublication left, OpaqueDcrPublication right) =>
        left.Generation == right.Generation
        && left.UsageLimit == right.UsageLimit
        && left.EffectiveExpiresAtUnixSeconds == right.EffectiveExpiresAtUnixSeconds
        && OpaqueValue.FixedEquals(left.ObjectCiphertextHash, right.ObjectCiphertextHash)
        && left.Ciphertext.AsSpan().SequenceEqual(right.Ciphertext);

    private static bool Same(OpaqueXurEvent left, OpaqueXurEvent right) =>
        left.Generation == right.Generation
        && left.EffectiveExpiresAtUnixSeconds == right.EffectiveExpiresAtUnixSeconds
        && OpaqueValue.FixedEquals(left.PredecessorEventHash, right.PredecessorEventHash)
        && OpaqueValue.FixedEquals(left.EventHash, right.EventHash)
        && OpaqueValue.FixedEquals(left.EventCiphertextHash, right.EventCiphertextHash)
        && left.Ciphertext.AsSpan().SequenceEqual(right.Ciphertext);
}

internal sealed class ContactResolverRequestDispatcher
{
    private readonly ContactResolverApplicationService service;

    internal ContactResolverRequestDispatcher(ContactResolverApplicationService service)
    {
        this.service = service ?? throw new ArgumentNullException(nameof(service));
    }

    internal Task<ContactResolverApplicationResult> DispatchAsync(
        ContactResolverApplicationRequest? request,
        CancellationToken cancellationToken = default) =>
        request switch
        {
            ContactResolverPublishRequest publish => service.PublishDcrAsync(publish, cancellationToken),
            ContactResolverResolveRequest resolve => service.ResolveCurrentDcrAsync(resolve, cancellationToken),
            ContactResolverXurWriteRequest write => service.WriteXurAsync(write, cancellationToken),
            ContactResolverXurFetchRequest fetch => service.FetchXurAsync(fetch, cancellationToken),
            _ => Task.FromResult(ContactResolverApplicationResult.Invalid(request))
        };
}
