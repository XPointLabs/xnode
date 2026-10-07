using Deep.Protocol.ContactV1;
using XNode.Core.Mailbox;

namespace XNode.Core.ContactResolver;

internal sealed class ContactAuthorizedPublicationReplica
{
    private readonly IContactResolverReplica replica;
    private readonly IContactPublicationAuthorizationVerifier verifier;
    private readonly ContactPublicationAuthorizationSaga saga;
    private readonly IClock clock;

    internal ContactAuthorizedPublicationReplica(
        IContactResolverReplica replica,
        IContactPublicationAuthorizationVerifier verifier,
        ContactPublicationAuthorizationSaga saga,
        IClock clock)
    {
        this.replica = replica ?? throw new ArgumentNullException(nameof(replica));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.saga = saga ?? throw new ArgumentNullException(nameof(saga));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    internal async ValueTask<ContactResolverMutationResult> PublishAsync(
        Xpu1Request request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var authorization = await verifier.VerifyAsync(request, cancellationToken)
            .ConfigureAwait(false);
        ContactServiceOpaqueFacade.ValidatePublicationAuthorization(authorization, request);
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        await authorization.EnsureCurrentAsync(cancellationToken).ConfigureAwait(false);
        var reservation = saga.Reserve(authorization, request, now);
        if (reservation == ContactPublicationAuthorizationSagaDisposition.ConflictLatched)
        {
            throw new InvalidDataException("The XPA authorization is conflict-latched.");
        }

        var opaque = await OpaqueDcrPublishRequest.FromAuthorizedPublicationAsync(
            authorization, request, cancellationToken).ConfigureAwait(false);
        var result = await replica.PublishDcrAsync(
            opaque,
            cancellationToken).ConfigureAwait(false);
        if (result.Disposition is ContactResolverMutationDisposition.Committed
            or ContactResolverMutationDisposition.ExactReplay)
        {
            saga.Commit(authorization, request, now);
        }
        return result;
    }
}
