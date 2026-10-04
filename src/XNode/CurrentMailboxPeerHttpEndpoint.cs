using System.Diagnostics;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using XNode.Core.Mailbox;

namespace XNode;

/// <summary>Binary current-only peer ingress. The listener/TLS/length/budget
/// gates precede allocation; no raw exception, payload or authority logs.</summary>
internal sealed class CurrentMailboxPeerHttpEndpoint(CurrentMailboxReplicaReceiver receiver, int peerPort)
{
    private readonly MailboxPeerIngressLimiter limiter = new();

    internal void Map(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(MailboxWireHttpContract.PeerStoreRoute, (HttpContext context, CancellationToken token) =>
            HandleAsync(context, MailboxWireHttpContract.PeerStore, MailboxPeerReplicationOperation.Store, token));
        endpoints.MapPost(MailboxWireHttpContract.PeerTombstoneRoute, (HttpContext context, CancellationToken token) =>
            HandleAsync(context, MailboxWireHttpContract.PeerTombstone, MailboxPeerReplicationOperation.Tombstone, token));
    }
    internal async Task<IResult> HandleAsync(HttpContext context, MailboxHttpEndpointContract contract,
        MailboxPeerReplicationOperation operation, CancellationToken token)
    {
        if (context.Connection.LocalPort != peerPort || !context.Request.IsHttps) return Results.NotFound();
        var invalid = MailboxPeerHttpRequestValidator.Validate(context.Request, contract);
        if (invalid is not null) return Failure(invalid.Value);
        // This monotonic value controls only ingress resource budgeting, never
        // grant, descriptor, revocation, replay or receipt validity.
        if (!limiter.TryEnter(operation, checked((ulong)(Stopwatch.GetTimestamp() / Stopwatch.Frequency)), out var lease))
            return Failure(MailboxHttpFailure.RateOrConcurrencyExceeded);
        using (lease)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(contract.RequestTimeoutSeconds));
            try
            {
                var body = new byte[checked((int)context.Request.ContentLength!.Value)];
                await context.Request.Body.ReadExactlyAsync(body, deadline.Token).ConfigureAwait(false);
                if (await context.Request.Body.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(false) != 0)
                    return Failure(MailboxHttpFailure.MalformedCanonicalBody);
                var response = await receiver.ReceiveAsync(body, operation, deadline.Token).ConfigureAwait(false);
                return Results.Bytes(response.ToArray(), contract.ResponseContentType);
            }
            catch (EndOfStreamException) { return Failure(MailboxHttpFailure.MalformedCanonicalBody); }
            catch (OperationCanceledException) when (!token.IsCancellationRequested && deadline.IsCancellationRequested)
            { return Failure(MailboxHttpFailure.DeadlineExceeded); }
            catch (MailboxPeerReplicationException error)
            { return Failure(error.Error == MailboxPeerReplicationError.ReplayConflict
                ? MailboxHttpFailure.ReplayOrIdempotencyConflict : MailboxHttpFailure.MalformedCanonicalBody); }
            catch (MailboxGrantRevocationFloorException) { return Failure(MailboxHttpFailure.DependencyUnavailable); }
            catch (CryptographicException) { return Failure(MailboxHttpFailure.AuthorizationFailed); }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or InvalidOperationException
                or MailboxPeerReplayCapacityException or ArgumentException)
            { return Failure(MailboxHttpFailure.DependencyUnavailable); }
        }
    }
    private static IResult Failure(MailboxHttpFailure failure) => Results.StatusCode(MailboxWireHttpContract.StatusCode(failure));
}
