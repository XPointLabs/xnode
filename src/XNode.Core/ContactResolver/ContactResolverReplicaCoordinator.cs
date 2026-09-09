using System.Security.Cryptography;

namespace XNode.Core.ContactResolver;

internal interface IContactResolverReplica
{
    ReadOnlyMemory<byte> ReplicaId { get; }

    ValueTask<ContactResolverMutationResult> PublishDcrAsync(
        OpaqueDcrPublishRequest request,
        CancellationToken cancellationToken);

    ValueTask<ContactResolverDcrReadResult> ResolveCurrentDcrAsync(
        ReadOnlyMemory<byte> locatorHash32,
        CancellationToken cancellationToken);

    ValueTask<ContactResolverDcrResolveResult> ResolveDcrAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken);

    ValueTask<ContactResolverDcrResolveResult> ReadDcrClaimAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken);

    ValueTask<ContactResolverMutationResult> WriteXurSuccessorAsync(
        OpaqueXurWriteRequest request,
        CancellationToken cancellationToken);

    ValueTask<ContactResolverXurReadResult> ResolveXurSuccessorsAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        ReadOnlyMemory<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents,
        CancellationToken cancellationToken);
}

internal sealed class ContactResolverStoreReplica : IContactResolverReplica
{
    private readonly byte[] replicaId;
    private readonly ContactResolverOpaqueStore store;

    internal ContactResolverStoreReplica(
        ReadOnlySpan<byte> replicaId32,
        ContactResolverOpaqueStore store)
    {
        replicaId = OpaqueValue.CopyNonZero32(replicaId32, nameof(replicaId32));
        this.store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

    public ValueTask<ContactResolverMutationResult> PublishDcrAsync(
        OpaqueDcrPublishRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.PublishDcr(request));
    }

    public ValueTask<ContactResolverDcrReadResult> ResolveCurrentDcrAsync(
        ReadOnlyMemory<byte> locatorHash32,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.ResolveCurrentDcr(locatorHash32.Span));
    }

    public ValueTask<ContactResolverDcrResolveResult> ResolveDcrAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.ResolveDcr(request));
    }

    public ValueTask<ContactResolverDcrResolveResult> ReadDcrClaimAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.ReadDcrClaim(request));
    }

    public ValueTask<ContactResolverMutationResult> WriteXurSuccessorAsync(
        OpaqueXurWriteRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.WriteXurSuccessor(request));
    }

    public ValueTask<ContactResolverXurReadResult> ResolveXurSuccessorsAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        ReadOnlyMemory<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.ResolveXurSuccessors(
            serviceCapability32.Span,
            exactXur1Hash32.Span,
            afterGeneration,
            maximumEvents));
    }
}

internal sealed class ContactResolverReplicaCoordinatorOptions
{
    internal TimeSpan ReplicaTimeout { get; init; } = TimeSpan.FromSeconds(5);
    internal int ExecutionStripeCount { get; init; } = 64;

    internal void Validate()
    {
        if (ReplicaTimeout < TimeSpan.FromMilliseconds(10)
            || ReplicaTimeout > TimeSpan.FromSeconds(30)
            || ExecutionStripeCount is < 1 or > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(ContactResolverReplicaCoordinatorOptions));
        }
    }
}

internal sealed record ContactResolverMutationQuorumResult(
    ContactResolverApplicationStatus Status,
    ContactResolverApplicationMutationOutcome MutationOutcome,
    int DurableReplicaCount,
    ulong Generation,
    byte[] ObjectHash);

internal sealed record ContactResolverResolveQuorumResult(
    ContactResolverApplicationStatus Status,
    ContactResolverApplicationMutationOutcome MutationOutcome,
    int DurableReplicaCount,
    OpaqueDcrPublication? Publication,
    ulong ClaimCommitGeneration,
    byte[] CanonicalRouteClosure,
    ulong ResponseUnixSeconds);

internal sealed class ContactResolverTwoReplicaCoordinator : IDisposable
{
    private readonly IContactResolverReplica first;
    private readonly IContactResolverReplica second;
    private readonly TimeSpan replicaTimeout;
    private readonly SemaphoreSlim[] executionGates;
    private bool disposed;

    internal ContactResolverTwoReplicaCoordinator(
        IContactResolverReplica first,
        IContactResolverReplica second,
        ContactResolverReplicaCoordinatorOptions? options = null)
    {
        this.first = first ?? throw new ArgumentNullException(nameof(first));
        this.second = second ?? throw new ArgumentNullException(nameof(second));
        var firstId = ValidateReplicaId(first.ReplicaId, nameof(first));
        var secondId = ValidateReplicaId(second.ReplicaId, nameof(second));
        if (CryptographicOperations.FixedTimeEquals(firstId, secondId))
        {
            throw new ArgumentException("The two contact resolver replicas must be distinct.");
        }
        var effectiveOptions = options ?? new ContactResolverReplicaCoordinatorOptions();
        effectiveOptions.Validate();
        replicaTimeout = effectiveOptions.ReplicaTimeout;
        executionGates = Enumerable.Range(0, effectiveOptions.ExecutionStripeCount)
            .Select(static _ => new SemaphoreSlim(1, 1))
            .ToArray();
    }

    internal Task<ContactResolverMutationQuorumResult> PublishDcrAsync(
        OpaqueDcrPublishRequest request,
        CancellationToken cancellationToken = default) =>
        CoordinateMutationAsync(
            request?.LocatorHash.ToArray() ?? throw new ArgumentNullException(nameof(request)),
            (replica, token) => replica.PublishDcrAsync(request, token),
            cancellationToken);

    internal Task<ContactResolverMutationQuorumResult> WriteXurAsync(
        OpaqueXurWriteRequest request,
        CancellationToken cancellationToken = default) =>
        CoordinateMutationAsync(
            request?.ServiceCapability.ToArray() ?? throw new ArgumentNullException(nameof(request)),
            (replica, token) => replica.WriteXurSuccessorAsync(request, token),
            cancellationToken);

    internal async Task<(ReplicaCall<ContactResolverDcrReadResult> First,
        ReplicaCall<ContactResolverDcrReadResult> Second)> ReadDcrAsync(
        ReadOnlyMemory<byte> locatorHash32,
        CancellationToken cancellationToken = default)
    {
        var gate = SelectGate(locatorHash32.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await InvokePairAsync(
                (replica, token) => replica.ResolveCurrentDcrAsync(locatorHash32, token),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async Task<ContactResolverResolveQuorumResult> ResolveDcrAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var gate = SelectGate(request.LocatorHash);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var preflight = await InvokePairAsync(
                (replica, token) => replica.ReadDcrClaimAsync(request, token),
                cancellationToken).ConfigureAwait(false);
            if (!preflight.First.Succeeded || !preflight.Second.Succeeded)
            {
                return UnknownResolve(0);
            }
            var admitted = ReconcileResolve(
                preflight.First.Value!, preflight.Second.Value!);
            if (admitted.Status != ContactResolverApplicationStatus.Success
                || admitted.Publication?.UsageLimit == 0)
            {
                return admitted;
            }

            var firstCall = await InvokeReplicaAsync(
                first,
                (replica, token) => replica.ResolveDcrAsync(request, token),
                cancellationToken).ConfigureAwait(false);
            if (!firstCall.Succeeded)
            {
                return UnknownResolve(0);
            }

            var left = firstCall.Value!;
            if (left.Disposition is not ContactResolverResolveDisposition.Current
                && !IsDurable(left))
            {
                // Deterministic first-replica ordering prevents a new operation
                // from claiming a lagging second replica after a partial commit.
                return new(
                    MapResolve(left.Disposition),
                    ContactResolverApplicationMutationOutcome.None,
                    0,
                    null,
                    0,
                    [],
                    0);
            }

            var secondCall = await InvokeReplicaAsync(
                second,
                (replica, token) => replica.ResolveDcrAsync(request, token),
                cancellationToken).ConfigureAwait(false);
            if (!secondCall.Succeeded)
            {
                return UnknownResolve(IsDurable(left) ? 1 : 0);
            }
            return ReconcileResolve(left, secondCall.Value!);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async Task<ContactResolverResolveQuorumResult> ReadDcrClaimAsync(
        OpaqueDcrResolveRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var gate = SelectGate(request.LocatorHash);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pair = await InvokePairAsync(
                (replica, token) => replica.ReadDcrClaimAsync(request, token),
                cancellationToken).ConfigureAwait(false);
            return !pair.First.Succeeded || !pair.Second.Succeeded
                ? UnknownResolve(0)
                : ReconcileResolve(pair.First.Value!, pair.Second.Value!);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async Task<(ReplicaCall<ContactResolverXurReadResult> First,
        ReplicaCall<ContactResolverXurReadResult> Second)> ReadXurAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        ReadOnlyMemory<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents,
        CancellationToken cancellationToken = default)
    {
        var gate = SelectGate(serviceCapability32.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await InvokePairAsync(
                (replica, token) => replica.ResolveXurSuccessorsAsync(
                    serviceCapability32,
                    exactXur1Hash32,
                    afterGeneration,
                    maximumEvents,
                    token),
                cancellationToken).ConfigureAwait(false);
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

    private async Task<ContactResolverMutationQuorumResult> CoordinateMutationAsync(
        ReadOnlyMemory<byte> key,
        Func<IContactResolverReplica, CancellationToken, ValueTask<ContactResolverMutationResult>> operation,
        CancellationToken cancellationToken)
    {
        var gate = SelectGate(key.Span);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pair = await InvokePairAsync(operation, cancellationToken).ConfigureAwait(false);
            return Reconcile(pair.First, pair.Second);
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<(ReplicaCall<T> First, ReplicaCall<T> Second)> InvokePairAsync<T>(
        Func<IContactResolverReplica, CancellationToken, ValueTask<T>> operation,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var firstTask = InvokeReplicaAsync(first, operation, cancellationToken);
        var secondTask = InvokeReplicaAsync(second, operation, cancellationToken);
        await Task.WhenAll(firstTask, secondTask).ConfigureAwait(false);
        return (await firstTask.ConfigureAwait(false), await secondTask.ConfigureAwait(false));
    }

    private async Task<ReplicaCall<T>> InvokeReplicaAsync<T>(
        IContactResolverReplica replica,
        Func<IContactResolverReplica, CancellationToken, ValueTask<T>> operation,
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(replicaTimeout);
            var value = await operation(replica, timeout.Token).AsTask()
                .WaitAsync(replicaTimeout, cancellationToken)
                .ConfigureAwait(false);
            return new(true, value);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, default);
        }
        catch (TimeoutException)
        {
            return new(false, default);
        }
        catch (Exception exception) when (exception is IOException
            or InvalidDataException
            or UnauthorizedAccessException
            or InvalidOperationException
            or ObjectDisposedException)
        {
            return new(false, default);
        }
    }

    private static ContactResolverMutationQuorumResult Reconcile(
        ReplicaCall<ContactResolverMutationResult> first,
        ReplicaCall<ContactResolverMutationResult> second)
    {
        var durableCount = (IsDurable(first.Value) ? 1 : 0) + (IsDurable(second.Value) ? 1 : 0);
        if (!first.Succeeded || !second.Succeeded)
        {
            return new(
                ContactResolverApplicationStatus.OutcomeUnknown,
                ContactResolverApplicationMutationOutcome.OutcomeUnknown,
                durableCount,
                0,
                []);
        }

        var left = first.Value!;
        var right = second.Value!;
        if (IsDurable(left)
            && IsDurable(right)
            && left.Generation == right.Generation
            && OpaqueValue.FixedEquals(left.ObjectHash, right.ObjectHash))
        {
            return new(
                left.Disposition == ContactResolverMutationDisposition.ExactReplay
                    && right.Disposition == ContactResolverMutationDisposition.ExactReplay
                        ? ContactResolverApplicationStatus.ExactReplay
                        : ContactResolverApplicationStatus.Committed,
                ContactResolverApplicationMutationOutcome.DurablyCommitted,
                2,
                left.Generation,
                left.ObjectHash.ToArray());
        }

        if (left.Disposition == right.Disposition)
        {
            return new(
                Map(left.Disposition),
                ContactResolverApplicationMutationOutcome.None,
                0,
                0,
                []);
        }

        return new(
            ContactResolverApplicationStatus.Conflict,
            ContactResolverApplicationMutationOutcome.None,
            durableCount,
            0,
            []);
    }

    private static bool IsDurable(ContactResolverMutationResult? result) =>
        result?.Disposition is ContactResolverMutationDisposition.Committed
            or ContactResolverMutationDisposition.ExactReplay;

    private static bool IsDurable(ContactResolverDcrResolveResult result) =>
        result.Disposition is ContactResolverResolveDisposition.Committed
            or ContactResolverResolveDisposition.ExactReplay;

    private static ContactResolverResolveQuorumResult ReconcileResolve(
        ContactResolverDcrResolveResult left,
        ContactResolverDcrResolveResult right)
    {
        var durableCount = (IsDurable(left) ? 1 : 0) + (IsDurable(right) ? 1 : 0);
        if (left.Disposition == ContactResolverResolveDisposition.Current
            && right.Disposition == ContactResolverResolveDisposition.Current
            && Same(left.Publication, right.Publication))
        {
            return new(
                ContactResolverApplicationStatus.Success,
                ContactResolverApplicationMutationOutcome.None,
                0,
                left.Publication,
                0,
                [],
                0);
        }
        if (left.Disposition == ContactResolverResolveDisposition.Current
            && right.Disposition == ContactResolverResolveDisposition.Current)
        {
            return new(
                ContactResolverApplicationStatus.Conflict,
                ContactResolverApplicationMutationOutcome.None,
                0,
                null,
                0,
                [],
                0);
        }
        if (Same(left.Publication, right.Publication)
            && (IsDurable(left)
                && right.Disposition == ContactResolverResolveDisposition.Current
                || IsDurable(right)
                && left.Disposition == ContactResolverResolveDisposition.Current))
        {
            var committed = IsDurable(left) ? left : right;
            return new(
                ContactResolverApplicationStatus.Success,
                ContactResolverApplicationMutationOutcome.OutcomeUnknown,
                1,
                committed.Publication,
                committed.ClaimCommitGeneration,
                committed.CanonicalRouteClosure.ToArray(),
                committed.ResponseUnixSeconds);
        }
        if (IsDurable(left)
            && IsDurable(right)
            && left.ClaimCommitGeneration == right.ClaimCommitGeneration
            && left.ClaimCommitGeneration != 0
            && Same(left.Publication, right.Publication)
            && left.ResponseUnixSeconds == right.ResponseUnixSeconds
            && left.CanonicalRouteClosure.AsSpan().SequenceEqual(
                right.CanonicalRouteClosure))
        {
            return new(
                left.Disposition == ContactResolverResolveDisposition.ExactReplay
                    && right.Disposition == ContactResolverResolveDisposition.ExactReplay
                        ? ContactResolverApplicationStatus.ExactReplay
                        : ContactResolverApplicationStatus.Committed,
                ContactResolverApplicationMutationOutcome.DurablyCommitted,
                2,
                left.Publication,
                left.ClaimCommitGeneration,
                left.CanonicalRouteClosure.ToArray(),
                left.ResponseUnixSeconds);
        }
        if (left.Disposition == right.Disposition
            && left.Disposition is ContactResolverResolveDisposition.NotFound
                or ContactResolverResolveDisposition.Expired
                or ContactResolverResolveDisposition.Conflict
                or ContactResolverResolveDisposition.AlreadyClaimed
                or ContactResolverResolveDisposition.QuotaExceeded)
        {
            return new(
                MapResolve(left.Disposition),
                ContactResolverApplicationMutationOutcome.None,
                0,
                null,
                0,
                [],
                0);
        }
        return new(
            durableCount == 0
                && left.Disposition != ContactResolverResolveDisposition.Conflict
                && right.Disposition != ContactResolverResolveDisposition.Conflict
                    ? ContactResolverApplicationStatus.TemporarilyUnavailable
                    : ContactResolverApplicationStatus.Conflict,
            ContactResolverApplicationMutationOutcome.None,
            durableCount,
            null,
            0,
            [],
            0);
    }

    private static ContactResolverResolveQuorumResult UnknownResolve(int durableCount) => new(
        ContactResolverApplicationStatus.OutcomeUnknown,
        ContactResolverApplicationMutationOutcome.OutcomeUnknown,
        durableCount,
        null,
        0,
        [],
        0);

    private static ContactResolverApplicationStatus MapResolve(
        ContactResolverResolveDisposition value) => value switch
        {
            ContactResolverResolveDisposition.NotFound => ContactResolverApplicationStatus.NotFound,
            ContactResolverResolveDisposition.Expired => ContactResolverApplicationStatus.Expired,
            ContactResolverResolveDisposition.AlreadyClaimed =>
                ContactResolverApplicationStatus.AlreadyClaimed,
            ContactResolverResolveDisposition.QuotaExceeded =>
                ContactResolverApplicationStatus.RateLimited,
            _ => ContactResolverApplicationStatus.Conflict
        };

    private static bool Same(
        OpaqueDcrPublication? left,
        OpaqueDcrPublication? right) => left is not null
        && right is not null
        && left.Generation == right.Generation
        && left.UsageLimit == right.UsageLimit
        && left.EffectiveExpiresAtUnixSeconds == right.EffectiveExpiresAtUnixSeconds
        && OpaqueValue.FixedEquals(left.ObjectCiphertextHash, right.ObjectCiphertextHash)
        && left.Ciphertext.AsSpan().SequenceEqual(right.Ciphertext);

    private static ContactResolverApplicationStatus Map(ContactResolverMutationDisposition value) =>
        value switch
        {
            ContactResolverMutationDisposition.Expired => ContactResolverApplicationStatus.Expired,
            ContactResolverMutationDisposition.StaleGeneration => ContactResolverApplicationStatus.StaleGeneration,
            ContactResolverMutationDisposition.QuotaExceeded => ContactResolverApplicationStatus.RateLimited,
            ContactResolverMutationDisposition.Conflict or ContactResolverMutationDisposition.ForkLatched =>
                ContactResolverApplicationStatus.Conflict,
            _ => ContactResolverApplicationStatus.Conflict
        };

    private SemaphoreSlim SelectGate(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        if (key.Length != 32)
        {
            throw new ArgumentException("A 32-byte contact resolver execution key is required.", nameof(key));
        }
        return executionGates[key[0] % executionGates.Length];
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);

    private static byte[] ValidateReplicaId(ReadOnlyMemory<byte> value, string parameter) =>
        OpaqueValue.CopyNonZero32(value.Span, parameter);
}

internal readonly record struct ReplicaCall<T>(bool Succeeded, T? Value);
