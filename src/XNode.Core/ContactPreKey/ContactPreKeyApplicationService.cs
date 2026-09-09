namespace XNode.Core.ContactPreKey;

internal enum ContactPreKeyApplicationStatus
{
    Claimed = 1,
    Replay = 2,
    PreKeysUnavailable = 3,
    Expired = 4,
    StaleBundle = 5,
    RateLimited = 6,
    Conflict = 7,
    OutcomeUnknown = 8
}

internal enum ContactPreKeyMutationOutcome
{
    None = 0,
    DurablyCommitted = 1,
    OutcomeUnknown = 2
}

internal sealed class ContactPreKeyApplicationResult
{
    internal ContactPreKeyApplicationResult(
        ContactPreKeyApplicationStatus status,
        ContactPreKeyMutationOutcome mutationOutcome,
        int durableReplicaCount,
        ContactPreKeyClaimResult claim)
    {
        Status = status;
        MutationOutcome = mutationOutcome;
        DurableReplicaCount = durableReplicaCount;
        Claim = claim?.Clone() ?? throw new ArgumentNullException(nameof(claim));
    }

    internal ContactPreKeyApplicationStatus Status { get; }
    internal ContactPreKeyMutationOutcome MutationOutcome { get; }
    internal int DurableReplicaCount { get; }
    internal ContactPreKeyClaimResult Claim { get; }
}

internal interface IContactPreKeyReplica
{
    ReadOnlyMemory<byte> ReplicaId { get; }

    ValueTask<ContactPreKeyClaimResult> ClaimAsync(
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken);

    ValueTask LatchForkAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        CancellationToken cancellationToken);
}

internal sealed class ContactPreKeyStoreReplica : IContactPreKeyReplica
{
    private readonly byte[] replicaId;
    private readonly ContactPreKeyOpaqueStore store;

    internal ContactPreKeyStoreReplica(ReadOnlySpan<byte> replicaId32, ContactPreKeyOpaqueStore store)
    {
        replicaId = ContactPreKeyOpaqueValue.CopyNonZero32(replicaId32, nameof(replicaId32));
        this.store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

    public ValueTask<ContactPreKeyClaimResult> ClaimAsync(
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.Claim(request));
    }

    public ValueTask LatchForkAsync(
        ReadOnlyMemory<byte> serviceCapability32,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        store.LatchFork(serviceCapability32.Span);
        return ValueTask.CompletedTask;
    }
}

internal sealed class ContactPreKeyCoordinatorOptions
{
    internal TimeSpan ReplicaTimeout { get; init; } = TimeSpan.FromSeconds(5);
    internal int ExecutionStripeCount { get; init; } = 64;

    internal void Validate()
    {
        if (ReplicaTimeout < TimeSpan.FromMilliseconds(10)
            || ReplicaTimeout > TimeSpan.FromSeconds(30)
            || ExecutionStripeCount is < 1 or > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(ContactPreKeyCoordinatorOptions));
        }
    }
}

internal readonly record struct ContactPreKeyReplicaCall<T>(bool Succeeded, T? Value);

internal sealed class ContactPreKeyTwoReplicaCoordinator : IDisposable
{
    private readonly IContactPreKeyReplica first;
    private readonly IContactPreKeyReplica second;
    private readonly TimeSpan replicaTimeout;
    private readonly SemaphoreSlim[] executionGates;
    private bool disposed;

    internal ContactPreKeyTwoReplicaCoordinator(
        IContactPreKeyReplica first,
        IContactPreKeyReplica second,
        ContactPreKeyCoordinatorOptions? options = null)
    {
        this.first = first ?? throw new ArgumentNullException(nameof(first));
        this.second = second ?? throw new ArgumentNullException(nameof(second));
        var firstId = ContactPreKeyOpaqueValue.CopyNonZero32(first.ReplicaId.Span, nameof(first));
        var secondId = ContactPreKeyOpaqueValue.CopyNonZero32(second.ReplicaId.Span, nameof(second));
        if (ContactPreKeyOpaqueValue.FixedEquals(firstId, secondId))
        {
            throw new ArgumentException("The two contact pre-key replicas must be distinct.");
        }
        var effectiveOptions = options ?? new ContactPreKeyCoordinatorOptions();
        effectiveOptions.Validate();
        replicaTimeout = effectiveOptions.ReplicaTimeout;
        executionGates = Enumerable.Range(0, effectiveOptions.ExecutionStripeCount)
            .Select(static _ => new SemaphoreSlim(1, 1))
            .ToArray();
    }

    internal async Task<ContactPreKeyApplicationResult> ClaimAsync(
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var gate = SelectGate(request.ServiceCapability);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var firstTask = InvokeAsync(first, request, cancellationToken);
            var secondTask = InvokeAsync(second, request, cancellationToken);
            await Task.WhenAll(firstTask, secondTask).ConfigureAwait(false);
            var leftCall = await firstTask.ConfigureAwait(false);
            var rightCall = await secondTask.ConfigureAwait(false);
            var durableCount = (IsDurable(leftCall.Value) ? 1 : 0)
                + (IsDurable(rightCall.Value) ? 1 : 0);
            if (!leftCall.Succeeded || !rightCall.Succeeded)
            {
                return new(
                    ContactPreKeyApplicationStatus.OutcomeUnknown,
                    ContactPreKeyMutationOutcome.OutcomeUnknown,
                    durableCount,
                    new ContactPreKeyClaimResult(ContactPreKeyClaimDisposition.Conflict, request.RequestHash));
            }

            var left = leftCall.Value!;
            var right = rightCall.Value!;
            if (IsDurable(left) && IsDurable(right) && SameCommittedTuple(left, right))
            {
                return new(
                    left.Disposition == ContactPreKeyClaimDisposition.ExactReplay
                        && right.Disposition == ContactPreKeyClaimDisposition.ExactReplay
                            ? ContactPreKeyApplicationStatus.Replay
                            : ContactPreKeyApplicationStatus.Claimed,
                    ContactPreKeyMutationOutcome.DurablyCommitted,
                    2,
                    left);
            }

            if (left.Disposition == right.Disposition
                && !IsDurable(left)
                && SameNonSuccess(left, right))
            {
                return new(Map(left.Disposition), ContactPreKeyMutationOutcome.None, 0, left);
            }

            await LatchBothAsync(request.ServiceCapability.ToArray(), cancellationToken).ConfigureAwait(false);
            return new(
                ContactPreKeyApplicationStatus.Conflict,
                ContactPreKeyMutationOutcome.None,
                durableCount,
                new ContactPreKeyClaimResult(ContactPreKeyClaimDisposition.Conflict, request.RequestHash));
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

    private async Task<ContactPreKeyReplicaCall<ContactPreKeyClaimResult>> InvokeAsync(
        IContactPreKeyReplica replica,
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(replicaTimeout);
            var result = await replica.ClaimAsync(request, timeout.Token).AsTask()
                .WaitAsync(replicaTimeout, cancellationToken)
                .ConfigureAwait(false);
            return new(true, result);
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

    private async Task LatchBothAsync(ReadOnlyMemory<byte> capability, CancellationToken cancellationToken)
    {
        var firstTask = LatchAsync(first, capability, cancellationToken);
        var secondTask = LatchAsync(second, capability, cancellationToken);
        await Task.WhenAll(firstTask, secondTask).ConfigureAwait(false);
    }

    private async Task LatchAsync(
        IContactPreKeyReplica replica,
        ReadOnlyMemory<byte> capability,
        CancellationToken cancellationToken)
    {
        try
        {
            await replica.LatchForkAsync(capability, cancellationToken).AsTask()
                .WaitAsync(replicaTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException
            or InvalidDataException
            or UnauthorizedAccessException
            or InvalidOperationException
            or ObjectDisposedException
            or TimeoutException)
        {
            // The claim is already a closed conflict. A failed latch keeps the
            // affected replica unavailable/faulted; it never turns into success.
        }
    }

    private static bool IsDurable(ContactPreKeyClaimResult? result) =>
        result?.Disposition is ContactPreKeyClaimDisposition.Claimed
            or ContactPreKeyClaimDisposition.ExactReplay;

    private static bool SameCommittedTuple(ContactPreKeyClaimResult left, ContactPreKeyClaimResult right) =>
        left.ServiceGeneration == right.ServiceGeneration
        && left.PreKeyExpiresAt == right.PreKeyExpiresAt
        && left.LastResortUseCounter == right.LastResortUseCounter
        && left.ClaimCommitGeneration == right.ClaimCommitGeneration
        && left.InventoryEpoch == right.InventoryEpoch
        && left.InventoryIndex == right.InventoryIndex
        && ContactPreKeyOpaqueValue.FixedEquals(left.RequestHash, right.RequestHash)
        && ContactPreKeyOpaqueValue.FixedEquals(left.OneTimePreKeyId, right.OneTimePreKeyId)
        && ContactPreKeyOpaqueValue.FixedEquals(left.ExactDpk2Hash, right.ExactDpk2Hash)
        && ContactPreKeyOpaqueValue.FixedEquals(left.ExactCurrentDmd1Hash, right.ExactCurrentDmd1Hash)
        && ContactPreKeyOpaqueValue.FixedEquals(left.Xpi1Hash, right.Xpi1Hash)
        && left.ExactCurrentDrs1Ref.SequenceEqual(right.ExactCurrentDrs1Ref)
        && left.ExactDpk2.SequenceEqual(right.ExactDpk2)
        && left.ExactXpi1.SequenceEqual(right.ExactXpi1)
        && left.InclusionProof.SequenceEqual(right.InclusionProof)
        && SameReplicaSet(left.ReplicaNodeIds, right.ReplicaNodeIds);

    private static bool SameNonSuccess(ContactPreKeyClaimResult left, ContactPreKeyClaimResult right) =>
        ContactPreKeyOpaqueValue.FixedEquals(left.RequestHash, right.RequestHash)
        && left.RequiredDcb1Hash.SequenceEqual(right.RequiredDcb1Hash)
        && left.RequiredXps1Hash.SequenceEqual(right.RequiredXps1Hash)
        && left.RequiredXpi1Hash.SequenceEqual(right.RequiredXpi1Hash);

    private static bool SameReplicaSet(
        IReadOnlyList<ReadOnlyMemory<byte>> left,
        IReadOnlyList<ReadOnlyMemory<byte>> right) =>
        left.Count == right.Count
        && !left.Where((value, index) => !value.Span.SequenceEqual(right[index].Span)).Any();

    private static ContactPreKeyApplicationStatus Map(ContactPreKeyClaimDisposition disposition) =>
        disposition switch
        {
            ContactPreKeyClaimDisposition.PreKeysUnavailable => ContactPreKeyApplicationStatus.PreKeysUnavailable,
            ContactPreKeyClaimDisposition.Expired => ContactPreKeyApplicationStatus.Expired,
            ContactPreKeyClaimDisposition.StaleBundle => ContactPreKeyApplicationStatus.StaleBundle,
            ContactPreKeyClaimDisposition.QuotaExceeded => ContactPreKeyApplicationStatus.RateLimited,
            _ => ContactPreKeyApplicationStatus.Conflict
        };

    private SemaphoreSlim SelectGate(ReadOnlySpan<byte> capability)
    {
        ThrowIfDisposed();
        return executionGates[capability[0] % executionGates.Length];
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);
}

internal sealed class ContactPreKeyApplicationService
{
    private readonly ContactPreKeyTwoReplicaCoordinator coordinator;

    internal ContactPreKeyApplicationService(ContactPreKeyTwoReplicaCoordinator coordinator)
    {
        this.coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
    }

    internal Task<ContactPreKeyApplicationResult> ClaimAsync(
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken = default) =>
        coordinator.ClaimAsync(request, cancellationToken);

    internal Task<ContactPreKeyApplicationResult> ReconcileAsync(
        OpaquePreKeyClaimRequest request,
        CancellationToken cancellationToken = default) =>
        coordinator.ClaimAsync(request, cancellationToken);
}
