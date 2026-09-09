using System.Security.Cryptography;

namespace XNode.Core.GroupControl;

internal enum GroupControlApplicationStatus
{
    Committed = 1,
    ExactReplay = 2,
    Events = 3,
    NoChange = 4,
    NotFound = 5,
    Expired = 6,
    Gap = 7,
    StaleSequence = 8,
    Conflict = 9,
    RateLimited = 10,
    OutcomeUnknown = 11,
    TemporarilyUnavailable = 12,
    SizeFailure = 13,
    RecordTooLarge = 14
}

internal enum GroupControlMutationOutcome
{
    None = 0,
    DurablyCommitted = 1,
    OutcomeUnknown = 2
}

internal sealed class GroupControlApplicationResult
{
    private readonly byte[] requestHash;
    private readonly byte[] currentHash;
    private readonly OpaqueGroupControlRecord[] records;

    internal GroupControlApplicationResult(
        GroupControlApplicationStatus status,
        GroupControlMutationOutcome mutationOutcome,
        ReadOnlySpan<byte> requestHash32,
        int durableReplicaCount,
        ulong currentSequence,
        ReadOnlySpan<byte> currentHash32,
        IReadOnlyList<OpaqueGroupControlRecord>? records = null,
        bool hasMore = false)
    {
        Status = status;
        MutationOutcome = mutationOutcome;
        requestHash = requestHash32.ToArray();
        DurableReplicaCount = durableReplicaCount;
        CurrentSequence = currentSequence;
        currentHash = currentHash32.ToArray();
        this.records = records?.Select(Clone).ToArray() ?? [];
        HasMore = hasMore;
    }

    internal GroupControlApplicationStatus Status { get; }
    internal GroupControlMutationOutcome MutationOutcome { get; }
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal int DurableReplicaCount { get; }
    internal ulong CurrentSequence { get; }
    internal ReadOnlySpan<byte> CurrentHash => currentHash;
    internal IReadOnlyList<OpaqueGroupControlRecord> Records => records.Select(Clone).ToArray();
    internal bool HasMore { get; }

    private static OpaqueGroupControlRecord Clone(OpaqueGroupControlRecord record) =>
        new(
            record.ControlSequence,
            record.PredecessorControlHash.ToArray(),
            record.SealedGcf1Hash.ToArray(),
            record.SealedGcf1.ToArray(),
            record.EffectiveExpiresAtUnixSeconds);
}

internal interface IGroupControlReplica
{
    ReadOnlyMemory<byte> ReplicaId { get; }

    ValueTask<GroupControlMutationResult> WriteAsync(
        OpaqueGroupControlWriteRequest request,
        CancellationToken cancellationToken);

    ValueTask<GroupControlReadResult> FetchAsync(
        OpaqueGroupControlFetchRequest request,
        CancellationToken cancellationToken);
}

internal sealed class GroupControlStoreReplica : IGroupControlReplica
{
    private readonly byte[] replicaId;
    private readonly GroupControlOpaqueStore store;

    internal GroupControlStoreReplica(ReadOnlySpan<byte> replicaId32, GroupControlOpaqueStore store)
    {
        replicaId = GroupControlOpaqueValue.CopyNonZero32(replicaId32, nameof(replicaId32));
        this.store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public ReadOnlyMemory<byte> ReplicaId => replicaId.ToArray();

    public ValueTask<GroupControlMutationResult> WriteAsync(
        OpaqueGroupControlWriteRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.Write(request));
    }

    public ValueTask<GroupControlReadResult> FetchAsync(
        OpaqueGroupControlFetchRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(store.Fetch(request));
    }
}

internal sealed class GroupControlReplicaCoordinatorOptions
{
    internal TimeSpan ReplicaTimeout { get; init; } = TimeSpan.FromSeconds(5);
    internal int ExecutionStripeCount { get; init; } = 64;

    internal void Validate()
    {
        if (ReplicaTimeout < TimeSpan.FromMilliseconds(10)
            || ReplicaTimeout > TimeSpan.FromSeconds(30)
            || ExecutionStripeCount is < 1 or > 1_024)
        {
            throw new ArgumentOutOfRangeException(nameof(GroupControlReplicaCoordinatorOptions));
        }
    }
}

internal readonly record struct GroupControlReplicaCall<T>(bool Succeeded, T? Value);

internal sealed record GroupControlMutationQuorumResult(
    GroupControlApplicationStatus Status,
    GroupControlMutationOutcome MutationOutcome,
    int DurableReplicaCount,
    ulong ControlSequence,
    byte[] SealedGcf1Hash);

internal sealed class GroupControlTwoReplicaCoordinator : IDisposable
{
    private readonly IGroupControlReplica first;
    private readonly IGroupControlReplica second;
    private readonly TimeSpan replicaTimeout;
    private readonly SemaphoreSlim[] executionGates;
    private bool disposed;

    internal GroupControlTwoReplicaCoordinator(
        IGroupControlReplica first,
        IGroupControlReplica second,
        GroupControlReplicaCoordinatorOptions? options = null)
    {
        this.first = first ?? throw new ArgumentNullException(nameof(first));
        this.second = second ?? throw new ArgumentNullException(nameof(second));
        var firstId = GroupControlOpaqueValue.CopyNonZero32(first.ReplicaId.Span, nameof(first));
        var secondId = GroupControlOpaqueValue.CopyNonZero32(second.ReplicaId.Span, nameof(second));
        if (CryptographicOperations.FixedTimeEquals(firstId, secondId))
        {
            throw new ArgumentException("The two group-control replicas must be distinct.");
        }
        var effectiveOptions = options ?? new GroupControlReplicaCoordinatorOptions();
        effectiveOptions.Validate();
        replicaTimeout = effectiveOptions.ReplicaTimeout;
        executionGates = Enumerable.Range(0, effectiveOptions.ExecutionStripeCount)
            .Select(static _ => new SemaphoreSlim(1, 1))
            .ToArray();
    }

    internal async Task<GroupControlMutationQuorumResult> WriteAsync(
        OpaqueGroupControlWriteRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var gate = SelectGate(request.ServiceCapability);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var pair = await InvokePairAsync(
                (replica, token) => replica.WriteAsync(request, token),
                cancellationToken).ConfigureAwait(false);
            return ReconcileMutation(pair.First, pair.Second);
        }
        finally
        {
            gate.Release();
        }
    }

    internal async Task<(GroupControlReplicaCall<GroupControlReadResult> First,
        GroupControlReplicaCall<GroupControlReadResult> Second)> FetchAsync(
        OpaqueGroupControlFetchRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var gate = SelectGate(request.ServiceCapability);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await InvokePairAsync(
                (replica, token) => replica.FetchAsync(request, token),
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

    private async Task<(GroupControlReplicaCall<T> First, GroupControlReplicaCall<T> Second)>
        InvokePairAsync<T>(
            Func<IGroupControlReplica, CancellationToken, ValueTask<T>> operation,
            CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var firstTask = InvokeReplicaAsync(first, operation, cancellationToken);
        var secondTask = InvokeReplicaAsync(second, operation, cancellationToken);
        await Task.WhenAll(firstTask, secondTask).ConfigureAwait(false);
        return (await firstTask.ConfigureAwait(false), await secondTask.ConfigureAwait(false));
    }

    private async Task<GroupControlReplicaCall<T>> InvokeReplicaAsync<T>(
        IGroupControlReplica replica,
        Func<IGroupControlReplica, CancellationToken, ValueTask<T>> operation,
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

    private static GroupControlMutationQuorumResult ReconcileMutation(
        GroupControlReplicaCall<GroupControlMutationResult> first,
        GroupControlReplicaCall<GroupControlMutationResult> second)
    {
        var durableCount = (IsDurable(first.Value) ? 1 : 0) + (IsDurable(second.Value) ? 1 : 0);
        if (!first.Succeeded || !second.Succeeded)
        {
            return new(
                GroupControlApplicationStatus.OutcomeUnknown,
                GroupControlMutationOutcome.OutcomeUnknown,
                durableCount,
                0,
                []);
        }

        var left = first.Value!;
        var right = second.Value!;
        if (IsDurable(left)
            && IsDurable(right)
            && left.ControlSequence == right.ControlSequence
            && GroupControlOpaqueValue.FixedEquals(left.SealedGcf1Hash, right.SealedGcf1Hash))
        {
            return new(
                left.Disposition == GroupControlMutationDisposition.ExactReplay
                    && right.Disposition == GroupControlMutationDisposition.ExactReplay
                        ? GroupControlApplicationStatus.ExactReplay
                        : GroupControlApplicationStatus.Committed,
                GroupControlMutationOutcome.DurablyCommitted,
                2,
                left.ControlSequence,
                left.SealedGcf1Hash.ToArray());
        }
        if (left.Disposition == right.Disposition)
        {
            if (left.Disposition == GroupControlMutationDisposition.StaleSequence)
            {
                if (left.ControlSequence == 0
                    || !GroupControlOpaqueValue.FixedEquals(
                        left.SealedGcf1Hash,
                        right.SealedGcf1Hash)
                    || left.ControlSequence != right.ControlSequence)
                {
                    return new(
                        GroupControlApplicationStatus.Conflict,
                        GroupControlMutationOutcome.None,
                        0,
                        0,
                        []);
                }
                return new(
                    GroupControlApplicationStatus.StaleSequence,
                    GroupControlMutationOutcome.None,
                    0,
                    left.ControlSequence,
                    left.SealedGcf1Hash.ToArray());
            }
            return new(Map(left.Disposition), GroupControlMutationOutcome.None, 0, 0, []);
        }
        return new(
            GroupControlApplicationStatus.Conflict,
            GroupControlMutationOutcome.None,
            durableCount,
            0,
            []);
    }

    private static bool IsDurable(GroupControlMutationResult? result) =>
        result?.Disposition is GroupControlMutationDisposition.Committed
            or GroupControlMutationDisposition.ExactReplay;

    private static GroupControlApplicationStatus Map(GroupControlMutationDisposition disposition) =>
        disposition switch
        {
            GroupControlMutationDisposition.Expired => GroupControlApplicationStatus.Expired,
            GroupControlMutationDisposition.StaleSequence => GroupControlApplicationStatus.StaleSequence,
            GroupControlMutationDisposition.QuotaExceeded => GroupControlApplicationStatus.RateLimited,
            _ => GroupControlApplicationStatus.Conflict
        };

    private SemaphoreSlim SelectGate(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        return executionGates[key[0] % executionGates.Length];
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);
}

internal sealed class GroupControlApplicationService
{
    private readonly GroupControlTwoReplicaCoordinator coordinator;

    internal GroupControlApplicationService(GroupControlTwoReplicaCoordinator coordinator)
    {
        this.coordinator = coordinator ?? throw new ArgumentNullException(nameof(coordinator));
    }

    internal async Task<GroupControlApplicationResult> WriteAsync(
        OpaqueGroupControlWriteRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = await coordinator.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        return new(
            result.Status,
            result.MutationOutcome,
            request.RequestHash,
            result.DurableReplicaCount,
            result.ControlSequence,
            result.SealedGcf1Hash);
    }

    internal async Task<GroupControlApplicationResult> FetchAsync(
        OpaqueGroupControlFetchRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var pair = await coordinator.FetchAsync(request, cancellationToken).ConfigureAwait(false);
        if (!pair.First.Succeeded || !pair.Second.Succeeded)
        {
            return new(
                GroupControlApplicationStatus.TemporarilyUnavailable,
                GroupControlMutationOutcome.None,
                request.RequestHash,
                0,
                0,
                []);
        }

        var left = pair.First.Value!;
        var right = pair.Second.Value!;
        if (left.Disposition != right.Disposition)
        {
            return ReadConflict(request);
        }
        if (left.CurrentControlSequence != right.CurrentControlSequence
            || !GroupControlOpaqueValue.FixedEquals(left.CurrentControlHash, right.CurrentControlHash))
        {
            return ReadConflict(request);
        }
        if (left.Disposition == GroupControlReadDisposition.Events)
        {
            if (left.HasMore != right.HasMore || left.Records.Count != right.Records.Count)
            {
                return ReadConflict(request);
            }
            for (var index = 0; index < left.Records.Count; index++)
            {
                if (!Same(left.Records[index], right.Records[index]))
                {
                    return ReadConflict(request);
                }
            }
        }

        return new(
            Map(left.Disposition),
            GroupControlMutationOutcome.None,
            request.RequestHash,
            0,
            left.CurrentControlSequence,
            left.CurrentControlHash,
            left.Records,
            left.HasMore);
    }

    internal Task<GroupControlApplicationResult> ReconcileAsync(
        OpaqueGroupControlWriteRequest request,
        CancellationToken cancellationToken = default) =>
        WriteAsync(request, cancellationToken);

    private static GroupControlApplicationResult ReadConflict(OpaqueGroupControlFetchRequest request) =>
        new(
            GroupControlApplicationStatus.Conflict,
            GroupControlMutationOutcome.None,
            request.RequestHash,
            0,
            0,
            []);

    private static GroupControlApplicationStatus Map(GroupControlReadDisposition disposition) =>
        disposition switch
        {
            GroupControlReadDisposition.Events => GroupControlApplicationStatus.Events,
            GroupControlReadDisposition.NoChange => GroupControlApplicationStatus.NoChange,
            GroupControlReadDisposition.NotFound => GroupControlApplicationStatus.NotFound,
            GroupControlReadDisposition.Expired => GroupControlApplicationStatus.Expired,
            GroupControlReadDisposition.Gap => GroupControlApplicationStatus.Gap,
            GroupControlReadDisposition.StaleCursor => GroupControlApplicationStatus.StaleSequence,
            _ => GroupControlApplicationStatus.Conflict
        };

    private static bool Same(OpaqueGroupControlRecord left, OpaqueGroupControlRecord right) =>
        left.ControlSequence == right.ControlSequence
        && left.EffectiveExpiresAtUnixSeconds == right.EffectiveExpiresAtUnixSeconds
        && GroupControlOpaqueValue.FixedEquals(left.PredecessorControlHash, right.PredecessorControlHash)
        && GroupControlOpaqueValue.FixedEquals(left.SealedGcf1Hash, right.SealedGcf1Hash)
        && left.SealedGcf1.AsSpan().SequenceEqual(right.SealedGcf1);
}
