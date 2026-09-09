namespace XNode.Core.ContactResolver;

internal enum ContactResolverApplicationOperation
{
    PublishDcr = 1,
    ResolveCurrentDcr = 2,
    WriteXur = 3,
    FetchXur = 4
}

internal enum ContactResolverApplicationStatus
{
    Committed = 1,
    ExactReplay = 2,
    Success = 3,
    Events = 4,
    NoChange = 5,
    NotFound = 6,
    Expired = 7,
    StaleGeneration = 8,
    Conflict = 9,
    RateLimited = 10,
    OutcomeUnknown = 11,
    TemporarilyUnavailable = 12,
    InvalidRequest = 13,
    AlreadyClaimed = 14
}

internal enum ContactResolverApplicationMutationOutcome
{
    None = 0,
    DurablyCommitted = 1,
    OutcomeUnknown = 2
}

internal abstract class ContactResolverApplicationRequest
{
    private readonly byte[] operationId;
    private readonly byte[] requestHash;

    protected ContactResolverApplicationRequest(
        ContactResolverApplicationOperation operation,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32)
    {
        Operation = operation;
        operationId = OpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = OpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
    }

    internal ContactResolverApplicationOperation Operation { get; }
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
}

internal sealed class ContactResolverPublishRequest : ContactResolverApplicationRequest
{
    internal ContactResolverPublishRequest(OpaqueDcrPublishRequest request)
        : base(
            ContactResolverApplicationOperation.PublishDcr,
            Require(request).OperationId,
            Require(request).RequestHash)
    {
        StoreRequest = Require(request);
    }

    internal OpaqueDcrPublishRequest StoreRequest { get; }

    private static OpaqueDcrPublishRequest Require(OpaqueDcrPublishRequest? request) =>
        request ?? throw new ArgumentNullException(nameof(request));
}

internal sealed class ContactResolverResolveRequest : ContactResolverApplicationRequest
{
    private readonly byte[] locatorHash;

    internal ContactResolverResolveRequest(
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> locatorHash32,
        ReadOnlySpan<byte> canonicalRouteClosure = default,
        ulong responseUnixSeconds = 0)
        : base(ContactResolverApplicationOperation.ResolveCurrentDcr, operationId32, requestHash32)
    {
        locatorHash = OpaqueValue.CopyNonZero32(locatorHash32, nameof(locatorHash32));
        StoreRequest = new OpaqueDcrResolveRequest(
            locatorHash, operationId32, requestHash32,
            canonicalRouteClosure, responseUnixSeconds);
    }

    internal ReadOnlySpan<byte> LocatorHash => locatorHash;
    internal OpaqueDcrResolveRequest StoreRequest { get; }
}

internal sealed class ContactResolverXurWriteRequest : ContactResolverApplicationRequest
{
    internal ContactResolverXurWriteRequest(OpaqueXurWriteRequest request)
        : base(
            ContactResolverApplicationOperation.WriteXur,
            Require(request).OperationId,
            Require(request).RequestHash)
    {
        StoreRequest = Require(request);
    }

    internal OpaqueXurWriteRequest StoreRequest { get; }

    private static OpaqueXurWriteRequest Require(OpaqueXurWriteRequest? request) =>
        request ?? throw new ArgumentNullException(nameof(request));
}

internal sealed class ContactResolverXurFetchRequest : ContactResolverApplicationRequest
{
    private readonly byte[] serviceCapability;
    private readonly byte[] exactXur1Hash;

    internal ContactResolverXurFetchRequest(
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents)
        : base(ContactResolverApplicationOperation.FetchXur, operationId32, requestHash32)
    {
        serviceCapability = OpaqueValue.CopyNonZero32(
            serviceCapability32,
            nameof(serviceCapability32));
        exactXur1Hash = OpaqueValue.CopyNonZero32(exactXur1Hash32, nameof(exactXur1Hash32));
        if (maximumEvents is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEvents));
        }
        AfterGeneration = afterGeneration;
        MaximumEvents = maximumEvents;
    }

    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> ExactXur1Hash => exactXur1Hash;
    internal ulong AfterGeneration { get; }
    internal int MaximumEvents { get; }
}

internal sealed class ContactResolverApplicationResult
{
    private readonly byte[] requestHash;
    private readonly byte[] objectHash;
    private readonly byte[] currentHash;
    private readonly byte[] canonicalRouteClosure;
    private readonly OpaqueDcrPublication? publication;
    private readonly OpaqueXurEvent[] events;

    private ContactResolverApplicationResult(
        ContactResolverApplicationOperation operation,
        ContactResolverApplicationStatus status,
        ContactResolverApplicationMutationOutcome mutationOutcome,
        ReadOnlySpan<byte> requestHash,
        int durableReplicaCount,
        ulong generation,
        ReadOnlySpan<byte> objectHash,
        OpaqueDcrPublication? publication,
        IReadOnlyList<OpaqueXurEvent>? events,
        ulong currentGeneration,
        ReadOnlySpan<byte> currentHash,
        ulong claimCommitGeneration,
        ReadOnlySpan<byte> canonicalRouteClosure,
        ulong responseUnixSeconds)
    {
        Operation = operation;
        Status = status;
        MutationOutcome = mutationOutcome;
        this.requestHash = requestHash.ToArray();
        DurableReplicaCount = durableReplicaCount;
        Generation = generation;
        this.objectHash = objectHash.ToArray();
        this.publication = publication is null ? null : Clone(publication);
        this.events = events?.Select(Clone).ToArray() ?? [];
        CurrentGeneration = currentGeneration;
        this.currentHash = currentHash.ToArray();
        ClaimCommitGeneration = claimCommitGeneration;
        this.canonicalRouteClosure = canonicalRouteClosure.ToArray();
        ResponseUnixSeconds = responseUnixSeconds;
    }

    internal ContactResolverApplicationOperation Operation { get; }
    internal ContactResolverApplicationStatus Status { get; }
    internal ContactResolverApplicationMutationOutcome MutationOutcome { get; }
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal int DurableReplicaCount { get; }
    internal ulong Generation { get; }
    internal ReadOnlySpan<byte> ObjectHash => objectHash;
    internal OpaqueDcrPublication? Publication => publication is null ? null : Clone(publication);
    internal IReadOnlyList<OpaqueXurEvent> Events => events.Select(Clone).ToArray();
    internal ulong CurrentGeneration { get; }
    internal ReadOnlySpan<byte> CurrentHash => currentHash;
    internal ulong ClaimCommitGeneration { get; }
    internal ReadOnlySpan<byte> CanonicalRouteClosure => canonicalRouteClosure;
    internal ulong ResponseUnixSeconds { get; }

    internal static ContactResolverApplicationResult Mutation(
        ContactResolverApplicationRequest request,
        ContactResolverApplicationStatus status,
        ContactResolverApplicationMutationOutcome outcome,
        int durableReplicaCount,
        ulong generation = 0,
        ReadOnlySpan<byte> objectHash = default) =>
        new(
            request.Operation,
            status,
            outcome,
            request.RequestHash,
            durableReplicaCount,
            generation,
            objectHash,
            null,
            null,
            0,
            default,
            0,
            default,
            0);

    internal static ContactResolverApplicationResult DcrRead(
        ContactResolverResolveRequest request,
        ContactResolverApplicationStatus status,
        OpaqueDcrPublication? publication = null,
        ContactResolverApplicationMutationOutcome mutationOutcome =
            ContactResolverApplicationMutationOutcome.None,
        int durableReplicaCount = 0,
        ulong claimCommitGeneration = 0,
        ReadOnlySpan<byte> canonicalRouteClosure = default,
        ulong responseUnixSeconds = 0) =>
        new(
            request.Operation,
            status,
            mutationOutcome,
            request.RequestHash,
            durableReplicaCount,
            publication?.Generation ?? 0,
            publication?.ObjectCiphertextHash ?? [],
            publication,
            null,
            0,
            default,
            claimCommitGeneration,
            canonicalRouteClosure,
            responseUnixSeconds);

    internal static ContactResolverApplicationResult XurRead(
        ContactResolverXurFetchRequest request,
        ContactResolverApplicationStatus status,
        IReadOnlyList<OpaqueXurEvent>? events,
        ulong currentGeneration,
        ReadOnlySpan<byte> currentHash) =>
        new(
            request.Operation,
            status,
            ContactResolverApplicationMutationOutcome.None,
            request.RequestHash,
            0,
            0,
            default,
            null,
            events,
            currentGeneration,
            currentHash,
            0,
            default,
            0);

    internal static ContactResolverApplicationResult Invalid(
        ContactResolverApplicationRequest? request)
    {
        var requestHash = request is null ? [] : request.RequestHash.ToArray();
        return new(
            request?.Operation ?? 0,
            ContactResolverApplicationStatus.InvalidRequest,
            ContactResolverApplicationMutationOutcome.None,
            requestHash,
            0,
            0,
            default,
            null,
            null,
            0,
            default,
            0,
            default,
            0);
    }

    private static OpaqueDcrPublication Clone(OpaqueDcrPublication item) =>
        new(
            item.Generation,
            item.ObjectCiphertextHash.ToArray(),
            item.Ciphertext.ToArray(),
            item.UsageLimit,
            item.EffectiveExpiresAtUnixSeconds);

    private static OpaqueXurEvent Clone(OpaqueXurEvent item) =>
        new(
            item.Generation,
            item.PredecessorEventHash.ToArray(),
            item.EventHash.ToArray(),
            item.EventCiphertextHash.ToArray(),
            item.Ciphertext.ToArray(),
            item.EffectiveExpiresAtUnixSeconds);
}
