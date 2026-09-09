using System.Buffers.Binary;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using XNode.Core.Mailbox;

namespace XNode.Core.ContactResolver;

internal enum ContactResolverMutationDisposition
{
    Committed = 1,
    ExactReplay = 2,
    Expired = 3,
    StaleGeneration = 4,
    Conflict = 5,
    ForkLatched = 6,
    QuotaExceeded = 7
}

internal enum ContactResolverReadDisposition
{
    Current = 1,
    NotFound = 2,
    Expired = 3,
    Conflict = 4,
    StaleGeneration = 5,
    NoChange = 6
}

internal enum ContactResolverResolveDisposition
{
    Current = 1,
    Committed = 2,
    ExactReplay = 3,
    AlreadyClaimed = 4,
    NotFound = 5,
    Expired = 6,
    Conflict = 7,
    QuotaExceeded = 8
}

internal sealed class ContactResolverOpaqueStoreOptions
{
    internal const int DcrCiphertextMinimumBytes = 40;
    internal const int DcrCiphertextMaximumBytes = 1_048_576;
    internal const int XurCiphertextMaximumBytes = 32_768;
    internal const int XurMinimumRetainedGenerations = 1_024;
    internal static readonly TimeSpan DcrMaximumRetention = TimeSpan.FromDays(400);
    internal static readonly TimeSpan OneTimeDcrMaximumRetention = TimeSpan.FromDays(30);
    internal static readonly TimeSpan DcrPredecessorGrace = TimeSpan.FromHours(48);
    internal static readonly TimeSpan XurRetention = TimeSpan.FromDays(400);

    internal int MaximumPublicationLocators { get; init; } = 16_384;
    internal long MaximumPublicationCiphertextBytes { get; init; } = 256L * 1024 * 1024;
    internal int MaximumXurStreams { get; init; } = 16_384;
    internal int MaximumXurEventsPerStream { get; init; } = 4_096;
    internal long MaximumXurCiphertextBytes { get; init; } = 256L * 1024 * 1024;
    internal long MaximumPersistedBytes { get; init; } = 640L * 1024 * 1024;

    internal void Validate()
    {
        if (MaximumPublicationLocators < 1
            || MaximumPublicationCiphertextBytes < DcrCiphertextMaximumBytes
            || MaximumXurStreams < 1
            || MaximumXurEventsPerStream < XurMinimumRetainedGenerations
            || MaximumXurCiphertextBytes < XurCiphertextMaximumBytes
            || MaximumPersistedBytes < MaximumPublicationCiphertextBytes + MaximumXurCiphertextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(ContactResolverOpaqueStoreOptions));
        }
    }
}

internal sealed class OpaqueDcrPublishRequest
{
    private readonly byte[] locatorHash, operationId, requestHash, predecessorObjectHash,
        objectCiphertextHash, ciphertext;

    internal OpaqueDcrPublishRequest(
        ReadOnlySpan<byte> locatorHash32,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ulong generation,
        ReadOnlySpan<byte> predecessorObjectHash32,
        ReadOnlySpan<byte> objectCiphertextHash32,
        ReadOnlySpan<byte> ciphertext,
        uint usageLimit,
        ulong effectiveExpiresAtUnixSeconds)
    {
        locatorHash = OpaqueValue.CopyNonZero32(locatorHash32, nameof(locatorHash32));
        operationId = OpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = OpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
        predecessorObjectHash = OpaqueValue.CopyGenerationPredecessor(
            generation, predecessorObjectHash32, nameof(predecessorObjectHash32));
        objectCiphertextHash = OpaqueValue.CopyNonZero32(
            objectCiphertextHash32, nameof(objectCiphertextHash32));
        if (ciphertext.Length is < ContactResolverOpaqueStoreOptions.DcrCiphertextMinimumBytes
            or > ContactResolverOpaqueStoreOptions.DcrCiphertextMaximumBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext));
        }
        if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(ciphertext),
                objectCiphertextHash32))
        {
            throw new ArgumentException("The opaque DCR ciphertext hash does not match.", nameof(objectCiphertextHash32));
        }
        if (usageLimit is not (0 or 1))
        {
            throw new ArgumentOutOfRangeException(nameof(usageLimit));
        }
        this.ciphertext = ciphertext.ToArray();
        Generation = generation;
        UsageLimit = usageLimit;
        EffectiveExpiresAtUnixSeconds = effectiveExpiresAtUnixSeconds;
    }

    internal ReadOnlySpan<byte> LocatorHash => locatorHash;
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ulong Generation { get; }
    internal ReadOnlySpan<byte> PredecessorObjectHash => predecessorObjectHash;
    internal ReadOnlySpan<byte> ObjectCiphertextHash => objectCiphertextHash;
    internal ReadOnlySpan<byte> Ciphertext => ciphertext;
    internal uint UsageLimit { get; }
    internal ulong EffectiveExpiresAtUnixSeconds { get; }
}

internal sealed class OpaqueDcrResolveRequest
{
    internal const int MinimumRouteClosureBytes = 4_143;
    internal const int MaximumRouteClosureBytes = 23_295;
    private readonly byte[] locatorHash, operationId, requestHash, routeClosure;

    internal OpaqueDcrResolveRequest(
        ReadOnlySpan<byte> locatorHash32,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> canonicalRouteClosure = default,
        ulong responseUnixSeconds = 0)
    {
        locatorHash = OpaqueValue.CopyNonZero32(locatorHash32, nameof(locatorHash32));
        operationId = OpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = OpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
        if (canonicalRouteClosure.Length != 0
            && canonicalRouteClosure.Length is < MinimumRouteClosureBytes
                or > MaximumRouteClosureBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(canonicalRouteClosure));
        }
        routeClosure = canonicalRouteClosure.ToArray();
        ResponseUnixSeconds = responseUnixSeconds;
    }

    internal ReadOnlySpan<byte> LocatorHash => locatorHash;
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ReadOnlySpan<byte> CanonicalRouteClosure => routeClosure;
    internal ulong ResponseUnixSeconds { get; }
}

internal sealed class OpaqueXurWriteRequest
{
    private readonly byte[] serviceCapability, operationId, requestHash, exactXur1Hash,
        predecessorEventHash, eventHash, eventCiphertextHash, ciphertext;

    internal OpaqueXurWriteRequest(
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ReadOnlySpan<byte> exactXur1Hash32,
        ulong eventGeneration,
        ReadOnlySpan<byte> predecessorEventHash32,
        ReadOnlySpan<byte> eventHash32,
        ReadOnlySpan<byte> eventCiphertextHash32,
        ReadOnlySpan<byte> ciphertext,
        ulong effectiveExpiresAtUnixSeconds)
    {
        serviceCapability = OpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        operationId = OpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = OpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
        exactXur1Hash = OpaqueValue.CopyNonZero32(exactXur1Hash32, nameof(exactXur1Hash32));
        predecessorEventHash = OpaqueValue.CopyXurPredecessor(
            eventGeneration, predecessorEventHash32, nameof(predecessorEventHash32));
        eventHash = OpaqueValue.CopyNonZero32(eventHash32, nameof(eventHash32));
        eventCiphertextHash = OpaqueValue.CopyNonZero32(
            eventCiphertextHash32, nameof(eventCiphertextHash32));
        if (ciphertext.Length is < 1 or > ContactResolverOpaqueStoreOptions.XurCiphertextMaximumBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(ciphertext));
        }
        if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(ciphertext),
                eventCiphertextHash32))
        {
            throw new ArgumentException("The opaque XUR ciphertext hash does not match.", nameof(eventCiphertextHash32));
        }
        this.ciphertext = ciphertext.ToArray();
        EventGeneration = eventGeneration;
        EffectiveExpiresAtUnixSeconds = effectiveExpiresAtUnixSeconds;
    }

    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ReadOnlySpan<byte> ExactXur1Hash => exactXur1Hash;
    internal ulong EventGeneration { get; }
    internal ReadOnlySpan<byte> PredecessorEventHash => predecessorEventHash;
    internal ReadOnlySpan<byte> EventHash => eventHash;
    internal ReadOnlySpan<byte> EventCiphertextHash => eventCiphertextHash;
    internal ReadOnlySpan<byte> Ciphertext => ciphertext;
    internal ulong EffectiveExpiresAtUnixSeconds { get; }
}

internal sealed class VerifiedXurCompactionCheckpoint
{
    private readonly byte[] serviceCapability, eventHash;

    private VerifiedXurCompactionCheckpoint(
        ReadOnlySpan<byte> serviceCapability32,
        ulong generation,
        ReadOnlySpan<byte> eventHash32)
    {
        serviceCapability = OpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        eventHash = OpaqueValue.CopyNonZero32(eventHash32, nameof(eventHash32));
        Generation = generation;
    }

    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ulong Generation { get; }
    internal ReadOnlySpan<byte> EventHash => eventHash;

    // The future CONTACT service verifier is the sole production caller of this
    // boundary. The store deliberately accepts no raw checkpoint generation.
    internal static VerifiedXurCompactionCheckpoint FromVerifiedClosure(
        ReadOnlySpan<byte> serviceCapability32,
        ulong generation,
        ReadOnlySpan<byte> eventHash32) =>
        new(serviceCapability32, generation, eventHash32);
}

internal sealed record ContactResolverMutationResult(
    ContactResolverMutationDisposition Disposition,
    ulong Generation,
    byte[] ObjectHash)
{
    internal static ContactResolverMutationResult Empty(ContactResolverMutationDisposition disposition) =>
        new(disposition, 0, []);
}

internal sealed record OpaqueDcrPublication(
    ulong Generation,
    byte[] ObjectCiphertextHash,
    byte[] Ciphertext,
    uint UsageLimit,
    ulong EffectiveExpiresAtUnixSeconds);

internal sealed record ContactResolverDcrReadResult(
    ContactResolverReadDisposition Disposition,
    OpaqueDcrPublication? Publication);

internal sealed record ContactResolverDcrResolveResult(
    ContactResolverResolveDisposition Disposition,
    OpaqueDcrPublication? Publication,
    ulong ClaimCommitGeneration,
    byte[] CanonicalRouteClosure,
    ulong ResponseUnixSeconds);

internal sealed record OpaqueXurEvent(
    ulong Generation,
    byte[] PredecessorEventHash,
    byte[] EventHash,
    byte[] EventCiphertextHash,
    byte[] Ciphertext,
    ulong EffectiveExpiresAtUnixSeconds);

internal sealed record ContactResolverXurReadResult(
    ContactResolverReadDisposition Disposition,
    IReadOnlyList<OpaqueXurEvent> Events,
    ulong CurrentGeneration,
    byte[] CurrentEventHash);

internal sealed class ContactResolverStoreCorruptException : IOException
{
    internal ContactResolverStoreCorruptException(Exception? inner = null)
        : base("The opaque contact resolver store is corrupt and has been quarantined.", inner)
    {
    }
}

/// <summary>
/// Durable transport-neutral storage for already-authorized opaque resolver and
/// XUR successor bytes. It parses no DCR1, DID, account, device, or contact data
/// and is not connected to an HTTP or runtime activation surface.
/// </summary>
internal sealed class ContactResolverOpaqueStore : IDisposable
{
    private const int StateVersion = 3;
    private const int EnvelopeOverhead = 8 + sizeof(uint) + 32;
    private static readonly byte[] EnvelopeMagic = "XCRSTR01"u8.ToArray();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly object gate = new();
    private readonly string path;
    private readonly ContactResolverOpaqueStoreOptions options;
    private readonly IClock clock;
    private readonly IMailboxStorageSecurity storageSecurity;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly FileStream lifetimeLease;
    private PersistedState state;
    private bool disposed;
    private bool faulted;

    internal ContactResolverOpaqueStore(
        string statePath,
        ContactResolverOpaqueStoreOptions? options = null,
        IClock? clock = null,
        IMailboxStorageSecurity? storageSecurity = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        path = Path.GetFullPath(statePath);
        this.options = options ?? new ContactResolverOpaqueStoreOptions();
        this.options.Validate();
        this.clock = clock ?? new SystemClock();
        this.storageSecurity = storageSecurity ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();

        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The resolver state path has no parent directory.", nameof(statePath));
        this.storageSecurity.SecureDirectory(directory);
        var lockPath = path + ".lock";
        lifetimeLease = new FileStream(
            lockPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            1,
            FileOptions.WriteThrough);
        this.storageSecurity.SecureFile(lockPath);
        try
        {
            state = LoadState();
        }
        catch
        {
            lifetimeLease.Dispose();
            throw;
        }
    }

    internal ContactResolverMutationResult PublishDcr(OpaqueDcrPublishRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfDisposed();
            var now = CurrentUnixSeconds();
            ValidateFutureDeadline(
                request.EffectiveExpiresAtUnixSeconds,
                now,
                request.UsageLimit == 1
                    ? ContactResolverOpaqueStoreOptions.OneTimeDcrMaximumRetention
                    : ContactResolverOpaqueStoreOptions.DcrMaximumRetention,
                nameof(request));
            if (request.EffectiveExpiresAtUnixSeconds <= now)
            {
                return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Expired);
            }

            var operation = FindDcrOperation(request.OperationId, out var operationPublication);
            if (operation is not null)
            {
                return operationPublication is not null
                    && OpaqueValue.FixedEquals(operationPublication.LocatorHash, request.LocatorHash)
                    && Matches(operation, request)
                    ? Mutation(ContactResolverMutationDisposition.ExactReplay, operation.Generation, operation.ObjectCiphertextHash)
                    : ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
            }
            if (FindDcrRedemption(request.OperationId, out _) is not null)
            {
                return ContactResolverMutationResult.Empty(
                    ContactResolverMutationDisposition.Conflict);
            }

            var locator = FindPublication(request.LocatorHash);
            if (locator is null)
            {
                if (request.Generation != 0 || !OpaqueValue.IsZero(request.PredecessorObjectHash))
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.StaleGeneration);
                }
                if (state.Publications.Count >= options.MaximumPublicationLocators
                    || PublicationBytes() + request.Ciphertext.Length > options.MaximumPublicationCiphertextBytes)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.QuotaExceeded);
                }
                locator = new PublicationState { LocatorHash = request.LocatorHash.ToArray() };
                state.Publications.Add(locator);
            }
            else
            {
                if (locator.ForkLatched)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.ForkLatched);
                }
                var current = locator.Records[^1];
                if (current.UsageLimit == 1)
                {
                    return ContactResolverMutationResult.Empty(
                        ContactResolverMutationDisposition.Conflict);
                }
                if (request.Generation == current.Generation)
                {
                    locator.ForkLatched = true;
                    SaveState();
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
                }
                if (current.Generation == ulong.MaxValue
                    || request.Generation != current.Generation + 1)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.StaleGeneration);
                }
                if (!OpaqueValue.FixedEquals(request.PredecessorObjectHash, current.ObjectCiphertextHash))
                {
                    locator.ForkLatched = true;
                    SaveState();
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
                }
                if (PublicationBytes() + request.Ciphertext.Length > options.MaximumPublicationCiphertextBytes)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.QuotaExceeded);
                }
            }

            locator.Records.Add(ToState(request, now));
            CanonicalizeState();
            SaveState();
            return Mutation(
                ContactResolverMutationDisposition.Committed,
                request.Generation,
                request.ObjectCiphertextHash);
        }
    }

    internal ContactResolverDcrReadResult ResolveCurrentDcr(ReadOnlySpan<byte> locatorHash32)
    {
        var locator = OpaqueValue.CopyNonZero32(locatorHash32, nameof(locatorHash32));
        lock (gate)
        {
            ThrowIfDisposed();
            var found = FindPublication(locator);
            if (found is null)
            {
                return new(ContactResolverReadDisposition.NotFound, null);
            }
            if (found.ForkLatched)
            {
                return new(ContactResolverReadDisposition.Conflict, null);
            }
            var current = found.Records[^1];
            if (current.EffectiveExpiresAtUnixSeconds <= CurrentUnixSeconds())
            {
                return new(ContactResolverReadDisposition.Expired, null);
            }
            return new(
                ContactResolverReadDisposition.Current,
                new OpaqueDcrPublication(
                    current.Generation,
                    current.ObjectCiphertextHash.ToArray(),
                    current.Ciphertext.ToArray(),
                    current.UsageLimit,
                    current.EffectiveExpiresAtUnixSeconds));
        }
    }

    internal ContactResolverDcrResolveResult ResolveDcr(OpaqueDcrResolveRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfDisposed();

            var priorPublicationOperation = FindDcrOperation(
                request.OperationId, out _);
            if (priorPublicationOperation is not null)
            {
                return ResolveResult(ContactResolverResolveDisposition.Conflict);
            }

            var priorRedemption = FindDcrRedemption(
                request.OperationId, out var priorOwner);
            if (priorRedemption is not null)
            {
                return priorOwner is not null
                    && OpaqueValue.FixedEquals(priorOwner.LocatorHash, request.LocatorHash)
                    && OpaqueValue.FixedEquals(
                        priorRedemption.RedemptionRequestHash, request.RequestHash)
                    ? ResolveResult(
                        ContactResolverResolveDisposition.ExactReplay,
                        priorRedemption,
                        priorRedemption.ClaimCommitGeneration)
                    : ResolveResult(ContactResolverResolveDisposition.Conflict);
            }

            var found = FindPublication(request.LocatorHash);
            if (found is null)
            {
                return ResolveResult(ContactResolverResolveDisposition.NotFound);
            }
            if (found.ForkLatched)
            {
                return ResolveResult(ContactResolverResolveDisposition.Conflict);
            }

            var current = found.Records[^1];
            if (current.EffectiveExpiresAtUnixSeconds <= CurrentUnixSeconds())
            {
                return ResolveResult(ContactResolverResolveDisposition.Expired);
            }
            if (current.UsageLimit == 0)
            {
                return ResolveResult(ContactResolverResolveDisposition.Current, current);
            }
            if (current.RedemptionOperationId.Length != 0)
            {
                return ResolveResult(ContactResolverResolveDisposition.AlreadyClaimed);
            }

            if (request.CanonicalRouteClosure.IsEmpty
                || request.ResponseUnixSeconds == 0)
            {
                return ResolveResult(ContactResolverResolveDisposition.Conflict);
            }
            if (PublicationBytes() + request.CanonicalRouteClosure.Length
                > options.MaximumPublicationCiphertextBytes)
            {
                return ResolveResult(ContactResolverResolveDisposition.QuotaExceeded);
            }

            current.RedemptionOperationId = request.OperationId.ToArray();
            current.RedemptionRequestHash = request.RequestHash.ToArray();
            current.ClaimCommitGeneration = 1;
            current.RedemptionRouteClosure = request.CanonicalRouteClosure.ToArray();
            current.RedemptionResponseUnixSeconds = request.ResponseUnixSeconds;
            SaveState();
            return ResolveResult(
                ContactResolverResolveDisposition.Committed,
                current,
                current.ClaimCommitGeneration);
        }
    }

    internal ContactResolverDcrResolveResult ReadDcrClaim(
        OpaqueDcrResolveRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfDisposed();
            if (FindDcrOperation(request.OperationId, out _) is not null)
            {
                return ResolveResult(ContactResolverResolveDisposition.Conflict);
            }

            var priorRedemption = FindDcrRedemption(
                request.OperationId, out var priorOwner);
            if (priorRedemption is not null)
            {
                return priorOwner is not null
                    && OpaqueValue.FixedEquals(priorOwner.LocatorHash, request.LocatorHash)
                    && OpaqueValue.FixedEquals(
                        priorRedemption.RedemptionRequestHash, request.RequestHash)
                    ? ResolveResult(
                        ContactResolverResolveDisposition.ExactReplay,
                        priorRedemption,
                        priorRedemption.ClaimCommitGeneration)
                    : ResolveResult(ContactResolverResolveDisposition.Conflict);
            }

            var found = FindPublication(request.LocatorHash);
            if (found is null)
            {
                return ResolveResult(ContactResolverResolveDisposition.NotFound);
            }
            if (found.ForkLatched)
            {
                return ResolveResult(ContactResolverResolveDisposition.Conflict);
            }
            var current = found.Records[^1];
            if (current.EffectiveExpiresAtUnixSeconds <= CurrentUnixSeconds())
            {
                return ResolveResult(ContactResolverResolveDisposition.Expired);
            }
            if (current.UsageLimit == 1
                && current.RedemptionOperationId.Length != 0)
            {
                return ResolveResult(ContactResolverResolveDisposition.AlreadyClaimed);
            }
            return ResolveResult(ContactResolverResolveDisposition.Current, current);
        }
    }

    internal ContactResolverMutationResult WriteXurSuccessor(OpaqueXurWriteRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (gate)
        {
            ThrowIfDisposed();
            var now = CurrentUnixSeconds();
            ValidateFutureDeadline(
                request.EffectiveExpiresAtUnixSeconds,
                now,
                ContactResolverOpaqueStoreOptions.XurRetention,
                nameof(request));
            if (request.EffectiveExpiresAtUnixSeconds <= now)
            {
                return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Expired);
            }

            var operation = FindXurOperation(request.OperationId, out var operationStream);
            if (operation is not null)
            {
                return operationStream is not null
                    && OpaqueValue.FixedEquals(operationStream.ServiceCapability, request.ServiceCapability)
                    && Matches(operation, request)
                    ? Mutation(ContactResolverMutationDisposition.ExactReplay, operation.Generation, operation.EventHash)
                    : ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
            }

            var stream = FindXurStream(request.ServiceCapability);
            if (stream is null)
            {
                if (request.EventGeneration != 1 || !OpaqueValue.IsZero(request.PredecessorEventHash))
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.StaleGeneration);
                }
                if (state.XurStreams.Count >= options.MaximumXurStreams)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.QuotaExceeded);
                }
                stream = new XurStreamState
                {
                    ServiceCapability = request.ServiceCapability.ToArray(),
                    ExactXur1Hash = request.ExactXur1Hash.ToArray()
                };
                state.XurStreams.Add(stream);
            }
            else
            {
                if (stream.ForkLatched)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.ForkLatched);
                }
                if (!OpaqueValue.FixedEquals(stream.ExactXur1Hash, request.ExactXur1Hash))
                {
                    stream.ForkLatched = true;
                    SaveState();
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
                }
                if (stream.Events.Count == 0)
                {
                    throw QuarantineAndCreateException(new InvalidDataException("Compacted XUR stream has no retained head."));
                }
                var current = stream.Events[^1];
                if (request.EventGeneration == current.Generation)
                {
                    stream.ForkLatched = true;
                    SaveState();
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
                }
                if (current.Generation == ulong.MaxValue
                    || request.EventGeneration != current.Generation + 1)
                {
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.StaleGeneration);
                }
                if (!OpaqueValue.FixedEquals(request.PredecessorEventHash, current.EventHash))
                {
                    stream.ForkLatched = true;
                    SaveState();
                    return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.Conflict);
                }
            }

            if (stream.Events.Count >= options.MaximumXurEventsPerStream
                || XurBytes() + request.Ciphertext.Length > options.MaximumXurCiphertextBytes)
            {
                return ContactResolverMutationResult.Empty(ContactResolverMutationDisposition.QuotaExceeded);
            }
            stream.Events.Add(ToState(request, now));
            CanonicalizeState();
            SaveState();
            return Mutation(
                ContactResolverMutationDisposition.Committed,
                request.EventGeneration,
                request.EventHash);
        }
    }

    internal ContactResolverXurReadResult ResolveXurSuccessors(
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactXur1Hash32,
        ulong afterGeneration,
        int maximumEvents)
    {
        var capability = OpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        var exactXur1Hash = OpaqueValue.CopyNonZero32(exactXur1Hash32, nameof(exactXur1Hash32));
        if (maximumEvents is < 1 or > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumEvents));
        }
        lock (gate)
        {
            ThrowIfDisposed();
            var stream = FindXurStream(capability);
            if (stream is null)
            {
                return XurRead(ContactResolverReadDisposition.NotFound, [], 0, []);
            }
            if (!OpaqueValue.FixedEquals(stream.ExactXur1Hash, exactXur1Hash))
            {
                return XurRead(ContactResolverReadDisposition.NotFound, [], 0, []);
            }
            if (stream.ForkLatched)
            {
                return XurRead(ContactResolverReadDisposition.Conflict, [], 0, []);
            }
            var current = stream.Events[^1];
            if (stream.HasCompactionAnchor && afterGeneration < stream.CompactedThroughGeneration)
            {
                return XurRead(
                    ContactResolverReadDisposition.StaleGeneration,
                    [],
                    current.Generation,
                    current.EventHash);
            }
            var events = stream.Events
                .Where(item => item.Generation > afterGeneration)
                .Take(maximumEvents)
                .Select(ToPublic)
                .ToArray();
            return XurRead(
                events.Length == 0
                    ? ContactResolverReadDisposition.NoChange
                    : ContactResolverReadDisposition.Current,
                events,
                current.Generation,
                current.EventHash);
        }
    }

    internal int CollectGarbage(VerifiedXurCompactionCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        lock (gate)
        {
            ThrowIfDisposed();
            var now = CurrentUnixSeconds();
            var changed = CollectDcrPredecessors(now);
            var removed = 0;
            var stream = FindXurStream(checkpoint.ServiceCapability);
            if (stream is not null && !stream.ForkLatched)
            {
                var checkpointEvent = stream.Events.SingleOrDefault(item =>
                    item.Generation == checkpoint.Generation);
                if (checkpointEvent is null
                    || !OpaqueValue.FixedEquals(checkpointEvent.EventHash, checkpoint.EventHash))
                {
                    return 0;
                }
                var horizon = checked((ulong)ContactResolverOpaqueStoreOptions.XurRetention.TotalSeconds);
                while (stream.Events.Count > ContactResolverOpaqueStoreOptions.XurMinimumRetainedGenerations)
                {
                    var candidate = stream.Events[0];
                    if (candidate.Generation > checkpoint.Generation
                        || candidate.AcceptedAtUnixSeconds > ulong.MaxValue - horizon
                        || candidate.AcceptedAtUnixSeconds + horizon > now)
                    {
                        break;
                    }
                    stream.HasCompactionAnchor = true;
                    stream.CompactedThroughGeneration = candidate.Generation;
                    stream.CompactedThroughEventHash = candidate.EventHash.ToArray();
                    stream.Events.RemoveAt(0);
                    removed++;
                }
            }
            if (changed || removed != 0)
            {
                SaveState();
            }
            return removed;
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }
            disposed = true;
            lifetimeLease.Dispose();
        }
    }

    private PersistedState LoadState()
    {
        if (!File.Exists(path))
        {
            return new PersistedState();
        }
        try
        {
            var info = new FileInfo(path);
            if (info.Length < EnvelopeOverhead || info.Length > options.MaximumPersistedBytes)
            {
                throw new InvalidDataException("Resolver state envelope length is invalid.");
            }
            var bytes = File.ReadAllBytes(path);
            if (!bytes.AsSpan(0, EnvelopeMagic.Length).SequenceEqual(EnvelopeMagic))
            {
                throw new InvalidDataException("Resolver state envelope magic is invalid.");
            }
            var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(EnvelopeMagic.Length, 4));
            if (payloadLength > int.MaxValue
                || checked(EnvelopeOverhead + (int)payloadLength) != bytes.Length)
            {
                throw new InvalidDataException("Resolver state payload length is invalid.");
            }
            var payload = bytes.AsSpan(EnvelopeMagic.Length + 4, (int)payloadLength);
            var digest = bytes.AsSpan(EnvelopeMagic.Length + 4 + (int)payloadLength, 32);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), digest))
            {
                throw new InvalidDataException("Resolver state digest is invalid.");
            }
            var loaded = JsonSerializer.Deserialize<PersistedState>(payload, JsonOptions)
                ?? throw new InvalidDataException("Resolver state payload is empty.");
            ValidateState(loaded);
            return loaded;
        }
        catch (Exception exception) when (exception is InvalidDataException
            or JsonException
            or OverflowException
            or ArgumentException)
        {
            throw QuarantineAndCreateException(exception);
        }
    }

    private void SaveState()
    {
        try
        {
            ValidateState(state);
            var payload = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
            if ((long)payload.Length + EnvelopeOverhead > options.MaximumPersistedBytes)
            {
                throw new InvalidOperationException("The resolver state exceeds its configured durable bound.");
            }
            var envelope = new byte[checked(payload.Length + EnvelopeOverhead)];
            EnvelopeMagic.CopyTo(envelope, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                envelope.AsSpan(EnvelopeMagic.Length, 4),
                checked((uint)payload.Length));
            payload.CopyTo(envelope.AsSpan(EnvelopeMagic.Length + 4));
            SHA256.HashData(payload).CopyTo(envelope, EnvelopeMagic.Length + 4 + payload.Length);
            var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(
                           temporary,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           64 * 1024,
                           FileOptions.WriteThrough))
                {
                    stream.Write(envelope);
                    stream.Flush(flushToDisk: true);
                }
                storageSecurity.SecureFile(temporary);
                durability.FlushFileAndParentDirectory(temporary);
                ReplaceFileWithBoundedRetry(temporary);
                durability.FlushFileAndParentDirectory(path);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(envelope);
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
        }
        catch
        {
            faulted = true;
            throw;
        }
    }

    private void ReplaceFileWithBoundedRetry(string temporary)
    {
        const int maximumAttempts = 8;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                durability.ReplaceFile(temporary, path);
                return;
            }
            catch (Win32Exception exception) when (
                OperatingSystem.IsWindows()
                && attempt < maximumAttempts
                && exception.NativeErrorCode is 5 or 32)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(1 << (attempt - 1)));
            }
        }
    }

    private ContactResolverStoreCorruptException QuarantineAndCreateException(Exception exception)
    {
        try
        {
            if (File.Exists(path))
            {
                var quarantine = path + ".quarantine." + Guid.NewGuid().ToString("N");
                durability.ReplaceFile(path, quarantine);
                durability.FlushFileAndParentDirectory(quarantine);
            }
        }
        catch (Exception quarantineFailure)
        {
            return new ContactResolverStoreCorruptException(
                new AggregateException(exception, quarantineFailure));
        }
        return new ContactResolverStoreCorruptException(exception);
    }

    private bool CollectDcrPredecessors(ulong now)
    {
        var changed = false;
        var grace = checked((ulong)ContactResolverOpaqueStoreOptions.DcrPredecessorGrace.TotalSeconds);
        foreach (var locator in state.Publications)
        {
            while (locator.Records.Count > 1)
            {
                var successor = locator.Records[1];
                if (successor.AcceptedAtUnixSeconds > ulong.MaxValue - grace
                    || successor.AcceptedAtUnixSeconds + grace > now)
                {
                    break;
                }
                locator.Records.RemoveAt(0);
                changed = true;
            }
        }
        return changed;
    }

    private void ValidateState(PersistedState candidate)
    {
        if (candidate.Version != StateVersion
            || candidate.Publications is null
            || candidate.XurStreams is null
            || candidate.Publications.Count > options.MaximumPublicationLocators
            || candidate.XurStreams.Count > options.MaximumXurStreams)
        {
            throw new InvalidDataException("Resolver state version or top-level bounds are invalid.");
        }

        var priorKey = Array.Empty<byte>();
        var operations = new HashSet<string>(StringComparer.Ordinal);
        long publicationBytes = 0;
        foreach (var locator in candidate.Publications)
        {
            Validate32(locator.LocatorHash);
            if (priorKey.Length != 0 && priorKey.AsSpan().SequenceCompareTo(locator.LocatorHash) >= 0)
            {
                throw new InvalidDataException("Resolver publication keys are not canonical.");
            }
            priorKey = locator.LocatorHash;
            if (locator.Records is null || locator.Records.Count == 0)
            {
                throw new InvalidDataException("Resolver publication history is empty.");
            }
            PublicationStateRecord? previous = null;
            foreach (var record in locator.Records)
            {
                Validate32(record.OperationId);
                Validate32(record.RequestHash);
                Validate32(record.ObjectCiphertextHash);
                ValidateGenerationPredecessor(record.Generation, record.PredecessorObjectHash);
                if (record.Ciphertext is null
                    || record.Ciphertext.Length is < ContactResolverOpaqueStoreOptions.DcrCiphertextMinimumBytes
                        or > ContactResolverOpaqueStoreOptions.DcrCiphertextMaximumBytes
                    || record.UsageLimit is not (0 or 1)
                    || record.AcceptedAtUnixSeconds >= record.EffectiveExpiresAtUnixSeconds
                    || record.EffectiveExpiresAtUnixSeconds - record.AcceptedAtUnixSeconds
                        > (ulong)(record.UsageLimit == 1
                            ? ContactResolverOpaqueStoreOptions.OneTimeDcrMaximumRetention.TotalSeconds
                            : ContactResolverOpaqueStoreOptions.DcrMaximumRetention.TotalSeconds)
                    || !OpaqueValue.FixedEquals(SHA256.HashData(record.Ciphertext), record.ObjectCiphertextHash)
                    || !operations.Add(Convert.ToHexString(record.OperationId)))
                {
                    throw new InvalidDataException("Resolver publication record is invalid.");
                }
                if (record.RedemptionOperationId is null
                    || record.RedemptionRequestHash is null
                    || record.RedemptionRouteClosure is null)
                {
                    throw new InvalidDataException(
                        "Resolver one-time redemption state is invalid.");
                }
                var unclaimed = record.RedemptionOperationId.Length == 0
                    && record.RedemptionRequestHash.Length == 0
                    && record.ClaimCommitGeneration == 0
                    && record.RedemptionRouteClosure.Length == 0
                    && record.RedemptionResponseUnixSeconds == 0;
                var claimed = record.UsageLimit == 1
                    && record.RedemptionOperationId.Length == 32
                    && !OpaqueValue.IsZero(record.RedemptionOperationId)
                    && record.RedemptionRequestHash.Length == 32
                    && !OpaqueValue.IsZero(record.RedemptionRequestHash)
                    && record.ClaimCommitGeneration == 1
                    && record.RedemptionRouteClosure.Length
                        is >= OpaqueDcrResolveRequest.MinimumRouteClosureBytes
                            and <= OpaqueDcrResolveRequest.MaximumRouteClosureBytes
                    && record.RedemptionResponseUnixSeconds >= record.AcceptedAtUnixSeconds
                    && record.RedemptionResponseUnixSeconds
                        < record.EffectiveExpiresAtUnixSeconds
                    && operations.Add(Convert.ToHexString(record.RedemptionOperationId));
                if (!unclaimed && !claimed)
                {
                    throw new InvalidDataException(
                        "Resolver one-time redemption state is invalid.");
                }
                if (previous is not null
                    && (previous.Generation == ulong.MaxValue
                        || record.Generation != previous.Generation + 1
                        || !OpaqueValue.FixedEquals(record.PredecessorObjectHash, previous.ObjectCiphertextHash)
                        || previous.UsageLimit == 1))
                {
                    throw new InvalidDataException("Resolver publication history is discontinuous.");
                }
                publicationBytes = checked(publicationBytes
                    + record.Ciphertext.Length
                    + record.RedemptionRouteClosure.Length);
                previous = record;
            }
        }
        if (publicationBytes > options.MaximumPublicationCiphertextBytes)
        {
            throw new InvalidDataException("Resolver publication quota is exceeded.");
        }

        priorKey = [];
        operations.Clear();
        long xurBytes = 0;
        foreach (var stream in candidate.XurStreams)
        {
            Validate32(stream.ServiceCapability);
            Validate32(stream.ExactXur1Hash);
            if (priorKey.Length != 0 && priorKey.AsSpan().SequenceCompareTo(stream.ServiceCapability) >= 0)
            {
                throw new InvalidDataException("XUR stream keys are not canonical.");
            }
            priorKey = stream.ServiceCapability;
            if (stream.Events is null
                || stream.Events.Count == 0
                || stream.Events.Count > options.MaximumXurEventsPerStream)
            {
                throw new InvalidDataException("XUR retained history bounds are invalid.");
            }
            if (stream.HasCompactionAnchor)
            {
                Validate32(stream.CompactedThroughEventHash);
            }
            else if (stream.CompactedThroughGeneration != 0
                     || stream.CompactedThroughEventHash is null
                     || stream.CompactedThroughEventHash.Length != 0)
            {
                throw new InvalidDataException("XUR compaction anchor is invalid.");
            }
            XurEventState? previous = null;
            foreach (var item in stream.Events)
            {
                Validate32(item.OperationId);
                Validate32(item.RequestHash);
                Validate32(item.ExactXur1Hash);
                Validate32(item.EventHash);
                Validate32(item.EventCiphertextHash);
                ValidateXurPredecessor(item.Generation, item.PredecessorEventHash);
                if (item.Ciphertext is null
                    || item.Ciphertext.Length is < 1 or > ContactResolverOpaqueStoreOptions.XurCiphertextMaximumBytes
                    || item.AcceptedAtUnixSeconds >= item.EffectiveExpiresAtUnixSeconds
                    || item.EffectiveExpiresAtUnixSeconds - item.AcceptedAtUnixSeconds
                        > (ulong)ContactResolverOpaqueStoreOptions.XurRetention.TotalSeconds
                    || !OpaqueValue.FixedEquals(SHA256.HashData(item.Ciphertext), item.EventCiphertextHash)
                    || !operations.Add(Convert.ToHexString(item.OperationId)))
                {
                    throw new InvalidDataException("XUR event record is invalid.");
                }
                if (previous is null)
                {
                    if (stream.HasCompactionAnchor
                        && (stream.CompactedThroughGeneration == ulong.MaxValue
                            || item.Generation != stream.CompactedThroughGeneration + 1
                            || !OpaqueValue.FixedEquals(
                                item.PredecessorEventHash,
                                stream.CompactedThroughEventHash)))
                    {
                        throw new InvalidDataException("XUR compaction lineage is invalid.");
                    }
                    if (!stream.HasCompactionAnchor && item.Generation != 1)
                    {
                        throw new InvalidDataException("XUR uncompacted history does not begin at generation one.");
                    }
                }
                else if (previous.Generation == ulong.MaxValue
                         || item.Generation != previous.Generation + 1
                         || !OpaqueValue.FixedEquals(item.PredecessorEventHash, previous.EventHash))
                {
                    throw new InvalidDataException("XUR event history is discontinuous.");
                }
                xurBytes = checked(xurBytes + item.Ciphertext.Length);
                previous = item;
            }
        }
        if (xurBytes > options.MaximumXurCiphertextBytes)
        {
            throw new InvalidDataException("XUR ciphertext quota is exceeded.");
        }
    }

    private void CanonicalizeState()
    {
        state.Publications.Sort(static (left, right) =>
            left.LocatorHash.AsSpan().SequenceCompareTo(right.LocatorHash));
        state.XurStreams.Sort(static (left, right) =>
            left.ServiceCapability.AsSpan().SequenceCompareTo(right.ServiceCapability));
    }

    private PublicationState? FindPublication(ReadOnlySpan<byte> locator)
    {
        foreach (var item in state.Publications)
        {
            if (OpaqueValue.FixedEquals(item.LocatorHash, locator))
            {
                return item;
            }
        }
        return null;
    }

    private XurStreamState? FindXurStream(ReadOnlySpan<byte> capability)
    {
        foreach (var item in state.XurStreams)
        {
            if (OpaqueValue.FixedEquals(item.ServiceCapability, capability))
            {
                return item;
            }
        }
        return null;
    }

    private PublicationStateRecord? FindDcrOperation(
        ReadOnlySpan<byte> operationId,
        out PublicationState? owner)
    {
        foreach (var publication in state.Publications)
        {
            foreach (var item in publication.Records)
            {
                if (OpaqueValue.FixedEquals(item.OperationId, operationId))
                {
                    owner = publication;
                    return item;
                }
            }
        }
        owner = null;
        return null;
    }

    private PublicationStateRecord? FindDcrRedemption(
        ReadOnlySpan<byte> operationId,
        out PublicationState? owner)
    {
        foreach (var publication in state.Publications)
        {
            foreach (var item in publication.Records)
            {
                if (item.RedemptionOperationId.Length == 32
                    && OpaqueValue.FixedEquals(item.RedemptionOperationId, operationId))
                {
                    owner = publication;
                    return item;
                }
            }
        }
        owner = null;
        return null;
    }

    private XurEventState? FindXurOperation(
        ReadOnlySpan<byte> operationId,
        out XurStreamState? owner)
    {
        foreach (var stream in state.XurStreams)
        {
            foreach (var item in stream.Events)
            {
                if (OpaqueValue.FixedEquals(item.OperationId, operationId))
                {
                    owner = stream;
                    return item;
                }
            }
        }
        owner = null;
        return null;
    }

    private long PublicationBytes() =>
        state.Publications.SelectMany(static item => item.Records).Sum(static item =>
            (long)item.Ciphertext.Length + item.RedemptionRouteClosure.Length);

    private long XurBytes() =>
        state.XurStreams.SelectMany(static item => item.Events).Sum(static item => (long)item.Ciphertext.Length);

    private ulong CurrentUnixSeconds()
    {
        var seconds = clock.UtcNow.ToUnixTimeSeconds();
        if (seconds < 0)
        {
            throw new InvalidOperationException("Resolver trusted service time is before the Unix epoch.");
        }
        return checked((ulong)seconds);
    }

    private static void ValidateFutureDeadline(
        ulong deadline,
        ulong now,
        TimeSpan maximum,
        string parameter)
    {
        if (deadline <= now)
        {
            return;
        }
        var maximumSeconds = checked((ulong)maximum.TotalSeconds);
        if (deadline - now > maximumSeconds)
        {
            throw new ArgumentOutOfRangeException(parameter, "The signed opaque object exceeds its retention bound.");
        }
    }

    private static PublicationStateRecord ToState(OpaqueDcrPublishRequest request, ulong now) => new()
    {
        OperationId = request.OperationId.ToArray(),
        RequestHash = request.RequestHash.ToArray(),
        Generation = request.Generation,
        PredecessorObjectHash = request.PredecessorObjectHash.ToArray(),
        ObjectCiphertextHash = request.ObjectCiphertextHash.ToArray(),
        Ciphertext = request.Ciphertext.ToArray(),
        UsageLimit = request.UsageLimit,
        AcceptedAtUnixSeconds = now,
        EffectiveExpiresAtUnixSeconds = request.EffectiveExpiresAtUnixSeconds
    };

    private static XurEventState ToState(OpaqueXurWriteRequest request, ulong now) => new()
    {
        OperationId = request.OperationId.ToArray(),
        RequestHash = request.RequestHash.ToArray(),
        ExactXur1Hash = request.ExactXur1Hash.ToArray(),
        Generation = request.EventGeneration,
        PredecessorEventHash = request.PredecessorEventHash.ToArray(),
        EventHash = request.EventHash.ToArray(),
        EventCiphertextHash = request.EventCiphertextHash.ToArray(),
        Ciphertext = request.Ciphertext.ToArray(),
        AcceptedAtUnixSeconds = now,
        EffectiveExpiresAtUnixSeconds = request.EffectiveExpiresAtUnixSeconds
    };

    private static OpaqueXurEvent ToPublic(XurEventState item) => new(
        item.Generation,
        item.PredecessorEventHash.ToArray(),
        item.EventHash.ToArray(),
        item.EventCiphertextHash.ToArray(),
        item.Ciphertext.ToArray(),
        item.EffectiveExpiresAtUnixSeconds);

    private static OpaqueDcrPublication ToPublic(PublicationStateRecord item) => new(
        item.Generation,
        item.ObjectCiphertextHash.ToArray(),
        item.Ciphertext.ToArray(),
        item.UsageLimit,
        item.EffectiveExpiresAtUnixSeconds);

    private static ContactResolverDcrResolveResult ResolveResult(
        ContactResolverResolveDisposition disposition,
        PublicationStateRecord? item = null,
        ulong claimCommitGeneration = 0) => new(
            disposition,
            item is null ? null : ToPublic(item),
            claimCommitGeneration,
            item?.RedemptionRouteClosure.ToArray() ?? [],
            item?.RedemptionResponseUnixSeconds ?? 0);

    private static bool Matches(PublicationStateRecord item, OpaqueDcrPublishRequest request) =>
        item.Generation == request.Generation
        && item.UsageLimit == request.UsageLimit
        && item.EffectiveExpiresAtUnixSeconds == request.EffectiveExpiresAtUnixSeconds
        && OpaqueValue.FixedEquals(item.RequestHash, request.RequestHash)
        && OpaqueValue.FixedEquals(item.PredecessorObjectHash, request.PredecessorObjectHash)
        && OpaqueValue.FixedEquals(item.ObjectCiphertextHash, request.ObjectCiphertextHash)
        && item.Ciphertext.AsSpan().SequenceEqual(request.Ciphertext);

    private static bool Matches(XurEventState item, OpaqueXurWriteRequest request) =>
        item.Generation == request.EventGeneration
        && item.EffectiveExpiresAtUnixSeconds == request.EffectiveExpiresAtUnixSeconds
        && OpaqueValue.FixedEquals(item.RequestHash, request.RequestHash)
        && OpaqueValue.FixedEquals(item.ExactXur1Hash, request.ExactXur1Hash)
        && OpaqueValue.FixedEquals(item.PredecessorEventHash, request.PredecessorEventHash)
        && OpaqueValue.FixedEquals(item.EventHash, request.EventHash)
        && OpaqueValue.FixedEquals(item.EventCiphertextHash, request.EventCiphertextHash)
        && item.Ciphertext.AsSpan().SequenceEqual(request.Ciphertext);

    private static ContactResolverMutationResult Mutation(
        ContactResolverMutationDisposition disposition,
        ulong generation,
        ReadOnlySpan<byte> hash) =>
        new(disposition, generation, hash.ToArray());

    private static ContactResolverXurReadResult XurRead(
        ContactResolverReadDisposition disposition,
        IReadOnlyList<OpaqueXurEvent> events,
        ulong generation,
        ReadOnlySpan<byte> hash) =>
        new(disposition, events, generation, hash.ToArray());

    private static void Validate32(byte[]? value)
    {
        if (value is null || value.Length != 32 || OpaqueValue.IsZero(value))
        {
            throw new InvalidDataException("Opaque resolver state contains an invalid 32-byte value.");
        }
    }

    private static void ValidateGenerationPredecessor(ulong generation, byte[]? predecessor)
    {
        if (predecessor is null
            || predecessor.Length != 32
            || OpaqueValue.IsZero(predecessor) != (generation == 0))
        {
            throw new InvalidDataException("Opaque resolver generation predecessor is invalid.");
        }
    }

    private static void ValidateXurPredecessor(ulong generation, byte[]? predecessor)
    {
        if (predecessor is null
            || predecessor.Length != 32
            || OpaqueValue.IsZero(predecessor) != (generation == 1))
        {
            throw new InvalidDataException("Opaque XUR event predecessor is invalid.");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (faulted)
        {
            throw new InvalidOperationException(
                "The opaque contact resolver store is faulted after a durability failure.");
        }
    }

    private sealed class PersistedState
    {
        public int Version { get; set; } = StateVersion;
        public List<PublicationState> Publications { get; set; } = [];
        public List<XurStreamState> XurStreams { get; set; } = [];
    }

    private sealed class PublicationState
    {
        public byte[] LocatorHash { get; set; } = [];
        public bool ForkLatched { get; set; }
        public List<PublicationStateRecord> Records { get; set; } = [];
    }

    private sealed class PublicationStateRecord
    {
        public byte[] OperationId { get; set; } = [];
        public byte[] RequestHash { get; set; } = [];
        public ulong Generation { get; set; }
        public byte[] PredecessorObjectHash { get; set; } = [];
        public byte[] ObjectCiphertextHash { get; set; } = [];
        public byte[] Ciphertext { get; set; } = [];
        public uint UsageLimit { get; set; }
        public ulong AcceptedAtUnixSeconds { get; set; }
        public ulong EffectiveExpiresAtUnixSeconds { get; set; }
        public byte[] RedemptionOperationId { get; set; } = [];
        public byte[] RedemptionRequestHash { get; set; } = [];
        public ulong ClaimCommitGeneration { get; set; }
        public byte[] RedemptionRouteClosure { get; set; } = [];
        public ulong RedemptionResponseUnixSeconds { get; set; }
    }

    private sealed class XurStreamState
    {
        public byte[] ServiceCapability { get; set; } = [];
        public byte[] ExactXur1Hash { get; set; } = [];
        public bool ForkLatched { get; set; }
        public bool HasCompactionAnchor { get; set; }
        public ulong CompactedThroughGeneration { get; set; }
        public byte[] CompactedThroughEventHash { get; set; } = [];
        public List<XurEventState> Events { get; set; } = [];
    }

    private sealed class XurEventState
    {
        public byte[] OperationId { get; set; } = [];
        public byte[] RequestHash { get; set; } = [];
        public byte[] ExactXur1Hash { get; set; } = [];
        public ulong Generation { get; set; }
        public byte[] PredecessorEventHash { get; set; } = [];
        public byte[] EventHash { get; set; } = [];
        public byte[] EventCiphertextHash { get; set; } = [];
        public byte[] Ciphertext { get; set; } = [];
        public ulong AcceptedAtUnixSeconds { get; set; }
        public ulong EffectiveExpiresAtUnixSeconds { get; set; }
    }
}

internal static class OpaqueValue
{
    internal static byte[] CopyNonZero32(ReadOnlySpan<byte> value, string parameter)
    {
        if (value.Length != 32 || IsZero(value))
        {
            throw new ArgumentException("A nonzero opaque 32-byte value is required.", parameter);
        }
        return value.ToArray();
    }

    internal static byte[] CopyGenerationPredecessor(
        ulong generation,
        ReadOnlySpan<byte> value,
        string parameter)
    {
        if (value.Length != 32 || IsZero(value) != (generation == 0))
        {
            throw new ArgumentException("The opaque predecessor must be zero exactly at generation zero.", parameter);
        }
        return value.ToArray();
    }

    internal static byte[] CopyXurPredecessor(
        ulong generation,
        ReadOnlySpan<byte> value,
        string parameter)
    {
        if (generation == 0 || value.Length != 32 || IsZero(value) != (generation == 1))
        {
            throw new ArgumentException("The XUR predecessor must be zero exactly at generation one.", parameter);
        }
        return value.ToArray();
    }

    internal static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }
        return aggregate == 0;
    }
}
