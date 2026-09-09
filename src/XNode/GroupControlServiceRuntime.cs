using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.GroupV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using XNode.Core;
using XNode.Core.GroupControl;
using XNode.Core.Mailbox;

namespace XNode;

public enum GroupControlOperation : byte
{
    Write = 1,
    Fetch = 2
}

public sealed class GroupControlServiceOptions
{
    public bool RuntimeActivation { get; set; }
    public bool MapReplicaEndpoint { get; set; }
    public int ReplicaTimeoutSeconds { get; set; } = 5;
    public int ReplayCapacity { get; set; } = 100_000;
    public int ReplayTtlSeconds { get; set; } = 300;
    public int OutcomeUnknownRetrySeconds { get; set; } = 5;

    internal TimeSpan ReplicaTimeout => TimeSpan.FromSeconds(ReplicaTimeoutSeconds);
    internal TimeSpan ReplayTtl => TimeSpan.FromSeconds(ReplayTtlSeconds);

    public void Validate()
    {
        if (ReplicaTimeoutSeconds is < 1 or > 30
            || ReplayCapacity is < 1_000 or > 10_000_000
            || ReplayTtlSeconds is < 120 or > 3_600
            || OutcomeUnknownRetrySeconds is < 1 or > 3_600)
        {
            throw new InvalidOperationException(
                "GroupControlService transport resource bounds are invalid.");
        }
        if (MapReplicaEndpoint && !RuntimeActivation)
        {
            throw new InvalidOperationException(
                "GroupControlService replica endpoint mapping requires an active runtime.");
        }
    }
}

public sealed record GroupControlTerminalDispatchResult(
    ReadOnlyMemory<byte> CanonicalGss1,
    ushort ResponsePaddingClass);

public interface IGroupControlTerminalDispatcher
{
    ValueTask<GroupControlTerminalDispatchResult> DispatchAsync(
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken);
}

internal sealed class GroupControlAuthorityUnavailableException : IOException
{
    internal GroupControlAuthorityUnavailableException()
        : base("Current group-control placement and route authority is unavailable.")
    {
    }
}

internal sealed class VerifiedGroupControlRequestAuthority
{
    private readonly byte[] networkId;
    private readonly byte[] viewHash;
    private readonly byte[] placementHash;
    private readonly byte[] serviceCapability;
    private readonly byte[] exactGsr1Hash;
    private readonly byte[] routeClosureHash;
    private readonly byte[][] replicaIds;

    internal VerifiedGroupControlRequestAuthority(
        GroupControlOperation operation,
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> viewHash32,
        ReadOnlySpan<byte> placementHash32,
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactGsr1Hash32,
        ReadOnlySpan<byte> verifiedRouteClosureHash32,
        ulong validUntilUnixSeconds,
        IReadOnlyList<ReadOnlyMemory<byte>> exactReplicaIds)
    {
        if (!Enum.IsDefined(operation)
            || networkId16.Length != 16
            || GroupControlOpaqueValue.IsZero(networkId16))
        {
            throw new ArgumentException("The verified group-control operation or network is invalid.");
        }

        Operation = operation;
        networkId = networkId16.ToArray();
        viewHash = GroupControlOpaqueValue.CopyNonZero32(viewHash32, nameof(viewHash32));
        placementHash = GroupControlOpaqueValue.CopyNonZero32(
            placementHash32,
            nameof(placementHash32));
        serviceCapability = GroupControlOpaqueValue.CopyNonZero32(
            serviceCapability32,
            nameof(serviceCapability32));
        exactGsr1Hash = GroupControlOpaqueValue.CopyNonZero32(
            exactGsr1Hash32,
            nameof(exactGsr1Hash32));
        routeClosureHash = GroupControlOpaqueValue.CopyNonZero32(
            verifiedRouteClosureHash32,
            nameof(verifiedRouteClosureHash32));
        ArgumentNullException.ThrowIfNull(exactReplicaIds);
        if (exactReplicaIds.Count != 2)
        {
            throw new ArgumentException(
                "Group-control placement must contain exactly two replicas.",
                nameof(exactReplicaIds));
        }
        replicaIds = exactReplicaIds
            .Select((value, index) => GroupControlOpaqueValue.CopyNonZero32(
                value.Span,
                $"{nameof(exactReplicaIds)}[{index}]"))
            .ToArray();
        if (GroupControlOpaqueValue.FixedEquals(replicaIds[0], replicaIds[1]))
        {
            throw new ArgumentException(
                "Group-control replica identities must be distinct.",
                nameof(exactReplicaIds));
        }
        if (validUntilUnixSeconds == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(validUntilUnixSeconds));
        }
        ValidUntilUnixSeconds = validUntilUnixSeconds;
    }

    internal GroupControlOperation Operation { get; }
    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ReadOnlyMemory<byte> ViewHash => viewHash.ToArray();
    internal ReadOnlyMemory<byte> PlacementHash => placementHash.ToArray();
    internal ReadOnlyMemory<byte> ServiceCapability => serviceCapability.ToArray();
    internal ReadOnlyMemory<byte> ExactGsr1Hash => exactGsr1Hash.ToArray();
    internal ReadOnlyMemory<byte> RouteClosureHash => routeClosureHash.ToArray();
    internal ulong ValidUntilUnixSeconds { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> ReplicaIds =>
        Array.AsReadOnly(replicaIds
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
            .ToArray());

    internal void EnsureBinds(GroupControlRequestProjection request, ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (ValidUntilUnixSeconds <= nowUnixSeconds
            || request.Operation != Operation
            || !Fixed(networkId, request.NetworkId.Span)
            || !Fixed(viewHash, request.ViewHash.Span)
            || !Fixed(placementHash, request.PlacementHash.Span)
            || !Fixed(serviceCapability, request.ServiceCapability.Span)
            || !Fixed(exactGsr1Hash, request.ExactGsr1Hash.Span))
        {
            throw new GroupControlAuthorityUnavailableException();
        }
    }

    internal bool ContainsReplica(ReadOnlySpan<byte> replicaId)
    {
        foreach (var value in replicaIds)
        {
            if (Fixed(value, replicaId))
            {
                return true;
            }
        }
        return false;
    }

    internal byte[] OtherReplica(ReadOnlySpan<byte> localReplicaId)
    {
        if (!ContainsReplica(localReplicaId))
        {
            throw new GroupControlAuthorityUnavailableException();
        }
        foreach (var value in replicaIds)
        {
            if (!Fixed(value, localReplicaId))
            {
                return value.ToArray();
            }
        }
        throw new GroupControlAuthorityUnavailableException();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}

internal interface IGroupControlAuthoritySource
{
    ValueTask<VerifiedGroupControlRequestAuthority> AuthorizeAsync(
        GroupControlOperation operation,
        GroupRecord exactRequest,
        CancellationToken cancellationToken);
}

internal interface IGroupControlReplicaBindingSource
{
    ValueTask<IReadOnlyList<GroupControlReplicaBinding>> ResolveAsync(
        VerifiedGroupControlRequestAuthority authority,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken);
}

internal sealed class GroupControlRequestProjection
{
    private GroupControlRequestProjection(
        GroupControlOperation operation,
        GroupRecord record,
        ReadOnlyMemory<byte> canonical,
        byte[] requestHash)
    {
        Operation = operation;
        Record = record;
        Canonical = canonical.ToArray();
        RequestHash = requestHash;
    }

    internal GroupControlOperation Operation { get; }
    internal GroupRecord Record { get; }
    internal ReadOnlyMemory<byte> Canonical { get; }
    internal ReadOnlyMemory<byte> NetworkId => Record.Field(1);
    internal ReadOnlyMemory<byte> OperationId => Record.Field(2);
    internal ReadOnlyMemory<byte> ViewHash => Record.Field(3);
    internal ReadOnlyMemory<byte> PlacementHash => Record.Field(4);
    internal ulong IssuedAtUnixSeconds => U64(Record.Field(5).Span);
    internal ulong ExpiresAtUnixSeconds => U64(Record.Field(6).Span);
    internal ReadOnlyMemory<byte> ServiceCapability => Record.Field(16);
    internal ReadOnlyMemory<byte> ExactGsr1Hash => Record.Field(17);
    internal ReadOnlyMemory<byte> RequestHash { get; }
    internal ushort RequestedPaddingClass => Operation == GroupControlOperation.Fetch
        ? U16(Record.Field(20).Span)
        : (ushort)0;

    internal OpaqueGroupControlWriteRequest ToWrite()
    {
        if (Record is not GroupControlWriteRecord)
        {
            throw new InvalidOperationException("The group-control request is not GSW1.");
        }
        return new OpaqueGroupControlWriteRequest(
            ServiceCapability.Span,
            ExactGsr1Hash.Span,
            OperationId.Span,
            RequestHash.Span,
            U64(Record.Field(18).Span),
            Record.Field(19).Span,
            Record.Field(20).Span,
            DecodeLp32(Record.Field(21).Span),
            U64(Record.Field(22).Span));
    }

    internal OpaqueGroupControlFetchRequest ToFetch()
    {
        if (Record is not GroupControlQueryRecord)
        {
            throw new InvalidOperationException("The group-control request is not GSQ1.");
        }
        return new OpaqueGroupControlFetchRequest(
            ServiceCapability.Span,
            ExactGsr1Hash.Span,
            OperationId.Span,
            RequestHash.Span,
            U64(Record.Field(18).Span),
            U16(Record.Field(19).Span));
    }

    internal static GroupControlRequestProjection Decode(ReadOnlyMemory<byte> exact)
    {
        if (exact.Length is < 304 or > 33_160)
        {
            throw new GroupFormatException(
                GroupValidationStage.Length,
                "RecordLengthOutOfRange");
        }
        var record = GroupCodec.Decode(exact.Span);
        var operation = record switch
        {
            GroupControlWriteRecord => GroupControlOperation.Write,
            GroupControlQueryRecord => GroupControlOperation.Fetch,
            _ => throw new GroupFormatException(
                GroupValidationStage.Header,
                "WrongRecordType")
        };
        if (!record.CanonicalBytes.Span.SequenceEqual(exact.Span))
        {
            throw new GroupFormatException(
                GroupValidationStage.Bounds,
                "TrailingBytes");
        }
        return new GroupControlRequestProjection(
            operation,
            record,
            exact,
            HashDomain("Deep/ContactResolver/V1/request", exact.Span));
    }

    internal static byte[] HashDomain(string domain, ReadOnlySpan<byte> value)
    {
        var label = Encoding.ASCII.GetBytes(domain);
        var input = new byte[checked(label.Length + 5 + value.Length)];
        label.CopyTo(input, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            input.AsSpan(label.Length + 1),
            checked((uint)value.Length));
        value.CopyTo(input.AsSpan(label.Length + 5));
        return SHA256.HashData(input);
    }

    private static byte[] DecodeLp32(ReadOnlySpan<byte> value)
    {
        if (value.Length < 4)
        {
            throw new InvalidDataException("The sealed GCF1 field is truncated.");
        }
        var length = BinaryPrimitives.ReadUInt32BigEndian(value);
        if (length > int.MaxValue || value.Length != 4 + (int)length)
        {
            throw new InvalidDataException("The sealed GCF1 field length is non-canonical.");
        }
        return value[4..].ToArray();
    }

    internal static ushort U16(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt16BigEndian(value);

    internal static ulong U64(ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);
}

internal sealed class ProductionGroupControlTerminalDispatcher : IGroupControlTerminalDispatcher
{
    private static readonly int[] PaddingBytes = [256, 1_024, 4_096, 16_384, 65_536];
    private readonly IGroupControlAuthoritySource authoritySource;
    private readonly IGroupControlReplicaBindingSource replicaSource;
    private readonly IClock clock;
    private readonly GroupControlServiceOptions options;

    internal ProductionGroupControlTerminalDispatcher(
        IGroupControlAuthoritySource authoritySource,
        IGroupControlReplicaBindingSource replicaSource,
        IClock clock,
        GroupControlServiceOptions options)
    {
        this.authoritySource = authoritySource ?? throw new ArgumentNullException(nameof(authoritySource));
        this.replicaSource = replicaSource ?? throw new ArgumentNullException(nameof(replicaSource));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public async ValueTask<GroupControlTerminalDispatchResult> DispatchAsync(
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken)
    {
        var request = GroupControlRequestProjection.Decode(exactCanonicalRequest);
        var now = CurrentUnixSeconds();
        if (request.ExpiresAtUnixSeconds <= now)
        {
            return GroupControlGss1Author.Author(
                request,
                GroupControlApplicationStatus.Expired,
                GroupControlMutationOutcome.None,
                now,
                0,
                request.Operation == GroupControlOperation.Fetch
                    ? request.RequestedPaddingClass
                    : null);
        }

        var authority = await authoritySource.AuthorizeAsync(
            request.Operation,
            request.Record,
            cancellationToken).ConfigureAwait(false);
        authority.EnsureBinds(request, now);
        if (request.IssuedAtUnixSeconds > now)
        {
            throw new GroupControlAuthorityUnavailableException();
        }

        var bindings = await replicaSource.ResolveAsync(
            authority,
            exactCanonicalRequest,
            cancellationToken).ConfigureAwait(false);
        ValidateBindings(authority, bindings);
        using var coordinator = new GroupControlTwoReplicaCoordinator(
            bindings[0].Replica,
            bindings[1].Replica,
            new GroupControlReplicaCoordinatorOptions
            {
                ReplicaTimeout = options.ReplicaTimeout
            });
        var service = new GroupControlApplicationService(coordinator);

        if (request.Operation == GroupControlOperation.Write)
        {
            var result = await service.WriteAsync(
                request.ToWrite(),
                cancellationToken).ConfigureAwait(false);
            return await AuthorWriteAsync(
                request,
                authority,
                bindings,
                result,
                now,
                cancellationToken).ConfigureAwait(false);
        }

        var fetched = await service.FetchAsync(
            request.ToFetch(),
            cancellationToken).ConfigureAwait(false);
        return AuthorFetch(request, fetched, now);
    }

    private async ValueTask<GroupControlTerminalDispatchResult> AuthorWriteAsync(
        GroupControlRequestProjection request,
        VerifiedGroupControlRequestAuthority authority,
        IReadOnlyList<GroupControlReplicaBinding> bindings,
        GroupControlApplicationResult result,
        ulong now,
        CancellationToken cancellationToken)
    {
        if (result.MutationOutcome == GroupControlMutationOutcome.DurablyCommitted)
        {
            try
            {
                var commitGeneration = result.CurrentSequence;
                var receiptRequest = new GroupControlReplicaReceiptRequest(
                    request.RequestHash.Span,
                    result.CurrentSequence,
                    result.CurrentHash,
                    commitGeneration);
                var tasks = bindings.Select(binding => binding.ReceiptAuthority
                    .IssueAsync(receiptRequest, cancellationToken).AsTask()).ToArray();
                await Task.WhenAll(tasks).ConfigureAwait(false);
                var receipts = tasks.Select(static task => task.Result)
                    .OrderBy(static value => value.ReplicaId, ReadOnlyMemoryComparer.Instance)
                    .ToArray();
                var exactRows = new byte[receipts.Length * 96];
                for (var index = 0; index < receipts.Length; index++)
                {
                    var receipt = receipts[index];
                    if (!authority.ContainsReplica(receipt.ReplicaId.Span)
                        || !GroupControlReceiptTranscript.Verify(
                            receipt.ReplicaId.Span,
                            receiptRequest,
                            receipt.Signature.Span))
                    {
                        throw new InvalidDataException(
                            "A group-control receipt is outside the verified replica set or invalid.");
                    }
                    receipt.ReplicaId.Span.CopyTo(exactRows.AsSpan(index * 96));
                    receipt.Signature.Span.CopyTo(exactRows.AsSpan(index * 96 + 32));
                }

                return GroupControlGss1Author.Author(
                    request,
                    result.Status,
                    result.MutationOutcome,
                    now,
                    0,
                    null,
                    GroupControlGss1Payload.WriteCommitted(
                        result.CurrentSequence,
                        result.CurrentHash,
                        commitGeneration,
                        exactRows));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception) when (exception is IOException
                or InvalidDataException
                or InvalidOperationException
                or UnauthorizedAccessException)
            {
                return GroupControlGss1Author.Author(
                    request,
                    GroupControlApplicationStatus.OutcomeUnknown,
                    GroupControlMutationOutcome.OutcomeUnknown,
                    now,
                    checked((uint)options.OutcomeUnknownRetrySeconds),
                    null);
            }
        }

        var payload = result.Status switch
        {
            GroupControlApplicationStatus.StaleSequence =>
                GroupControlGss1Payload.Stale(
                    result.CurrentSequence,
                    NonZeroEvidence(result.CurrentHash, request.RequestHash.Span, "stale")),
            GroupControlApplicationStatus.Conflict =>
                GroupControlGss1Payload.Conflict(Evidence(request.RequestHash.Span, "conflict")),
            _ => GroupControlGss1Payload.Empty
        };
        var retry = result.Status is GroupControlApplicationStatus.RateLimited
            or GroupControlApplicationStatus.OutcomeUnknown
                ? checked((uint)options.OutcomeUnknownRetrySeconds)
                : 0;
        return GroupControlGss1Author.Author(
            request,
            result.Status,
            result.MutationOutcome,
            now,
            retry,
            null,
            payload);
    }

    private static GroupControlTerminalDispatchResult AuthorFetch(
        GroupControlRequestProjection request,
        GroupControlApplicationResult result,
        ulong now)
    {
        if (result.Status == GroupControlApplicationStatus.TemporarilyUnavailable)
        {
            throw new GroupControlAuthorityUnavailableException();
        }

        if (result.Status == GroupControlApplicationStatus.Events)
        {
            var records = result.Records.ToArray();
            for (var count = records.Length; count > 0; count--)
            {
                var eventPayload = GroupControlGss1Payload.Events(
                    records.Take(count).ToArray(),
                    result.HasMore || count != records.Length);
                var candidate = GroupControlGss1Author.Author(
                    request,
                    GroupControlApplicationStatus.Events,
                    GroupControlMutationOutcome.None,
                    now,
                    0,
                    request.RequestedPaddingClass,
                    eventPayload,
                    requireFit: false);
                if (candidate.CanonicalGss1.Length <= PaddingBytes[request.RequestedPaddingClass])
                {
                    return candidate;
                }
            }

            var firstBytes = GroupControlGss1Payload.EncodedRecordLength(records[0]);
            var requiredClass = RequiredClass(request, records[0], now);
            return GroupControlGss1Author.Author(
                request,
                GroupControlApplicationStatus.RecordTooLarge,
                GroupControlMutationOutcome.None,
                now,
                0,
                request.RequestedPaddingClass,
                GroupControlGss1Payload.RecordTooLarge(requiredClass, firstBytes));
        }

        var status = result.Status switch
        {
            GroupControlApplicationStatus.NotFound or GroupControlApplicationStatus.Gap =>
                GroupControlApplicationStatus.Gap,
            GroupControlApplicationStatus.StaleSequence =>
                GroupControlApplicationStatus.Gap,
            _ => result.Status
        };
        var payload = status switch
        {
            GroupControlApplicationStatus.Gap => GroupControlGss1Payload.Stale(
                result.CurrentSequence,
                NonZeroEvidence(result.CurrentHash, request.RequestHash.Span, "gap")),
            GroupControlApplicationStatus.Conflict =>
                GroupControlGss1Payload.Conflict(Evidence(request.RequestHash.Span, "conflict")),
            _ => GroupControlGss1Payload.Empty
        };
        return GroupControlGss1Author.Author(
            request,
            status,
            GroupControlMutationOutcome.None,
            now,
            0,
            request.RequestedPaddingClass,
            payload);
    }

    private static ushort RequiredClass(
        GroupControlRequestProjection request,
        OpaqueGroupControlRecord record,
        ulong now)
    {
        for (ushort padding = 0; padding < PaddingBytes.Length; padding++)
        {
            var candidate = GroupControlGss1Author.Author(
                request,
                GroupControlApplicationStatus.Events,
                GroupControlMutationOutcome.None,
                now,
                0,
                padding,
                GroupControlGss1Payload.Events([record], false),
                requireFit: false);
            if (candidate.CanonicalGss1.Length <= PaddingBytes[padding])
            {
                return padding;
            }
        }
        throw new GroupControlStoreCorruptException();
    }

    private static void ValidateBindings(
        VerifiedGroupControlRequestAuthority authority,
        IReadOnlyList<GroupControlReplicaBinding> bindings)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        if (bindings.Count != 2)
        {
            throw new GroupControlAuthorityUnavailableException();
        }
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var binding in bindings)
        {
            binding.Validate();
            var id = binding.Replica.ReplicaId.Span;
            if (!authority.ContainsReplica(id)
                || !seen.Add(Convert.ToHexString(id)))
            {
                throw new GroupControlAuthorityUnavailableException();
            }
        }
    }

    private ulong CurrentUnixSeconds()
    {
        var value = clock.UtcNow.ToUnixTimeSeconds();
        if (value < 0)
        {
            throw new InvalidOperationException("Group-control service time is before Unix epoch.");
        }
        return checked((ulong)value);
    }

    private static byte[] Evidence(ReadOnlySpan<byte> requestHash, string kind) =>
        GroupControlRequestProjection.HashDomain($"Deep/Group/V1/{kind}-evidence", requestHash);

    private static byte[] NonZeroEvidence(
        ReadOnlySpan<byte> candidate,
        ReadOnlySpan<byte> requestHash,
        string kind) => candidate.Length == 32 && !GroupControlOpaqueValue.IsZero(candidate)
            ? candidate.ToArray()
            : Evidence(requestHash, kind);

    private sealed class ReadOnlyMemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly ReadOnlyMemoryComparer Instance = new();
        public int Compare(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) =>
            left.Span.SequenceCompareTo(right.Span);
    }
}

internal sealed record GroupControlGss1Payload(
    byte[] First,
    byte[] Second,
    byte[] Third,
    byte[] Fourth)
{
    internal static readonly GroupControlGss1Payload Empty = new([], [], [], []);

    internal static GroupControlGss1Payload WriteCommitted(
        ulong sequence,
        ReadOnlySpan<byte> hash32,
        ulong commitGeneration,
        ReadOnlySpan<byte> receipts) =>
        new(Be(sequence), hash32.ToArray(), Be(commitGeneration), receipts.ToArray());

    internal static GroupControlGss1Payload Stale(ulong sequence, ReadOnlySpan<byte> hash32) =>
        new(Be(sequence), hash32.ToArray(), [], []);

    internal static GroupControlGss1Payload Conflict(ReadOnlySpan<byte> evidenceHash32) =>
        new(evidenceHash32.ToArray(), [], [], []);

    internal static GroupControlGss1Payload Events(
        IReadOnlyList<OpaqueGroupControlRecord> records,
        bool hasMore)
    {
        if (records.Count is < 1 or > GroupControlOpaqueStoreOptions.MaximumFetchRecords)
        {
            throw new ArgumentOutOfRangeException(nameof(records));
        }
        var encoded = new byte[records.Sum(EncodedRecordLength)];
        var offset = 0;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(offset), record.ControlSequence);
            offset += 8;
            record.PredecessorControlHash.CopyTo(encoded, offset);
            offset += 32;
            record.SealedGcf1Hash.CopyTo(encoded, offset);
            offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(
                encoded.AsSpan(offset),
                record.EffectiveExpiresAtUnixSeconds);
            offset += 8;
            BinaryPrimitives.WriteUInt32BigEndian(
                encoded.AsSpan(offset),
                checked((uint)record.SealedGcf1.Length));
            offset += 4;
            record.SealedGcf1.CopyTo(encoded, offset);
            offset += record.SealedGcf1.Length;
        }
        return new(Be(checked((ushort)records.Count)), encoded,
            Be(records[^1].ControlSequence), [hasMore ? (byte)1 : (byte)0]);
    }

    internal static GroupControlGss1Payload RecordTooLarge(
        ushort requiredPaddingClass,
        int nextRecordBytes) =>
        new(Be(requiredPaddingClass), Be(checked((uint)nextRecordBytes)), [], []);

    internal static int EncodedRecordLength(OpaqueGroupControlRecord record) =>
        checked(84 + record.SealedGcf1.Length);

    private static byte[] Be(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] Be(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    private static byte[] Be(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }
}

internal static class GroupControlGss1Author
{
    private static readonly ushort[] Tags = [1, 2, 3, 4, 5, 6, 7, 8, 16, 17, 18, 19, 20];
    private static readonly int[] PaddingBytes = [256, 1_024, 4_096, 16_384, 65_536];

    internal static GroupControlTerminalDispatchResult Author(
        GroupControlRequestProjection request,
        GroupControlApplicationStatus status,
        GroupControlMutationOutcome outcome,
        ulong serverTime,
        uint retryAfterSeconds,
        ushort? requestedPaddingClass,
        GroupControlGss1Payload? payload = null,
        bool requireFit = true)
    {
        ArgumentNullException.ThrowIfNull(request);
        payload ??= GroupControlGss1Payload.Empty;
        var statusId = StatusId(status);
        var operation = checked((byte)request.Operation);
        var fields = new byte[][]
        {
            request.NetworkId.ToArray(), request.OperationId.ToArray(), request.RequestHash.ToArray(),
            Be(statusId), [(byte)OutcomeId(outcome)], Be(serverTime), Be(retryAfterSeconds), [],
            [operation], payload.First, payload.Second, payload.Third, payload.Fourth
        };

        if (requestedPaddingClass is ushort fixedPadding)
        {
            ValidatePadding(fixedPadding);
            fields[7] = Be(fixedPadding);
            return ValidateAndReturn(request, fields, fixedPadding, requireFit);
        }

        for (ushort padding = 0; padding < PaddingBytes.Length; padding++)
        {
            fields[7] = Be(padding);
            var candidate = Encode(fields);
            if (candidate.Length <= PaddingBytes[padding])
            {
                return ValidateAndReturn(request, fields, padding, true);
            }
        }
        throw new InvalidDataException("The canonical GSS1 result exceeds every V1 padding class.");
    }

    private static GroupControlTerminalDispatchResult ValidateAndReturn(
        GroupControlRequestProjection request,
        byte[][] fields,
        ushort padding,
        bool requireFit)
    {
        var canonical = Encode(fields);
        if (requireFit && canonical.Length > PaddingBytes[padding])
        {
            throw new InvalidDataException("The canonical GSS1 result does not fit its padding class.");
        }
        var decoded = GroupCodec.Decode(canonical);
        if (decoded is not GroupControlResultRecord
            || !decoded.CanonicalBytes.Span.SequenceEqual(canonical)
            || !decoded.Field(1).Span.SequenceEqual(request.NetworkId.Span)
            || !decoded.Field(2).Span.SequenceEqual(request.OperationId.Span)
            || !decoded.Field(3).Span.SequenceEqual(request.RequestHash.Span))
        {
            throw new InvalidDataException("Deep.Protocol rejected or rebound the canonical GSS1 result.");
        }
        return new GroupControlTerminalDispatchResult(canonical, padding);
    }

    private static byte[] Encode(IReadOnlyList<byte[]> fields)
    {
        var total = checked(12 + fields.Sum(static field => 8 + field.Length));
        var output = new byte[total];
        Encoding.ASCII.GetBytes("GSS1").CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), Tags[index]);
            BinaryPrimitives.WriteUInt32BigEndian(
                output.AsSpan(offset + 4),
                checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private static ushort StatusId(GroupControlApplicationStatus status) => status switch
    {
        GroupControlApplicationStatus.Committed => 1,
        GroupControlApplicationStatus.ExactReplay => 2,
        GroupControlApplicationStatus.Events => 3,
        GroupControlApplicationStatus.NoChange => 4,
        GroupControlApplicationStatus.NotFound or GroupControlApplicationStatus.Expired => 5,
        GroupControlApplicationStatus.RateLimited => 6,
        GroupControlApplicationStatus.Gap or GroupControlApplicationStatus.StaleSequence => 7,
        GroupControlApplicationStatus.Conflict => 8,
        GroupControlApplicationStatus.OutcomeUnknown => 9,
        GroupControlApplicationStatus.SizeFailure => 10,
        GroupControlApplicationStatus.RecordTooLarge => 11,
        _ => throw new GroupControlAuthorityUnavailableException()
    };

    private static byte OutcomeId(GroupControlMutationOutcome outcome) => outcome switch
    {
        GroupControlMutationOutcome.None => 0,
        GroupControlMutationOutcome.DurablyCommitted => 1,
        GroupControlMutationOutcome.OutcomeUnknown => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(outcome))
    };

    private static void ValidatePadding(ushort value)
    {
        if (value >= PaddingBytes.Length)
        {
            throw new InvalidDataException("The GSS1 response padding class is invalid.");
        }
    }

    private static byte[] Be(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] Be(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    private static byte[] Be(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }
}

internal sealed class GroupControlLocalReplicaRuntime : IDisposable
{
    private readonly GroupControlOpaqueStore store;
    private readonly LocalGroupControlReplicaReceiptAuthority receiptAuthority;
    private bool disposed;

    internal GroupControlLocalReplicaRuntime(
        RouterNodeOptions node,
        IClock clock,
        IMailboxStorageSecurity storageSecurity,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentNullException.ThrowIfNull(node);
        var root = Path.Combine(Path.GetFullPath(node.DataDirectory), "group-control-v1");
        Directory.CreateDirectory(root);
        var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
        try
        {
            receiptAuthority = new LocalGroupControlReplicaReceiptAuthority(seed);
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
                "The local group-control receipt key must be the local node identity.");
        }

        store = new GroupControlOpaqueStore(
            Path.Combine(root, "control.state"),
            clock: clock,
            storageSecurity: storageSecurity,
            durability: durability);
        Binding = new GroupControlReplicaBinding(
            new GroupControlStoreReplica(receiptAuthority.ReplicaId.Span, store),
            receiptAuthority);
        Binding.Validate();
    }

    internal GroupControlReplicaBinding Binding { get; }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }
        disposed = true;
        store.Dispose();
        receiptAuthority.Dispose();
    }
}

internal sealed class FixedGroupControlReplicaBindingSource : IGroupControlReplicaBindingSource
{
    private readonly GroupControlReplicaBinding[] bindings;

    internal FixedGroupControlReplicaBindingSource(params GroupControlReplicaBinding[] bindings)
    {
        this.bindings = bindings?.ToArray() ?? throw new ArgumentNullException(nameof(bindings));
        if (this.bindings.Length != 2)
        {
            throw new ArgumentException("Exactly two UAT group-control replicas are required.");
        }
        foreach (var binding in this.bindings)
        {
            binding.Validate();
        }
    }

    public ValueTask<IReadOnlyList<GroupControlReplicaBinding>> ResolveAsync(
        VerifiedGroupControlRequestAuthority authority,
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken)
    {
        _ = authority ?? throw new ArgumentNullException(nameof(authority));
        _ = exactCanonicalRequest;
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult<IReadOnlyList<GroupControlReplicaBinding>>(bindings.ToArray());
    }
}

internal sealed class GroupControlServiceHostCompositionPlan
{
    internal GroupControlServiceHostCompositionPlan(bool active, bool mapReplicaEndpoint)
    {
        RuntimeActivation = active;
        MapReplicaEndpoint = mapReplicaEndpoint;
    }

    internal bool RuntimeActivation { get; }
    internal bool MapReplicaEndpoint { get; }
}

internal static class GroupControlServiceHostComposition
{
    internal static GroupControlServiceHostCompositionPlan AddGroupControlServiceBoundary(
        this IServiceCollection services,
        GroupControlServiceOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        // Configuration alone is deliberately insufficient to activate this service.
        // A verified authority source and an exact replica composition must be supplied
        // through one of the explicit methods below.
        var plan = new GroupControlServiceHostCompositionPlan(false, false);
        services.TryAddSingleton(options);
        services.TryAddSingleton(plan);
        services.TryAddSingleton<IGroupControlTerminalDispatcher,
            UnavailableGroupControlTerminalDispatcher>();
        services.TryAddSingleton<GroupControlOnionTerminalAdapter>();
        return plan;
    }

    internal static GroupControlServiceHostCompositionPlan AddProductionGroupControlServiceBoundary(
        this IServiceCollection services,
        GroupControlServiceOptions options,
        IGroupControlAuthoritySource authoritySource)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authoritySource);
        options.Validate();
        if (!options.RuntimeActivation || !options.MapReplicaEndpoint)
        {
            throw new InvalidOperationException(
                "Production group-control composition requires active runtime and replica endpoint flags.");
        }

        var plan = new GroupControlServiceHostCompositionPlan(true, true);
        services.AddSingleton(options);
        services.AddSingleton(plan);
        services.AddSingleton(authoritySource);
        services.AddSingleton(provider => new GroupControlLocalReplicaRuntime(
            provider.GetRequiredService<RouterNodeOptions>(),
            provider.GetRequiredService<IClock>(),
            provider.GetRequiredService<IMailboxStorageSecurity>(),
            provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton<IGroupControlReplicaPeerClient, HttpGroupControlReplicaPeerClient>();
        services.AddSingleton<IGroupControlReplicaBindingSource>(provider =>
            new ProductionGroupControlReplicaBindingSource(
                provider.GetRequiredService<GroupControlLocalReplicaRuntime>(),
                provider.GetRequiredService<IGroupControlReplicaPeerClient>()));
        AddActiveBoundaryServices(services);
        return plan;
    }

    internal static GroupControlServiceHostCompositionPlan AddProductionGroupControlAuthorityBoundary(
        this IServiceCollection services,
        RouterNodeOptions node,
        GroupControlServiceOptions options,
        ProductionGroupControlAuthorityConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(configuration);
        RequireRegistered<IContactVerifiedAuthoritySnapshotSource>(services);
        RequireRegistered<IOnionMonotonicClock>(services);
        RequireRegistered<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(services);

        services.AddSingleton(configuration);
        services.AddSingleton<IGroupControlAuthorityArtifactSource>(provider =>
            new FileGroupControlAuthorityArtifactSource(
                provider.GetRequiredService<ProductionGroupControlAuthorityConfiguration>(),
                provider.GetRequiredService<IMailboxStorageSecurity>()));
        services.AddSingleton<IGroupControlAuthorityLineageStore>(provider =>
            new FileGroupControlAuthorityLineageStore(
                provider.GetRequiredService<ProductionGroupControlAuthorityConfiguration>(),
                provider.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
                provider.GetRequiredService<IMailboxStorageSecurity>(),
                provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton(provider => new ProductionGroupControlAuthoritySource(
            provider.GetRequiredService<IContactVerifiedAuthoritySnapshotSource>(),
            provider.GetRequiredService<IGroupControlAuthorityArtifactSource>(),
            provider.GetRequiredService<IOnionMonotonicClock>(),
            provider.GetRequiredService<IGroupControlAuthorityLineageStore>(),
            provider.GetRequiredService<RouterNodeOptions>(),
            provider.GetRequiredService<ProductionGroupControlAuthorityConfiguration>()));
        services.AddSingleton<IGroupControlAuthoritySource>(provider =>
            provider.GetRequiredService<ProductionGroupControlAuthoritySource>());
        var plan = new GroupControlServiceHostCompositionPlan(true, true);
        services.AddSingleton(options);
        services.AddSingleton(plan);
        services.AddSingleton(provider => new GroupControlLocalReplicaRuntime(
            provider.GetRequiredService<RouterNodeOptions>(),
            provider.GetRequiredService<IClock>(),
            provider.GetRequiredService<IMailboxStorageSecurity>(),
            provider.GetRequiredService<IMailboxDurabilityBarrier>()));
        services.AddSingleton<IGroupControlReplicaPeerClient, HttpGroupControlReplicaPeerClient>();
        services.AddSingleton<IGroupControlReplicaBindingSource>(provider =>
            new ProductionGroupControlReplicaBindingSource(
                provider.GetRequiredService<GroupControlLocalReplicaRuntime>(),
                provider.GetRequiredService<IGroupControlReplicaPeerClient>()));
        AddActiveBoundaryServices(services);
        services.AddHostedService<ProductionGroupControlAuthorityHostedService>();
        return plan;
    }

    internal static GroupControlServiceHostCompositionPlan AddUatGroupControlServiceBoundary(
        this IServiceCollection services,
        GroupControlServiceOptions options,
        IGroupControlAuthoritySource authoritySource,
        IGroupControlReplicaBindingSource replicaSource)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authoritySource);
        ArgumentNullException.ThrowIfNull(replicaSource);
        options.Validate();
        if (!options.RuntimeActivation)
        {
            throw new InvalidOperationException(
                "The explicit UAT group-control composition requires runtime activation.");
        }
        if (options.MapReplicaEndpoint)
        {
            throw new InvalidOperationException(
                "The injected UAT replica pair is terminal-only; HTTP mapping requires production local-replica composition.");
        }
        var plan = new GroupControlServiceHostCompositionPlan(true, false);
        services.AddSingleton(options);
        services.AddSingleton(plan);
        services.AddSingleton(authoritySource);
        services.AddSingleton(replicaSource);
        AddActiveBoundaryServices(services, includeReplicaReceiver: false);
        return plan;
    }

    private static void AddActiveBoundaryServices(
        IServiceCollection services,
        bool includeReplicaReceiver = true)
    {
        services.AddSingleton(provider => new ProductionGroupControlTerminalDispatcher(
            provider.GetRequiredService<IGroupControlAuthoritySource>(),
            provider.GetRequiredService<IGroupControlReplicaBindingSource>(),
            provider.GetRequiredService<IClock>(),
            provider.GetRequiredService<GroupControlServiceOptions>()));
        services.AddSingleton<IGroupControlTerminalDispatcher>(provider =>
            provider.GetRequiredService<ProductionGroupControlTerminalDispatcher>());
        services.AddSingleton<GroupControlOnionTerminalAdapter>();
        if (includeReplicaReceiver)
        {
            services.AddSingleton<GroupControlReplicaReplayGuard>();
            services.AddSingleton(provider => new GroupControlReplicaRequestReceiver(
                provider.GetRequiredService<IGroupControlAuthoritySource>(),
                provider.GetRequiredService<GroupControlLocalReplicaRuntime>(),
                provider.GetRequiredService<IClock>()));
        }
    }

    private static void RequireRegistered<T>(IServiceCollection services)
    {
        if (!services.Any(static descriptor => descriptor.ServiceType == typeof(T)))
        {
            throw new InvalidOperationException(
                $"GroupControlService production activation requires a registered {typeof(T).Name}.");
        }
    }
}

public sealed class UnavailableGroupControlTerminalDispatcher : IGroupControlTerminalDispatcher
{
    public ValueTask<GroupControlTerminalDispatchResult> DispatchAsync(
        ReadOnlyMemory<byte> exactCanonicalRequest,
        CancellationToken cancellationToken)
    {
        _ = exactCanonicalRequest;
        cancellationToken.ThrowIfCancellationRequested();
        throw new GroupControlAuthorityUnavailableException();
    }
}

/// <summary>
/// Adapter for an already authenticated and decrypted ONION terminal payload.
/// It does not register a direct HTTP client path and cannot choose placement.
/// </summary>
public sealed class GroupControlOnionTerminalAdapter
{
    private readonly IGroupControlTerminalDispatcher dispatcher;

    public GroupControlOnionTerminalAdapter(IGroupControlTerminalDispatcher dispatcher) =>
        this.dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

    public async Task<NativeMailboxDispatchResult> DispatchAsync(
        ReadOnlyMemory<byte> exactCanonicalGroupControlRequest,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await dispatcher.DispatchAsync(
                exactCanonicalGroupControlRequest,
                cancellationToken).ConfigureAwait(false);
            return new NativeMailboxDispatchResult(
                StatusCodes.Status200OK,
                result.CanonicalGss1);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is GroupFormatException
            or ArgumentException
            or InvalidDataException
            or OverflowException)
        {
            return new NativeMailboxDispatchResult(
                StatusCodes.Status400BadRequest,
                ReadOnlyMemory<byte>.Empty,
                NativeMailboxDispatchCertainty.RejectedBeforeForward);
        }
        catch (GroupControlAuthorityUnavailableException)
        {
            return NativeMailboxDispatchResult.RejectedBeforeForward();
        }
        catch (Exception exception) when (exception is IOException
            or InvalidOperationException
            or UnauthorizedAccessException)
        {
            return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
        }
    }
}
