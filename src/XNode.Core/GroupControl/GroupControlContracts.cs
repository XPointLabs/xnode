using System.Security.Cryptography;

namespace XNode.Core.GroupControl;

internal enum GroupControlMutationDisposition
{
    Committed = 1,
    ExactReplay = 2,
    Expired = 3,
    StaleSequence = 4,
    Conflict = 5,
    ForkLatched = 6,
    QuotaExceeded = 7
}

internal enum GroupControlReadDisposition
{
    Events = 1,
    NoChange = 2,
    NotFound = 3,
    Expired = 4,
    Gap = 5,
    StaleCursor = 6,
    Conflict = 7
}

internal sealed class GroupControlOpaqueStoreOptions
{
    internal const int MaximumSealedGcf1Bytes = 32_768;
    internal const int MaximumFetchRecords = 64;
    internal const int MinimumRetainedCommits = 1_024;
    internal static readonly TimeSpan MaximumRetention = TimeSpan.FromDays(400);

    internal int MaximumStreams { get; init; } = 16_384;
    internal int MaximumRecordsPerStream { get; init; } = 4_096;
    internal long MaximumCiphertextBytes { get; init; } = 256L * 1024 * 1024;
    internal long MaximumPersistedBytes { get; init; } = 384L * 1024 * 1024;

    internal void Validate()
    {
        if (MaximumStreams < 1
            || MaximumRecordsPerStream < MinimumRetainedCommits
            || MaximumCiphertextBytes < MaximumSealedGcf1Bytes
            || MaximumPersistedBytes < MaximumCiphertextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(GroupControlOpaqueStoreOptions));
        }
    }
}

internal sealed class OpaqueGroupControlWriteRequest
{
    private readonly byte[] serviceCapability;
    private readonly byte[] exactGsr1Hash;
    private readonly byte[] operationId;
    private readonly byte[] requestHash;
    private readonly byte[] predecessorControlHash;
    private readonly byte[] sealedGcf1Hash;
    private readonly byte[] sealedGcf1;

    internal OpaqueGroupControlWriteRequest(
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactGsr1Hash32,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ulong controlSequence,
        ReadOnlySpan<byte> predecessorControlHash32,
        ReadOnlySpan<byte> sealedGcf1Hash32,
        ReadOnlySpan<byte> sealedExactGcf1,
        ulong effectiveExpiresAtUnixSeconds)
    {
        serviceCapability = GroupControlOpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        exactGsr1Hash = GroupControlOpaqueValue.CopyNonZero32(exactGsr1Hash32, nameof(exactGsr1Hash32));
        operationId = GroupControlOpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = GroupControlOpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
        predecessorControlHash = GroupControlOpaqueValue.CopySequencePredecessor(
            controlSequence,
            predecessorControlHash32,
            nameof(predecessorControlHash32));
        sealedGcf1Hash = GroupControlOpaqueValue.CopyNonZero32(sealedGcf1Hash32, nameof(sealedGcf1Hash32));
        if (sealedExactGcf1.Length is < 1 or > GroupControlOpaqueStoreOptions.MaximumSealedGcf1Bytes)
        {
            throw new ArgumentOutOfRangeException(nameof(sealedExactGcf1));
        }
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(sealedExactGcf1), sealedGcf1Hash32))
        {
            throw new ArgumentException("The sealed GCF1 hash does not match its opaque bytes.", nameof(sealedGcf1Hash32));
        }

        sealedGcf1 = sealedExactGcf1.ToArray();
        ControlSequence = controlSequence;
        EffectiveExpiresAtUnixSeconds = effectiveExpiresAtUnixSeconds;
    }

    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> ExactGsr1Hash => exactGsr1Hash;
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ulong ControlSequence { get; }
    internal ReadOnlySpan<byte> PredecessorControlHash => predecessorControlHash;
    internal ReadOnlySpan<byte> SealedGcf1Hash => sealedGcf1Hash;
    internal ReadOnlySpan<byte> SealedGcf1 => sealedGcf1;
    internal ulong EffectiveExpiresAtUnixSeconds { get; }
}

internal sealed class OpaqueGroupControlFetchRequest
{
    private readonly byte[] serviceCapability;
    private readonly byte[] exactGsr1Hash;
    private readonly byte[] operationId;
    private readonly byte[] requestHash;

    internal OpaqueGroupControlFetchRequest(
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> exactGsr1Hash32,
        ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> requestHash32,
        ulong afterControlSequence,
        int maximumRecords)
    {
        serviceCapability = GroupControlOpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        exactGsr1Hash = GroupControlOpaqueValue.CopyNonZero32(exactGsr1Hash32, nameof(exactGsr1Hash32));
        operationId = GroupControlOpaqueValue.CopyNonZero32(operationId32, nameof(operationId32));
        requestHash = GroupControlOpaqueValue.CopyNonZero32(requestHash32, nameof(requestHash32));
        if (maximumRecords is < 1 or > GroupControlOpaqueStoreOptions.MaximumFetchRecords)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        }

        AfterControlSequence = afterControlSequence;
        MaximumRecords = maximumRecords;
    }

    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ReadOnlySpan<byte> ExactGsr1Hash => exactGsr1Hash;
    internal ReadOnlySpan<byte> OperationId => operationId;
    internal ReadOnlySpan<byte> RequestHash => requestHash;
    internal ulong AfterControlSequence { get; }
    internal int MaximumRecords { get; }
}

internal sealed record GroupControlMutationResult(
    GroupControlMutationDisposition Disposition,
    ulong ControlSequence,
    byte[] SealedGcf1Hash)
{
    internal static GroupControlMutationResult Empty(GroupControlMutationDisposition disposition) =>
        new(disposition, 0, []);
}

internal sealed record OpaqueGroupControlRecord(
    ulong ControlSequence,
    byte[] PredecessorControlHash,
    byte[] SealedGcf1Hash,
    byte[] SealedGcf1,
    ulong EffectiveExpiresAtUnixSeconds);

internal sealed record GroupControlReadResult(
    GroupControlReadDisposition Disposition,
    IReadOnlyList<OpaqueGroupControlRecord> Records,
    ulong CurrentControlSequence,
    byte[] CurrentControlHash,
    bool HasMore);

internal sealed class GroupControlStoreCorruptException : IOException
{
    internal GroupControlStoreCorruptException(Exception? inner = null)
        : base("The opaque group-control store is corrupt and has been quarantined.", inner)
    {
    }
}

internal sealed class VerifiedGroupControlCompactionCheckpoint
{
    private readonly byte[] serviceCapability;
    private readonly byte[] controlHash;

    private VerifiedGroupControlCompactionCheckpoint(
        ReadOnlySpan<byte> serviceCapability32,
        ulong controlSequence,
        ReadOnlySpan<byte> controlHash32)
    {
        serviceCapability = GroupControlOpaqueValue.CopyNonZero32(serviceCapability32, nameof(serviceCapability32));
        controlHash = GroupControlOpaqueValue.CopyNonZero32(controlHash32, nameof(controlHash32));
        ControlSequence = controlSequence;
    }

    internal ReadOnlySpan<byte> ServiceCapability => serviceCapability;
    internal ulong ControlSequence { get; }
    internal ReadOnlySpan<byte> ControlHash => controlHash;

    // The future GROUP verifier is the sole production caller. No raw sequence
    // can cross this non-forgeable boundary into compaction.
    internal static VerifiedGroupControlCompactionCheckpoint FromVerifiedClosure(
        ReadOnlySpan<byte> serviceCapability32,
        ulong controlSequence,
        ReadOnlySpan<byte> controlHash32) =>
        new(serviceCapability32, controlSequence, controlHash32);
}

internal static class GroupControlOpaqueValue
{
    internal static byte[] CopyNonZero32(ReadOnlySpan<byte> value, string parameter)
    {
        if (value.Length != 32 || IsZero(value))
        {
            throw new ArgumentException("A non-zero 32-byte opaque value is required.", parameter);
        }
        return value.ToArray();
    }

    internal static byte[] CopySequencePredecessor(
        ulong sequence,
        ReadOnlySpan<byte> predecessor,
        string parameter)
    {
        if (sequence == 0 || predecessor.Length != 32 || (sequence == 1) != IsZero(predecessor))
        {
            throw new ArgumentException("Sequence one requires ZERO32; successors require a non-zero predecessor.", parameter);
        }
        return predecessor.ToArray();
    }

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        var aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }
        return aggregate == 0;
    }

    internal static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
