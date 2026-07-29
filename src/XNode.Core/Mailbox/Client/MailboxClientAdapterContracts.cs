using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.Core.Mailbox.Client;

public enum MailboxClientOperation
{
    Store = 1,
    Retrieve = 2,
    Acknowledge = 3
}

public sealed record MailboxCapabilityBinding(
    ulong Epoch,
    ReadOnlyMemory<byte> BlindedMailboxId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    MailboxClientOperation AllowedOperation)
{
    public ReadOnlyMemory<byte> OuterOperationId { get; init; }
    public ReadOnlyMemory<byte> CanonicalRequestDigest { get; init; }
    public ReadOnlyMemory<byte> CanonicalCapabilityDigest { get; init; }
    public ulong ReplayCounter { get; init; }
    public ReadOnlyMemory<byte> IdempotencyKey { get; init; }
    public MailboxCapabilityReplayDisposition ReplayDisposition { get; init; }
}

public interface IMailboxClientCapabilityVerifier
{
    bool IsConfigured { get; }
    bool ProvidesDurableAtomicReplay { get; }

    ValueTask<MailboxCapabilityBinding?> VerifyAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        MailboxClientOperation operation,
        CancellationToken cancellationToken);
}

public interface IMailboxClientCapabilityCompletion
{
    void Complete(
        ReadOnlyMemory<byte> canonicalRequestDigest,
        ReadOnlyMemory<byte> canonicalOutcome);
}

public sealed class RejectAllMailboxClientCapabilityVerifier : IMailboxClientCapabilityVerifier
{
    public bool IsConfigured => false;
    public bool ProvidesDurableAtomicReplay => false;

    public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        MailboxClientOperation operation,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<MailboxCapabilityBinding?>(null);
}

public sealed record MailboxReplicaStoreContext(
    ulong Cursor,
    ulong Epoch,
    ReadOnlyMemory<byte> OperationId,
    ReadOnlyMemory<byte> BlindedMailboxId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    ReadOnlyMemory<byte> EnvelopeDigest,
    ulong ExpiresAtUnixSeconds,
    ReadOnlyMemory<byte> CanonicalEnvelope,
    MailboxReplicaDisposition Disposition,
    ulong AcceptedAtUnixSeconds,
    IReadOnlyList<ReadOnlyMemory<byte>> ExpectedReplicaIds)
{
    public ReadOnlyMemory<byte> BlindedPlacementId { get; init; }
}

public sealed record MailboxReplicaTombstoneContext(
    ulong Cursor,
    ulong Epoch,
    ReadOnlyMemory<byte> OperationId,
    ReadOnlyMemory<byte> BlindedMailboxId,
    ReadOnlyMemory<byte> PlacementCommitment,
    ReadOnlyMemory<byte> MembershipCommitment,
    ReadOnlyMemory<byte> EnvelopeDigest,
    ulong ExpiresAtUnixSeconds,
    ulong AcceptedAtUnixSeconds,
    IReadOnlyList<ReadOnlyMemory<byte>> ExpectedReplicaIds)
{
    public ReadOnlyMemory<byte> BlindedPlacementId { get; init; }
}

public interface IMailboxClientReplicaAuthorizer
{
    bool IsConfigured { get; }

    ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
        ulong epoch,
        ReadOnlyMemory<byte> membershipCommitment,
        ReadOnlyMemory<byte> placementCommitment,
        CancellationToken cancellationToken);
}

public sealed class RejectAllMailboxClientReplicaAuthorizer : IMailboxClientReplicaAuthorizer
{
    public bool IsConfigured => false;

    public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
        ulong epoch,
        ReadOnlyMemory<byte> membershipCommitment,
        ReadOnlyMemory<byte> placementCommitment,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>([]);
}

public interface IMailboxClientReplicaFanout
{
    bool IsConfigured { get; }

    Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
        MailboxReplicaStoreContext context,
        CancellationToken cancellationToken);
}

public sealed record MailboxClientCanonicalFanoutResult(
    IReadOnlyList<ReadOnlyMemory<byte>> ReplicaReceipts,
    ulong CoordinatorSequence);

/// <summary>
/// Optional PRQ2-aware fanout. The coordinator sequence is the exact canonical
/// PRQ2 request-digest sequence used by MQR3.
/// </summary>
public interface IMailboxClientCanonicalReplicaFanout : IMailboxClientReplicaFanout
{
    Task<MailboxClientCanonicalFanoutResult> StoreCanonicalAsync(
        MailboxReplicaStoreContext context,
        CancellationToken cancellationToken);
}

public sealed class DisabledMailboxClientReplicaFanout : IMailboxClientReplicaFanout
{
    public bool IsConfigured => false;

    public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
        MailboxReplicaStoreContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>([]);
}

public interface IMailboxClientTombstoneFanout
{
    bool IsConfigured { get; }

    Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
        MailboxReplicaTombstoneContext context,
        CancellationToken cancellationToken);
}

public interface IMailboxClientCanonicalTombstoneFanout : IMailboxClientTombstoneFanout
{
    Task<MailboxClientCanonicalFanoutResult> TombstoneCanonicalAsync(
        MailboxReplicaTombstoneContext context,
        CancellationToken cancellationToken);
}

public sealed class DisabledMailboxClientTombstoneFanout : IMailboxClientTombstoneFanout
{
    public bool IsConfigured => false;

    public Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
        MailboxReplicaTombstoneContext context,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>([]);
}

public sealed class MailboxClientAdapterOptions
{
    public bool Enabled { get; set; }

    public string DirectoryName { get; set; } = "mailbox-client-adapter-v1";

    public string CurrentMembershipCommitment { get; set; } = "";

    public string NextMembershipCommitment { get; set; } = "";

    public ulong CurrentEpoch { get; set; }

    public ulong NextEpoch { get; set; }

    public ulong CurrentNotBeforeUnixSeconds { get; set; }

    public ulong NextNotBeforeUnixSeconds { get; set; }

    public ulong CurrentExpiresAtUnixSeconds { get; set; }

    public ulong NextExpiresAtUnixSeconds { get; set; }

    public int MaxOperationEntries { get; set; } = 100_000;

    public int MaxCursorAuthorities { get; set; } = 4096;

    public int MaxConcurrentSingleFlights { get; set; } = 1024;

    public TimeSpan ContinuationTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    public int MaxTombstoneCleanupPerInitialization { get; set; } = 1000;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || MaxOperationEntries is < 1 or > 1_000_000
            || MaxCursorAuthorities is < 1 or > 100_000
            || MaxCursorAuthorities > MaxOperationEntries
            || MaxConcurrentSingleFlights is < 1 or > 100_000
            || MaxConcurrentSingleFlights > MaxOperationEntries
            || ContinuationTokenLifetime < TimeSpan.FromMinutes(1)
            || ContinuationTokenLifetime > TimeSpan.FromHours(1)
            || MaxTombstoneCleanupPerInitialization is < 1 or > 100_000)
        {
            throw new InvalidOperationException("MailboxClientAdapter limits are invalid.");
        }

        if (!Enabled)
        {
            return;
        }

        if (!TryDecodeFixedLowerHex(NextMembershipCommitment, 32, out var next)
            || !TryDecodeFixedLowerHex(CurrentMembershipCommitment, 32, out var current)
            || CryptographicOperations.FixedTimeEquals(current, next))
        {
            throw new InvalidOperationException(
                "MailboxClientAdapter epoch membership commitments must be 32-byte lowercase hex.");
        }

        EpochWindow().Validate();
    }

    public MailboxEpochWindow EpochWindow() => new()
    {
        CurrentEpoch = CurrentEpoch,
        NextEpoch = NextEpoch,
        CurrentNotBeforeUnixSeconds = CurrentNotBeforeUnixSeconds,
        NextNotBeforeUnixSeconds = NextNotBeforeUnixSeconds,
        CurrentExpiresAtUnixSeconds = CurrentExpiresAtUnixSeconds,
        NextExpiresAtUnixSeconds = NextExpiresAtUnixSeconds
    };

    public byte[] GetMembershipCommitment(ulong epoch)
    {
        var configured = epoch == CurrentEpoch
            ? CurrentMembershipCommitment
            : epoch == NextEpoch
                ? NextMembershipCommitment
                : "";
        return TryDecodeFixedLowerHex(configured, 32, out var value)
            ? value
            : throw new InvalidOperationException("Mailbox membership commitment is invalid.");
    }

    private static bool TryDecodeFixedLowerHex(string? value, int length, out byte[] decoded)
    {
        decoded = [];
        if (value is null
            || value.Length != length * 2
            || value.Any(static character =>
                character is not (>= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            return false;
        }

        decoded = Convert.FromHexString(value);
        return decoded.AsSpan().IndexOfAnyExcept((byte)0) >= 0;
    }
}

public enum MailboxClientStoreStatus
{
    Durable,
    Disabled,
    NotReady,
    Unauthorized,
    Malformed,
    Conflict,
    Rejected,
    QuorumUnavailable
}

public sealed record MailboxClientStoreResult(
    MailboxClientStoreStatus Status,
    ReadOnlyMemory<byte> DurableQuorumReceipt,
    string Error)
{
    public static MailboxClientStoreResult Failure(
        MailboxClientStoreStatus status,
        string error) => new(status, ReadOnlyMemory<byte>.Empty, error);
}

public sealed record MailboxClientAdapterStatus(
    bool Enabled,
    bool CapabilityVerifierConfigured,
    bool ReplicaAuthorizerConfigured,
    bool ReplicaFanoutConfigured,
    bool Ready,
    string Reason)
{
    public bool CapabilityVerifierProvidesDurableAtomicReplay { get; init; }
    public bool TombstoneFanoutConfigured { get; init; }
    public bool StoreReady { get; init; }
    public bool RetrieveReady { get; init; }
    public bool AcknowledgeReady { get; init; }
    public string StoreReason { get; init; } = "";
    public string RetrieveReason { get; init; } = "";
    public string AcknowledgeReason { get; init; } = "";
}

public enum MailboxClientRetrieveStatus
{
    Success,
    Disabled,
    NotReady,
    Unauthorized,
    Malformed,
    Rejected
}

public sealed record MailboxClientRetrieveResult(
    MailboxClientRetrieveStatus Status,
    ReadOnlyMemory<byte> CanonicalPage,
    string Error)
{
    public static MailboxClientRetrieveResult Failure(
        MailboxClientRetrieveStatus status,
        string error) => new(status, ReadOnlyMemory<byte>.Empty, error);
}

public enum MailboxClientAckStatus
{
    Durable,
    Disabled,
    NotReady,
    Unauthorized,
    Malformed,
    Conflict,
    Rejected,
    QuorumUnavailable
}

public sealed record MailboxClientAckReceipt(
    ulong Cursor,
    ReadOnlyMemory<byte> EnvelopeDigest,
    ReadOnlyMemory<byte> DurableQuorumReceipt);

public sealed record MailboxClientAckResult(
    MailboxClientAckStatus Status,
    IReadOnlyList<MailboxClientAckReceipt> Receipts,
    string Error)
{
    public static MailboxClientAckResult Failure(
        MailboxClientAckStatus status,
        string error) => new(status, [], error);
}
