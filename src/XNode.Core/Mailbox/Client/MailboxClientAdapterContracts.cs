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
    MailboxClientOperation AllowedOperation);

public interface IMailboxClientCapabilityVerifier
{
    bool IsConfigured { get; }

    ValueTask<MailboxCapabilityBinding?> VerifyAsync(
        ReadOnlyMemory<byte> canonicalRequest,
        MailboxClientOperation operation,
        CancellationToken cancellationToken);
}

public sealed class RejectAllMailboxClientCapabilityVerifier : IMailboxClientCapabilityVerifier
{
    public bool IsConfigured => false;

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
    ReadOnlyMemory<byte> CanonicalEnvelope);

public interface IMailboxClientReplicaFanout
{
    bool IsConfigured { get; }

    Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
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

public sealed class MailboxClientAdapterOptions
{
    public bool Enabled { get; set; }

    public string DirectoryName { get; set; } = "mailbox-client-adapter-v1";

    public string MembershipCommitment { get; set; } = "";

    public ulong CurrentEpoch { get; set; }

    public ulong NextEpoch { get; set; }

    public ulong CurrentNotBeforeUnixSeconds { get; set; }

    public ulong NextNotBeforeUnixSeconds { get; set; }

    public ulong CurrentExpiresAtUnixSeconds { get; set; }

    public ulong NextExpiresAtUnixSeconds { get; set; }

    public int MaxOperationEntries { get; set; } = 100_000;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || MaxOperationEntries is < 1 or > 1_000_000)
        {
            throw new InvalidOperationException("MailboxClientAdapter limits are invalid.");
        }

        if (!Enabled)
        {
            return;
        }

        if (!TryDecodeFixedLowerHex(MembershipCommitment, 32, out _))
        {
            throw new InvalidOperationException(
                "MailboxClientAdapter:MembershipCommitment must be 32-byte lowercase hex.");
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

    public byte[] GetMembershipCommitment() =>
        TryDecodeFixedLowerHex(MembershipCommitment, 32, out var value)
            ? value
            : throw new InvalidOperationException("Mailbox membership commitment is invalid.");

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
    bool ReplicaFanoutConfigured,
    bool Ready,
    string Reason);
