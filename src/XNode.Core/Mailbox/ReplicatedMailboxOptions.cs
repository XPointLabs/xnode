namespace XNode.Core.Mailbox;

public sealed class ReplicatedMailboxOptions
{
    public bool Enabled { get; set; }

    public string DirectoryName { get; set; } = "mailbox-v1";

    public int MaxBlobBytes { get; set; } = 80 * 1024;

    public int MaxStoredBlobs { get; set; } = 100_000;

    public int MaxRecoveryScanFiles { get; set; } = 200_000;

    public TimeSpan MinimumTtl { get; set; } = TimeSpan.FromMinutes(1);

    public TimeSpan MaximumTtl { get; set; } = TimeSpan.FromDays(7);

    public int ReplicationFactor { get; set; } = 3;

    public int WriteQuorum { get; set; } = 2;

    public TimeSpan PeerTimeout { get; set; } = TimeSpan.FromSeconds(5);

    public int MaxReplayEntriesPerPeer { get; set; } = 2048;

    public int MaxReplicaRequestsPerPeerPerMinute { get; set; } = 240;

    public int MaxReplayPeerStates { get; set; } = 4096;

    public TimeSpan ReplayRetention { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan ReplayReservationTimeout { get; set; } = TimeSpan.FromMinutes(2);

    public bool AllowInsecureHttpPeerTransport { get; set; }

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(DirectoryName)
            || Path.IsPathRooted(DirectoryName)
            || DirectoryName is "." or ".."
            || DirectoryName.Contains('/')
            || DirectoryName.Contains('\\')
            || DirectoryName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new InvalidOperationException("Mailbox:DirectoryName must be a relative directory name.");
        }

        if (MaxBlobBytes is < 1024 or > 1024 * 1024
            || MaxStoredBlobs <= 0
            || MaxRecoveryScanFiles < MaxStoredBlobs
            || MaxRecoveryScanFiles > 2_000_000
            || MinimumTtl <= TimeSpan.Zero
            || MaximumTtl < MinimumTtl
            || MaximumTtl > TimeSpan.FromDays(30)
            || ReplicationFactor is < 1 or > 9
            || WriteQuorum is < 1
            || WriteQuorum > ReplicationFactor
            || PeerTimeout <= TimeSpan.Zero
            || PeerTimeout > TimeSpan.FromMinutes(1)
            || MaxReplayEntriesPerPeer is < 1 or > 100_000
            || MaxReplicaRequestsPerPeerPerMinute is < 1 or > 100_000
            || MaxReplayPeerStates is < 1 or > 100_000
            || ReplayRetention < TimeSpan.FromMinutes(1)
            || ReplayRetention > TimeSpan.FromHours(1)
            || ReplayReservationTimeout < PeerTimeout
            || ReplayReservationTimeout > ReplayRetention)
        {
            throw new InvalidOperationException("Replicated mailbox limits are invalid.");
        }
    }
}
