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

    // P10B3 freezes exactly two selected replicas and a 2-of-2 durable quorum.
    public int ReplicationFactor { get; set; } = 2;

    public int WriteQuorum { get; set; } = 2;

    public TimeSpan PeerTimeout { get; set; } = TimeSpan.FromSeconds(5);

    public string PeerReplayDirectoryName { get; set; } = "mailbox-peer-replay-v2";

    public string PeerMutationDirectoryName { get; set; } = "mailbox-peer-mutations-v2";

    public int MaxPeerReplayRecords { get; set; } = 100_000;

    public int MaxPeerReplayRecordsPerRouterPairEpoch { get; set; } = 20_000;

    public int MaxPeerReplayGcBatch { get; set; } = 1024;

    public int MaxPeerMutationRecords { get; set; } = 100_000;

    public int MaxPeerMutationGcBatch { get; set; } = 1024;

    public bool AllowInsecureHttpPeerTransport { get; set; }

    public void Validate()
    {
        if (!IsSafeDirectoryName(DirectoryName)
            || !IsSafeDirectoryName(PeerReplayDirectoryName)
            || !IsSafeDirectoryName(PeerMutationDirectoryName)
            || string.Equals(
                DirectoryName,
                PeerReplayDirectoryName,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                DirectoryName,
                PeerMutationDirectoryName,
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(
                PeerReplayDirectoryName,
                PeerMutationDirectoryName,
                StringComparison.OrdinalIgnoreCase)
            || MaxBlobBytes is < 81920 or > 1024 * 1024
            || MaxStoredBlobs <= 0
            || MaxRecoveryScanFiles < MaxStoredBlobs
            || MaxRecoveryScanFiles > 2_000_000
            || MinimumTtl <= TimeSpan.Zero
            || MaximumTtl < MinimumTtl
            || MaximumTtl > TimeSpan.FromDays(7)
            || ReplicationFactor != 2
            || WriteQuorum != 2
            || PeerTimeout <= TimeSpan.Zero
            || PeerTimeout > TimeSpan.FromSeconds(15)
            || MaxPeerReplayRecords is < 1 or > 1_000_000
            || MaxPeerReplayRecordsPerRouterPairEpoch is < 1 or > 1_000_000
            || MaxPeerReplayRecordsPerRouterPairEpoch > MaxPeerReplayRecords
            || MaxPeerReplayGcBatch is < 1 or > 1024
            || MaxPeerMutationRecords is < 1 or > 1_000_000
            || MaxPeerMutationGcBatch is < 1 or > 1024)
        {
            throw new InvalidOperationException("Replicated mailbox limits are invalid.");
        }
    }

    private static bool IsSafeDirectoryName(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && !Path.IsPathRooted(value)
        && value is not ("." or "..")
        && !value.Contains('/')
        && !value.Contains('\\')
        && value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;
}
