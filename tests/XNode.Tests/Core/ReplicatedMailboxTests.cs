using System.Security.Cryptography;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ReplicatedMailboxTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-mailbox-{Guid.NewGuid():N}");
    private readonly FixedClock _clock = new(
        new DateTimeOffset(2026, 7, 26, 12, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task Store_IsIdempotentAndPersistsOnlyEncryptedBlob()
    {
        var options = Options();
        var blob = Blob(_clock.UtcNow, "mailbox-a", [1, 2, 3, 4]);
        var firstStore = new ReplicatedMailboxStore(_root, options, _clock);
        await firstStore.InitializeAsync();

        Assert.Equal(MailboxPutDisposition.Stored, (await firstStore.PutAsync(blob)).Disposition);
        Assert.Equal(MailboxPutDisposition.Duplicate, (await firstStore.PutAsync(blob)).Disposition);

        var reopened = new ReplicatedMailboxStore(_root, options, _clock);
        await reopened.InitializeAsync();
        var read = await reopened.ReadAsync(blob.MailboxId, 10);

        var stored = Assert.Single(read);
        Assert.Equal(blob, stored);
        var diskText = await File.ReadAllTextAsync(
            Directory.GetFiles(_root, "*.json", SearchOption.AllDirectories).Single());
        Assert.DoesNotContain("user", diskText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("plaintext", diskText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Store_RejectsDigestTtlAndSizeViolations()
    {
        var options = Options();
        options.MaxBlobBytes = 1024;
        var store = new ReplicatedMailboxStore(_root, options, _clock);
        var valid = Blob(_clock.UtcNow, "mailbox-a", [1, 2, 3, 4]);

        Assert.Equal(
            "mailbox-blob-digest-mismatch",
            (await store.PutAsync(valid with { BlobId = new string('0', 64) })).Error);
        Assert.Equal(
            "mailbox-blob-ttl-rejected",
            (await store.PutAsync(valid with
            {
                ExpiresAtUnixMs = _clock.UtcNow.AddSeconds(1).ToUnixTimeMilliseconds()
            })).Error);
        Assert.Equal(
            "mailbox-blob-size-rejected",
            (await store.PutAsync(Blob(
                _clock.UtcNow,
                "mailbox-a",
                Enumerable.Repeat((byte)1, 1025).ToArray()))).Error);
    }

    [Fact]
    public async Task Receiver_AuthenticatesRegisteredPeerAndRejectsReplay()
    {
        var sender = Identity(1);
        var receiver = Identity(2);
        var options = Options();
        var store = new ReplicatedMailboxStore(_root, options, _clock);
        var service = new MailboxReplicaReceiver(
            receiver.Id,
            receiver.Seed,
            options,
            store,
            new AllowOnlyPeer(sender.Id),
            new MailboxReplicaReplayGuard(),
            _clock);
        var request = MailboxReplicationProtocol.SignRequest(
            sender.Id,
            receiver.Id,
            sender.Seed,
            Blob(_clock.UtcNow, "mailbox-a", [1, 2, 3]),
            _clock.UtcNow,
            "00112233445566778899aabbccddeeff");

        var accepted = await service.ReceiveAsync(request);
        var replay = await service.ReceiveAsync(request);

        Assert.Equal(MailboxReplicaReceiveStatus.Accepted, accepted.Status);
        Assert.True(MailboxReplicationProtocol.VerifyReceipt(
            accepted.Receipt,
            receiver.Id,
            request.Blob,
            _clock.UtcNow));
        Assert.Equal(MailboxReplicaReceiveStatus.Replay, replay.Status);
    }

    [Fact]
    public async Task Coordinator_NodeUnavailableFailsClosedBelowQuorum()
    {
        var local = Identity(1);
        var peerA = Identity(2);
        var peerB = Identity(3);
        var options = Options(replicationFactor: 3, writeQuorum: 3);
        var client = new FakePeerClient(_ => throw new HttpRequestException("offline"));
        var coordinator = Coordinator(local, options, client);

        var result = await coordinator.PutAsync(
            Blob(_clock.UtcNow, "mailbox-a", [1, 2, 3]),
            [Peer(peerA), Peer(peerB)]);

        Assert.False(result.QuorumAchieved);
        Assert.Equal("mailbox-write-quorum-not-reached", result.Error);
        Assert.Equal(2, result.FailedReplicas);
        Assert.Equal(2, coordinator.Metrics.ReplicaFailures);
    }

    [Fact]
    public async Task Coordinator_TimesOutHangingNode()
    {
        var local = Identity(1);
        var peer = Identity(2);
        var options = Options(replicationFactor: 2, writeQuorum: 2);
        options.PeerTimeout = TimeSpan.FromMilliseconds(20);
        var coordinator = Coordinator(local, options, new HangingPeerClient());

        var result = await coordinator.PutAsync(
            Blob(_clock.UtcNow, "mailbox-a", [1, 3, 5]),
            [Peer(peer)]);

        Assert.False(result.QuorumAchieved);
        Assert.Equal(1, result.FailedReplicas);
        Assert.Equal(1, coordinator.Metrics.ReplicaFailures);
    }

    [Theory]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("../escape")]
    [InlineData("nested/path")]
    public void Options_RejectDirectoryTraversal(string directoryName)
    {
        var options = Options();
        options.DirectoryName = directoryName;

        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Fact]
    public async Task Coordinator_PartialFailureStillSucceedsAtConfiguredQuorum()
    {
        var local = Identity(1);
        var peerA = Identity(2);
        var peerB = Identity(3);
        var identities = new Dictionary<string, IdentityData>
        {
            [peerA.Id.Value] = peerA,
            [peerB.Id.Value] = peerB
        };
        var calls = 0;
        var client = new FakePeerClient((peer, request) =>
        {
            calls++;
            if (peer.RouterId == peerB.Id)
            {
                throw new HttpRequestException("offline");
            }

            var identity = identities[peer.RouterId.Value];
            return MailboxReplicationProtocol.SignReceipt(
                identity.Id,
                identity.Seed,
                request.Blob,
                _clock.UtcNow,
                MailboxPutDisposition.Stored);
        });
        var coordinator = Coordinator(local, Options(replicationFactor: 3, writeQuorum: 2), client);

        var result = await coordinator.PutAsync(
            Blob(_clock.UtcNow, "mailbox-a", [9, 8, 7]),
            [Peer(peerA), Peer(peerB)]);

        Assert.True(result.QuorumAchieved);
        Assert.Equal(2, result.Receipts.Count);
        Assert.Equal(2, calls);
        Assert.Equal(1, result.FailedReplicas);
    }

    [Fact]
    public async Task Coordinator_DoesNotCountMaliciousReceipt()
    {
        var local = Identity(1);
        var peerA = Identity(2);
        var malicious = Identity(9);
        var client = new FakePeerClient((_, request) =>
            MailboxReplicationProtocol.SignReceipt(
                malicious.Id,
                malicious.Seed,
                request.Blob,
                _clock.UtcNow,
                MailboxPutDisposition.Stored));
        var coordinator = Coordinator(local, Options(replicationFactor: 2, writeQuorum: 2), client);

        var result = await coordinator.PutAsync(
            Blob(_clock.UtcNow, "mailbox-a", [4, 5, 6]),
            [Peer(peerA)]);

        Assert.False(result.QuorumAchieved);
        Assert.Single(result.Receipts);
        Assert.Equal(1, coordinator.Metrics.InvalidReceipts);
    }

    [Fact]
    public async Task Coordinator_DuplicateWriteReturnsValidQuorumReceipts()
    {
        var local = Identity(1);
        var peer = Identity(2);
        var client = new FakePeerClient((candidate, request) =>
            MailboxReplicationProtocol.SignReceipt(
                candidate.RouterId,
                peer.Seed,
                request.Blob,
                _clock.UtcNow,
                MailboxPutDisposition.Duplicate));
        var coordinator = Coordinator(local, Options(replicationFactor: 2, writeQuorum: 2), client);
        var blob = Blob(_clock.UtcNow, "mailbox-a", [6, 6, 6]);

        Assert.True((await coordinator.PutAsync(blob, [Peer(peer)])).QuorumAchieved);
        var duplicate = await coordinator.PutAsync(blob, [Peer(peer)]);

        Assert.True(duplicate.QuorumAchieved);
        Assert.Equal(1, coordinator.Metrics.Duplicates);
        Assert.All(duplicate.Receipts, receipt => Assert.True(
            MailboxReplicationProtocol.VerifyReceipt(
                receipt,
                RouterId.FromHex(receipt.StorageRouterId),
                blob,
                _clock.UtcNow)));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private MailboxReplicationCoordinator Coordinator(
        IdentityData local,
        ReplicatedMailboxOptions options,
        IMailboxReplicaPeerClient client) =>
        new(
            local.Id,
            local.Seed,
            options,
            new ReplicatedMailboxStore(_root, options, _clock),
            client,
            _clock);

    private static MailboxReplicaPeer Peer(IdentityData identity) =>
        new(identity.Id, $"https://8.8.8.8/api/peer/mailbox/replica");

    private static EncryptedMailboxBlob Blob(
        DateTimeOffset now,
        string mailboxSeed,
        byte[] ciphertext)
    {
        var mailboxId = Convert.ToHexString(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(mailboxSeed))).ToLowerInvariant();
        var blobId = Convert.ToHexString(SHA256.HashData(ciphertext)).ToLowerInvariant();
        return new EncryptedMailboxBlob(
            mailboxId,
            blobId,
            now.AddHours(1).ToUnixTimeMilliseconds(),
            Convert.ToBase64String(ciphertext));
    }

    private static ReplicatedMailboxOptions Options(
        int replicationFactor = 3,
        int writeQuorum = 2) =>
        new()
        {
            Enabled = true,
            MaximumTtl = TimeSpan.FromDays(1),
            ReplicationFactor = replicationFactor,
            WriteQuorum = writeQuorum,
            PeerTimeout = TimeSpan.FromSeconds(1)
        };

    private static IdentityData Identity(byte value)
    {
        var seed = Enumerable.Repeat(value, 32).ToArray();
        var pair = PublicKeyAuth.GenerateKeyPair(seed);
        return new IdentityData(
            RouterId.FromBytes(pair.PublicKey),
            Convert.ToHexString(seed).ToLowerInvariant());
    }

    private sealed record IdentityData(RouterId Id, string Seed);

    private sealed class FixedClock : IClock
    {
        public FixedClock(DateTimeOffset now)
        {
            UtcNow = now;
        }

        public DateTimeOffset UtcNow { get; }
    }

    private sealed class AllowOnlyPeer : IMailboxPeerAuthorizer
    {
        private readonly RouterId _allowed;

        public AllowOnlyPeer(RouterId allowed)
        {
            _allowed = allowed;
        }

        public bool IsAuthorized(RouterId routerId, DateTimeOffset now) => routerId == _allowed;
    }

    private sealed class FakePeerClient : IMailboxReplicaPeerClient
    {
        private readonly Func<MailboxReplicaPeer, SignedMailboxReplicaRequest, MailboxWriteReceipt?> _handler;

        public FakePeerClient(Func<MailboxReplicaPeer, MailboxWriteReceipt?> handler)
            : this((peer, _) => handler(peer))
        {
        }

        public FakePeerClient(
            Func<MailboxReplicaPeer, SignedMailboxReplicaRequest, MailboxWriteReceipt?> handler)
        {
            _handler = handler;
        }

        public Task<MailboxWriteReceipt?> PutAsync(
            MailboxReplicaPeer peer,
            SignedMailboxReplicaRequest request,
            CancellationToken cancellationToken) =>
            Task.FromResult(_handler(peer, request));
    }

    private sealed class HangingPeerClient : IMailboxReplicaPeerClient
    {
        public async Task<MailboxWriteReceipt?> PutAsync(
            MailboxReplicaPeer peer,
            SignedMailboxReplicaRequest request,
            CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return null;
        }
    }
}
