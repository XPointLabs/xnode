using System.Collections.Concurrent;
using System.Security.Cryptography;
using Sodium;
using XNode;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Runtime;

namespace XNode.IntegrationTests.Runtime;

public sealed class ReplicatedMailboxIntegrationTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-mailbox-integration-{Guid.NewGuid():N}");
    private readonly FixedClock _clock = new(
        new DateTimeOffset(2026, 7, 26, 12, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task ThreeNodeWrite_PersistsTwoReplicas_WhenOneNodeIsUnavailable()
    {
        var identities = new[] { Identity(1), Identity(2), Identity(3) };
        var options = new ReplicatedMailboxOptions
        {
            Enabled = true,
            ReplicationFactor = 3,
            WriteQuorum = 2,
            PeerTimeout = TimeSpan.FromSeconds(1)
        };
        var stores = identities.ToDictionary(
            identity => identity.Id,
            identity => new ReplicatedMailboxStore(
                Path.Combine(_root, identity.Id.Value),
                options,
                _clock));
        var authorizer = new AllowPeers(identities.Select(identity => identity.Id));
        var receivers = identities.Skip(1).ToDictionary(
            identity => identity.Id,
            identity => new MailboxReplicaReceiver(
                identity.Id,
                identity.Seed,
                options,
                stores[identity.Id],
                authorizer,
                new MailboxReplicaReplayGuard(),
                _clock));
        var client = new InMemoryPeerClient(receivers, unavailable: identities[2].Id);
        var coordinator = new MailboxReplicationCoordinator(
            identities[0].Id,
            identities[0].Seed,
            options,
            stores[identities[0].Id],
            client,
            _clock);
        var blob = Blob([10, 20, 30, 40]);

        var result = await coordinator.PutAsync(blob,
        [
            new MailboxReplicaPeer(identities[1].Id, "https://node-2/api/peer/mailbox/replica"),
            new MailboxReplicaPeer(identities[2].Id, "https://node-3/api/peer/mailbox/replica")
        ]);

        Assert.True(result.QuorumAchieved);
        Assert.Equal(2, result.Receipts.Count);
        Assert.Single(await stores[identities[0].Id].ReadAsync(blob.MailboxId, 10));
        Assert.Single(await stores[identities[1].Id].ReadAsync(blob.MailboxId, 10));
        Assert.Empty(await stores[identities[2].Id].ReadAsync(blob.MailboxId, 10));

        var duplicate = await coordinator.PutAsync(blob,
        [
            new MailboxReplicaPeer(identities[1].Id, "https://node-2/api/peer/mailbox/replica"),
            new MailboxReplicaPeer(identities[2].Id, "https://node-3/api/peer/mailbox/replica")
        ]);
        Assert.True(duplicate.QuorumAchieved);
        Assert.Equal(1, coordinator.Metrics.Duplicates);
        Assert.Equal(1, receivers[identities[1].Id].Metrics.Duplicates);
    }

    [Fact]
    public async Task Receiver_FailsClosedForUnregisteredPeerAndTamperedCiphertext()
    {
        var sender = Identity(1);
        var receiverIdentity = Identity(2);
        var options = new ReplicatedMailboxOptions { Enabled = true };
        var store = new ReplicatedMailboxStore(_root, options, _clock);
        var receiver = new MailboxReplicaReceiver(
            receiverIdentity.Id,
            receiverIdentity.Seed,
            options,
            store,
            new AllowPeers([]),
            new MailboxReplicaReplayGuard(),
            _clock);
        var blob = Blob([1, 2, 3]);
        var request = MailboxReplicationProtocol.SignRequest(
            sender.Id,
            receiverIdentity.Id,
            sender.Seed,
            blob,
            _clock.UtcNow);

        Assert.Equal(
            MailboxReplicaReceiveStatus.Unauthorized,
            (await receiver.ReceiveAsync(request)).Status);

        var authorized = new MailboxReplicaReceiver(
            receiverIdentity.Id,
            receiverIdentity.Seed,
            options,
            store,
            new AllowPeers([sender.Id]),
            new MailboxReplicaReplayGuard(),
            _clock);
        Assert.Equal(
            MailboxReplicaReceiveStatus.Unauthorized,
            (await authorized.ReceiveAsync(request with
            {
                Blob = request.Blob with { Ciphertext = Convert.ToBase64String([9, 9, 9]) }
            })).Status);
        Assert.Empty(await store.ReadAsync(blob.MailboxId, 10));
    }

    [Fact]
    public async Task HttpPeerClient_RejectsPrivateEndpointBeforeNetworkAccess()
    {
        var sender = Identity(1);
        var peer = Identity(2);
        var handler = new CountingHandler(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        using var http = new HttpClient(handler);
        var client = new HttpMailboxReplicaPeerClient(
            http,
            new RouterRuntimeOptions(),
            new ReplicatedMailboxOptions());
        var request = MailboxReplicationProtocol.SignRequest(
            sender.Id,
            peer.Id,
            sender.Seed,
            Blob([1, 2, 3]),
            _clock.UtcNow);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.PutAsync(
            new MailboxReplicaPeer(peer.Id, "http://10.1.2.3:8081/api/peer/mailbox/replica"),
            request,
            CancellationToken.None));
        Assert.Equal(0, handler.Requests);
    }

    [Fact]
    public async Task HttpPeerClient_RejectsPlainHttpByDefault()
    {
        var sender = Identity(1);
        var peer = Identity(2);
        var handler = new CountingHandler(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        using var http = new HttpClient(handler);
        var client = new HttpMailboxReplicaPeerClient(
            http,
            new RouterRuntimeOptions(),
            new ReplicatedMailboxOptions());
        var request = MailboxReplicationProtocol.SignRequest(
            sender.Id,
            peer.Id,
            sender.Seed,
            Blob([1, 2, 3]),
            _clock.UtcNow);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.PutAsync(
            new MailboxReplicaPeer(peer.Id, "http://8.8.8.8/api/peer/mailbox/replica"),
            request,
            CancellationToken.None));
        Assert.Equal(0, handler.Requests);
    }

    [Fact]
    public async Task HttpPeerClient_BoundsChunkedResponseWithoutTrustingContentLength()
    {
        var sender = Identity(1);
        var peer = Identity(2);
        var content = new StreamContent(new MemoryStream(new byte[1025]));
        content.Headers.ContentLength = null;
        var handler = new CountingHandler(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = content
        });
        using var http = new HttpClient(handler);
        var client = new HttpMailboxReplicaPeerClient(
            http,
            new RouterRuntimeOptions { MaxPeerRequestBodyBytes = 1024 },
            new ReplicatedMailboxOptions());
        var request = MailboxReplicationProtocol.SignRequest(
            sender.Id,
            peer.Id,
            sender.Seed,
            Blob([1, 2, 3]),
            _clock.UtcNow);

        var receipt = await client.PutAsync(
            new MailboxReplicaPeer(peer.Id, "https://8.8.8.8/api/peer/mailbox/replica"),
            request,
            CancellationToken.None);

        Assert.Null(receipt);
        Assert.Equal(1, handler.Requests);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private EncryptedMailboxBlob Blob(byte[] ciphertext)
    {
        var mailboxId = Convert.ToHexString(SHA256.HashData("opaque-rotating-mailbox"u8.ToArray()))
            .ToLowerInvariant();
        var blobId = Convert.ToHexString(SHA256.HashData(ciphertext)).ToLowerInvariant();
        return new EncryptedMailboxBlob(
            mailboxId,
            blobId,
            _clock.UtcNow.AddHours(1).ToUnixTimeMilliseconds(),
            Convert.ToBase64String(ciphertext));
    }

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

    private sealed class AllowPeers : IMailboxPeerAuthorizer
    {
        private readonly IReadOnlySet<RouterId> _allowed;

        public AllowPeers(IEnumerable<RouterId> allowed)
        {
            _allowed = allowed.ToHashSet();
        }

        public bool IsAuthorized(RouterId routerId, DateTimeOffset now) => _allowed.Contains(routerId);
    }

    private sealed class InMemoryPeerClient : IMailboxReplicaPeerClient
    {
        private readonly IReadOnlyDictionary<RouterId, MailboxReplicaReceiver> _receivers;
        private readonly RouterId _unavailable;
        private readonly ConcurrentDictionary<string, byte> _seen = new();

        public InMemoryPeerClient(
            IReadOnlyDictionary<RouterId, MailboxReplicaReceiver> receivers,
            RouterId unavailable)
        {
            _receivers = receivers;
            _unavailable = unavailable;
        }

        public async Task<MailboxWriteReceipt?> PutAsync(
            MailboxReplicaPeer peer,
            SignedMailboxReplicaRequest request,
            CancellationToken cancellationToken)
        {
            if (peer.RouterId == _unavailable)
            {
                throw new HttpRequestException("simulated unavailable node");
            }

            _seen.TryAdd($"{peer.RouterId}:{request.Blob.BlobId}", 0);
            return (await _receivers[peer.RouterId].ReceiveAsync(request, cancellationToken)).Receipt;
        }
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public CountingHandler(HttpResponseMessage response)
        {
            _response = response;
        }

        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(_response);
        }
    }
}
