using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ReplicatedMailboxIntegrationTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"xnode-prq2-integration-{Guid.NewGuid():N}");

    [Fact]
    public async Task Coordinator_RequiresExactTwoOfTwoAndEmitsVerifiedMqr3()
    {
        var fixture = new Fixture(_root);
        using var recipient = await fixture.OpenRecipientAsync();
        using var sender = await fixture.OpenSenderAsync(
            new ReceiverPeerClient(recipient.Receiver));

        var result = await sender.Coordinator.ReplicateAsync(
            fixture.RecipientPeer,
            fixture.CanonicalStore,
            fixture.Policy);

        Assert.Equal(MailboxPeerQuorumStatus.Durable, result.Status);
        Assert.Equal(2, result.DurableReplicaCount);
        Assert.Equal(776, result.CanonicalMqr3.Length);
        var verified = MailboxPeerWireV2Codec.VerifyAndReserve(
            fixture.CanonicalStore,
            fixture.Policy,
            fixture.Crypto,
            fixture.MembershipVerifier,
            sender.Journal);
        var quorum = MailboxPeerWireV2Codec.VerifyDurableQuorumResponse(
            result.CanonicalMqr3.Span,
            verified,
            fixture.Crypto);
        Assert.Equal(2, quorum.ReplicaReceipts.Count);
        Assert.Equal(
            new[] { fixture.SenderId.Value, fixture.RecipientId.Value }.Order(StringComparer.Ordinal),
            quorum.ReplicaReceipts
                .Select(receipt => Convert.ToHexString(receipt.ReplicaId.Span).ToLowerInvariant())
                .Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task PartialFailure_IsNeverQuorumAndExactRetryCanResume()
    {
        var fixture = new Fixture(_root);
        var switchable = new SwitchablePeerClient();
        using var sender = await fixture.OpenSenderAsync(switchable);

        var partial = await sender.Coordinator.ReplicateAsync(
            fixture.RecipientPeer,
            fixture.CanonicalStore,
            fixture.Policy);

        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, partial.Status);
        Assert.Equal(1, partial.DurableReplicaCount);
        Assert.True(partial.CanonicalMqr3.IsEmpty);

        using var recipient = await fixture.OpenRecipientAsync();
        switchable.Receiver = recipient.Receiver;
        var resumed = await sender.Coordinator.ReplicateAsync(
            fixture.RecipientPeer,
            fixture.CanonicalStore,
            fixture.Policy);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, resumed.Status);
        Assert.Equal(2, resumed.DurableReplicaCount);
    }

    [Fact]
    public async Task Coordinator_RestartsAndPastFreshnessRetry_KeepMqr3ByteIdentical()
    {
        var fixture = new Fixture(_root);
        byte[] canonicalMqr3;
        using (var recipient = await fixture.OpenRecipientAsync())
        using (var sender = await fixture.OpenSenderAsync(
                   new ReceiverPeerClient(recipient.Receiver)))
        {
            var first = await sender.Coordinator.ReplicateAsync(
                fixture.RecipientPeer,
                fixture.CanonicalStore,
                fixture.CurrentPolicy);
            Assert.Equal(MailboxPeerQuorumStatus.Durable, first.Status);
            canonicalMqr3 = first.CanonicalMqr3.ToArray();
        }

        fixture.Clock.UtcNow += TimeSpan.FromSeconds(
            MailboxPeerWireV2Limits.MaximumPastAgeSeconds + 1);
        using (var recipient = await fixture.OpenRecipientAsync())
        using (var sender = await fixture.OpenSenderAsync(
                   new ReceiverPeerClient(recipient.Receiver)))
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var retry = await sender.Coordinator.ReplicateAsync(
                    fixture.RecipientPeer,
                    fixture.CanonicalStore,
                    fixture.CurrentPolicy);
                Assert.Equal(MailboxPeerQuorumStatus.Durable, retry.Status);
                Assert.Equal(canonicalMqr3, retry.CanonicalMqr3.ToArray());
            }
        }

        using var secondRecipientRestart = await fixture.OpenRecipientAsync();
        using var secondSenderRestart = await fixture.OpenSenderAsync(
            new ReceiverPeerClient(secondRecipientRestart.Receiver));
        var finalRetry = await secondSenderRestart.Coordinator.ReplicateAsync(
            fixture.RecipientPeer,
            fixture.CanonicalStore,
            fixture.CurrentPolicy);
        Assert.Equal(MailboxPeerQuorumStatus.Durable, finalRetry.Status);
        Assert.Equal(canonicalMqr3, finalRetry.CanonicalMqr3.ToArray());
    }

    [Fact]
    public async Task DeadlineOrInvalidMrr2_CountsOnlyTheLocalReplica()
    {
        var timeoutFixture = new Fixture(Path.Combine(_root, "timeout"));
        var timeoutOptions = timeoutFixture.Options;
        timeoutOptions.PeerTimeout = TimeSpan.FromMilliseconds(50);
        using (var sender = await timeoutFixture.OpenSenderAsync(new HangingPeerClient()))
        {
            var timedOut = await sender.Coordinator.ReplicateAsync(
                timeoutFixture.RecipientPeer,
                timeoutFixture.CanonicalStore,
                timeoutFixture.Policy);
            Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, timedOut.Status);
            Assert.Equal(1, timedOut.DurableReplicaCount);
        }

        var invalidFixture = new Fixture(Path.Combine(_root, "invalid"));
        using var invalidSender = await invalidFixture.OpenSenderAsync(
            new ConstantPeerClient(new byte[MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength]));
        var invalid = await invalidSender.Coordinator.ReplicateAsync(
            invalidFixture.RecipientPeer,
            invalidFixture.CanonicalStore,
            invalidFixture.Policy);
        Assert.Equal(MailboxPeerQuorumStatus.PartialFailure, invalid.Status);
        Assert.Equal(1, invalid.DurableReplicaCount);
    }

    [Fact]
    public async Task HttpPeerClient_UsesOnlyCanonicalPathsMediaAndExactMrr2Length()
    {
        var fixture = new Fixture(_root);
        var responseBytes = Enumerable.Repeat(
            (byte)0x5a,
            MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength).ToArray();
        var handler = new CaptureHandler(responseBytes);
        var client = new HttpMailboxReplicaPeerClient(
            new HttpClient(handler),
            XNode.Core.Runtime.PeerEndpointPolicy.PublicOnly(),
            new ReplicatedMailboxOptions
            {
                Enabled = true,
                AllowInsecureHttpPeerTransport = true
            });
        var peer = new MailboxReplicaPeer(
            fixture.RecipientId,
            $"https://recipient.test{MailboxWireHttpContract.PeerStoreRoute}");

        var result = await client.SendAsync(
            peer,
            MailboxPeerReplicationOperation.Store,
            fixture.CanonicalStore,
            CancellationToken.None);

        Assert.Equal(responseBytes, result?.ToArray());
        Assert.Equal(MailboxWireHttpContract.PeerStoreRoute, handler.SeenUri?.AbsolutePath);
        Assert.Equal(
            MailboxWireHttpContract.Prq2ContentType,
            handler.SeenContentType);
        Assert.Equal(fixture.CanonicalStore.Length, handler.SeenContentLength);
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.SendAsync(
                peer with { Endpoint = "http://127.0.0.1:8081/api/peer/mailbox/replica" },
                MailboxPeerReplicationOperation.Store,
                fixture.CanonicalStore,
                CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.SendAsync(
                peer with
                {
                    Endpoint =
                        $"https://attacker.test{MailboxWireHttpContract.PeerStoreRoute}"
                },
                MailboxPeerReplicationOperation.Store,
                fixture.CanonicalStore,
                CancellationToken.None));
    }

    [Fact]
    public void HttpPreflight_EnforcesContentLengthMediaEncodingAndOperationBounds()
    {
        var contract = MailboxWireHttpContract.PeerStore;
        var context = new DefaultHttpContext();
        Assert.Equal(
            MailboxHttpFailure.MissingContentLength,
            MailboxPeerHttpRequestValidator.Validate(context.Request, contract));

        context.Request.ContentLength = contract.MinimumRequestBytes;
        context.Request.ContentType = "application/json";
        Assert.Equal(
            MailboxHttpFailure.UnsupportedContentTypeOrEncoding,
            MailboxPeerHttpRequestValidator.Validate(context.Request, contract));

        context.Request.ContentType = contract.RequestContentType;
        context.Request.Headers.ContentEncoding = "gzip";
        Assert.Equal(
            MailboxHttpFailure.UnsupportedContentTypeOrEncoding,
            MailboxPeerHttpRequestValidator.Validate(context.Request, contract));

        context.Request.Headers.Remove("Content-Encoding");
        context.Request.ContentLength = contract.MinimumRequestBytes - 1;
        Assert.Equal(
            MailboxHttpFailure.MalformedCanonicalBody,
            MailboxPeerHttpRequestValidator.Validate(context.Request, contract));
        context.Request.ContentLength = contract.MaximumRequestBytes + 1;
        Assert.Equal(
            MailboxHttpFailure.PayloadTooLarge,
            MailboxPeerHttpRequestValidator.Validate(context.Request, contract));
        context.Request.ContentLength = contract.MaximumRequestBytes;
        Assert.Null(MailboxPeerHttpRequestValidator.Validate(context.Request, contract));
    }

    [Fact]
    public void PreAuthAdmission_IsHostGlobalAndPerOperationForRateAndConcurrency()
    {
        var now = 1000UL;
        var rate = new MailboxPeerIngressLimiter();
        for (var index = 0;
             index < MailboxWireHttpContract.PeerStore.RequestsPerMinute;
             index++)
        {
            Assert.True(rate.TryEnter(
                MailboxPeerReplicationOperation.Store,
                now,
                out var lease));
            lease.Dispose();
        }

        Assert.False(rate.TryEnter(
            MailboxPeerReplicationOperation.Store,
            now,
            out var rejected));
        rejected.Dispose();
        Assert.True(rate.TryEnter(
            MailboxPeerReplicationOperation.Tombstone,
            now,
            out var independent));
        independent.Dispose();

        var concurrency = new MailboxPeerIngressLimiter();
        var held = new List<IDisposable>();
        try
        {
            for (var index = 0;
                 index < MailboxWireHttpContract.PeerStore.MaximumConcurrentRequests;
                 index++)
            {
                Assert.True(concurrency.TryEnter(
                    MailboxPeerReplicationOperation.Store,
                    now,
                    out var lease));
                held.Add(lease);
            }

            Assert.False(concurrency.TryEnter(
                MailboxPeerReplicationOperation.Store,
                now,
                out var saturated));
            saturated.Dispose();
            Assert.True(concurrency.TryEnter(
                MailboxPeerReplicationOperation.Tombstone,
                now,
                out var otherEndpoint));
            otherEndpoint.Dispose();
        }
        finally
        {
            foreach (var lease in held)
            {
                lease.Dispose();
            }
        }
    }

    [Fact]
    public async Task PeerStartup_EagerlyRejectsCorruptDurableStateAndFailsReadiness()
    {
        var root = Path.Combine(_root, "startup-corruption");
        var options = Fixture.CreateOptions();
        Directory.CreateDirectory(Path.Combine(root, options.PeerMutationDirectoryName));
        await File.WriteAllTextAsync(
            Path.Combine(root, options.PeerMutationDirectoryName, "corrupt.json"),
            "{}");
        var clock = new FixedClock(
            new DateTimeOffset(2026, 7, 28, 8, 0, 0, TimeSpan.Zero));
        var services = new ServiceCollection();
        services.AddSingleton<IClock>(clock);
        services.AddSingleton(options);
        services.AddSingleton(provider => new ReplicatedMailboxStore(
            root,
            options,
            provider.GetRequiredService<IClock>()));
        services.AddSingleton(provider => new DurableMailboxPeerReplayJournal(
            root,
            options,
            provider.GetRequiredService<IClock>()));
        services.AddSingleton(provider => new MailboxPeerMutationStore(
            root,
            options,
            provider.GetRequiredService<ReplicatedMailboxStore>(),
            provider.GetRequiredService<IClock>()));
        using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<ReplicatedMailboxStore>().InitializeAsync();
        var readiness = new MailboxPeerRuntimeReadiness();
        var hosted = new MailboxPeerStoreHostedService(options, provider, readiness);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            hosted.StartAsync(CancellationToken.None));
        Assert.False(readiness.Ready);
        Assert.Equal("failed", readiness.Status);
    }

    [Theory]
    [InlineData("replay")]
    [InlineData("mutation")]
    public async Task PeerReadiness_RejectsFutureRetainedSemanticCorruption(
        string journalKind)
    {
        var fixture = new Fixture(_root);
        using (var runtime = await fixture.OpenRecipientAsync())
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.Accepted,
                (await runtime.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        var root = Path.Combine(_root, "recipient");
        var directory = journalKind == "replay"
            ? fixture.Options.PeerReplayDirectoryName
            : fixture.Options.PeerMutationDirectoryName;
        var path = Assert.Single(Directory.EnumerateFiles(
            Path.Combine(root, directory),
            "*.json"));
        var record = Assert.IsType<JsonObject>(JsonNode.Parse(await File.ReadAllTextAsync(path)));
        if (journalKind == "replay")
        {
            record["canonicalResponse"] = Convert.ToBase64String(
                new byte[MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength]);
        }
        else
        {
            record["retainUntilUnixSeconds"] =
                record["retainUntilUnixSeconds"]!.GetValue<ulong>() + 1;
        }

        await File.WriteAllTextAsync(path, record.ToJsonString());
        var services = new ServiceCollection();
        services.AddSingleton<IClock>(fixture.Clock);
        services.AddSingleton(fixture.Options);
        services.AddSingleton(provider => new ReplicatedMailboxStore(
            root,
            fixture.Options,
            provider.GetRequiredService<IClock>()));
        services.AddSingleton(provider => new DurableMailboxPeerReplayJournal(
            root,
            fixture.Options,
            provider.GetRequiredService<IClock>()));
        services.AddSingleton(provider => new MailboxPeerMutationStore(
            root,
            fixture.Options,
            provider.GetRequiredService<ReplicatedMailboxStore>(),
            provider.GetRequiredService<IClock>()));
        using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<ReplicatedMailboxStore>().InitializeAsync();
        var readiness = new MailboxPeerRuntimeReadiness();
        var hosted = new MailboxPeerStoreHostedService(
            fixture.Options,
            provider,
            readiness);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            hosted.StartAsync(CancellationToken.None));
        Assert.False(readiness.Ready);
        Assert.Equal("failed", readiness.Status);
    }

    [Fact]
    public async Task LegacyEndpointIs404AndCanonicalPeerRoutesAreNotPublicListenerRoutes()
    {
        using var factory = new NoHostedServicesFactory();
        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var legacy = await client.PostAsync(
            "/api/peer/mailbox/replica",
            new ByteArrayContent([]));
        using var canonical = await client.PostAsync(
            MailboxWireHttpContract.PeerStoreRoute,
            new ByteArrayContent([]));
        using var wrongStoreMethod = await client.GetAsync(
            MailboxWireHttpContract.PeerStoreRoute);
        using var wrongTombstoneMethod = await client.PutAsync(
            MailboxWireHttpContract.PeerTombstoneRoute,
            new ByteArrayContent([]));
        using var dormantClientStore = await client.PostAsync(
            MailboxWireHttpContract.StoreRoute,
            new ByteArrayContent([]));
        using var dormantClientRetrieve = await client.PostAsync(
            MailboxWireHttpContract.RetrieveRoute,
            new ByteArrayContent([]));
        using var dormantClientAck = await client.PostAsync(
            MailboxWireHttpContract.AcknowledgeRoute,
            new ByteArrayContent([]));

        Assert.Equal(System.Net.HttpStatusCode.NotFound, legacy.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, canonical.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, wrongStoreMethod.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, wrongTombstoneMethod.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, dormantClientStore.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, dormantClientRetrieve.StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NotFound, dormantClientAck.StatusCode);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class Fixture
    {
        private readonly string _root;
        private readonly byte[] _senderSeed = Range(0x10, 32);
        private readonly byte[] _recipientSeed = Range(0x50, 32);
        private readonly FixedClock _clock = new(
            new DateTimeOffset(2026, 7, 28, 8, 0, 0, TimeSpan.Zero));

        public Fixture(string root)
        {
            _root = root;
            Crypto = new SodiumMailboxPeerReplicationCrypto();
            SenderId = RouterId.FromBytes(Range(0x01, 32));
            RecipientId = RouterId.FromBytes(Range(0x41, 32));
            var descriptors = new[]
            {
                Descriptor(SenderId, Crypto.GetPublicKey(_senderSeed), "https://sender.test"),
                Descriptor(RecipientId, Crypto.GetPublicKey(_recipientSeed), "https://recipient.test")
            };
            var commitment = MembershipRouteDescriptorCodec.ComputeRoot(descriptors);
            var inclusion = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
            var senderProof = Proof(descriptors[0], inclusion[0], commitment);
            var recipientProof = Proof(descriptors[1], inclusion[1], commitment);
            Envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(Range(0xc0, 32)),
                PlacementId = new BlindedPlacementId(Range(0xa0, 32)),
                OperationId = Range(0x70, 16),
                DeduplicationDigest = SHA256.HashData(Range(1, 64)),
                CreatedAtUnixSeconds = Now - 30,
                ExpiresAtUnixSeconds = Now + 3600,
                Ciphertext = Range(1, 64)
            };
            var payload = MailboxClientCodec.EncodeEncryptedEnvelope(Envelope);
            var unsigned = new MailboxPeerWireRequestV2
            {
                Operation = MailboxPeerReplicationOperation.Store,
                Epoch = 7,
                OperationId = Envelope.OperationId,
                SenderRouterId = SenderId.ToBytes(),
                RecipientRouterId = RecipientId.ToBytes(),
                MembershipCommitment = commitment,
                PlacementCommitment = MailboxPlacementCommitment.Compute(Envelope.PlacementId),
                BlindedMailboxId = Envelope.MailboxId.Bytes,
                Cursor = 42,
                CreatedAtUnixSeconds = Now,
                ExpiresAtUnixSeconds = Envelope.ExpiresAtUnixSeconds,
                ReplayNonce = Range(0x30, 32),
                PayloadDigest = SHA256.HashData(payload),
                Payload = payload,
                SenderMembershipProof = senderProof,
                RecipientMembershipProof = recipientProof,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            CanonicalStore = MailboxPeerWireV2Codec.Encode(
                Crypto.SignRequest(unsigned, _senderSeed));
            Options = CreateOptions();
            Authority = new MailboxPeerAuthorityOptions
            {
                CurrentEpoch = 7,
                CurrentMembershipCommitment =
                    Convert.ToHexString(commitment).ToLowerInvariant(),
                CurrentEpochExpiresAtUnixSeconds = Now + 7200,
                PlacementSelections =
                [
                    new()
                    {
                        Epoch = 7,
                        PlacementCommitment = Convert.ToHexString(
                            unsigned.PlacementCommitment.Span).ToLowerInvariant(),
                        FirstRouterId = SenderId.Value,
                        SecondRouterId = RecipientId.Value
                    }
                ]
            };
            Policy = new MailboxPeerWireVerificationPolicyV2
            {
                ExpectedOperation = MailboxPeerReplicationOperation.Store,
                Epoch = 7,
                OperationId = Envelope.OperationId,
                SenderRouterId = SenderId.ToBytes(),
                RecipientRouterId = RecipientId.ToBytes(),
                MembershipCommitment = commitment,
                PlacementCommitment = unsigned.PlacementCommitment,
                PlacementId = Envelope.PlacementId,
                NowUnixSeconds = Now,
                EpochExpiresAtUnixSeconds = Now + 7200
            };
            RecipientPeer = new MailboxReplicaPeer(
                RecipientId,
                $"https://recipient.test{MailboxWireHttpContract.PeerStoreRoute}");
        }

        public SodiumMailboxPeerReplicationCrypto Crypto { get; }
        public MembershipRoutesMailboxReplicaProofVerifier MembershipVerifier { get; } = new();
        public RouterId SenderId { get; }
        public RouterId RecipientId { get; }
        public MailboxEncryptedEnvelope Envelope { get; }
        public byte[] CanonicalStore { get; }
        public ReplicatedMailboxOptions Options { get; }
        public MailboxPeerAuthorityOptions Authority { get; }
        public FixedClock Clock => _clock;
        public MailboxPeerWireVerificationPolicyV2 Policy { get; }
        public MailboxPeerWireVerificationPolicyV2 CurrentPolicy =>
            Policy with { NowUnixSeconds = Now };
        public MailboxReplicaPeer RecipientPeer { get; }
        private ulong Now => checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());

        public static ReplicatedMailboxOptions CreateOptions() => new()
        {
            Enabled = true,
            MinimumTtl = TimeSpan.FromSeconds(1),
            MaxPeerReplayRecords = 64,
            MaxPeerReplayRecordsPerRouterPairEpoch = 32,
            MaxPeerMutationRecords = 64
        };

        public async Task<RecipientRuntime> OpenRecipientAsync()
        {
            var root = Path.Combine(_root, "recipient");
            Directory.CreateDirectory(root);
            var blobs = new ReplicatedMailboxStore(root, Options, _clock);
            await blobs.InitializeAsync();
            var mutations = new MailboxPeerMutationStore(root, Options, blobs, _clock);
            await mutations.InitializeAsync();
            var journal = new DurableMailboxPeerReplayJournal(root, Options, _clock);
            var policy = new MailboxPeerRequestPolicyResolver(
                RecipientId,
                Convert.ToHexString(_recipientSeed),
                Authority,
                mutations);
            var receiver = new MailboxReplicaReceiver(
                Convert.ToHexString(_recipientSeed),
                Options,
                mutations,
                policy,
                MembershipVerifier,
                journal,
                _clock);
            return new RecipientRuntime(mutations, journal, receiver);
        }

        public async Task<SenderRuntime> OpenSenderAsync(IMailboxReplicaPeerClient client)
        {
            var root = Path.Combine(_root, "sender");
            Directory.CreateDirectory(root);
            var blobs = new ReplicatedMailboxStore(root, Options, _clock);
            await blobs.InitializeAsync();
            var mutations = new MailboxPeerMutationStore(root, Options, blobs, _clock);
            await mutations.InitializeAsync();
            var journal = new DurableMailboxPeerReplayJournal(root, Options, _clock);
            var coordinator = new MailboxReplicationCoordinator(
                SenderId,
                Convert.ToHexString(_senderSeed),
                Options,
                mutations,
                client,
                MembershipVerifier,
                journal);
            return new SenderRuntime(mutations, journal, coordinator);
        }

        private MembershipRouteDescriptor Descriptor(
            RouterId id,
            byte[] signingKey,
            string endpoint) => new()
        {
            RouterId = id.ToBytes(),
            Ed25519PublicKey = signingKey,
            X25519PublicKey = SHA256.HashData(signingKey),
            RpcEndpoint = endpoint,
            Roles = MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.Storage,
            Epoch = 7,
            ValidFromUnixSeconds = Now - 60,
            ValidUntilUnixSeconds = Now + 7200
        };

        private static MailboxReplicaMembershipProof Proof(
            MembershipRouteDescriptor descriptor,
            MembershipRouteInclusionProof proof,
            byte[] commitment) => new()
        {
            ReplicaId = descriptor.RouterId,
            SigningPublicKey = descriptor.Ed25519PublicKey,
            Epoch = descriptor.Epoch,
            MembershipCommitment = commitment,
            CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(descriptor, proof)
        };

        private static byte[] Range(int start, int length) =>
            Enumerable.Range(start, length)
                .Select(value => unchecked((byte)value))
                .ToArray();
    }

    private sealed record RecipientRuntime(
        MailboxPeerMutationStore Mutations,
        DurableMailboxPeerReplayJournal Journal,
        MailboxReplicaReceiver Receiver) : IDisposable
    {
        public void Dispose()
        {
            Journal.Dispose();
            Mutations.Dispose();
        }
    }

    private sealed record SenderRuntime(
        MailboxPeerMutationStore Mutations,
        DurableMailboxPeerReplayJournal Journal,
        MailboxReplicationCoordinator Coordinator) : IDisposable
    {
        public void Dispose()
        {
            Journal.Dispose();
            Mutations.Dispose();
        }
    }

    private sealed class ReceiverPeerClient(MailboxReplicaReceiver receiver)
        : IMailboxReplicaPeerClient
    {
        public async Task<ReadOnlyMemory<byte>?> SendAsync(
            MailboxReplicaPeer peer,
            MailboxPeerReplicationOperation operation,
            ReadOnlyMemory<byte> canonicalPrq2,
            CancellationToken cancellationToken)
        {
            var result = await receiver.ReceiveAsync(canonicalPrq2, operation, cancellationToken);
            return result.Status == MailboxPeerReceiveStatus.Accepted
                ? result.CanonicalResponse
                : null;
        }
    }

    private sealed class SwitchablePeerClient : IMailboxReplicaPeerClient
    {
        public MailboxReplicaReceiver? Receiver { get; set; }

        public async Task<ReadOnlyMemory<byte>?> SendAsync(
            MailboxReplicaPeer peer,
            MailboxPeerReplicationOperation operation,
            ReadOnlyMemory<byte> canonicalPrq2,
            CancellationToken cancellationToken)
        {
            if (Receiver is null)
            {
                return null;
            }

            var result = await Receiver.ReceiveAsync(canonicalPrq2, operation, cancellationToken);
            return result.Status == MailboxPeerReceiveStatus.Accepted
                ? result.CanonicalResponse
                : null;
        }
    }

    private sealed class HangingPeerClient : IMailboxReplicaPeerClient
    {
        public async Task<ReadOnlyMemory<byte>?> SendAsync(
            MailboxReplicaPeer peer,
            MailboxPeerReplicationOperation operation,
            ReadOnlyMemory<byte> canonicalPrq2,
            CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return null;
        }
    }

    private sealed class ConstantPeerClient(byte[] response) : IMailboxReplicaPeerClient
    {
        public Task<ReadOnlyMemory<byte>?> SendAsync(
            MailboxReplicaPeer peer,
            MailboxPeerReplicationOperation operation,
            ReadOnlyMemory<byte> canonicalPrq2,
            CancellationToken cancellationToken) =>
            Task.FromResult<ReadOnlyMemory<byte>?>(response);
    }

    private sealed class CaptureHandler(byte[] response) : HttpMessageHandler
    {
        public Uri? SeenUri { get; private set; }
        public string? SeenContentType { get; private set; }
        public long? SeenContentLength { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            SeenUri = request.RequestUri;
            SeenContentType = request.Content?.Headers.ContentType?.ToString();
            SeenContentLength = request.Content?.Headers.ContentLength;
            var message = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(response)
            };
            message.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue(
                    MailboxWireHttpContract.Mrr2ContentType);
            return Task.FromResult(message);
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = now;
    }

    private sealed class NoHostedServicesFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHostedService>();
            });
        }
    }
}
