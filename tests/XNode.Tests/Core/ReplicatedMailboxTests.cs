using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ReplicatedMailboxTests : IDisposable
{
    private readonly string _root =
        Path.Combine(Path.GetTempPath(), $"xnode-prq2-{Guid.NewGuid():N}");

    [Fact]
    public async Task CanonicalStore_IsDurableAndExactRetryReturnsIdenticalMrr2()
    {
        var fixture = new PeerFixture(_root);
        using var runtime = await fixture.OpenRecipientAsync();

        var first = await runtime.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        var retry = await runtime.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);

        Assert.Equal(MailboxPeerReceiveStatus.Accepted, first.Status);
        Assert.Equal(
            "b7baab9b4c5d7fe268194a6a75c5b3f0687855b3020a72bbc2382ada6d61387e",
            Convert.ToHexString(SHA256.HashData(fixture.CanonicalStore)).ToLowerInvariant());
        Assert.Equal(
            "385c1625256743518bf7d8c1839561a8aa0c905a593807dc8062b686eccdb6c2",
            Convert.ToHexString(SHA256.HashData(first.CanonicalResponse.Span)).ToLowerInvariant());
        Assert.Equal(MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength, first.CanonicalResponse.Length);
        Assert.Equal(first.CanonicalResponse.ToArray(), retry.CanonicalResponse.ToArray());
        Assert.True(retry.WasCached);
        var decoded = MailboxReceiptV2Codec.DecodeReplica(first.CanonicalResponse.Span);
        Assert.Equal(MailboxReplicaDisposition.Stored, decoded.Disposition);
        Assert.Equal(fixture.RecipientId.ToBytes(), decoded.ReplicaId.ToArray());
        Assert.Single(await runtime.Blobs.ReadAsync(
            Convert.ToHexString(fixture.Envelope.MailboxId.Bytes.Span).ToLowerInvariant(),
            10));
    }

    [Fact]
    public async Task SameNonceEquivocation_FailsClosedWithoutSecondMutation()
    {
        var fixture = new PeerFixture(_root);
        using var runtime = await fixture.OpenRecipientAsync();
        Assert.Equal(
            MailboxPeerReceiveStatus.Accepted,
            (await runtime.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store)).Status);
        var conflict = fixture.Sign(fixture.StoreRequest with
        {
            Cursor = fixture.StoreRequest.Cursor + 1,
            Signature = ReadOnlyMemory<byte>.Empty
        });

        var result = await runtime.Receiver.ReceiveAsync(
            MailboxPeerWireV2Codec.Encode(conflict),
            MailboxPeerReplicationOperation.Store);

        Assert.Equal(MailboxPeerReceiveStatus.Conflict, result.Status);
        Assert.Single(await runtime.Blobs.ReadAsync(
            Convert.ToHexString(fixture.Envelope.MailboxId.Bytes.Span).ToLowerInvariant(),
            10));
    }

    [Fact]
    public async Task Prq1Mqr2AndCrossOperationFrames_AreNeverAccepted()
    {
        var fixture = new PeerFixture(_root);
        using var runtime = await fixture.OpenRecipientAsync();
        var prq1 = fixture.CanonicalStore.ToArray();
        "PRQ1"u8.CopyTo(prq1);

        Assert.Equal(
            MailboxPeerReceiveStatus.Malformed,
            (await runtime.Receiver.ReceiveAsync(
                prq1,
                MailboxPeerReplicationOperation.Store)).Status);
        Assert.Equal(
            MailboxPeerReceiveStatus.AuthorizationFailed,
            (await runtime.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Tombstone)).Status);
        Assert.Equal(
            MailboxPeerReceiveStatus.Malformed,
            (await runtime.Receiver.ReceiveAsync(
                new byte[MailboxReceiptV2Limits.QuorumFixedHeaderLength],
                MailboxPeerReplicationOperation.Store)).Status);
    }

    [Fact]
    public async Task ZeroFutureSkewAndForgedMembershipKey_FailClosed()
    {
        var fixture = new PeerFixture(_root);
        using var runtime = await fixture.OpenRecipientAsync();
        var future = fixture.Sign(fixture.StoreRequest with
        {
            CreatedAtUnixSeconds = fixture.NowUnixSeconds + 1,
            Signature = ReadOnlyMemory<byte>.Empty
        });
        var forgedProof = fixture.StoreRequest.RecipientMembershipProof with
        {
            SigningPublicKey = SHA256.HashData("forged"u8)
        };
        var forged = fixture.Sign(fixture.StoreRequest with
        {
            RecipientMembershipProof = forgedProof,
            Signature = ReadOnlyMemory<byte>.Empty
        });

        Assert.Equal(
            MailboxPeerReceiveStatus.Conflict,
            (await runtime.Receiver.ReceiveAsync(
                MailboxPeerWireV2Codec.Encode(future),
                MailboxPeerReplicationOperation.Store)).Status);
        Assert.Equal(
            MailboxPeerReceiveStatus.AuthorizationFailed,
            (await runtime.Receiver.ReceiveAsync(
                MailboxPeerWireV2Codec.Encode(forged),
                MailboxPeerReplicationOperation.Store)).Status);
    }

    [Fact]
    public async Task VerifiedSenderRateLimit_UsesTheProtocol120PerMinuteBound()
    {
        var fixture = new PeerFixture(_root);
        using var runtime = await fixture.OpenRecipientAsync();
        for (var index = 0; index < MailboxWireHttpContract.PeerStore.RequestsPerMinute; index++)
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.Accepted,
                (await runtime.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        Assert.Equal(
            MailboxPeerReceiveStatus.RateLimited,
            (await runtime.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store)).Status);
    }

    [Fact]
    public void PeerAuthorityAndTwoOfTwoQuorumConfiguration_FailClosed()
    {
        var invalidQuorum = PeerFixture.Options();
        invalidQuorum.ReplicationFactor = 3;
        Assert.Throws<InvalidOperationException>(invalidQuorum.Validate);
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxPeerAuthorityOptions().Validate(required: true));

        var same = Convert.ToHexString(PeerFixture.Range(1, 32)).ToLowerInvariant();
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxPeerAuthorityOptions
            {
                CurrentEpoch = 7,
                CurrentMembershipCommitment = same,
                CurrentEpochExpiresAtUnixSeconds = 100,
                NextEpoch = 8,
                NextMembershipCommitment = same,
                NextEpochExpiresAtUnixSeconds = 200
            }.Validate(required: true));
    }

    [Fact]
    public async Task PersistedPendingClaim_RecoversAfterRestartAndThenCaches()
    {
        var fixture = new PeerFixture(_root);
        using (var first = await fixture.OpenRecipientAsync())
        {
            var decoded = MailboxPeerWireV2Codec.Decode(fixture.CanonicalStore);
            var policy = Assert.IsType<MailboxPeerWireVerificationPolicyV2>(
                first.Policy.Resolve(
                    decoded,
                    MailboxPeerReplicationOperation.Store,
                    fixture.NowUnixSeconds));
            var verified = MailboxPeerWireV2Codec.VerifyAndReserve(
                fixture.CanonicalStore,
                policy,
                fixture.Crypto,
                first.MembershipVerifier,
                first.Journal);
            Assert.Equal(MailboxPeerReplayDisposition.NewReserved, verified.ReplayDisposition);
        }

        ReadOnlyMemory<byte> recoveredResponse;
        using (var recovered = await fixture.OpenRecipientAsync())
        {
            var result = await recovered.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store);
            Assert.Equal(MailboxPeerReceiveStatus.Accepted, result.Status);
            recoveredResponse = result.CanonicalResponse.ToArray();
        }

        using var final = await fixture.OpenRecipientAsync();
        var retry = await final.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        Assert.True(retry.WasCached);
        Assert.Equal(recoveredResponse.ToArray(), retry.CanonicalResponse.ToArray());
    }

    [Fact]
    public async Task CrashAfterDurableMutationBeforeReplayCompletion_RecoversStoredDisposition()
    {
        var fixture = new PeerFixture(_root);
        using (var crashing = await fixture.OpenRecipientAsync(failReplayCompletion: true))
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.DependencyUnavailable,
                (await crashing.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
            Assert.Single(await crashing.Blobs.ReadAsync(
                Convert.ToHexString(fixture.Envelope.MailboxId.Bytes.Span).ToLowerInvariant(),
                10));
        }

        using var recovered = await fixture.OpenRecipientAsync();
        var result = await recovered.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerReceiveStatus.Accepted, result.Status);
        Assert.Equal(
            MailboxReplicaDisposition.Stored,
            MailboxReceiptV2Codec.DecodeReplica(result.CanonicalResponse.Span).Disposition);
    }

    [Fact]
    public async Task Tombstone_IsLogicalBeforeCleanupAndDurablyIdempotent()
    {
        var fixture = new PeerFixture(_root);
        using var runtime = await fixture.OpenRecipientAsync();
        Assert.Equal(
            MailboxPeerReceiveStatus.Accepted,
            (await runtime.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store)).Status);
        var tombstone = fixture.CanonicalTombstone();

        var first = await runtime.Receiver.ReceiveAsync(
            tombstone,
            MailboxPeerReplicationOperation.Tombstone);
        var retry = await runtime.Receiver.ReceiveAsync(
            tombstone,
            MailboxPeerReplicationOperation.Tombstone);

        Assert.Equal(MailboxPeerReceiveStatus.Accepted, first.Status);
        Assert.Equal(
            MailboxReplicaDisposition.Tombstone,
            MailboxReceiptV2Codec.DecodeReplica(first.CanonicalResponse.Span).Disposition);
        Assert.True(retry.WasCached);
        Assert.Equal(first.CanonicalResponse.ToArray(), retry.CanonicalResponse.ToArray());
        Assert.Empty(await runtime.Blobs.ReadAsync(
            Convert.ToHexString(fixture.Envelope.MailboxId.Bytes.Span).ToLowerInvariant(),
            10));
    }

    [Fact]
    public void ReplayGc_UsesProtocolRetirementPlusFixedRetentionAndIsBounded()
    {
        var options = PeerFixture.Options();
        Directory.CreateDirectory(_root);
        using var journal = new DurableMailboxPeerReplayJournal(_root, options);
        var claim = new MailboxPeerReplayClaim
        {
            ScopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(
                PeerFixture.Range(1, 32),
                PeerFixture.Range(40, 32),
                7,
                PeerFixture.Range(80, 32)),
            RequestDigest = PeerFixture.Range(120, 32),
            SenderRouterId = PeerFixture.Range(1, 32),
            RecipientRouterId = PeerFixture.Range(40, 32),
            ReplayNonce = PeerFixture.Range(80, 32),
            OperationId = PeerFixture.Range(160, 16),
            Operation = MailboxPeerReplicationOperation.Store,
            Epoch = 7,
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1100,
            ReservedAtUnixSeconds = 1050,
            EpochExpiresAtUnixSeconds = 1200,
            RetainUntilUnixSeconds = 1200 + MailboxPeerWireV2Limits.ReplayRetentionSeconds
        };
        Assert.Equal(
            MailboxPeerReplayState.NewReserved,
            journal.EvaluateAndReserve(claim).State);
        Assert.Equal(0, journal.CollectExpired(claim.RetainUntilUnixSeconds - 1, 1));
        Assert.Equal(1, journal.CollectExpired(claim.RetainUntilUnixSeconds, 1));
    }

    [Fact]
    public void ReplayAndMutationJournals_AreExclusive()
    {
        var fixture = new PeerFixture(_root);
        var options = PeerFixture.Options();
        Directory.CreateDirectory(_root);
        using var blobs = new RuntimeBlobOwner(_root, options);
        using var replay = new DurableMailboxPeerReplayJournal(_root, options);
        Assert.Throws<InvalidOperationException>(() =>
            new DurableMailboxPeerReplayJournal(_root, options));
        using var mutations = new MailboxPeerMutationStore(_root, options, blobs.Store);
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxPeerMutationStore(_root, options, blobs.Store));
        GC.KeepAlive(fixture);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class RuntimeBlobOwner : IDisposable
    {
        public RuntimeBlobOwner(string root, ReplicatedMailboxOptions options)
        {
            Store = new ReplicatedMailboxStore(root, options, new FixedClock(TestData.Now));
            Store.InitializeAsync().GetAwaiter().GetResult();
        }

        public ReplicatedMailboxStore Store { get; }
        public void Dispose()
        {
        }
    }

    private sealed class PeerFixture
    {
        private readonly FixedClock _clock = new(TestData.Now);
        private readonly string _root;
        private readonly byte[] _senderSeed = Range(0x10, 32);
        private readonly byte[] _recipientSeed = Range(0x50, 32);

        public PeerFixture(string root)
        {
            _root = root;
            Crypto = new SodiumMailboxPeerReplicationCrypto();
            SenderId = RouterId.FromBytes(Crypto.GetPublicKey(_senderSeed));
            RecipientId = RouterId.FromBytes(Crypto.GetPublicKey(_recipientSeed));
            var descriptors = new[]
            {
                Descriptor(SenderId, Crypto.GetPublicKey(_senderSeed), "https://sender.test"),
                Descriptor(RecipientId, Crypto.GetPublicKey(_recipientSeed), "https://recipient.test")
            };
            var rootCommitment = MembershipRouteDescriptorCodec.ComputeRoot(descriptors);
            var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
            SenderProof = Proof(descriptors[0], proofs[0], rootCommitment);
            RecipientProof = Proof(descriptors[1], proofs[1], rootCommitment);
            Envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(Range(0xc0, 32)),
                PlacementId = new BlindedPlacementId(Range(0xa0, 32)),
                OperationId = Range(0x70, 16),
                DeduplicationDigest = SHA256.HashData(Range(1, 64)),
                CreatedAtUnixSeconds = NowUnixSeconds - 30,
                ExpiresAtUnixSeconds = NowUnixSeconds + 3600,
                Ciphertext = Range(1, 64)
            };
            var payload = MailboxClientCodec.EncodeEncryptedEnvelope(Envelope);
            StoreRequest = new MailboxPeerWireRequestV2
            {
                Operation = MailboxPeerReplicationOperation.Store,
                Epoch = 7,
                OperationId = Envelope.OperationId,
                SenderRouterId = SenderId.ToBytes(),
                RecipientRouterId = RecipientId.ToBytes(),
                MembershipCommitment = rootCommitment,
                PlacementCommitment = MailboxPlacementCommitment.Compute(Envelope.PlacementId),
                BlindedMailboxId = Envelope.MailboxId.Bytes,
                Cursor = 42,
                CreatedAtUnixSeconds = NowUnixSeconds,
                ExpiresAtUnixSeconds = Envelope.ExpiresAtUnixSeconds,
                ReplayNonce = Range(0x30, 32),
                PayloadDigest = SHA256.HashData(payload),
                Payload = payload,
                SenderMembershipProof = SenderProof,
                RecipientMembershipProof = RecipientProof,
                Signature = ReadOnlyMemory<byte>.Empty
            };
            CanonicalStore = MailboxPeerWireV2Codec.Encode(Sign(StoreRequest));
            Authority = new MailboxPeerAuthorityOptions
            {
                CurrentEpoch = 7,
                CurrentMembershipCommitment =
                    Convert.ToHexString(rootCommitment).ToLowerInvariant(),
                CurrentEpochExpiresAtUnixSeconds = NowUnixSeconds + 7200
            };
        }

        public SodiumMailboxPeerReplicationCrypto Crypto { get; }
        public RouterId SenderId { get; }
        public RouterId RecipientId { get; }
        public MailboxReplicaMembershipProof SenderProof { get; }
        public MailboxReplicaMembershipProof RecipientProof { get; }
        public MailboxEncryptedEnvelope Envelope { get; }
        public MailboxPeerWireRequestV2 StoreRequest { get; }
        public byte[] CanonicalStore { get; }
        public MailboxPeerAuthorityOptions Authority { get; }
        public ulong NowUnixSeconds => checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());

        public MailboxPeerWireRequestV2 Sign(MailboxPeerWireRequestV2 request) =>
            Crypto.SignRequest(
                request with { Signature = ReadOnlyMemory<byte>.Empty },
                _senderSeed);

        public byte[] CanonicalTombstone()
        {
            var payload = Envelope.DeduplicationDigest.ToArray();
            return MailboxPeerWireV2Codec.Encode(Sign(StoreRequest with
            {
                Operation = MailboxPeerReplicationOperation.Tombstone,
                OperationId = Range(0x91, 16),
                ReplayNonce = Range(0x81, 32),
                Payload = payload,
                PayloadDigest = SHA256.HashData(payload),
                Signature = ReadOnlyMemory<byte>.Empty
            }));
        }

        public async Task<PeerRuntime> OpenRecipientAsync(bool failReplayCompletion = false)
        {
            Directory.CreateDirectory(_root);
            var options = Options();
            var blobs = new ReplicatedMailboxStore(_root, options, _clock);
            await blobs.InitializeAsync();
            var mutations = new MailboxPeerMutationStore(_root, options, blobs);
            await mutations.InitializeAsync();
            var journal = new DurableMailboxPeerReplayJournal(_root, options);
            var verifier = new MembershipRoutesMailboxReplicaProofVerifier();
            var policy = new MailboxPeerRequestPolicyResolver(
                RecipientId,
                Convert.ToHexString(_recipientSeed),
                Authority,
                mutations);
            var receiver = new MailboxReplicaReceiver(
                Convert.ToHexString(_recipientSeed),
                options,
                mutations,
                policy,
                verifier,
                failReplayCompletion
                    ? new FailCompletionReplayJournal(journal)
                    : journal,
                _clock);
            return new PeerRuntime(blobs, mutations, journal, verifier, policy, receiver);
        }

        public static ReplicatedMailboxOptions Options() => new()
        {
            Enabled = true,
            MinimumTtl = TimeSpan.FromSeconds(1),
            MaxPeerReplayRecords = 64,
            MaxPeerReplayRecordsPerRouterPairEpoch = 32,
            MaxPeerMutationRecords = 64
        };

        public static byte[] Range(int start, int length) =>
            Enumerable.Range(start, length)
                .Select(value => unchecked((byte)value))
                .ToArray();

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
            ValidFromUnixSeconds = NowUnixSeconds - 60,
            ValidUntilUnixSeconds = NowUnixSeconds + 7200
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
    }

    private sealed class FailCompletionReplayJournal(IMailboxPeerReplayJournal inner)
        : IMailboxPeerReplayJournal
    {
        public MailboxPeerReplayEvaluation EvaluateAndReserve(MailboxPeerReplayClaim claim) =>
            inner.EvaluateAndReserve(claim);

        public void CompleteAtomically(
            MailboxPeerReplayClaim claim,
            ReadOnlyMemory<byte> canonicalMrr2Response) =>
            throw new IOException("simulated-crash-before-replay-completion");

        public int CollectExpired(ulong nowUnixSeconds, int maximumRecords) =>
            inner.CollectExpired(nowUnixSeconds, maximumRecords);
    }

    private sealed record PeerRuntime(
        ReplicatedMailboxStore Blobs,
        MailboxPeerMutationStore Mutations,
        DurableMailboxPeerReplayJournal Journal,
        MembershipRoutesMailboxReplicaProofVerifier MembershipVerifier,
        MailboxPeerRequestPolicyResolver Policy,
        MailboxReplicaReceiver Receiver) : IDisposable
    {
        public void Dispose()
        {
            Journal.Dispose();
            Mutations.Dispose();
        }
    }
}
