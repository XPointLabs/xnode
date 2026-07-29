using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxClientActivatedEndToEndTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-p10e-client-e2e-{Guid.NewGuid():N}");
    private readonly FixedClock _clock = new(
        new DateTimeOffset(2026, 7, 29, 8, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task ActivatedFirstRequestsAndRestartRetries_UseRealPrq2Mrr2AndStableMqr3()
    {
        var fixture = await ActivatedFixture.OpenAsync(_root, _clock);
        using (fixture)
        {
            var storeRequest = fixture.CreateStoreRequest(replayCounter: 1);
            byte[] firstStoreReceipt;
            using (var first = await fixture.OpenCoordinatorAsync())
            {
                var stored = await first.Adapter.StoreAsync(storeRequest);
                Assert.True(
                    stored.Status == MailboxClientStoreStatus.Durable,
                    $"{stored.Status}: {stored.Error}");
                firstStoreReceipt = stored.DurableQuorumReceipt.ToArray();
                Assert.Equal(
                    1UL,
                    MailboxReceiptV3Codec.DecodeDurableQuorum(
                        firstStoreReceipt).CoordinatorSequence);
            }

            Assert.Equal(1, fixture.PeerClient.StoreCalls);
            using (var restarted = await fixture.OpenCoordinatorAsync())
            {
                var retry = await restarted.Adapter.StoreAsync(storeRequest);
                Assert.Equal(MailboxClientStoreStatus.Durable, retry.Status);
                Assert.Equal(firstStoreReceipt, retry.DurableQuorumReceipt.ToArray());

                var retrieve = await restarted.Adapter.RetrieveAsync(
                    fixture.CreateRetrieveRequest(replayCounter: 1));
                Assert.Equal(MailboxClientRetrieveStatus.Success, retrieve.Status);
                var page = MailboxClientCodec.DecodeRetrievePage(
                    retrieve.CanonicalPage.Span,
                    fixture.DecodePolicy);
                var item = Assert.Single(page.Items);

                var ackRequest = fixture.CreateAckRequest(
                    item.ToAcknowledgement(),
                    replayCounter: 2);
                var ack = await restarted.Adapter.AcknowledgeAsync(ackRequest);
                Assert.Equal(MailboxClientAckStatus.Durable, ack.Status);
                var ackReceipt = Assert.Single(ack.Receipts).DurableQuorumReceipt.ToArray();
                Assert.Equal(
                    2UL,
                    MailboxReceiptV3Codec.DecodeDurableQuorum(
                        ackReceipt).CoordinatorSequence);
                fixture.CanonicalAckRequest = ackRequest;
                fixture.CanonicalAckReceipt = ackReceipt;
            }

            Assert.Equal(1, fixture.PeerClient.StoreCalls);
            Assert.Equal(1, fixture.PeerClient.TombstoneCalls);
            using var restartedAgain = await fixture.OpenCoordinatorAsync();
            var ackRetry = await restartedAgain.Adapter.AcknowledgeAsync(
                fixture.CanonicalAckRequest);
            Assert.Equal(MailboxClientAckStatus.Durable, ackRetry.Status);
            Assert.Equal(
                fixture.CanonicalAckReceipt,
                Assert.Single(ackRetry.Receipts).DurableQuorumReceipt.ToArray());
            Assert.Equal(1, fixture.PeerClient.TombstoneCalls);
        }
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class ActivatedFixture : IDisposable
    {
        private readonly string _root;
        private readonly FixedClock _clock;
        private readonly byte[] _issuerSeed = Range(0x90, 32);
        private readonly byte[] _holderSeed = Range(0xb0, 32);
        private readonly byte[] _localSeed = Range(0x10, 32);
        private readonly byte[] _remoteSeed = Range(0x50, 32);
        private readonly byte[] _network = Range(0xe0, 16);
        private readonly byte[] _mailboxId = Range(0x30, 32);
        private readonly byte[] _placementId = Range(0x70, 32);
        private readonly SodiumMailboxCapabilityCrypto _capabilityCrypto = new();
        private readonly MailboxPeerMutationStore _remoteMutations;
        private readonly DurableMailboxPeerReplayJournal _remoteReplay;
        private readonly ReplicatedMailboxStore _localStore;
        private readonly MailboxClientActivationOptions _activation;
        private readonly RouterNodeOptions _node;

        private ActivatedFixture(string root, FixedClock clock)
        {
            _root = root;
            _clock = clock;
            var peerCrypto = new SodiumMailboxPeerReplicationCrypto();
            var localId = peerCrypto.GetPublicKey(_localSeed);
            var remoteId = peerCrypto.GetPublicKey(_remoteSeed);
            LocalRouterId = RouterId.FromBytes(localId);
            RemoteRouterId = RouterId.FromBytes(remoteId);
            var now = Now;
            var current = ProofPair(
                epoch: 7,
                localId,
                remoteId,
                now,
                peerCrypto);
            var next = ProofPair(
                epoch: 8,
                localId,
                remoteId,
                now,
                peerCrypto);
            var placement = MailboxPlacementCommitment.Compute(
                new BlindedPlacementId(_placementId));
            var nextPlacementId = Range(0x71, 32);
            var nextPlacement = MailboxPlacementCommitment.Compute(
                new BlindedPlacementId(nextPlacementId));
            AdapterOptions = new()
            {
                Enabled = true,
                CurrentEpoch = 7,
                NextEpoch = 8,
                CurrentMembershipCommitment = Hex(current.Commitment),
                NextMembershipCommitment = Hex(next.Commitment),
                CurrentNotBeforeUnixSeconds = now - 60,
                NextNotBeforeUnixSeconds = now + 7100,
                CurrentExpiresAtUnixSeconds = now + 7200,
                NextExpiresAtUnixSeconds = now + 10_800,
                MaxOperationEntries = 64,
                MaxCursorAuthorities = 16,
                MaxConcurrentSingleFlights = 16
            };
            _activation = new()
            {
                Enabled = true,
                DevelopmentFixture = new()
                {
                    Enabled = true,
                    NetworkId = Hex(_network),
                    IssuerPublicKey = Hex(_capabilityCrypto.GetPublicKey(_issuerSeed)),
                    MinimumGeneration = 7,
                    MaximumGeneration = 8,
                    IssuerValidFromUnixSeconds = now - 60,
                    IssuerValidUntilUnixSeconds = now + 10_800,
                    CoordinatorUrl = "https://local.test/",
                    CurrentPlacementId = Hex(_placementId),
                    CurrentPlacementCommitment = Hex(placement),
                    NextPlacementId = Hex(nextPlacementId),
                    NextPlacementCommitment = Hex(nextPlacement),
                    ReplicaIds = [Hex(localId), Hex(remoteId)],
                    ReplicaSigningPublicKeys = [Hex(localId), Hex(remoteId)],
                    CurrentLocalMembershipProof = EncodeProof(current.Local),
                    CurrentRemoteMembershipProof = EncodeProof(current.Remote),
                    NextLocalMembershipProof = EncodeProof(next.Local),
                    NextRemoteMembershipProof = EncodeProof(next.Remote)
                }
            };
            _node = new()
            {
                RouterId = Hex(localId),
                Ed25519PrivateKey = Hex(_localSeed),
                PublicHost = "local.test",
                PublicPort = 443
            };
            MailboxOptions = new()
            {
                Enabled = true,
                MinimumTtl = TimeSpan.FromSeconds(1),
                MaxPeerReplayRecords = 64,
                MaxPeerReplayRecordsPerRouterPairEpoch = 32,
                MaxPeerMutationRecords = 64
            };

            var remoteRoot = Path.Combine(root, "remote");
            var remoteStore = new ReplicatedMailboxStore(remoteRoot, MailboxOptions, clock);
            remoteStore.InitializeAsync().GetAwaiter().GetResult();
            _remoteMutations = new(
                remoteRoot,
                MailboxOptions,
                remoteStore,
                clock);
            _remoteMutations.InitializeAsync().GetAwaiter().GetResult();
            _remoteReplay = new(remoteRoot, MailboxOptions, clock);
            var authority = new MailboxPeerAuthorityOptions
            {
                CurrentEpoch = 7,
                CurrentMembershipCommitment = Hex(current.Commitment),
                CurrentEpochExpiresAtUnixSeconds = now + 7200,
                PlacementSelections =
                [
                    new()
                    {
                        Epoch = 7,
                        PlacementCommitment = Hex(placement),
                        FirstRouterId = Hex(localId),
                        SecondRouterId = Hex(remoteId)
                    }
                ]
            };
            var receiver = new MailboxReplicaReceiver(
                Hex(_remoteSeed),
                MailboxOptions,
                _remoteMutations,
                new MailboxPeerRequestPolicyResolver(
                    RemoteRouterId,
                    Hex(_remoteSeed),
                    authority,
                    _remoteMutations),
                new MembershipRoutesMailboxReplicaProofVerifier(),
                _remoteReplay,
                clock);
            PeerClient = new(receiver);

            var localRoot = Path.Combine(root, "local");
            _localStore = new(localRoot, MailboxOptions, clock);
            _localStore.InitializeAsync().GetAwaiter().GetResult();
            DecodePolicy = new()
            {
                NowUnixSeconds = now,
                EpochWindow = AdapterOptions.EpochWindow(),
                CapabilityPolicy = new()
                {
                    CurrentBucket = checked((uint)now),
                    MinimumGeneration = 7,
                    AllowLegacyMirrorOverlap = false,
                    AllowRevoked = false,
                    AllowRecovery = false
                },
                AllowLegacyMirrorOverlap = false
            };
        }

        public MailboxClientAdapterOptions AdapterOptions { get; }
        public ReplicatedMailboxOptions MailboxOptions { get; }
        public RouterId LocalRouterId { get; }
        public RouterId RemoteRouterId { get; }
        public ReceiverPeerClient PeerClient { get; }
        public MailboxClientDecodePolicy DecodePolicy { get; }
        public byte[] CanonicalAckRequest { get; set; } = [];
        public byte[] CanonicalAckReceipt { get; set; } = [];
        private ulong Now => checked((ulong)_clock.UtcNow.ToUnixTimeSeconds());

        public static Task<ActivatedFixture> OpenAsync(string root, FixedClock clock) =>
            Task.FromResult(new ActivatedFixture(root, clock));

        public async Task<CoordinatorRuntime> OpenCoordinatorAsync()
        {
            var localRoot = Path.Combine(_root, "local");
            var ledger = new MailboxClientOperationLedger(
                localRoot,
                AdapterOptions,
                _clock);
            var replay = new DurableMailboxCapabilityReplayJournal(
                localRoot,
                new DurableMailboxCapabilityReplayJournalOptions
                {
                    MaximumScopes = 64
                });
            var runtime = new MailboxAuthenticatedCapabilityRuntime(
                new DevelopmentMailboxCapabilityAuthority(_activation, AdapterOptions),
                new DevelopmentMailboxCapabilityRevocations(_activation),
                replay,
                _clock);
            var verifier = new MailboxAuthenticatedCapabilityVerifier(
                AdapterOptions,
                runtime,
                _clock);
            var fanout = new DevelopmentMailboxReplicaFanout(
                _activation,
                AdapterOptions,
                _node,
                PeerClient);
            var adapter = new MailboxClientStoreAdapter(
                AdapterOptions,
                MailboxOptions,
                _localStore,
                ledger,
                verifier,
                new DevelopmentMailboxReplicaAuthority(_activation, AdapterOptions),
                fanout,
                new MailboxClientReceiptCrypto(LocalRouterId, Hex(_localSeed)),
                _clock,
                fanout);
            await adapter.InitializeAsync();
            return new(adapter, ledger, replay);
        }

        public byte[] CreateStoreRequest(ulong replayCounter)
        {
            var envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(_mailboxId),
                PlacementId = new BlindedPlacementId(_placementId),
                OperationId = Filled(0x11, 16),
                DeduplicationDigest = SHA256.HashData(Range(1, 64)),
                CreatedAtUnixSeconds = Now - 30,
                ExpiresAtUnixSeconds = Now + 3600,
                Ciphertext = Range(1, 64)
            };
            var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
            return MailboxClientCodec.EncodeStore(new()
            {
                Epoch = 7,
                OperationId = envelope.OperationId,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                DepositCapability = OuterCapability(
                    MailboxCapabilityDomain.Deposit,
                    binding,
                    replayCounter,
                    serial: 0x21),
                Envelope = envelope
            });
        }

        public byte[] CreateRetrieveRequest(ulong replayCounter)
        {
            var operationId = Filled(0x31, 16);
            var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
                7,
                operationId,
                new BlindedMailboxId(_mailboxId),
                new BlindedPlacementId(_placementId),
                0,
                10,
                ReadOnlySpan<byte>.Empty);
            return MailboxClientCodec.EncodeRetrieve(new()
            {
                Epoch = 7,
                OperationId = operationId,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                RetrieveCapability = OuterCapability(
                    MailboxCapabilityDomain.Retrieve,
                    binding,
                    replayCounter,
                    serial: 0x41),
                MailboxId = new BlindedMailboxId(_mailboxId),
                PlacementId = new BlindedPlacementId(_placementId),
                AfterCursor = 0,
                MaximumItems = 10,
                ContinuationToken = ReadOnlyMemory<byte>.Empty
            });
        }

        public byte[] CreateAckRequest(
            MailboxAcknowledgement acknowledgement,
            ulong replayCounter)
        {
            var operationId = Filled(0x51, 16);
            var acknowledgements = new[] { acknowledgement };
            var binding = MailboxAuthenticatedRequestTranscript.ForAck(
                7,
                operationId,
                new BlindedMailboxId(_mailboxId),
                new BlindedPlacementId(_placementId),
                isFinalPage: true,
                ReadOnlySpan<byte>.Empty,
                acknowledgements);
            return MailboxClientCodec.EncodeAck(new()
            {
                Epoch = 7,
                OperationId = operationId,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                RetrieveCapability = OuterCapability(
                    MailboxCapabilityDomain.Retrieve,
                    binding,
                    replayCounter,
                    serial: 0x41),
                MailboxId = new BlindedMailboxId(_mailboxId),
                PlacementId = new BlindedPlacementId(_placementId),
                IsFinalPage = true,
                ContinuationToken = ReadOnlyMemory<byte>.Empty,
                Acknowledgements = acknowledgements
            });
        }

        private MailboxCapabilityPresentation OuterCapability(
            MailboxCapabilityDomain domain,
            MailboxAuthenticatedRequestBinding binding,
            ulong replayCounter,
            byte serial)
        {
            var grant = _capabilityCrypto.SignGrant(
                new MailboxAuthenticatedGrant
                {
                    Domain = domain,
                    Lifecycle = MailboxCapabilityLifecycle.Active,
                    NetworkId = _network,
                    Epoch = 7,
                    Generation = 7,
                    Serial = Filled(serial, 16),
                    NotBeforeUnixSeconds = Now - 60,
                    ExpiresAtUnixSeconds = Now + 3600,
                    OverlapUntilUnixSeconds = 0,
                    PlacementCommitment = MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(_placementId)),
                    MembershipCommitment =
                        Convert.FromHexString(AdapterOptions.CurrentMembershipCommitment),
                    IssuerPublicKey = _capabilityCrypto.GetPublicKey(_issuerSeed),
                    HolderPublicKey = _capabilityCrypto.GetPublicKey(_holderSeed),
                    IssuerSignature = ReadOnlyMemory<byte>.Empty
                },
                _issuerSeed);
            var presentation = _capabilityCrypto.SignPresentation(
                grant,
                binding,
                replayCounter,
                _holderSeed);
            var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(presentation);
            MailboxDomainValue domainValue = domain == MailboxCapabilityDomain.Deposit
                ? new RotatingDepositCapability(encoded)
                : new RotatingRetrieveCapability(encoded);
            return new()
            {
                DomainValue = domainValue,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                MixedVersion = MailboxMixedVersionMarker.StrictV1,
                Generation = 7,
                NotBeforeBucket = checked((uint)(Now - 60)),
                ExpiresAtBucket = checked((uint)(Now + 3600)),
                OverlapUntilBucket = 0,
                ReplayCounter = replayCounter,
                IdempotencyKey = Filled(checked((byte)(0x60 + replayCounter)), 16)
            };
        }

        public void Dispose()
        {
            _remoteReplay.Dispose();
            _remoteMutations.Dispose();
        }

        private static Proofs ProofPair(
            ulong epoch,
            byte[] localId,
            byte[] remoteId,
            ulong now,
            SodiumMailboxPeerReplicationCrypto crypto)
        {
            var descriptors = new[]
            {
                Descriptor(epoch, localId, "https://local.test", now),
                Descriptor(epoch, remoteId, "https://remote.test", now)
            };
            var commitment = MembershipRouteDescriptorCodec.ComputeRoot(descriptors);
            var inclusions = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
            return new(
                commitment,
                Proof(descriptors[0], inclusions[0], commitment),
                Proof(descriptors[1], inclusions[1], commitment));
        }

        private static MembershipRouteDescriptor Descriptor(
            ulong epoch,
            byte[] id,
            string endpoint,
            ulong now) => new()
        {
            RouterId = id,
            Ed25519PublicKey = id,
            X25519PublicKey = SHA256.HashData(id),
            RpcEndpoint = endpoint,
            Roles = MembershipRouteRole.Storage,
            Capabilities = MembershipRouteCapability.Storage,
            Epoch = epoch,
            ValidFromUnixSeconds = now - 60,
            ValidUntilUnixSeconds = now + 10_800
        };

        private static MailboxReplicaMembershipProof Proof(
            MembershipRouteDescriptor descriptor,
            MembershipRouteInclusionProof inclusion,
            byte[] commitment) => new()
        {
            ReplicaId = descriptor.RouterId,
            SigningPublicKey = descriptor.Ed25519PublicKey,
            Epoch = descriptor.Epoch,
            MembershipCommitment = commitment,
            CanonicalInclusionProof =
                MailboxReplicaRouteProofCodec.Encode(descriptor, inclusion)
        };

        private static string EncodeProof(MailboxReplicaMembershipProof proof) =>
            Convert.ToBase64String(
                MailboxPeerReplicationCodec.EncodeMembershipProof(proof));

        private static string Hex(ReadOnlySpan<byte> value) =>
            Convert.ToHexString(value).ToLowerInvariant();

        private static byte[] Range(int start, int length) =>
            Enumerable.Range(start, length)
                .Select(value => unchecked((byte)value))
                .ToArray();

        private static byte[] Filled(byte value, int length) =>
            Enumerable.Repeat(value, length).ToArray();

        private sealed record Proofs(
            byte[] Commitment,
            MailboxReplicaMembershipProof Local,
            MailboxReplicaMembershipProof Remote);
    }

    private sealed record CoordinatorRuntime(
        MailboxClientStoreAdapter Adapter,
        MailboxClientOperationLedger Ledger,
        DurableMailboxCapabilityReplayJournal Replay) : IDisposable
    {
        public void Dispose()
        {
            Adapter.Dispose();
            Ledger.Dispose();
            Replay.Dispose();
        }
    }

    private sealed class ReceiverPeerClient(MailboxReplicaReceiver receiver)
        : IMailboxReplicaPeerClient
    {
        public int StoreCalls { get; private set; }
        public int TombstoneCalls { get; private set; }

        public async Task<ReadOnlyMemory<byte>?> SendAsync(
            MailboxReplicaPeer peer,
            MailboxPeerReplicationOperation operation,
            ReadOnlyMemory<byte> canonicalPrq2,
            CancellationToken cancellationToken)
        {
            if (operation == MailboxPeerReplicationOperation.Store)
            {
                StoreCalls++;
            }
            else
            {
                TombstoneCalls++;
            }

            var result = await receiver.ReceiveAsync(
                canonicalPrq2,
                operation,
                cancellationToken);
            return result.Status == MailboxPeerReceiveStatus.Accepted
                ? result.CanonicalResponse
                : null;
        }
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow { get; } = now;
    }
}
