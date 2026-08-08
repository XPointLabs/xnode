using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class ProductionMailboxAuthorityProviderTests : IDisposable
{
    private const ulong Now = 2_000_000_000;
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-production-authority-{Guid.NewGuid():N}");

    [Fact]
    public async Task DisabledProviderAcceptsEmptyProductionConfiguration()
    {
        var provider = new ProductionMailboxAuthorityProvider(
            new ProductionMailboxAuthorityOptions(),
            new RouterNodeOptions { DataDirectory = _root },
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new PermissiveSecurity(),
            new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.False(provider.Status.Enabled);
        Assert.False(provider.Status.Ready);
        Assert.Equal("disabled", provider.Status.Reason);
    }

    [Fact]
    public async Task ValidFirstNextAndIdempotentArtifactsAdvanceExactlyOnce()
    {
        var fixture = Fixture.Create(_root);
        var writes = new CountingBarrier();
        var provider = fixture.Provider(writes);

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.True(provider.Status.ArtifactVerified);
        Assert.True(provider.Status.RevocationArtifactVerified);
        Assert.True(provider.Status.AuthorityRevocationReady);
        Assert.True(provider.Status.TopologyArtifactVerified);
        Assert.True(provider.Status.ProductionMailboxRoutesReady);
        Assert.True(provider.Status.Ready);
        Assert.Equal("", provider.Status.Reason);
        Assert.Equal(7UL, provider.Status.AuthorityGeneration);
        Assert.Equal("https://ingress.example.net/mau2/", provider.NodeIngress!.Endpoint.AbsoluteUri);
        Assert.False(CryptographicOperations.FixedTimeEquals(
            provider.NodeIngress.CurrentSpkiSha256.Span,
            provider.NodeIngress.NextSpkiSha256.Span));
        Assert.Equal(1, writes.ReplaceCount);

        var firstLkg = File.ReadAllBytes(fixture.LkgPath);
        await provider.InitializeAsync();
        Assert.Equal(1, writes.ReplaceCount);
        Assert.Equal(firstLkg, File.ReadAllBytes(fixture.LkgPath));

        var next = fixture.Successor();
        File.WriteAllBytes(fixture.ArtifactPath, ProductionMailboxAuthorityCodec.Encode(next));
        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured, provider.Status.Reason);
        Assert.Equal(8UL, provider.Status.AuthorityGeneration);
        Assert.Equal(7UL, provider.Status.RevocationGeneration);
        Assert.Equal(2, writes.ReplaceCount);
        var persisted = ProductionMailboxAuthorityLkgCodec.Decode(
            File.ReadAllBytes(fixture.LkgPath));
        Assert.Equal(8UL, persisted.Committed.Generation);
        Assert.Equal(7UL, persisted.AuthorityVerificationAnchor!.Generation);
    }

    [Fact]
    public async Task ConcurrentInitializationSerializesOneAtomicAdvance()
    {
        var fixture = Fixture.Create(_root);
        var writes = new CountingBarrier(delay: TimeSpan.FromMilliseconds(20));
        var provider = fixture.Provider(writes);

        await Task.WhenAll(
            provider.InitializeAsync(),
            provider.InitializeAsync(),
            provider.InitializeAsync());

        Assert.True(provider.IsConfigured);
        Assert.Equal(1, writes.ReplaceCount);
    }

    [Fact]
    public async Task ConcurrentProvidersShareTheDurableProcessLock()
    {
        var fixture = Fixture.Create(_root);
        var writes = new CountingBarrier(delay: TimeSpan.FromMilliseconds(30));
        var first = fixture.Provider(writes);
        var second = fixture.Provider(writes);

        await Task.WhenAll(first.InitializeAsync(), second.InitializeAsync());

        Assert.True(first.IsConfigured, first.Status.Reason);
        Assert.True(second.IsConfigured, second.Status.Reason);
        Assert.Equal(1, writes.ReplaceCount);
    }

    [Fact]
    public async Task VerifiedSnapshotIsExactAndUnknownSerialIsNotRevoked()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.True(provider.IsRevoked(Query(fixture, Bytes(0x10, 16))));
        Assert.False(provider.IsRevoked(Query(fixture, Bytes(0x20, 16))));
        Assert.Throws<ProductionMailboxRevocationSnapshotException>(() =>
            provider.IsRevoked(Query(fixture, Bytes(0x20, 16)) with
            {
                IssuerPublicKey = Bytes(0x30, 32)
            }));
    }

    [Fact]
    public async Task VerifiedCallerBoundSelectionReturnsExactlyTwoPinnedReplicas()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var epoch = fixture.Authority.CurrentEpoch;
        var selectionInput = fixture.Options.GetReadinessSelectionInputCommitment();
        var placementId = fixture.Options.GetReadinessBlindedPlacementId();
        var placement = MailboxPlacementCommitment.Compute(
            new BlindedPlacementId(placementId));

        Assert.True(provider.TryResolve(
            epoch.Epoch,
            epoch.MembershipCommitment,
            placement,
            placementId,
            selectionInput,
            out var selection));
        Assert.NotNull(selection);
        Assert.Equal(2, selection.Replicas.Count);
        Assert.Equal(2, selection.Replicas
            .Select(replica => Convert.ToHexString(replica.ReplicaId.Span))
            .Distinct(StringComparer.Ordinal)
            .Count());
        Assert.All(selection.Replicas, replica =>
        {
            Assert.Equal(Uri.UriSchemeHttps, replica.HttpsEndpoint.Scheme);
            Assert.False(CryptographicOperations.FixedTimeEquals(
                replica.CurrentSpkiSha256.Span,
                replica.NextSpkiSha256.Span));
            Assert.NotEmpty(replica.CanonicalMembershipProof.ToArray());
        });
        Assert.False(provider.TryResolve(
            epoch.Epoch,
            epoch.MembershipCommitment,
            placement,
            placementId,
            Bytes(0xE0, 32),
            out _));
    }

    [Fact]
    public async Task PublishedBundleFailsClosedAfterItsSelectionExpires()
    {
        var fixture = Fixture.Create(_root);
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var provider = fixture.Provider(clock: clock);
        await provider.InitializeAsync();

        Assert.True(provider.Status.Ready);
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)Now + 201);

        Assert.False(provider.Status.Ready);
        Assert.Equal("production-bundle-expired", provider.Status.Reason);
        Assert.False(provider.IsConfigured);
        Assert.True(provider.IsRevoked(Query(fixture, Bytes(0x20, 16))));
        Assert.False(provider.TryResolve(
            fixture.Authority.CurrentEpoch.Epoch,
            fixture.Authority.CurrentEpoch.MembershipCommitment,
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(
                fixture.Options.GetReadinessBlindedPlacementId())),
            fixture.Options.GetReadinessBlindedPlacementId(),
            fixture.Options.GetReadinessSelectionInputCommitment(),
            out _));
    }

    [Fact]
    public async Task ProductionFanoutUsesExactSelectedRouteProofAndSpkiPins()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var authorityEpoch = fixture.Authority.CurrentEpoch;
        var selectionInput = fixture.Options.GetReadinessSelectionInputCommitment();
        var placementId = fixture.Options.GetReadinessBlindedPlacementId();
        var placement = MailboxPlacementCommitment.Compute(
            new BlindedPlacementId(placementId));
        Assert.True(provider.TryResolve(
            authorityEpoch.Epoch,
            authorityEpoch.MembershipCommitment,
            placement,
            placementId,
            selectionInput,
            out var selection));
        var local = selection!.Replicas[0];
        var remote = selection.Replicas[1];
        var localSeed = fixture.SeedFor(local.ReplicaId.Span, authorityEpoch.Epoch);
        var peerClient = new RecordingPeerClient();
        var fanout = new ProductionMailboxReplicaFanout(
            provider,
            new RouterNodeOptions
            {
                RouterId = Hex(local.ReplicaId.ToArray()),
                Ed25519PrivateKey = Hex(localSeed)
            },
            peerClient);
        var payload = Bytes(0x70, 32);

        var receipts = await fanout.TombstoneAsync(new MailboxReplicaTombstoneContext(
            1,
            authorityEpoch.Epoch,
            Bytes(0x30, 16),
            Bytes(0x40, 32),
            placement,
            authorityEpoch.MembershipCommitment,
            payload,
            Now + 100,
            Now,
            selection.Replicas.Select(static replica => replica.ReplicaId).ToArray())
        {
            BlindedPlacementId = placementId
        }, CancellationToken.None);

        Assert.Single(receipts);
        Assert.NotNull(peerClient.Peer);
        Assert.Equal(
            new Uri(remote.HttpsEndpoint, MailboxWireHttpContract.PeerTombstoneRoute).AbsoluteUri,
            peerClient.Peer.Endpoint);
        Assert.Equal(remote.CurrentSpkiSha256.ToArray(), peerClient.Peer.CurrentSpkiSha256.ToArray());
        Assert.Equal(remote.NextSpkiSha256.ToArray(), peerClient.Peer.NextSpkiSha256.ToArray());
        var request = MailboxPeerWireV2Codec.Decode(peerClient.CanonicalRequest.Span);
        Assert.Equal(remote.ReplicaId.ToArray(), request.RecipientRouterId.ToArray());
    }

    [Fact]
    public async Task PrepositionedClosure_IsOwnerAuthenticatedDurableAndRejectsConcurrentFork()
    {
        var fixture = Fixture.Create(_root);
        var material = fixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var command = fixture.PrepositionCommand(material);

        await store.PrepositionAsync(command, CancellationToken.None);
        await store.PrepositionAsync(command, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(
                fixture.SameGenerationForkCommand(material), CancellationToken.None));

        var unsignedRequest = new ProductionMailboxClosureRequest(
            Now, Bytes(0x46, 32), material.SelectionInputCommitment,
            material.OldSelectionHash, material.OwnerPublicKey, new byte[64]);
        var request = unsignedRequest with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(unsignedRequest),
                material.OwnerPrivateKey)
        };
        var encodedRequest = ProductionMailboxClosureRequestCodec.Encode(request);
        Assert.Equal(material.CanonicalEnvelope,
            await store.FetchAsync(encodedRequest, CancellationToken.None));

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        Assert.Equal(material.CanonicalEnvelope,
            await restarted.FetchAsync(encodedRequest, CancellationToken.None));

        encodedRequest[^1] ^= 0x01;
        Assert.Null(await restarted.FetchAsync(encodedRequest, CancellationToken.None));
    }

    [Fact]
    public async Task PublisherAuthorizedOldCurrentReplica_ServesFutureClosureAfterTwentyFiveHours()
    {
        const ulong twentyFiveHours = 25 * 60 * 60;
        var fixture = Fixture.Create(
            Path.Combine(_root, "legacy-old-current"),
            survivalHorizonSeconds: 26 * 60 * 60);
        var material = fixture.CreateDirectClosure(
            twentyFiveHours,
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint);
        var legacyTarget = material.OldCurrentReplicaIds[0].ToArray();
        fixture.Node.RouterId = Hex(legacyTarget);
        var nowClock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, nowClock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(
                fixture.PrepositionCommand(material), CancellationToken.None));
        var command = fixture.PrepositionCommand(
            material, 0x47, material.OldCurrentReplicaIds);
        await store.PrepositionAsync(command, CancellationToken.None);

        var ordinarySelection = ProductionMailboxTopologyCodec.DecodeSelection(
            ProductionMailboxClosureEnvelopeCodec.Decode(material.CanonicalEnvelope)
                .Selection.Span);
        var ordinaryTarget = ordinarySelection.Replicas[0].ReplicaId.ToArray();
        fixture.Node.RouterId = Hex(ordinaryTarget);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(
                fixture.PrepositionCommand(material, 0x48,
                    [(ReadOnlyMemory<byte>)ordinaryTarget]), CancellationToken.None));

        fixture.Node.RouterId = Hex(legacyTarget);
        var tampered = ProductionMailboxPrepositionCommandCodec.Decode(command) with
        {
            AuthorizedLegacyReplicaIds =
                [(ReadOnlyMemory<byte>)Bytes(0x01, 32), (ReadOnlyMemory<byte>)Bytes(0x02, 32)]
        };
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(
                ProductionMailboxPrepositionCommandCodec.Encode(tampered),
                CancellationToken.None));

        var future = checked(Now + twentyFiveHours + 1);
        var futureClock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)future));
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, futureClock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var unsignedRequest = new ProductionMailboxClosureRequest(
            future, Bytes(0x49, 32), material.SelectionInputCommitment,
            material.OldSelectionHash, material.OwnerPublicKey, new byte[64]);
        var request = ProductionMailboxClosureRequestCodec.Encode(unsignedRequest with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(unsignedRequest),
                material.OwnerPrivateKey)
        });

        Assert.Equal(material.CanonicalEnvelope,
            await restarted.FetchAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task VersionedSchedule_PreservesCurrentAndServesHighestLiveFutureAcrossRestart()
    {
        const ulong day = 24 * 60 * 60;
        var currentFixture = Fixture.Create(
            Path.Combine(_root, "schedule-current"), survivalHorizonSeconds: 52 * 60 * 60);
        var futureOneFixture = Fixture.Create(
            Path.Combine(_root, "schedule-future-1"), survivalHorizonSeconds: 52 * 60 * 60);
        var futureTwoFixture = Fixture.Create(
            Path.Combine(_root, "schedule-future-2"), survivalHorizonSeconds: 52 * 60 * 60);
        var current = currentFixture.CreateDirectClosure();
        var futureOne = futureOneFixture.CreateDirectClosure(
            day + 60, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9);
        var futureTwo = futureTwoFixture.CreateDirectClosure(
            2 * day + 120, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 10);
        var target = current.OldCurrentReplicaIds[0].ToArray();
        currentFixture.Node.RouterId = Hex(target);
        futureOneFixture.Node.RouterId = Hex(target);
        futureTwoFixture.Node.RouterId = Hex(target);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());

        await store.PrepositionAsync(currentFixture.PrepositionCommand(
            current, 0x50, current.OldCurrentReplicaIds), CancellationToken.None);
        await store.PrepositionAsync(futureOneFixture.PrepositionCommand(
            futureOne, 0x51, futureOne.OldCurrentReplicaIds), CancellationToken.None);
        await store.PrepositionAsync(futureTwoFixture.PrepositionCommand(
            futureTwo, 0x52, futureTwo.OldCurrentReplicaIds), CancellationToken.None);
        var schedulePath = Assert.Single(Directory.EnumerateFiles(
            currentFixture.Options.ClosureDirectory, "*.pmcs1",
            SearchOption.AllDirectories));
        Assert.Equal(3, ProductionMailboxClosureScheduleCodec.Decode(
            File.ReadAllBytes(schedulePath),
            currentFixture.Options.MaximumClosureVersionsPerSelection).Count);

        static byte[] Request(ClosureMaterial material, ulong now, byte nonce)
        {
            var unsigned = new ProductionMailboxClosureRequest(
                now, Bytes(nonce, 32), material.SelectionInputCommitment,
                material.OldSelectionHash, material.OwnerPublicKey, new byte[64]);
            return ProductionMailboxClosureRequestCodec.Encode(unsigned with
            {
                OwnerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxClosureRequestCodec.GetSigningBytes(unsigned),
                    material.OwnerPrivateKey)
            });
        }

        Assert.Equal(current.CanonicalEnvelope,
            await store.FetchAsync(Request(current, Now, 0x53), CancellationToken.None));
        var gap = checked(Now + 1_000);
        var gapStore = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)gap)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Null(await gapStore.FetchAsync(
            Request(current, gap, 0x54), CancellationToken.None));
        var futureOneNow = checked(Now + day + 61);
        var futureOneStore = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)futureOneNow)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(futureOne.CanonicalEnvelope,
            await futureOneStore.FetchAsync(
                Request(futureOne, futureOneNow, 0x55), CancellationToken.None));
        var futureTwoNow = checked(Now + 2 * day + 121);
        var futureTwoStore = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)futureTwoNow)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(futureTwo.CanonicalEnvelope,
            await futureTwoStore.FetchAsync(
                Request(futureTwo, futureTwoNow, 0x56), CancellationToken.None));
    }

    [Fact]
    public async Task VersionedSchedule_OverlapChoosesHighestAndCapNeverEvictsLiveVersion()
    {
        var currentFixture = Fixture.Create(
            Path.Combine(_root, "schedule-cap-current"), survivalHorizonSeconds: 1_000);
        var futureFixture = Fixture.Create(
            Path.Combine(_root, "schedule-cap-future"), survivalHorizonSeconds: 1_000);
        var overflowFixture = Fixture.Create(
            Path.Combine(_root, "schedule-cap-overflow"), survivalHorizonSeconds: 1_000);
        var current = currentFixture.CreateDirectClosure();
        var future = futureFixture.CreateDirectClosure(
            100, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9);
        var overflow = overflowFixture.CreateDirectClosure(
            150, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 10);
        var target = current.OldCurrentReplicaIds[0].ToArray();
        currentFixture.Node.RouterId = Hex(target);
        futureFixture.Node.RouterId = Hex(target);
        overflowFixture.Node.RouterId = Hex(target);
        currentFixture.Options.MaximumClosureVersionsPerSelection = 2;
        var now = checked(Now + 150);
        var store = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(currentFixture.PrepositionCommand(
            current, 0x57, current.OldCurrentReplicaIds), CancellationToken.None);
        await store.PrepositionAsync(futureFixture.PrepositionCommand(
            future, 0x58, future.OldCurrentReplicaIds), CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.PrepositionAsync(overflowFixture.PrepositionCommand(
                overflow, 0x59, overflow.OldCurrentReplicaIds), CancellationToken.None));
        var schedulePath = Assert.Single(Directory.EnumerateFiles(
            currentFixture.Options.ClosureDirectory, "*.pmcs1",
            SearchOption.AllDirectories));
        Assert.Equal(2, ProductionMailboxClosureScheduleCodec.Decode(
            File.ReadAllBytes(schedulePath),
            currentFixture.Options.MaximumClosureVersionsPerSelection).Count);

        var unsigned = new ProductionMailboxClosureRequest(
            now, Bytes(0x5A, 32), current.SelectionInputCommitment,
            current.OldSelectionHash, current.OwnerPublicKey, new byte[64]);
        var request = ProductionMailboxClosureRequestCodec.Encode(unsigned with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(unsigned),
                current.OwnerPrivateKey)
        });
        var liveStore = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(future.CanonicalEnvelope,
            await liveStore.FetchAsync(request, CancellationToken.None));
        var cleanupNow = checked(Now + 250);
        var cleanupStore = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)cleanupNow)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await cleanupStore.PrepositionAsync(currentFixture.PrepositionCommand(
                current, 0x5F, current.OldCurrentReplicaIds), CancellationToken.None));
        await cleanupStore.PrepositionAsync(futureFixture.PrepositionCommand(
            future, 0x5E, future.OldCurrentReplicaIds), CancellationToken.None);
        Assert.Single(ProductionMailboxClosureScheduleCodec.Decode(
            File.ReadAllBytes(schedulePath),
            currentFixture.Options.MaximumClosureVersionsPerSelection));
    }

    [Fact]
    public async Task LineageBoundRequest_ServesTwoDeviceAnchorsAndWrongAnchorMisses()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "schedule-lineages"));
        var advancedFixture = Fixture.Create(
            Path.Combine(_root, "schedule-lineages-advanced"), 1_000);
        var thirdFixture = Fixture.Create(
            Path.Combine(_root, "schedule-lineages-third"), 1_000);
        fixture.Options.MaximumClosureLineagesPerSelection = 2;
        var first = fixture.CreateDirectClosure();
        var advancedRaw = advancedFixture.CreateDirectClosure(
            100, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9);
        var second = advancedFixture.ReanchorToAccepted(advancedRaw, first);
        var thirdRaw = thirdFixture.CreateDirectClosure(
            250, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 10);
        var third = thirdFixture.WithDistinctOldAnchor(thirdRaw, 2);
        advancedFixture.Node.RouterId = fixture.Node.RouterId;
        thirdFixture.Node.RouterId = fixture.Node.RouterId;
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(
            fixture.PrepositionCommand(first, 0x60), CancellationToken.None);
        await store.PrepositionAsync(
            advancedFixture.PrepositionCommand(second, 0x61), CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.PrepositionAsync(
                thirdFixture.PrepositionCommand(third, 0x62), CancellationToken.None));

        static byte[] Request(
            ClosureMaterial material, byte nonce, byte[]? oldHash = null,
            ulong timestamp = Now)
        {
            var unsigned = new ProductionMailboxClosureRequest(
                timestamp, Bytes(nonce, 32), material.SelectionInputCommitment,
                oldHash ?? material.OldSelectionHash,
                material.OwnerPublicKey, new byte[64]);
            return ProductionMailboxClosureRequestCodec.Encode(unsigned with
            {
                OwnerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxClosureRequestCodec.GetSigningBytes(unsigned),
                    material.OwnerPrivateKey)
            });
        }
        Assert.Equal(first.CanonicalEnvelope,
            await store.FetchAsync(Request(first, 0x63), CancellationToken.None));
        var advancedNow = checked(Now + 101);
        var advancedStore = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)advancedNow)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(second.CanonicalEnvelope,
            await advancedStore.FetchAsync(
                Request(second, 0x64, timestamp: advancedNow), CancellationToken.None));
        Assert.Null(await store.FetchAsync(
            Request(first, 0x65, Bytes(0xEE, 32)), CancellationToken.None));
        var pruneNow = checked(Now + 250);
        var pruneStore = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)pruneNow)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await pruneStore.PrepositionAsync(
            thirdFixture.PrepositionCommand(third, 0x66), CancellationToken.None);
        Assert.Equal(2, Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories).Count());
    }

    [Fact]
    public async Task VersionedSchedule_RestartRejectsRenamedRouteForkAndPerSelectionOverflow()
    {
        var renamedFixture = Fixture.Create(Path.Combine(_root, "schedule-renamed"));
        var renamedMaterial = renamedFixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var renamedStore = new ProductionMailboxClosureStore(
            renamedFixture.Options, renamedFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await renamedStore.PrepositionAsync(
            renamedFixture.PrepositionCommand(renamedMaterial), CancellationToken.None);
        var canonicalPath = Assert.Single(Directory.EnumerateFiles(
            renamedFixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
        var unrelatedPath = Path.Combine(renamedFixture.Options.ClosureDirectory,
            "unrelated.pmcs1");
        File.Move(canonicalPath, unrelatedPath);
        Assert.Throws<InvalidDataException>(() => new ProductionMailboxClosureStore(
            renamedFixture.Options, renamedFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));

        var forkFixture = Fixture.Create(Path.Combine(_root, "schedule-fork"));
        var forkMaterial = forkFixture.CreateDirectClosure();
        var forkStore = new ProductionMailboxClosureStore(
            forkFixture.Options, forkFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await forkStore.PrepositionAsync(
            forkFixture.PrepositionCommand(forkMaterial), CancellationToken.None);
        var forkEnvelope = ProductionMailboxPrepositionCommandCodec.Decode(
            forkFixture.SameGenerationForkCommand(forkMaterial)).CanonicalEnvelope.ToArray();
        var forkSchedulePath = Assert.Single(Directory.EnumerateFiles(
            forkFixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
        File.WriteAllBytes(forkSchedulePath,
            ProductionMailboxClosureScheduleCodec.Encode(
                [forkMaterial.CanonicalEnvelope, forkEnvelope],
                forkFixture.Options.MaximumClosureVersionsPerSelection));
        Assert.Throws<InvalidDataException>(() => new ProductionMailboxClosureStore(
            forkFixture.Options, forkFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));

        var currentFixture = Fixture.Create(
            Path.Combine(_root, "schedule-overflow-current"), 1_000);
        var futureFixture = Fixture.Create(
            Path.Combine(_root, "schedule-overflow-future"), 1_000);
        var lastFixture = Fixture.Create(
            Path.Combine(_root, "schedule-overflow-last"), 1_000);
        var current = currentFixture.CreateDirectClosure();
        var future = futureFixture.CreateDirectClosure(
            100, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9);
        var last = lastFixture.CreateDirectClosure(
            200, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 10);
        var target = current.OldCurrentReplicaIds[0].ToArray();
        currentFixture.Node.RouterId = Hex(target);
        futureFixture.Node.RouterId = Hex(target);
        lastFixture.Node.RouterId = Hex(target);
        currentFixture.Options.MaximumClosureVersionsPerSelection = 3;
        var overflowStore = new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await overflowStore.PrepositionAsync(currentFixture.PrepositionCommand(
            current, 0x5B, current.OldCurrentReplicaIds), CancellationToken.None);
        await overflowStore.PrepositionAsync(futureFixture.PrepositionCommand(
            future, 0x5C, future.OldCurrentReplicaIds), CancellationToken.None);
        await overflowStore.PrepositionAsync(lastFixture.PrepositionCommand(
            last, 0x5D, last.OldCurrentReplicaIds), CancellationToken.None);
        currentFixture.Options.MaximumClosureVersionsPerSelection = 2;
        Assert.Throws<InvalidDataException>(() => new ProductionMailboxClosureStore(
            currentFixture.Options, currentFixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
    }

    [Fact]
    public async Task ConcurrentPreposition_AllowsOneSameGenerationWinnerAndSurvivesRestart()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "concurrent"));
        var material = fixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var firstStore = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var secondStore = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        async Task<bool> TryStore(ProductionMailboxClosureStore store, byte[] command)
        {
            try
            {
                await store.PrepositionAsync(command, CancellationToken.None);
                return true;
            }
            catch (InvalidDataException) { return false; }
        }

        var outcomes = await Task.WhenAll(
            TryStore(firstStore, fixture.PrepositionCommand(material)),
            TryStore(secondStore, fixture.SameGenerationForkCommand(material)));

        Assert.Single(outcomes, static accepted => accepted);
        Assert.Single(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
    }

    [Fact]
    public async Task AmbiguousReplace_ReconcilesAccountingAndExactRetryIsIdempotent()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "ambiguous-replace"));
        var material = fixture.CreateDirectClosure();
        fixture.Options.MaximumStoredClosures = 1;
        var scheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [material.CanonicalEnvelope],
            fixture.Options.MaximumClosureVersionsPerSelection).Length;
        fixture.Options.MaximumClosureStoreBytes = checked(scheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var barrier = new ThrowOnceAfterReplaceBarrier();
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(), barrier);
        var command = fixture.PrepositionCommand(material);

        await Assert.ThrowsAsync<IOException>(async () =>
            await store.PrepositionAsync(command, CancellationToken.None));
        await store.PrepositionAsync(command, CancellationToken.None);

        Assert.Single(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
        Assert.Equal((1, (long)checked(scheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes)),
            store.StorageAccounting);
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
    }

    [Fact]
    public async Task CapacityReservation_TransfersAtomicallyAndExactReplayDoesNotDoubleCharge()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-transfer"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x91, 32);
        var scheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [material.CanonicalEnvelope],
            fixture.Options.MaximumClosureVersionsPerSelection).Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes));
        fixture.Options.MaximumStoredClosures = 1;
        fixture.Options.MaximumClosureStoreBytes = checked((long)charge);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var reserve = fixture.CapacityCommand(cohort, 1, charge, lifetimeSeconds: 60);

        var firstReceipt = await store.ReserveCapacityAsync(reserve, CancellationToken.None);
        var replayReceipt = await store.ReserveCapacityAsync(reserve, CancellationToken.None);
        Assert.Equal(firstReceipt, replayReceipt);
        Assert.True(ProductionMailboxCapacityReceiptCodec.VerifyNode(
            ProductionMailboxCapacityReceiptCodec.Decode(firstReceipt),
            PublicKeyAuth.GenerateKeyPair(
                Convert.FromHexString(fixture.Node.GetEd25519PrivateKey())).PublicKey));

        var preposition = fixture.PrepositionCommand(
            material, reservationCohortId: cohort);
        await store.PrepositionAsync(preposition, CancellationToken.None);
        await store.PrepositionAsync(preposition, CancellationToken.None);
        Assert.Equal((1, (long)charge), store.StorageAccounting);

        var renewal = fixture.CapacityCommand(
            cohort, 1, charge, revision: 2, lifetimeSeconds: 120, nonce: 0x47);
        var renewed = ProductionMailboxCapacityReceiptCodec.Decode(
            await store.ReserveCapacityAsync(renewal, CancellationToken.None));
        Assert.Equal((uint)1, renewed.ConsumedClosureCount);
        Assert.Equal(charge, renewed.ConsumedBytes);
        Assert.Equal(renewed.ReservedClosureCount, renewed.ConsumedClosureCount);
        Assert.Equal(renewed.ReservedBytes, renewed.ConsumedBytes);

        var releaseCommand = fixture.CapacityCommand(
            cohort, 0, 0, revision: 3, lifetimeSeconds: 180,
            operation: ProductionMailboxCapacityOperation.Release, nonce: 0x50);
        var releasedBytes = await store.ReserveCapacityAsync(
            releaseCommand, CancellationToken.None);
        var released = ProductionMailboxCapacityReceiptCodec.Decode(releasedBytes);
        Assert.Equal(released.ConsumedClosureCount, released.ReservedClosureCount);
        Assert.Equal(released.ConsumedBytes, released.ReservedBytes);
        Assert.Equal(releasedBytes, await store.ReserveCapacityAsync(
            releaseCommand, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.ReserveCapacityAsync(
                fixture.CapacityCommand(cohort, 1, charge, revision: 4,
                    lifetimeSeconds: 240, nonce: 0x51),
                CancellationToken.None));
    }

    [Fact]
    public async Task CapacityRelease_FreesAllUnusedHeadroomAndCannotBeResurrected()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-release-unused"));
        _ = fixture.CreateDirectClosure();
        fixture.Options.MaximumStoredClosures = 4;
        fixture.Options.MaximumClosureStoreBytes = 65_536;
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var cohort = Bytes(0x96, 32);
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 4, 65_536), CancellationToken.None);
        var release = fixture.CapacityCommand(
            cohort, 0, 0, revision: 2, lifetimeSeconds: 7_200,
            operation: ProductionMailboxCapacityOperation.Release, nonce: 0x52);
        var receipt = ProductionMailboxCapacityReceiptCodec.Decode(
            await store.ReserveCapacityAsync(release, CancellationToken.None));
        Assert.Equal((uint)0, receipt.ReservedClosureCount);
        Assert.Equal((ulong)0, receipt.ReservedBytes);
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(Bytes(0x97, 32), 4, 65_536, nonce: 0x53),
            CancellationToken.None);
    }

    [Fact]
    public async Task CapacityReservation_ExpiryFreesOnlyUnusedAndNeverActualUsage()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-expiry"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x92, 32);
        var scheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [material.CanonicalEnvelope],
            fixture.Options.MaximumClosureVersionsPerSelection).Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes));
        fixture.Options.MaximumStoredClosures = 1;
        fixture.Options.MaximumClosureStoreBytes = checked((long)charge);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 1, charge, lifetimeSeconds: 60),
            CancellationToken.None);
        await store.PrepositionAsync(
            fixture.PrepositionCommand(material, reservationCohortId: cohort),
            CancellationToken.None);

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 61))),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((1, (long)charge), restarted.StorageAccounting);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await restarted.ReserveCapacityAsync(
                fixture.CapacityCommand(Bytes(0x93, 32), 1, charge,
                    lifetimeSeconds: 60, nonce: 0x48,
                    timestampUnixSeconds: Now + 61),
                CancellationToken.None));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task CapacityTransfer_PartialCommitRecoversAcrossRealStoreRestart(
        int crashPhase)
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-crash"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x94, 32);
        var scheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [material.CanonicalEnvelope],
            fixture.Options.MaximumClosureVersionsPerSelection).Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes));
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var armed = 1;
        Action crash = () =>
        {
            if (Interlocked.Exchange(ref armed, 0) == 1)
                throw new IOException("Injected transfer process termination.");
        };
        var hooks = new ProductionMailboxClosureStoreTestHooks(
            AfterCapacityTransferJournal: crashPhase == 0 ? crash : null,
            AfterCapacityTransferSchedule: crashPhase == 1 ? crash : null,
            AfterCapacityTransferFloor: crashPhase == 2 ? crash : null,
            AfterCapacityTransferLedger: crashPhase == 3 ? crash : null,
            SimulateCapacityTransferProcessTermination: true);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), hooks);
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 1, charge), CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(async () =>
            await store.PrepositionAsync(
                fixture.PrepositionCommand(material, reservationCohortId: cohort),
                CancellationToken.None));
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await restarted.PrepositionAsync(
            fixture.PrepositionCommand(material, reservationCohortId: cohort),
            CancellationToken.None);
        var renewal = ProductionMailboxCapacityReceiptCodec.Decode(
            await restarted.ReserveCapacityAsync(
                fixture.CapacityCommand(cohort, 1, charge, revision: 2,
                    lifetimeSeconds: 7_200, nonce: 0x49),
                CancellationToken.None));
        Assert.Equal((uint)1, renewal.ConsumedClosureCount);
        Assert.Equal(charge, renewal.ConsumedBytes);
        Assert.False(File.Exists(Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity-transfer.pbt1")));
    }

    [Fact]
    public async Task CapacityRenewalRace_AcceptsOneForkAndExactWinnerReplays()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-renewal-race"));
        _ = fixture.CreateDirectClosure();
        var cohort = Bytes(0x95, 32);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 2, 32_768), CancellationToken.None);
        var left = fixture.CapacityCommand(
            cohort, 3, 49_152, revision: 2, lifetimeSeconds: 7_200, nonce: 0x4A);
        var right = fixture.CapacityCommand(
            cohort, 4, 65_536, revision: 2, lifetimeSeconds: 7_201, nonce: 0x4B);
        var outcomes = await Task.WhenAll(TryReserve(left), TryReserve(right));
        Assert.Single(outcomes, static accepted => accepted);
        var winner = outcomes[0] ? left : right;
        var first = await store.ReserveCapacityAsync(winner, CancellationToken.None);
        var replay = await store.ReserveCapacityAsync(winner, CancellationToken.None);
        Assert.Equal(first, replay);

        async Task<bool> TryReserve(byte[] command)
        {
            try
            {
                await store.ReserveCapacityAsync(command, CancellationToken.None);
                return true;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
    }

    [Fact]
    public async Task CapacityReservation_ExpiryMidSweepRejectsWriteAndLeavesNoSchedule()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-mid-sweep-expiry"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x99, 32);
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 1, 1_048_576, lifetimeSeconds: 60),
            CancellationToken.None);
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 61));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.PrepositionAsync(
                fixture.PrepositionCommand(material, reservationCohortId: cohort),
                CancellationToken.None));
        Assert.Empty(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
        Assert.Equal((0, 0L), store.StorageAccounting);
    }

    [Fact]
    public async Task CapacityLedger_TamperIsRebuiltFromAuthenticatedFloorAcrossRestart()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-ledger-tamper"));
        _ = fixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(Bytes(0x9A, 32), 1, 65_536),
            CancellationToken.None);
        var ledgerPath = Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity.pbl1");
        var bytes = File.ReadAllBytes(ledgerPath);
        bytes[^1] ^= 0x01;
        File.WriteAllBytes(ledgerPath, bytes);

        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        Assert.NotEqual(bytes, File.ReadAllBytes(ledgerPath));
    }

    [Fact]
    public async Task CapacityFloor_RejectsLedgerRollbackBeforeTransferRenewAndRelease()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-ledger-rollback"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x9B, 32);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var scheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [material.CanonicalEnvelope],
            fixture.Options.MaximumClosureVersionsPerSelection).Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes));
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 2, charge * 2), CancellationToken.None);
        var ledgerPath = Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity.pbl1");
        var key = File.ReadAllBytes(fixture.Options.ClosureStateHmacKeyPath);
        var beforeTransfer = File.ReadAllBytes(ledgerPath);

        await store.PrepositionAsync(
            fixture.PrepositionCommand(material, reservationCohortId: cohort),
            CancellationToken.None);
        var afterTransfer = File.ReadAllBytes(ledgerPath);
        File.WriteAllBytes(ledgerPath, beforeTransfer);
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var recoveredTransfer = Assert.Single(
            ProductionMailboxCapacityLedgerCodec.Decode(
                File.ReadAllBytes(ledgerPath), key,
                fixture.Options.MaximumClosureReservations));
        Assert.Equal((uint)1, recoveredTransfer.ConsumedClosureCount);
        Assert.Equal(charge, recoveredTransfer.ConsumedBytes);

        store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 3, charge * 3, revision: 2,
                lifetimeSeconds: 7_200, nonce: 0x54), CancellationToken.None);
        var afterRenew = File.ReadAllBytes(ledgerPath);
        File.WriteAllBytes(ledgerPath, afterTransfer);
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var recoveredRenew = Assert.Single(
            ProductionMailboxCapacityLedgerCodec.Decode(
                File.ReadAllBytes(ledgerPath), key,
                fixture.Options.MaximumClosureReservations));
        Assert.Equal((ulong)2, recoveredRenew.Revision);
        Assert.Equal((uint)3, recoveredRenew.ReservedClosureCount);

        store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await store.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 0, 0, revision: 3,
                lifetimeSeconds: 10_800,
                operation: ProductionMailboxCapacityOperation.Release, nonce: 0x55),
            CancellationToken.None);
        File.WriteAllBytes(ledgerPath, afterRenew);
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var recoveredRelease = Assert.Single(
            ProductionMailboxCapacityLedgerCodec.Decode(
                File.ReadAllBytes(ledgerPath), key,
                fixture.Options.MaximumClosureReservations));
        Assert.True(recoveredRelease.Terminal);
        Assert.Equal((ulong)3, recoveredRelease.Revision);
        Assert.Equal(recoveredRelease.ConsumedClosureCount,
            recoveredRelease.ReservedClosureCount);
        Assert.Equal(recoveredRelease.ConsumedBytes, recoveredRelease.ReservedBytes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task CapacityReservation_MarkerLedgerDeleteSplitsRecoverOnRestart(
        int crashPhase)
    {
        var fixture = Fixture.Create(Path.Combine(_root,
            $"capacity-reservation-split-{crashPhase}"));
        _ = fixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var cohort = Bytes(0x9C, 32);
        var first = fixture.CapacityCommand(cohort, 2, 65_536);
        await initial.ReserveCapacityAsync(first, CancellationToken.None);
        var armed = 1;
        Action crash = () =>
        {
            if (Interlocked.Exchange(ref armed, 0) == 1)
                throw new IOException("Injected capacity state split.");
        };
        var hooks = new ProductionMailboxClosureStoreTestHooks(
            AfterCapacityReservationFloor: crashPhase == 0 ? crash : null,
            AfterCapacityReservationLedger: crashPhase == 1 ? crash : null,
            AfterCapacityReservationDelete: crashPhase == 2 ? crash : null);
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), hooks);
        var renewal = fixture.CapacityCommand(
            cohort, 3, 98_304, revision: 2, lifetimeSeconds: 7_200,
            nonce: 0x56);
        await Assert.ThrowsAsync<IOException>(async () =>
            await writer.ReserveCapacityAsync(renewal, CancellationToken.None));

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        var receipt = ProductionMailboxCapacityReceiptCodec.Decode(
            await restarted.ReserveCapacityAsync(renewal, CancellationToken.None));
        Assert.Equal((ulong)2, receipt.Revision);
        Assert.Equal((uint)3, receipt.ReservedClosureCount);
        Assert.Single(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, ".capacity-*.pbf1",
            SearchOption.TopDirectoryOnly));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GlobalExpiredGc_ReclaimsInactiveLineageCapacityAcrossRestart(
        bool constrainBytes)
    {
        var suffix = constrainBytes ? "bytes" : "count";
        var fixture = Fixture.Create(Path.Combine(_root, $"global-gc-{suffix}"), 1_000);
        var replacementFixture = Fixture.Create(
            Path.Combine(_root, $"global-gc-{suffix}-replacement"), 1_000);
        var expired = fixture.CreateDirectClosure();
        var replacement = replacementFixture.WithDistinctSelection(
            replacementFixture.CreateDirectClosure(
                250, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9), 0xA3);
        replacementFixture.Node.RouterId = fixture.Node.RouterId;
        var expiredScheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [expired.CanonicalEnvelope], fixture.Options.MaximumClosureVersionsPerSelection).Length;
        var replacementScheduleLength = ProductionMailboxClosureScheduleCodec.Encode(
            [replacement.CanonicalEnvelope], fixture.Options.MaximumClosureVersionsPerSelection).Length;
        fixture.Options.MaximumStoredClosures = constrainBytes ? 8 : 1;
        fixture.Options.MaximumClosureStoreBytes = constrainBytes
            ? Math.Max(expiredScheduleLength, replacementScheduleLength)
                + fixture.Options.ClosureScheduleAccountingOverheadBytes
            : 32L * 1024 * 1024;
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await initial.PrepositionAsync(
            fixture.PrepositionCommand(expired, 0x81), CancellationToken.None);

        var afterExpiry = checked(Now + 250);
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterExpiry)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((0, 0L), restarted.StorageAccounting);
        Assert.Empty(Directory.EnumerateDirectories(
            fixture.Options.ClosureDirectory, "*", SearchOption.AllDirectories));

        await restarted.PrepositionAsync(
            replacementFixture.PrepositionCommand(replacement, 0x82),
            CancellationToken.None);
        Assert.Equal(1, restarted.StorageAccounting.Count);
        Assert.Equal(replacementScheduleLength
            + fixture.Options.ClosureScheduleAccountingOverheadBytes,
            restarted.StorageAccounting.Bytes);
    }

    [Fact]
    public async Task GlobalExpiredGc_IsDemandDrivenOnMutationCapacityPressure()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "global-gc-demand"), 1_000);
        var replacementFixture = Fixture.Create(
            Path.Combine(_root, "global-gc-demand-replacement"), 1_000);
        var expired = fixture.CreateDirectClosure();
        var replacement = replacementFixture.WithDistinctSelection(
            replacementFixture.CreateDirectClosure(
                250, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9), 0xA4);
        replacementFixture.Node.RouterId = fixture.Node.RouterId;
        fixture.Options.MaximumStoredClosures = 1;
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var globalGcRuns = 0;
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), new ProductionMailboxClosureStoreTestHooks(
                BeforeGlobalExpiredGc: () => Interlocked.Increment(ref globalGcRuns)));
        Assert.Equal(1, globalGcRuns);
        globalGcRuns = 0;
        await store.PrepositionAsync(
            fixture.PrepositionCommand(expired, 0x86), CancellationToken.None);
        Assert.Equal(0, globalGcRuns);

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)checked(Now + 250));
        await store.PrepositionAsync(
            replacementFixture.PrepositionCommand(replacement, 0x87),
            CancellationToken.None);
        Assert.Equal(1, globalGcRuns);
        Assert.Equal(1, store.StorageAccounting.Count);
    }

    [Fact]
    public async Task CapacityPressure_ReplacesExpiredTargetWithoutStaleAccounting()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "global-gc-target"), 1_000);
        var unrelatedFixture = Fixture.Create(
            Path.Combine(_root, "global-gc-target-unrelated"), 1_000);
        var futureFixture = Fixture.Create(
            Path.Combine(_root, "global-gc-target-future"), 1_000);
        var targetExpired = fixture.CreateDirectClosure();
        var unrelatedExpired = unrelatedFixture.WithDistinctSelection(
            unrelatedFixture.CreateDirectClosure(), 0xA5);
        var targetFuture = futureFixture.CreateDirectClosure(
            250, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9);
        unrelatedFixture.Node.RouterId = fixture.Node.RouterId;
        futureFixture.Node.RouterId = fixture.Node.RouterId;
        fixture.Options.MaximumStoredClosures = 2;
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await store.PrepositionAsync(
            fixture.PrepositionCommand(targetExpired, 0x88), CancellationToken.None);
        await store.PrepositionAsync(
            unrelatedFixture.PrepositionCommand(unrelatedExpired, 0x89),
            CancellationToken.None);
        Assert.Equal(2, store.StorageAccounting.Count);

        fixture.Options.MaximumStoredClosures = 1;
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)checked(Now + 250));
        await store.PrepositionAsync(
            futureFixture.PrepositionCommand(targetFuture, 0x8A),
            CancellationToken.None);

        Assert.Equal(1, store.StorageAccounting.Count);
        Assert.Single(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task GlobalExpiredGc_AmbiguousDeleteOrFlushReconcilesAndNeverEvictsFutureSchedule(
        bool failOnFlush)
    {
        var fixture = Fixture.Create(Path.Combine(_root, "global-gc-ambiguous"), 1_000);
        var expired = fixture.CreateDirectClosure();
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await initial.PrepositionAsync(
            fixture.PrepositionCommand(expired, 0x83), CancellationToken.None);
        var afterExpiry = checked(Now + 250);
        Assert.Throws<IOException>(() => new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterExpiry)),
            new MailboxStorageSecurity(), failOnFlush
                ? new ThrowOnceAfterExpiredFlushBarrier()
                : new ThrowOnceAfterExpiredDeleteBarrier()));
        var recovered = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterExpiry)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((0, 0L), recovered.StorageAccounting);

        var liveFixture = Fixture.Create(Path.Combine(_root, "global-gc-live"), 1_000);
        var futureFixture = Fixture.Create(Path.Combine(_root, "global-gc-future"), 1_000);
        var current = liveFixture.CreateDirectClosure();
        var future = futureFixture.CreateDirectClosure(
            300, ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint, 9);
        futureFixture.Node.RouterId = liveFixture.Node.RouterId;
        var liveStore = new ProductionMailboxClosureStore(
            liveFixture.Options, liveFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await liveStore.PrepositionAsync(
            liveFixture.PrepositionCommand(current, 0x84), CancellationToken.None);
        await liveStore.PrepositionAsync(
            futureFixture.PrepositionCommand(future, 0x85), CancellationToken.None);
        var beforeFuture = checked(Now + 250);
        var liveRestart = new ProductionMailboxClosureStore(
            liveFixture.Options, liveFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)beforeFuture)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(2, liveRestart.StorageAccounting.Count);
        Assert.Single(Directory.EnumerateFiles(
            liveFixture.Options.ClosureDirectory, "*.pmcs1", SearchOption.AllDirectories));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task EmptyShardDeleteAmbiguity_ReconcilesAtEveryDirectoryLevel(int faultIndex)
    {
        var fixture = Fixture.Create(
            Path.Combine(_root, $"empty-shard-fault-{faultIndex}"), 1_000);
        var expired = fixture.CreateDirectClosure();
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await initial.PrepositionAsync(
            fixture.PrepositionCommand(expired, 0x8B), CancellationToken.None);
        var afterExpiry = checked(Now + 250);

        Assert.Throws<IOException>(() => new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterExpiry)),
            new MailboxStorageSecurity(),
            new ThrowOnNthDirectoryDeleteBarrier(faultIndex)));
        var recovered = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterExpiry)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((0, 0L), recovered.StorageAccounting);
        Assert.Empty(Directory.EnumerateDirectories(
            fixture.Options.ClosureDirectory, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void StartupEmptyShardSweep_IsBoundedAndFailClosed()
    {
        var cleanupFixture = Fixture.Create(Path.Combine(_root, "empty-shard-cleanup"));
        Directory.CreateDirectory(Path.Combine(
            cleanupFixture.Options.ClosureDirectory, "aa", "selection", "lineage"));
        _ = new ProductionMailboxClosureStore(
            cleanupFixture.Options, cleanupFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Empty(Directory.EnumerateDirectories(
            cleanupFixture.Options.ClosureDirectory, "*", SearchOption.AllDirectories));

        var overflowFixture = Fixture.Create(Path.Combine(_root, "empty-shard-overflow"));
        overflowFixture.Options.MaximumStoredClosures = 1;
        for (var index = 0; index < 260; index++)
            Directory.CreateDirectory(Path.Combine(
                overflowFixture.Options.ClosureDirectory, $"empty-{index:D3}"));
        Assert.Throws<InvalidOperationException>(() => new ProductionMailboxClosureStore(
            overflowFixture.Options, overflowFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
    }

    [Fact]
    public async Task SecureFinalOrFlushFailure_ReconcilesBeforeExactRetry()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "secure-flush"));
        var material = fixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var command = fixture.PrepositionCommand(material);

        var security = new ThrowOnceOnFinalClosureSecurity();
        var secureStore = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, security, new MailboxDurabilityBarrier());
        await Assert.ThrowsAsync<IOException>(async () =>
            await secureStore.PrepositionAsync(command, CancellationToken.None));
        await secureStore.PrepositionAsync(command, CancellationToken.None);

        var flushFixture = Fixture.Create(Path.Combine(_root, "flush-only"));
        var flushMaterial = flushFixture.CreateDirectClosure();
        var flushCommand = flushFixture.PrepositionCommand(flushMaterial);
        var flushStore = new ProductionMailboxClosureStore(
            flushFixture.Options, flushFixture.Node, clock, new MailboxStorageSecurity(),
            new ThrowOnceOnClosureFlushBarrier());
        await Assert.ThrowsAsync<IOException>(async () =>
            await flushStore.PrepositionAsync(flushCommand, CancellationToken.None));
        await flushStore.PrepositionAsync(flushCommand, CancellationToken.None);
    }

    [Fact]
    public void OrphanAtomicTemporary_FailsClosedAtStartup()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "orphan-temp"));
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        File.WriteAllBytes(Path.Combine(fixture.Options.ClosureDirectory,
            "schedule.pmcs1.00000000000000000000000000000000.tmp"), [0x01]);

        Assert.Throws<InvalidOperationException>(() =>
            new ProductionMailboxClosureStore(
                fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
                new MailboxDurabilityBarrier()));
    }

    [Fact]
    public async Task ClosureRead_PathSwapBetweenNativeOpensFailsClosed()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "closure-path-swap"));
        var material = fixture.CreateDirectClosure();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        await writer.PrepositionAsync(
            fixture.PrepositionCommand(material), CancellationToken.None);
        var armed = false;
        var hook = new ProductionMailboxClosureStoreTestHooks(path =>
        {
            if (!armed) return;
            armed = false;
            var displaced = path + ".displaced";
            File.Move(path, displaced);
            File.WriteAllBytes(path, material.CanonicalEnvelope);
        });
        var reader = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), hook);
        var unsigned = new ProductionMailboxClosureRequest(
            Now, Bytes(0x46, 32), material.SelectionInputCommitment,
            material.OldSelectionHash, material.OwnerPublicKey, new byte[64]);
        var request = ProductionMailboxClosureRequestCodec.Encode(unsigned with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(unsigned),
                material.OwnerPrivateKey)
        });

        armed = true;
        Assert.Null(await reader.FetchAsync(request, CancellationToken.None));
    }

    [Fact]
    public async Task PrepositionHttp_IsPeerOnlyAndMalformedMaximumLengthIsCoarseBadRequest()
    {
        const int apiPort = 7080;
        const int peerPort = 7443;
        var fixture = Fixture.Create(Path.Combine(_root, "preposition-http"));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var malformed = new byte[ProductionMailboxPrepositionCommandCodec.HeaderLength];
        "PMP1"u8.CopyTo(malformed);
        malformed[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(malformed.AsSpan(272), uint.MaxValue);

        var apiContext = PrepositionContext(malformed, apiPort);
        var apiResult = await ProductionMailboxClosureHttpEndpoint.HandlePrepositionAsync(
            apiContext, store, peerPort, CancellationToken.None);
        await apiResult.ExecuteAsync(apiContext);
        Assert.Equal(StatusCodes.Status404NotFound, apiContext.Response.StatusCode);

        var peerContext = PrepositionContext(malformed, peerPort);
        var peerResult = await ProductionMailboxClosureHttpEndpoint.HandlePrepositionAsync(
            peerContext, store, peerPort, CancellationToken.None);
        await peerResult.ExecuteAsync(peerContext);
        var body = await ResponseBody(peerContext);

        Assert.Equal(StatusCodes.Status400BadRequest, peerContext.Response.StatusCode);
        Assert.Equal("no-store", peerContext.Response.Headers.CacheControl);
        Assert.DoesNotContain(nameof(OverflowException), body, StringComparison.Ordinal);
        Assert.DoesNotContain("ProductionMailbox", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CapacityHttp_IsPeerOnlyBoundedAndReturnsNodeReceipt()
    {
        const int apiPort = 7080;
        const int peerPort = 7443;
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-http"));
        _ = fixture.CreateDirectClosure();
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var command = fixture.CapacityCommand(Bytes(0x98, 32), 2, 65_536);

        var apiContext = PrepositionContext(command, apiPort,
            ProductionMailboxClosureHttpContract.CapacityCommandMediaType);
        var apiResult = await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            apiContext, store, peerPort, CancellationToken.None);
        await apiResult.ExecuteAsync(apiContext);
        Assert.Equal(StatusCodes.Status404NotFound, apiContext.Response.StatusCode);

        var peerContext = PrepositionContext(command, peerPort,
            ProductionMailboxClosureHttpContract.CapacityCommandMediaType);
        var peerResult = await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            peerContext, store, peerPort, CancellationToken.None);
        await peerResult.ExecuteAsync(peerContext);
        Assert.Equal(StatusCodes.Status200OK, peerContext.Response.StatusCode);
        Assert.Equal("no-store", peerContext.Response.Headers.CacheControl);
        Assert.Equal(ProductionMailboxClosureHttpContract.CapacityReceiptMediaType,
            peerContext.Response.ContentType);
        var canonicalReceipt = ((MemoryStream)peerContext.Response.Body).ToArray();
        var receipt = ProductionMailboxCapacityReceiptCodec.Decode(canonicalReceipt);
        Assert.True(ProductionMailboxCapacityReceiptCodec.VerifyNode(
            receipt, fixture.Node.GetRouterId().ToBytes()));

        var truncated = command[..^1];
        var badContext = PrepositionContext(truncated, peerPort,
            ProductionMailboxClosureHttpContract.CapacityCommandMediaType);
        var badResult = await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            badContext, store, peerPort, CancellationToken.None);
        await badResult.ExecuteAsync(badContext);
        Assert.Equal(StatusCodes.Status400BadRequest, badContext.Response.StatusCode);
        Assert.DoesNotContain("ProductionMailbox", await ResponseBody(badContext),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task CapacityAdmission_RejectsConfiguredOverflowAndTerminalReserveCoarsely()
    {
        const int peerPort = 7443;
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-bounds"));
        _ = fixture.CreateDirectClosure();
        fixture.Options.MaximumStoredClosures = 2;
        fixture.Options.MaximumClosureStoreBytes = 1_048_576;
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await store.ReserveCapacityAsync(
                fixture.CapacityCommand(Bytes(0x9D, 32), 1, 1_048_576,
                    revision: ulong.MaxValue, nonce: 0x57),
                CancellationToken.None));
        var oversized = fixture.CapacityCommand(
            Bytes(0x9E, 32), uint.MaxValue, ulong.MaxValue, nonce: 0x58);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.ReserveCapacityAsync(oversized, CancellationToken.None));

        var context = PrepositionContext(oversized, peerPort,
            ProductionMailboxClosureHttpContract.CapacityCommandMediaType);
        var result = await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            context, store, peerPort, CancellationToken.None);
        await result.ExecuteAsync(context);
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        var body = await ResponseBody(context);
        Assert.DoesNotContain(nameof(OverflowException), body, StringComparison.Ordinal);
        Assert.DoesNotContain("ProductionMailbox", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CapacityAdmission_RevalidatesClockAfterAcquiringMutationLock()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-stale-clock"));
        _ = fixture.CreateDirectClosure();
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var hooks = new ProductionMailboxClosureStoreTestHooks(
            BeforeCapacityAdmission: () => clock.UtcNow =
                DateTimeOffset.FromUnixTimeSeconds((long)(Now + 1)));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), hooks);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.ReserveCapacityAsync(
                fixture.CapacityCommand(Bytes(0x9F, 32), 1, 65_536),
                CancellationToken.None));
        Assert.Empty(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, ".capacity-*.pbf1",
            SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public void MonotonicClosureCas_RejectsOlderAuthorityTopologyAndEpoch()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "rollback"));
        var material = fixture.CreateDirectClosure();
        var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(material.CanonicalEnvelope);
        var existing = ProductionMailboxSelectionSuccessorCodec.Decode(envelope.Successor.Span);
        var authority = ProductionMailboxAuthorityCodec.Decode(existing.CanonicalNewAuthority.Span);
        var olderDraft = authority with
        {
            AuthorityGeneration = authority.AuthorityGeneration - 1,
            MrXApproval = authority.MrXApproval with
            {
                AuthorityPayloadHash = new byte[32]
            }
        };
        var olderAuthority = olderDraft with
        {
            MrXApproval = olderDraft.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec
                    .ComputePayloadHash(olderDraft)
            }
        };
        var candidate = existing with
        {
            CanonicalNewAuthority = ProductionMailboxAuthorityCodec.Encode(olderAuthority),
            NewTopologyGeneration = existing.NewTopologyGeneration - 1,
            NewEpoch = existing.NewEpoch - 1
        };

        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureStore.EnsureStrictlyForward(existing, candidate));

        var forwardDraft = authority with
        {
            AuthorityGeneration = authority.AuthorityGeneration + 1,
            MrXApproval = authority.MrXApproval with { AuthorityPayloadHash = new byte[32] }
        };
        var forwardAuthority = forwardDraft with
        {
            MrXApproval = forwardDraft.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec
                    .ComputePayloadHash(forwardDraft)
            }
        };
        var crossOwner = existing with
        {
            MailboxOwnerEd25519PublicKey = Bytes(0x7A, 32),
            CanonicalNewAuthority = ProductionMailboxAuthorityCodec.Encode(forwardAuthority),
            NewTopologyGeneration = existing.NewTopologyGeneration + 1,
            NewEpoch = existing.NewEpoch + 1
        };
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureStore.EnsureStrictlyForward(existing, crossOwner));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureStore.EnsureStrictlyForward(existing,
                crossOwner with
                {
                    MailboxOwnerEd25519PublicKey = existing.MailboxOwnerEd25519PublicKey,
                    OldCanonicalSelectionHash = Bytes(0x7B, 32)
                }));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureStore.EnsureStrictlyForward(existing,
                existing with
                {
                    CanonicalNewAuthority = ProductionMailboxAuthorityCodec.Encode(forwardAuthority),
                    NewTopologyGeneration = existing.NewTopologyGeneration + 1,
                    NewEpoch = existing.NewEpoch + 1,
                    IssuedAtUnixSeconds = existing.IssuedAtUnixSeconds + 1,
                    ExpiresAtUnixSeconds = existing.ExpiresAtUnixSeconds
                }));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public async Task MissingOrCorruptTopologyOrSelectionNeverPublishes(
        bool missing,
        bool selection)
    {
        var fixture = Fixture.Create(_root);
        var path = selection ? fixture.SelectionPath : fixture.TopologyArtifactPath;
        if (missing)
        {
            File.Delete(path);
        }
        else
        {
            File.WriteAllBytes(path, [0x01, 0x02]);
        }

        var original = File.ReadAllBytes(fixture.LkgPath);
        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal(original, File.ReadAllBytes(fixture.LkgPath));
    }

    [Fact]
    public async Task TopologyForkRetainsPriorCompleteBundleAndDurableState()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);
        var current = ProductionMailboxTopologyCodec.Decode(
            File.ReadAllBytes(fixture.TopologyArtifactPath));
        var fork = fixture.SignTopology(current with
        {
            TopologyGeneration = current.TopologyGeneration + 1,
            PreviousTopologyHash = Bytes(0xF0, 32)
        });
        File.WriteAllBytes(
            fixture.TopologyArtifactPath,
            ProductionMailboxTopologyCodec.Encode(fork));

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal("topology-chain-rejected", provider.Status.Reason);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
        Assert.True(provider.TryResolve(
            fixture.Authority.CurrentEpoch.Epoch,
            fixture.Authority.CurrentEpoch.MembershipCommitment,
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(
                fixture.Options.GetReadinessBlindedPlacementId())),
            fixture.Options.GetReadinessBlindedPlacementId(),
            fixture.Options.GetReadinessSelectionInputCommitment(),
            out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MissingOrCorruptRevocationFailsClosed(bool missing)
    {
        var fixture = Fixture.Create(_root);
        if (missing)
        {
            File.Delete(fixture.RevocationArtifactPath);
        }
        else
        {
            File.WriteAllBytes(fixture.RevocationArtifactPath, [0x01, 0x02]);
        }

        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.False(provider.Status.RevocationArtifactVerified);
        Assert.Equal(
            missing ? "authority-state-rejected" : "revocation-verification-rejected",
            provider.Status.Reason);
    }

    [Fact]
    public async Task InvalidSuccessorRevocationDoesNotAdvanceLkgOrReplacePublishedPair()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);

        var successor = fixture.Successor();
        var snapshot = ProductionMailboxRevocationSnapshotCodec.Decode(
            File.ReadAllBytes(fixture.RevocationArtifactPath));
        var invalid = snapshot with
        {
            IssuerSignature = Bytes(0xF0, 64)
        };
        var invalidBytes = ProductionMailboxRevocationSnapshotCodec.Encode(invalid);
        successor = fixture.Sign(successor with
        {
            Revocation = successor.Revocation with
            {
                SnapshotHash = SHA256.HashData(invalidBytes)
            }
        });
        fixture.WriteArtifact(successor);
        File.WriteAllBytes(fixture.RevocationArtifactPath, invalidBytes);

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal("revocation-signature-rejected", provider.Status.Reason);
        Assert.Equal(7UL, provider.Status.AuthorityGeneration);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
        Assert.True(provider.IsRevoked(Query(fixture, Bytes(0x10, 16))));
    }

    [Fact]
    public async Task SuccessorWithPreviousSnapshotFailsWithoutAdvancingPair()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);
        var previousSnapshot = File.ReadAllBytes(fixture.RevocationArtifactPath);
        var successor = fixture.Successor();
        fixture.WriteArtifact(successor);
        File.WriteAllBytes(fixture.RevocationArtifactPath, previousSnapshot);

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal("revocation-verification-rejected", provider.Status.Reason);
        Assert.Equal(7UL, provider.Status.AuthorityGeneration);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RollbackAndForkFailClosedWithoutChangingLkg(bool fork)
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var committed = File.ReadAllBytes(fixture.LkgPath);
        var rejected = fork
            ? fixture.Successor(previousAuthorityHash: Bytes(0x91, 32))
            : fixture.Sign(fixture.Authority with
            {
                AuthorityGeneration = 6,
                PreviousAuthorityHash = Bytes(0x41, 32)
            });
        File.WriteAllBytes(
            fixture.ArtifactPath,
            ProductionMailboxAuthorityCodec.Encode(rejected));

        await provider.InitializeAsync();

        Assert.True(provider.IsConfigured);
        Assert.Equal(
            fork ? "authority-chain-rejected" : "authority-rollback-rejected",
            provider.Status.Reason);
        Assert.Equal(committed, File.ReadAllBytes(fixture.LkgPath));
    }

    [Fact]
    public async Task BadMrXPinFailsClosed()
    {
        var fixture = Fixture.Create(_root);
        fixture.Options.PinnedMrXPublicKeySha256 = Hex(Bytes(0xE1, 32));
        var provider = fixture.Provider();

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal("mr-x-pin-rejected", provider.Status.Reason);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExpiredOrFutureRevocationFailsClosed(bool expired)
    {
        var fixture = Fixture.Create(_root);
        var revocation = fixture.Authority.Revocation with
        {
            IssuedAtUnixSeconds = expired ? Now - 500 : Now + 301,
            ExpiresAtUnixSeconds = expired ? Now - 301 : Now + 600
        };
        fixture.WriteArtifact(fixture.Sign(fixture.Authority with { Revocation = revocation }));
        var provider = fixture.Provider();

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal(
            expired ? "authority-expired" : "authority-not-yet-valid",
            provider.Status.Reason);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task MissingOrCorruptInputsFailClosed(bool missingArtifact, bool missingLkg)
    {
        var fixture = Fixture.Create(_root);
        if (missingArtifact)
        {
            File.Delete(fixture.ArtifactPath);
        }
        else if (missingLkg)
        {
            File.Delete(fixture.LkgPath);
        }
        else
        {
            File.WriteAllBytes(fixture.LkgPath, [0x01, 0x02, 0x03]);
        }

        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal("authority-state-rejected", provider.Status.Reason);
    }

    [Fact]
    public async Task FailedAtomicReplaceKeepsOldLkgAndPublishesNoAuthority()
    {
        var fixture = Fixture.Create(_root);
        var original = File.ReadAllBytes(fixture.LkgPath);
        var provider = fixture.Provider(new ThrowingBarrier());

        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.False(provider.Status.Ready);
        Assert.Equal(original, File.ReadAllBytes(fixture.LkgPath));
        Assert.Empty(Directory.GetFiles(_root, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task ResolverPinsIssuerNetworkEpochGenerationAndCommitments()
    {
        var fixture = Fixture.Create(_root);
        var provider = fixture.Provider();
        await provider.InitializeAsync();
        var epoch = fixture.Authority.CurrentEpoch;
        var placement = MailboxPlacementCommitment.Compute(
            new BlindedPlacementId(fixture.Options.GetReadinessBlindedPlacementId()));
        var query = new MailboxCapabilityAuthorityQuery(
            MailboxAuthenticatedOperation.Store,
            MailboxCapabilityDomain.Deposit,
            epoch.Epoch,
            epoch.Generation,
            MailboxCapabilityLifecycle.Active,
            fixture.Authority.NetworkId,
            placement,
            epoch.MembershipCommitment,
            fixture.Authority.MailboxIssuerEd25519PublicKey);

        Assert.True(provider.TryResolve(query, out var policy));
        Assert.NotNull(policy);
        Assert.Equal(epoch.Generation, policy.MinimumGeneration);
        Assert.False(provider.TryResolve(
            query with { Generation = epoch.Generation + 1 },
            out _));
        Assert.False(provider.TryResolve(
            query with { NetworkId = Bytes(0xF1, 16) },
            out _));
    }

    [Fact]
    public void OptionsEnforceProductionOnlyExactPublicConfigurationAndLkgRoot()
    {
        var fixture = Fixture.Create(_root);
        fixture.Options.Validate(fixture.Node, isProduction: true);
        Assert.Throws<InvalidOperationException>(() =>
            fixture.Options.Validate(fixture.Node, isProduction: false));
        fixture.Options.LastKnownGoodPath = Path.Combine(_root, "outside.pml1");
        Assert.Throws<InvalidOperationException>(() =>
            fixture.Options.Validate(fixture.Node, isProduction: true));

        fixture.Options.LastKnownGoodPath = Path.Combine(
            fixture.Node.DataDirectory,
            "authority.pml1");
        fixture.Options.ArtifactTrustRoot = fixture.Node.DataDirectory;
        Assert.Throws<InvalidOperationException>(() =>
            fixture.Options.Validate(fixture.Node, isProduction: true));
    }

    [Fact]
    public void ProtocolRejectsHttpAndOfficialPrivateEndpointPolicyMismatch()
    {
        var fixture = Fixture.Create(_root);
        Assert.Equal(
            ProductionMailboxAuthorityError.InvalidEndpoint,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityCodec.Encode(fixture.Sign(
                    fixture.Authority with
                    {
                        NodeIngress = fixture.Authority.NodeIngress with
                        {
                            Uri = "http://ingress.example.net/mau2/"
                        }
                    }))).Error);
        Assert.Equal(
            ProductionMailboxAuthorityError.InvalidEndpoint,
            Assert.Throws<ProductionMailboxAuthorityException>(() =>
                ProductionMailboxAuthorityCodec.Encode(fixture.Sign(
                    fixture.Authority with
                    {
                        NodeIngress = fixture.Authority.NodeIngress with
                        {
                            Uri = "https://192.168.1.2/mau2/"
                        }
                    }))).Error);
    }

    [Fact]
    public void DefaultSecurityRejectsWritableArtifact()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "authority.pma1");
        File.WriteAllBytes(path, [0x01]);

        Assert.Throws<UnauthorizedAccessException>(() =>
            new ProductionMailboxAuthorityFileSecurity()
                .ValidateReadOnlyArtifact(path, _root));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    public void WindowsAclValidationRejectsWrongOwnerAndExtraPrincipal()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var current = WindowsIdentity.GetCurrent().User!;
        var other = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
            ExactWindowsSecurity(current, current, FileSystemRights.Read),
            current,
            requireReadOnly: true);
        ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
            ExactWindowsSecurity(current, current, FileSystemRights.FullControl),
            current,
            requireReadOnly: false);
        var wrongOwner = ExactWindowsSecurity(other, other, FileSystemRights.Read);
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                wrongOwner,
                current,
                requireReadOnly: true));

        var extraPrincipal = ExactWindowsSecurity(current, current, FileSystemRights.Read);
        extraPrincipal.AddAccessRule(new FileSystemAccessRule(
            other,
            FileSystemRights.Read,
            AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                extraPrincipal,
                current,
                requireReadOnly: true));
    }

    [Fact]
    public void DefaultSecurityRejectsInheritedOrWritableAncestor()
    {
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsUnsafeAncestorRejected();
            return;
        }

        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "authority.pma1");
        File.WriteAllBytes(path, [0x01]);
        File.SetUnixFileMode(path, UnixFileMode.UserRead);
        File.SetUnixFileMode(
            _root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupWrite);

        Assert.Throws<UnauthorizedAccessException>(() =>
            new ProductionMailboxAuthorityFileSecurity()
                .ValidateReadOnlyArtifact(path, _root));
    }

    [Fact]
    public void DefaultSecurityAcceptsExactProtectedUnixTree()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        Directory.CreateDirectory(_root);
        File.SetUnixFileMode(
            _root,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var artifact = Path.Combine(_root, "authority.pma1");
        var lkg = Path.Combine(_root, "authority.pml1");
        File.WriteAllBytes(artifact, [0x01]);
        File.WriteAllBytes(lkg, [0x02]);
        File.SetUnixFileMode(artifact, UnixFileMode.UserRead);
        File.SetUnixFileMode(lkg, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var security = new ProductionMailboxAuthorityFileSecurity();
        security.ValidateReadOnlyArtifact(artifact, _root);
        security.ValidateProtectedLastKnownGood(lkg, _root);
    }

    [Fact]
    public void StableOpenRejectsPathSwap()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "authority.pma1");
        var replacement = Path.Combine(_root, "replacement.pma1");
        var old = Path.Combine(_root, "old.pma1");
        File.WriteAllBytes(path, [0x01]);
        File.WriteAllBytes(replacement, [0x02]);

        Assert.Throws<InvalidDataException>(() =>
        {
            using var ignored = ProductionMailboxAuthorityNativeFile.OpenStableRead(
                path,
                static () => { },
                () =>
                {
                    File.Move(path, old);
                    File.Move(replacement, path);
                });
        });
    }

    [Fact]
    public async Task PlantedLockLinkFailsClosed()
    {
        var fixture = Fixture.Create(_root);
        var target = Path.Combine(_root, "lock-target");
        File.WriteAllBytes(target, [0x01]);
        try
        {
            File.CreateSymbolicLink(fixture.LkgPath + ".lock", target);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        Assert.NotNull(File.ResolveLinkTarget(fixture.LkgPath + ".lock", returnFinalTarget: false));
        Assert.Throws<InvalidDataException>(() =>
        {
            using var ignored = ProductionMailboxAuthorityNativeFile.OpenStableRead(
                fixture.LkgPath + ".lock",
                static () => { });
        });

        var provider = fixture.Provider();
        await provider.InitializeAsync();

        Assert.False(provider.IsConfigured);
        Assert.Equal("authority-state-rejected", provider.Status.Reason);
        Assert.Equal(new byte[] { 0x01 }, File.ReadAllBytes(target));
    }

    [Fact]
    public void CreatedLockIsSecuredThroughItsOpenHandle()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "created.lock");

        using var lease = ProductionMailboxAuthorityNativeFile.AcquireLock(
            path,
            () =>
            {
                if (!File.Exists(path))
                {
                    throw new InvalidDataException("missing lock");
                }
            },
            new MailboxDurabilityBarrier());

        Assert.True(File.Exists(path));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(path));
        }
    }

    [Fact]
    public void CreatedLockPathSwapRejectsWithoutMutatingSubstitute()
    {
        Directory.CreateDirectory(_root);
        var path = Path.Combine(_root, "created.lock");
        var displaced = Path.Combine(_root, "created.displaced");
        var substitute = Path.Combine(_root, "substitute.lock");
        File.WriteAllBytes(substitute, [0x5a]);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                substitute,
                UnixFileMode.UserRead | UnixFileMode.UserWrite
                    | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        var permissionsBefore = PermissionSnapshot(substitute);

        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxAuthorityNativeFile.AcquireLock(
                path,
                () =>
                {
                    if (!File.Exists(path))
                    {
                        throw new InvalidDataException("missing lock");
                    }
                },
                new MailboxDurabilityBarrier(),
                () =>
                {
                    File.Move(path, displaced);
                    File.Move(substitute, path);
                }));

        Assert.Equal(new byte[] { 0x5a }, File.ReadAllBytes(path));
        Assert.Equal(permissionsBefore, PermissionSnapshot(path));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            foreach (var file in Directory.GetFiles(_root, "*", SearchOption.AllDirectories))
            {
                File.SetAttributes(file, FileAttributes.Normal);
            }

            Directory.Delete(_root, recursive: true);
        }
    }

    [SupportedOSPlatform("windows")]
    private static FileSecurity ExactWindowsSecurity(
        SecurityIdentifier owner,
        SecurityIdentifier principal,
        FileSystemRights rights)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(owner);
        security.AddAccessRule(new FileSystemAccessRule(
            principal,
            rights,
            AccessControlType.Allow));
        return security;
    }

    private static string PermissionSnapshot(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return Convert.ToHexString(
                new FileInfo(path).GetAccessControl().GetSecurityDescriptorBinaryForm());
        }

        return File.GetUnixFileMode(path).ToString();
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsUnsafeAncestorRejected()
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var other = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var unsafeDirectory = new DirectorySecurity();
        unsafeDirectory.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        unsafeDirectory.SetOwner(current);
        unsafeDirectory.AddAccessRule(new FileSystemAccessRule(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        unsafeDirectory.AddAccessRule(new FileSystemAccessRule(
            other,
            FileSystemRights.Modify,
            AccessControlType.Allow));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                unsafeDirectory,
                current,
                requireReadOnly: false));

        var inheritedPolicy = new DirectorySecurity();
        inheritedPolicy.SetOwner(current);
        inheritedPolicy.AddAccessRule(new FileSystemAccessRule(
            current,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        Assert.False(inheritedPolicy.AreAccessRulesProtected);
        Assert.Throws<UnauthorizedAccessException>(() =>
            ProductionMailboxAuthorityFileSecurity.ValidateWindowsAcl(
                inheritedPolicy,
                current,
                requireReadOnly: false));
    }

    private static DefaultHttpContext PrepositionContext(byte[] body, int localPort,
        string? contentType = null)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = localPort;
        context.Request.ContentLength = body.Length;
        context.Request.ContentType = contentType
            ?? ProductionMailboxClosureHttpContract.PrepositionMediaType;
        context.Request.Body = new MemoryStream(body, writable: false);
        context.Response.Body = new MemoryStream();
        context.RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider();
        return context;
    }

    private static async Task<string> ResponseBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }

    private static byte[] Bytes(byte seed, int length) => Enumerable.Range(0, length)
        .Select(index => unchecked((byte)(seed + index)))
        .ToArray();

    private static string Hex(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();

    private static MailboxCapabilityRevocationQuery Query(
        Fixture fixture,
        byte[] serial) => new()
        {
            IssuerPublicKey = fixture.Authority.MailboxIssuerEd25519PublicKey,
            Serial = serial,
            Domain = MailboxCapabilityDomain.Deposit,
            Generation = fixture.Authority.CurrentEpoch.Generation,
            Epoch = fixture.Authority.CurrentEpoch.Epoch,
            MembershipCommitment = fixture.Authority.CurrentEpoch.MembershipCommitment
        };

    private sealed record ClosureMaterial(
        byte[] CanonicalEnvelope,
        byte[] SelectionInputCommitment,
        byte[] OwnerPublicKey,
        byte[] OwnerPrivateKey,
        IReadOnlyList<ReadOnlyMemory<byte>> OldCurrentReplicaIds)
    {
        public byte[] OldSelectionHash =>
            ProductionMailboxSelectionSuccessorCodec.Decode(
                ProductionMailboxClosureEnvelopeCodec.Decode(CanonicalEnvelope)
                    .Successor.Span).OldCanonicalSelectionHash.ToArray();
    }

    private sealed class Fixture
    {
        private readonly byte[] _privateKey;
        private readonly byte[] _issuerPrivateKey;
        private readonly Dictionary<ulong, MembershipRouteDescriptor[]> _descriptors;
        private readonly ulong _survivalHorizonSeconds;

        private Fixture(
            RouterNodeOptions node,
            ProductionMailboxAuthorityOptions options,
            ProductionMailboxAuthority authority,
            byte[] privateKey,
            byte[] issuerPrivateKey,
            Dictionary<ulong, MembershipRouteDescriptor[]> descriptors,
            ulong survivalHorizonSeconds)
        {
            Node = node;
            Options = options;
            Authority = authority;
            _privateKey = privateKey;
            _issuerPrivateKey = issuerPrivateKey;
            _descriptors = descriptors;
            _survivalHorizonSeconds = survivalHorizonSeconds;
        }

        public RouterNodeOptions Node { get; }
        public ProductionMailboxAuthorityOptions Options { get; }
        public ProductionMailboxAuthority Authority { get; private set; }
        public string ArtifactPath => Options.ArtifactPath;
        public string RevocationArtifactPath => Options.RevocationArtifactPath;
        public string TopologyArtifactPath => Options.TopologyArtifactPath;
        public string SelectionPath => Path.Combine(
            Options.SelectionArtifactDirectory,
            Options.ReadinessSelectionInputCommitment + ".pms1");
        public string LkgPath => Options.LastKnownGoodPath;

        public static Fixture Create(string root, ulong survivalHorizonSeconds = 0)
        {
            var data = Path.Combine(root, "data");
            Directory.CreateDirectory(data);
            var artifactPath = Path.Combine(root, "authority.pma1");
            var revocationArtifactPath = Path.Combine(root, "revocation.pmr1");
            var topologyArtifactPath = Path.Combine(root, "topology.pmt1");
            var selectionDirectory = Path.Combine(root, "selections");
            Directory.CreateDirectory(selectionDirectory);
            var lkgPath = Path.Combine(data, "authority.pml1");
            var closureDirectory = Path.Combine(data, "production-mailbox-closures");
            var closureHmacKeyPath = Path.Combine(data, "production-mailbox-closure-hmac.key");
            File.WriteAllBytes(closureHmacKeyPath, Bytes(0x26, 32));
            var pair = PublicKeyAuth.GenerateKeyPair(Bytes(0x21, 32));
            var issuerPair = PublicKeyAuth.GenerateKeyPair(Bytes(0x22, 32));
            var currentUntil = checked(Now + (survivalHorizonSeconds == 0
                ? 600UL : survivalHorizonSeconds + 3_600));
            var nextUntil = checked(Now + (survivalHorizonSeconds == 0
                ? 1_200UL : survivalHorizonSeconds + 7_200));
            var authorityUntil = Now + 300;
            var currentDescriptors = Descriptors(20, Now - 60, currentUntil);
            var nextDescriptors = Descriptors(21, Now - 10, nextUntil);
            var readinessPlacementId = Bytes(0x24, 32);
            var selectionInput = ProductionMailboxReplicaSelection
                .ComputeSelectionInputCommitment(new BlindedPlacementId(readinessPlacementId));
            var unsigned = new ProductionMailboxAuthority
            {
                DevelopmentOnly = false,
                Environment = ProductionMailboxAuthorityEnvironment.Production,
                Transport = ProductionMailboxAuthorityTransport.AuthenticatedMau2,
                Ownership = ProductionMailboxAuthorityOwnership.OfficialManaged,
                EndpointPolicy = ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
                NetworkId = Bytes(0x11, 16),
                AuthorityGeneration = 7,
                PreviousAuthorityHash = Bytes(0x31, 32),
                MailboxIssuerEd25519PublicKey = issuerPair.PublicKey,
                MrXApprovalEd25519PublicKey = pair.PublicKey,
                Coordinator = Endpoint("https://coordinator.example.net/", 0x61),
                NodeIngress = Endpoint("https://ingress.example.net/mau2/", 0x71),
                CurrentEpoch = Epoch(
                    20,
                    70,
                    Now - 60,
                    currentUntil,
                    MembershipRouteDescriptorCodec.ComputeRoot(currentDescriptors),
                    MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(readinessPlacementId))),
                NextEpoch = Epoch(
                    21,
                    71,
                    Now - 10,
                    nextUntil,
                    MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors),
                    Bytes(0x92, 32)),
                Revocation = new()
                {
                    SnapshotHash = Bytes(0xA1, 32),
                    HeadHash = Bytes(0xB1, 32),
                    PreviousHeadHash = Bytes(0xC1, 32),
                    Generation = 6,
                    IssuedAtUnixSeconds = Now - 30,
                    ExpiresAtUnixSeconds = authorityUntil
                },
                MrXApproval = Approval(Now - 30, authorityUntil),
                Signature = new byte[64]
            };
            var fixture = new Fixture(
                new RouterNodeOptions { DataDirectory = data },
                new ProductionMailboxAuthorityOptions
                {
                    Enabled = true,
                    ArtifactPath = artifactPath,
                    RevocationArtifactPath = revocationArtifactPath,
                    TopologyArtifactPath = topologyArtifactPath,
                    SelectionArtifactDirectory = selectionDirectory,
                    ReadinessBlindedPlacementId = Hex(readinessPlacementId),
                    ReadinessSelectionInputCommitment = Hex(selectionInput),
                    ArtifactTrustRoot = root,
                    LastKnownGoodPath = lkgPath,
                    ClosureDirectory = closureDirectory,
                    ClosureStateHmacKeyPath = closureHmacKeyPath,
                    ClosurePublisherEd25519PublicKey = Hex(issuerPair.PublicKey),
                    PinnedMrXPublicKeySha256 = Hex(SHA256.HashData(pair.PublicKey)),
                    ExpectedNetworkId = Hex(unsigned.NetworkId.ToArray()),
                    ClockSkewSeconds = 0
                },
                unsigned,
                pair.PrivateKey,
                issuerPair.PrivateKey,
                new Dictionary<ulong, MembershipRouteDescriptor[]>
                {
                    [20] = currentDescriptors,
                    [21] = nextDescriptors
                },
                survivalHorizonSeconds);
            fixture.Authority = fixture.BindAndSignPair(unsigned);
            fixture.WriteArtifact(fixture.Authority);
            File.WriteAllBytes(lkgPath, ProductionMailboxAuthorityLkgCodec.Encode(new(
                new(
                    6,
                    Bytes(0x31, 32),
                    5,
                    Bytes(0xC1, 32),
                    Bytes(0xD1, 32),
                    0,
                    new byte[32]),
                null,
                null)));
            return fixture;
        }

        public ProductionMailboxAuthorityProvider Provider(
            IMailboxDurabilityBarrier? durability = null,
            IClock? clock = null) => new(
            Options,
            Node,
            clock ?? new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new PermissiveSecurity(),
            new MailboxStorageSecurity(),
            durability ?? new MailboxDurabilityBarrier());

        public byte[] SeedFor(ReadOnlySpan<byte> replicaId, ulong epoch)
        {
            for (var index = 0; index < 3; index++)
            {
                var seed = DescriptorSeed(epoch, index);
                if (PublicKeyAuth.GenerateKeyPair(seed).PublicKey.AsSpan().SequenceEqual(replicaId))
                {
                    return seed;
                }
            }

            throw new InvalidOperationException("Selected fixture replica seed is unavailable.");
        }

        public ProductionMailboxAuthority Successor(
            byte[]? previousAuthorityHash = null,
            ulong activationOffsetSeconds = 0,
            ulong successorGeneration = 8)
        {
            if (successorGeneration is < 8 or > 10)
                throw new ArgumentOutOfRangeException(nameof(successorGeneration));
            var currentHash = ProductionMailboxAuthorityCodec.ComputeCanonicalHash(Authority);
            var activationTime = checked(Now + activationOffsetSeconds);
            var successorUntil = checked(Now + (_survivalHorizonSeconds == 0
                ? 1_800UL : _survivalHorizonSeconds + 10_800));
            var approvalUntil = checked(Now + (_survivalHorizonSeconds == 0
                ? 600UL : _survivalHorizonSeconds + 3_600));
            var currentEpochNumber = checked(13UL + successorGeneration);
            var currentGeneration = checked(63UL + successorGeneration);
            var currentDescriptors = successorGeneration == 8
                ? _descriptors[Authority.NextEpoch.Epoch]
                : Descriptors(currentEpochNumber, activationTime - 60, successorUntil);
            var nextDescriptors = Descriptors(
                checked(currentEpochNumber + 1), activationTime + 120, successorUntil);
            _descriptors[currentEpochNumber] = currentDescriptors;
            _descriptors[currentEpochNumber + 1] = nextDescriptors;
            var currentEpoch = successorGeneration == 8
                ? Authority.NextEpoch
                : Epoch(currentEpochNumber, currentGeneration,
                    activationTime - 60, successorUntil,
                    MembershipRouteDescriptorCodec.ComputeRoot(currentDescriptors),
                    Bytes(0xD2, 32));
            var successor = BindAndSignPair(Authority with
            {
                AuthorityGeneration = successorGeneration,
                PreviousAuthorityHash = previousAuthorityHash ?? currentHash,
                CurrentEpoch = currentEpoch,
                NextEpoch = Epoch(
                    currentEpochNumber + 1,
                    currentGeneration + 1,
                    activationTime + 120,
                    successorUntil,
                    MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors),
                    Bytes(0xD3, 32)),
                Revocation = Authority.Revocation with
                {
                    SnapshotHash = Bytes(0xE2, 32),
                    PreviousHeadHash = Authority.Revocation.HeadHash,
                    HeadHash = Bytes(0xF2, 32),
                    Generation = successorGeneration - 1,
                    IssuedAtUnixSeconds = activationTime - 30,
                    ExpiresAtUnixSeconds = activationTime + 300
                },
                MrXApproval = activationOffsetSeconds == 0
                    ? Approval(Now - 5, approvalUntil)
                    : Approval(activationTime - 30, activationTime + 300)
            });
            return successor;
        }

        public ClosureMaterial CreateDirectClosure(
            ulong issuedAtOffsetSeconds = 0,
            ProductionMailboxSelectionSuccessorMode mode =
                ProductionMailboxSelectionSuccessorMode.DirectPromotion,
            ulong successorGeneration = 8)
        {
            var oldAuthority = Authority;
            var oldAuthorityBytes = ProductionMailboxAuthorityCodec.Encode(oldAuthority);
            var oldTopologyBytes = File.ReadAllBytes(TopologyArtifactPath);
            var oldTopology = ProductionMailboxTopologyCodec.Decode(oldTopologyBytes);
            var oldVerifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(
                oldAuthority,
                new ProductionMailboxAuthorityVerificationContext
                {
                    PinnedMrXPublicKeySha256 = SHA256.HashData(
                        oldAuthority.MrXApprovalEd25519PublicKey.Span),
                    ExpectedNetworkId = oldAuthority.NetworkId,
                    LastCommittedGeneration = oldAuthority.AuthorityGeneration - 1,
                    LastCommittedAuthorityHash = oldAuthority.PreviousAuthorityHash,
                    LastCommittedRevocationGeneration = oldAuthority.Revocation.Generation - 1,
                    LastCommittedRevocationHeadHash = oldAuthority.Revocation.PreviousHeadHash,
                    LastCommittedRevocationSnapshotHash = Bytes(0xD1, 32),
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxAuthoritySignatureVerifier());
            var oldVerifiedTopology = ProductionMailboxTopologyVerifier.Verify(
                oldTopologyBytes, oldVerifiedAuthority,
                new ProductionMailboxTopologyVerificationContext
                {
                    LastCommittedTopologyGeneration = oldTopology.TopologyGeneration - 1,
                    LastCommittedTopologyHash = oldTopology.PreviousTopologyHash,
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxTopologySignatureVerifier());
            var oldCurrentSelectionBytes = CreateSelectionBytes(
                oldTopology, oldVerifiedTopology, oldTopology.CurrentEpoch,
                _descriptors[oldTopology.CurrentEpoch.Epoch]);
            var oldCurrentSelection = ProductionMailboxTopologyCodec.DecodeSelection(
                oldCurrentSelectionBytes);
            var oldNextSelectionBytes = CreateSelectionBytes(
                oldTopology, oldVerifiedTopology, oldTopology.NextEpoch,
                _descriptors[oldTopology.NextEpoch.Epoch]);
            var oldNextSelection = ProductionMailboxTopologyCodec.DecodeSelection(
                oldNextSelectionBytes);

            var newAuthority = Successor(
                activationOffsetSeconds: issuedAtOffsetSeconds,
                successorGeneration: successorGeneration);
            var newAuthorityBytes = ProductionMailboxAuthorityCodec.Encode(newAuthority);
            var newRevocationBytes = File.ReadAllBytes(RevocationArtifactPath);
            var newTopologyBytes = File.ReadAllBytes(TopologyArtifactPath);
            var newTopology = ProductionMailboxTopologyCodec.Decode(newTopologyBytes);
            var newSelectionBytes = File.ReadAllBytes(SelectionPath);
            var newSelection = ProductionMailboxTopologyCodec.DecodeSelection(newSelectionBytes);
            var owner = PublicKeyAuth.GenerateKeyPair(Bytes(0x2A, 32));
            var placementId = Options.GetReadinessBlindedPlacementId();
            var draft = new ProductionMailboxSelectionSuccessorProof
            {
                Mode = mode,
                NetworkId = newAuthority.NetworkId,
                OldEpoch = oldNextSelection.Epoch,
                OldEpochGeneration = oldNextSelection.Generation,
                NewEpoch = newSelection.Epoch,
                NewEpochGeneration = newSelection.Generation,
                MailboxOwnerEd25519PublicKey = owner.PublicKey,
                BlindedMailboxId = Bytes(0x2B, 32),
                BlindedPlacementId = placementId,
                SelectionInputCommitment = Options.GetReadinessSelectionInputCommitment(),
                OldCanonicalAuthorityHash = SHA256.HashData(oldAuthorityBytes),
                NewCanonicalAuthorityHash = SHA256.HashData(newAuthorityBytes),
                OldTopologyGeneration = oldTopology.TopologyGeneration,
                OldCanonicalTopologyHash = SHA256.HashData(oldTopologyBytes),
                NewTopologyGeneration = newTopology.TopologyGeneration,
                NewCanonicalTopologyHash = SHA256.HashData(newTopologyBytes),
                OldCanonicalSelectionHash = SHA256.HashData(oldNextSelectionBytes),
                NewCanonicalSelectionHash = SHA256.HashData(newSelectionBytes),
                IssuedAtUnixSeconds = checked(Now + issuedAtOffsetSeconds),
                ExpiresAtUnixSeconds = checked(Now + issuedAtOffsetSeconds + 200),
                CanonicalNewAuthority = newAuthorityBytes,
                OldCanonicalSelection = oldNextSelectionBytes,
                NewCanonicalSelection = newSelectionBytes,
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            var withOld = mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion
                ? draft with
                {
                    OldIssuerSignature = PublicKeyAuth.SignDetached(
                        ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(draft),
                        _issuerPrivateKey)
                }
                : draft;
            var successor = withOld with
            {
                NewIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(withOld),
                    _issuerPrivateKey)
            };
            var canonicalSuccessor = ProductionMailboxSelectionSuccessorCodec.Encode(successor);
            Node.RouterId = Hex(oldNextSelection.Replicas[0].ReplicaId.ToArray());
            Node.Ed25519PrivateKey = Hex(SeedFor(
                oldNextSelection.Replicas[0].ReplicaId.Span,
                oldNextSelection.Epoch));
            var envelope = ProductionMailboxClosureEnvelopeCodec.Encode(new(
                newAuthorityBytes, newRevocationBytes, newTopologyBytes,
                newSelectionBytes, canonicalSuccessor));
            return new(envelope, Options.GetReadinessSelectionInputCommitment(),
                owner.PublicKey, owner.PrivateKey,
                oldCurrentSelection.Replicas
                    .Select(static replica => replica.ReplicaId.ToArray())
                    .OrderBy(static replicaId => Convert.ToHexString(replicaId),
                        StringComparer.Ordinal)
                    .Select(static replicaId => (ReadOnlyMemory<byte>)replicaId)
                    .ToArray());
        }

        public byte[] PrepositionCommand(
            ClosureMaterial material,
            byte nonce = 0x44,
            IReadOnlyList<ReadOnlyMemory<byte>>? authorizedLegacyReplicaIds = null,
            ReadOnlyMemory<byte> reservationCohortId = default)
        {
            var draft = new ProductionMailboxPrepositionCommand(
                Now, Bytes(nonce, 32), SHA256.HashData(material.CanonicalEnvelope),
                Node.GetRouterId().ToBytes(), authorizedLegacyReplicaIds ?? [],
                new byte[64], material.CanonicalEnvelope, reservationCohortId);
            var signed = draft with
            {
                PublisherSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxPrepositionCommandCodec.GetSigningBytes(draft),
                    _issuerPrivateKey)
            };
            return ProductionMailboxPrepositionCommandCodec.Encode(signed);
        }

        public byte[] CapacityCommand(
            ReadOnlyMemory<byte> cohortId,
            uint reservedClosureCount,
            ulong reservedBytes,
            ulong revision = 1,
            ulong lifetimeSeconds = 3_600,
            ProductionMailboxCapacityOperation operation =
                ProductionMailboxCapacityOperation.ReserveOrRenew,
            byte nonce = 0x46,
            ulong? timestampUnixSeconds = null)
        {
            var timestamp = timestampUnixSeconds ?? Now;
            var draft = new ProductionMailboxCapacityCommand(
                operation, timestamp, checked(timestamp + lifetimeSeconds), Bytes(nonce, 32),
                cohortId, Node.GetRouterId().ToBytes(), reservedClosureCount,
                reservedBytes, revision, new byte[64]);
            var signed = draft with
            {
                PublisherSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityCommandCodec.GetSigningBytes(draft),
                    _issuerPrivateKey)
            };
            return ProductionMailboxCapacityCommandCodec.Encode(signed);
        }

        public byte[] SameGenerationForkCommand(ClosureMaterial material)
        {
            var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(
                material.CanonicalEnvelope);
            var proof = ProductionMailboxSelectionSuccessorCodec.Decode(
                envelope.Successor.Span) with
            {
                BlindedMailboxId = Bytes(0x2C, 32),
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            proof = proof with
            {
                OldIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(proof),
                    _issuerPrivateKey)
            };
            proof = proof with
            {
                NewIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(proof),
                    _issuerPrivateKey)
            };
            var forkEnvelope = ProductionMailboxClosureEnvelopeCodec.Encode(envelope with
            {
                Successor = ProductionMailboxSelectionSuccessorCodec.Encode(proof)
            });
            var fork = material with { CanonicalEnvelope = forkEnvelope };
            return PrepositionCommand(fork, 0x45);
        }

        public ClosureMaterial WithDistinctOldAnchor(ClosureMaterial material, byte marker)
        {
            var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(
                material.CanonicalEnvelope);
            var proof = ProductionMailboxSelectionSuccessorCodec.Decode(
                envelope.Successor.Span);
            var oldSelection = ProductionMailboxTopologyCodec.DecodeSelection(
                proof.OldCanonicalSelection.Span) with
            {
                IssuedAtUnixSeconds = checked(
                    ProductionMailboxTopologyCodec.DecodeSelection(
                        proof.OldCanonicalSelection.Span).IssuedAtUnixSeconds - marker),
                IssuerSignature = new byte[64]
            };
            oldSelection = oldSelection with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxTopologyCodec.GetSelectionSigningBytes(oldSelection),
                    _issuerPrivateKey)
            };
            var oldBytes = ProductionMailboxTopologyCodec.EncodeSelection(oldSelection);
            var successor = proof with
            {
                Mode = ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
                OldCanonicalSelection = oldBytes,
                OldCanonicalSelectionHash = SHA256.HashData(oldBytes),
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            successor = successor with
            {
                NewIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(successor),
                    _issuerPrivateKey)
            };
            var canonical = ProductionMailboxClosureEnvelopeCodec.Encode(envelope with
            {
                Successor = ProductionMailboxSelectionSuccessorCodec.Encode(successor)
            });
            return material with { CanonicalEnvelope = canonical };
        }

        public ClosureMaterial WithDistinctSelection(ClosureMaterial material, byte marker)
        {
            var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(
                material.CanonicalEnvelope);
            var proof = ProductionMailboxSelectionSuccessorCodec.Decode(
                envelope.Successor.Span);
            var selectionInput = Bytes(marker, 32);
            var selection = ProductionMailboxTopologyCodec.DecodeSelection(
                envelope.Selection.Span) with
            {
                SelectionInputCommitment = selectionInput,
                IssuerSignature = new byte[64]
            };
            selection = selection with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxTopologyCodec.GetSelectionSigningBytes(selection),
                    _issuerPrivateKey)
            };
            var selectionBytes = ProductionMailboxTopologyCodec.EncodeSelection(selection);
            var successor = proof with
            {
                SelectionInputCommitment = selectionInput,
                NewCanonicalSelection = selectionBytes,
                NewCanonicalSelectionHash = SHA256.HashData(selectionBytes),
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            if (successor.Mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            {
                successor = successor with
                {
                    OldIssuerSignature = PublicKeyAuth.SignDetached(
                        ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(successor),
                        _issuerPrivateKey)
                };
            }
            successor = successor with
            {
                NewIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(successor),
                    _issuerPrivateKey)
            };
            var canonical = ProductionMailboxClosureEnvelopeCodec.Encode(envelope with
            {
                Selection = selectionBytes,
                Successor = ProductionMailboxSelectionSuccessorCodec.Encode(successor)
            });
            return material with
            {
                CanonicalEnvelope = canonical,
                SelectionInputCommitment = selectionInput
            };
        }

        public ClosureMaterial ReanchorToAccepted(
            ClosureMaterial target, ClosureMaterial accepted)
        {
            var targetEnvelope = ProductionMailboxClosureEnvelopeCodec.Decode(
                target.CanonicalEnvelope);
            var targetProof = ProductionMailboxSelectionSuccessorCodec.Decode(
                targetEnvelope.Successor.Span);
            var acceptedEnvelope = ProductionMailboxClosureEnvelopeCodec.Decode(
                accepted.CanonicalEnvelope);
            var acceptedProof = ProductionMailboxSelectionSuccessorCodec.Decode(
                acceptedEnvelope.Successor.Span);
            var acceptedSelection = ProductionMailboxTopologyCodec.DecodeSelection(
                acceptedProof.NewCanonicalSelection.Span);
            var successor = targetProof with
            {
                Mode = ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint,
                OldEpoch = acceptedSelection.Epoch,
                OldEpochGeneration = acceptedSelection.Generation,
                OldCanonicalAuthorityHash = acceptedProof.NewCanonicalAuthorityHash,
                OldTopologyGeneration = acceptedProof.NewTopologyGeneration,
                OldCanonicalTopologyHash = acceptedProof.NewCanonicalTopologyHash,
                OldCanonicalSelectionHash = acceptedProof.NewCanonicalSelectionHash,
                OldCanonicalSelection = acceptedProof.NewCanonicalSelection,
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            successor = successor with
            {
                NewIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(successor),
                    _issuerPrivateKey)
            };
            var canonical = ProductionMailboxClosureEnvelopeCodec.Encode(targetEnvelope with
            {
                Successor = ProductionMailboxSelectionSuccessorCodec.Encode(successor)
            });
            return target with { CanonicalEnvelope = canonical };
        }

        private ProductionMailboxAuthority BindAndSignPair(
            ProductionMailboxAuthority authority)
        {
            var snapshot = new ProductionMailboxRevocationSnapshot
            {
                NetworkId = authority.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec
                    .ComputeAuthorityBindingHash(authority),
                RevocationGeneration = authority.Revocation.Generation,
                RevocationHeadHash = authority.Revocation.HeadHash,
                PreviousRevocationHeadHash = authority.Revocation.PreviousHeadHash,
                IssuedAtUnixSeconds = authority.Revocation.IssuedAtUnixSeconds,
                ExpiresAtUnixSeconds = authority.Revocation.ExpiresAtUnixSeconds,
                RevokedGrantSerials = [(ReadOnlyMemory<byte>)Bytes(0x10, 16)],
                IssuerSignature = new byte[64]
            };
            snapshot = snapshot with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(snapshot),
                    _issuerPrivateKey)
            };
            var encoded = ProductionMailboxRevocationSnapshotCodec.Encode(snapshot);
            File.WriteAllBytes(RevocationArtifactPath, encoded);
            var signedAuthority = Sign(authority with
            {
                Revocation = authority.Revocation with
                {
                    SnapshotHash = SHA256.HashData(encoded)
                }
            });
            WriteTopologyAndSelection(signedAuthority);
            return signedAuthority;
        }

        private void WriteTopologyAndSelection(ProductionMailboxAuthority authority)
        {
            var artifactNow = authority.AuthorityGeneration > 7 && _survivalHorizonSeconds != 0
                ? authority.Revocation.IssuedAtUnixSeconds + 30
                : Now;
            var previousTopology = File.Exists(TopologyArtifactPath)
                ? ProductionMailboxTopologyCodec.Decode(File.ReadAllBytes(TopologyArtifactPath))
                : null;
            var currentDescriptors = _descriptors[authority.CurrentEpoch.Epoch];
            var nextDescriptors = _descriptors.TryGetValue(
                authority.NextEpoch.Epoch,
                out var configuredNext)
                    ? configuredNext
                    : currentDescriptors.Select((descriptor, index) => descriptor with
                    {
                        RouterId = Bytes(unchecked((byte)(0xA0 + index * 0x20)), 32),
                        Ed25519PublicKey = Bytes(unchecked((byte)(0xB0 + index * 0x20)), 32),
                        X25519PublicKey = Bytes(unchecked((byte)(0xC0 + index * 0x20)), 32),
                        Epoch = authority.NextEpoch.Epoch,
                        ValidFromUnixSeconds = authority.NextEpoch.NotBeforeUnixSeconds,
                        ValidUntilUnixSeconds = authority.NextEpoch.NotAfterUnixSeconds
                    }).ToArray();
            var topology = new ProductionMailboxTopologySnapshot
            {
                NetworkId = authority.NetworkId,
                AuthorityGeneration = authority.AuthorityGeneration,
                CanonicalAuthorityHash = ProductionMailboxAuthorityCodec
                    .ComputeCanonicalHash(authority),
                TopologyGeneration = Math.Max(
                    (previousTopology?.TopologyGeneration ?? 0) + 1,
                    authority.AuthorityGeneration - 6),
                PreviousTopologyHash = previousTopology is null
                    ? new byte[32]
                    : ProductionMailboxTopologyCodec.ComputeCanonicalHash(previousTopology),
                IssuedAtUnixSeconds = artifactNow - 5,
                ExpiresAtUnixSeconds = artifactNow + 250,
                CurrentEpoch = TopologyEpoch(authority.CurrentEpoch, currentDescriptors),
                NextEpoch = TopologyEpoch(authority.NextEpoch, nextDescriptors),
                IssuerSignature = new byte[64]
            };
            topology = topology with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxTopologyCodec.GetSigningBytes(topology),
                    _issuerPrivateKey)
            };
            var topologyBytes = ProductionMailboxTopologyCodec.Encode(topology);
            File.WriteAllBytes(TopologyArtifactPath, topologyBytes);
            var verifiedTopology = ProductionMailboxTopologyVerifier.Verify(
                topologyBytes,
                ProductionMailboxAuthorityVerifier.Verify(
                    authority,
                    new ProductionMailboxAuthorityVerificationContext
                    {
                        PinnedMrXPublicKeySha256 = SHA256.HashData(
                            authority.MrXApprovalEd25519PublicKey.Span),
                        ExpectedNetworkId = authority.NetworkId,
                        LastCommittedGeneration = authority.AuthorityGeneration - 1,
                        LastCommittedAuthorityHash = authority.PreviousAuthorityHash,
                        LastCommittedRevocationGeneration = authority.Revocation.Generation - 1,
                        LastCommittedRevocationHeadHash = authority.Revocation.PreviousHeadHash,
                        LastCommittedRevocationSnapshotHash =
                            authority.AuthorityGeneration == 7
                                ? Bytes(0xD1, 32)
                                : Authority.Revocation.SnapshotHash,
                        NowUnixSeconds = artifactNow,
                        ClockSkewSeconds = 0
                    },
                    new SodiumProductionMailboxAuthoritySignatureVerifier()),
                new ProductionMailboxTopologyVerificationContext
                {
                    LastCommittedTopologyGeneration = topology.TopologyGeneration - 1,
                    LastCommittedTopologyHash = topology.PreviousTopologyHash,
                    NowUnixSeconds = artifactNow,
                    ClockSkewSeconds = 0
                },
                new SodiumProductionMailboxTopologySignatureVerifier());
            var selectionInput = Options.GetReadinessSelectionInputCommitment();
            var selectionBytes = CreateSelectionBytes(
                topology, verifiedTopology, topology.CurrentEpoch, currentDescriptors);
            File.WriteAllBytes(
                Path.Combine(Options.SelectionArtifactDirectory,
                    Hex(selectionInput) + ".pms1"), selectionBytes);
        }

        private byte[] CreateSelectionBytes(
            ProductionMailboxTopologySnapshot topology,
            VerifiedProductionMailboxTopology verifiedTopology,
            ProductionMailboxTopologyEpoch epoch,
            MembershipRouteDescriptor[] descriptors)
        {
            var selectionInput = Options.GetReadinessSelectionInputCommitment();
            var selected = ProductionMailboxReplicaSelection.Select(
                topology.NetworkId.Span,
                epoch,
                selectionInput);
            var proofs = MembershipRouteDescriptorCodec.BuildProofs(descriptors);
            var replicas = selected.Select(id =>
            {
                var index = Array.FindIndex(
                    descriptors,
                    descriptor => descriptor.RouterId.Span.SequenceEqual(id.Span));
                var descriptor = descriptors[index];
                var mip = new MailboxReplicaMembershipProof
                {
                    ReplicaId = descriptor.RouterId,
                    SigningPublicKey = descriptor.Ed25519PublicKey,
                    Epoch = descriptor.Epoch,
                    MembershipCommitment = epoch.MembershipCommitment,
                    CanonicalInclusionProof = MailboxReplicaRouteProofCodec.Encode(
                        descriptor,
                        proofs[index])
                };
                return new ProductionMailboxSelectionReplica
                {
                    ReplicaId = descriptor.RouterId,
                    CanonicalMIP1Proof = MailboxPeerReplicationCodec.EncodeMembershipProof(mip)
                };
            }).ToArray();
            var selection = new ProductionMailboxSelectionProof
            {
                Algorithm = ProductionMailboxSelectionAlgorithm.RendezvousSha256V2,
                NetworkId = topology.NetworkId,
                AuthorityGeneration = topology.AuthorityGeneration,
                CanonicalAuthorityHash = topology.CanonicalAuthorityHash,
                TopologyGeneration = topology.TopologyGeneration,
                CanonicalTopologyHash = verifiedTopology.CanonicalTopologyHash,
                Epoch = epoch.Epoch,
                Generation = epoch.Generation,
                MembershipCommitment = epoch.MembershipCommitment,
                TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
                MailboxPlacementCommitment = MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(Options.GetReadinessBlindedPlacementId())),
                SelectionInputCommitment = selectionInput,
                IssuedAtUnixSeconds = topology.IssuedAtUnixSeconds + 3,
                ExpiresAtUnixSeconds = Math.Min(
                    topology.IssuedAtUnixSeconds + 205,
                    epoch.NotAfterUnixSeconds),
                Replicas = replicas,
                IssuerSignature = new byte[64]
            };
            selection = selection with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxTopologyCodec.GetSelectionSigningBytes(selection),
                    _issuerPrivateKey)
            };
            return ProductionMailboxTopologyCodec.EncodeSelection(selection);
        }

        private static MembershipRouteDescriptor[] Descriptors(
            ulong epoch,
            ulong from,
            ulong until) => Enumerable.Range(0, 3)
            .Select(index =>
            {
                var pair = PublicKeyAuth.GenerateKeyPair(
                    DescriptorSeed(epoch, index));
                return new MembershipRouteDescriptor
                {
                    RouterId = pair.PublicKey,
                    Ed25519PublicKey = pair.PublicKey,
                    X25519PublicKey = Bytes(unchecked((byte)(0x50 + index * 0x20)), 32),
                    RpcEndpoint = $"https://route-{epoch}-{index}.example.net/",
                    Roles = MembershipRouteRole.Storage,
                    Capabilities = MembershipRouteCapability.Storage,
                    Epoch = epoch,
                    ValidFromUnixSeconds = from,
                    ValidUntilUnixSeconds = until
                };
            }).OrderBy(
                static descriptor => Convert.ToHexString(descriptor.RouterId.Span),
                StringComparer.Ordinal)
            .ToArray();

        private static byte[] DescriptorSeed(ulong epoch, int index) =>
            Bytes(unchecked((byte)(epoch + (ulong)index * 0x20)), 32);

        private static ProductionMailboxTopologyEpoch TopologyEpoch(
            ProductionMailboxAuthorityEpoch epoch,
            IReadOnlyList<MembershipRouteDescriptor> descriptors) => new()
            {
                Epoch = epoch.Epoch,
                Generation = epoch.Generation,
                MembershipCommitment = epoch.MembershipCommitment,
                TopologyPlacementCommitment = epoch.TopologyPlacementCommitment,
                NotBeforeUnixSeconds = epoch.NotBeforeUnixSeconds,
                NotAfterUnixSeconds = epoch.NotAfterUnixSeconds,
                Nodes = descriptors.Select((descriptor, index) => new ProductionMailboxTopologyNode
                {
                    NodeId = descriptor.RouterId,
                    HttpsEndpoint = descriptor.RpcEndpoint,
                    CurrentSpkiSha256 = Bytes(unchecked((byte)(0x60 + index * 2)), 32),
                    NextSpkiSha256 = Bytes(unchecked((byte)(0x61 + index * 2)), 32)
                }).ToArray()
            };

        public ProductionMailboxAuthority Sign(ProductionMailboxAuthority authority)
        {
            var bound = authority with
            {
                MrXApproval = authority.MrXApproval with
                {
                    AuthorityPayloadHash = ProductionMailboxAuthorityCodec
                        .ComputePayloadHash(authority)
                },
                Signature = new byte[64]
            };
            return bound with
            {
                Signature = PublicKeyAuth.SignDetached(
                    ProductionMailboxAuthorityCodec.GetSigningBytes(bound),
                    _privateKey)
            };
        }

        public ProductionMailboxTopologySnapshot SignTopology(
            ProductionMailboxTopologySnapshot topology)
        {
            var unsigned = topology with { IssuerSignature = new byte[64] };
            return unsigned with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxTopologyCodec.GetSigningBytes(unsigned),
                    _issuerPrivateKey)
            };
        }

        public void WriteArtifact(ProductionMailboxAuthority authority) =>
            File.WriteAllBytes(
                ArtifactPath,
                ProductionMailboxAuthorityCodec.Encode(authority));

        private static ProductionMailboxAuthorityEndpoint Endpoint(string uri, byte seed) => new()
        {
            Uri = uri,
            CurrentSpkiSha256 = Bytes(seed, 32),
            NextSpkiSha256 = Bytes(unchecked((byte)(seed + 1)), 32)
        };

        private static ProductionMailboxAuthorityEpoch Epoch(
            ulong epoch,
            ulong generation,
            ulong from,
            ulong until,
            byte[] membership,
            byte[] placement) => new()
            {
                Epoch = epoch,
                Generation = generation,
                MembershipCommitment = membership,
                TopologyPlacementCommitment = placement,
                NotBeforeUnixSeconds = from,
                NotAfterUnixSeconds = until
            };

        private static ProductionMailboxAuthorityApproval Approval(ulong from, ulong until) => new()
        {
            AuthorityPayloadHash = Bytes(0x01, 32),
            AllowedAndroidSigningCertificateSha256 = [Bytes(0x02, 32)],
            AllowedWindowsSigningCertificateSha256 = [Bytes(0x03, 32)],
            AndroidReleaseBuildArtifactSha256 = [Bytes(0x04, 32)],
            WindowsReleaseBuildArtifactSha256 = [Bytes(0x05, 32)],
            RolloutNotBeforeUnixSeconds = from,
            RolloutNotAfterUnixSeconds = until
        };
    }

    private sealed class PermissiveSecurity : IProductionMailboxAuthorityFileSecurity
    {
        public void ValidateReadOnlyArtifact(string path, string trustRoot)
        {
            if (!File.Exists(path))
            {
                throw new InvalidDataException("Production mailbox authority artifact is missing.");
            }
        }

        public void ValidateProtectedLastKnownGood(string path, string trustRoot)
        {
            if (!File.Exists(path))
            {
                throw new InvalidDataException("Production mailbox authority LKG is missing.");
            }
        }

        public void ValidateProtectedLock(string path, string trustRoot)
        {
            if (!File.Exists(path))
            {
                throw new InvalidDataException("missing lock");
            }
        }
    }

    private sealed class RecordingPeerClient : IMailboxReplicaPeerClient
    {
        public MailboxReplicaPeer? Peer { get; private set; }
        public ReadOnlyMemory<byte> CanonicalRequest { get; private set; }

        public Task<ReadOnlyMemory<byte>?> SendAsync(
            MailboxReplicaPeer peer,
            MailboxPeerReplicationOperation operation,
            ReadOnlyMemory<byte> canonicalPrq2,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Peer = peer;
            CanonicalRequest = canonicalPrq2.ToArray();
            return Task.FromResult<ReadOnlyMemory<byte>?>(Bytes(0xA0, 32));
        }
    }

    private sealed class FixedClock(DateTimeOffset utcNow) : IClock
    {
        public DateTimeOffset UtcNow { get; } = utcNow;
    }

    private sealed class MutableClock(DateTimeOffset utcNow) : IClock
    {
        public DateTimeOffset UtcNow { get; set; } = utcNow;
    }

    private sealed class CountingBarrier(TimeSpan? delay = null) : IMailboxDurabilityBarrier
    {
        private int _replaceCount;
        public int ReplaceCount => Volatile.Read(ref _replaceCount);

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (delay is { } pause)
            {
                Thread.Sleep(pause);
            }

            File.Move(temporaryPath, finalPath, overwrite: true);
            Interlocked.Increment(ref _replaceCount);
        }
    }

    private sealed class ThrowingBarrier : IMailboxDurabilityBarrier
    {
        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            throw new IOException("simulated write failure");
    }

    private sealed class ThrowOnceAfterReplaceBarrier : IMailboxDurabilityBarrier
    {
        private int _armed = 1;

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            File.Move(temporaryPath, finalPath, overwrite: true);
            if (Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash after replace");
        }
    }

    private sealed class ThrowOnceOnFinalClosureSecurity : IMailboxStorageSecurity
    {
        private readonly MailboxStorageSecurity _inner = new();
        private int _armed = 1;

        public void SecureDirectory(string path) => _inner.SecureDirectory(path);

        public void SecureFile(string path)
        {
            _inner.SecureFile(path);
            if (path.EndsWith(".pmcs1", StringComparison.OrdinalIgnoreCase)
                && Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash while securing final closure");
        }
    }

    private sealed class ThrowOnceOnClosureFlushBarrier : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier _inner = new();
        private int _armed = 1;

        public void FlushFileAndParentDirectory(string path) =>
            _inner.FlushFileAndParentDirectory(path);

        public void FlushParentDirectory(string deletedPath)
        {
            _inner.FlushParentDirectory(deletedPath);
            if (deletedPath.EndsWith(".pmcs1", StringComparison.OrdinalIgnoreCase)
                && Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash while flushing closure directory");
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            _inner.ReplaceFile(temporaryPath, finalPath);

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }

    private sealed class ThrowOnceAfterExpiredDeleteBarrier : IMailboxDurabilityBarrier
    {
        private int _armed = 1;

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void DeleteFile(string path)
        {
            File.Delete(path);
            if (Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash after expired closure delete");
        }
    }

    private sealed class ThrowOnceAfterExpiredFlushBarrier : IMailboxDurabilityBarrier
    {
        private int _armed = 1;

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
            if (Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash after expired closure directory flush");
        }

        public void DeleteFile(string path) => File.Delete(path);
    }

    private sealed class ThrowOnNthDirectoryDeleteBarrier(int faultIndex)
        : IMailboxDurabilityBarrier
    {
        private int _directoryDeletes;

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void DeleteFile(string path) => File.Delete(path);

        public void DeleteDirectory(string path)
        {
            Directory.Delete(path);
            if (Interlocked.Increment(ref _directoryDeletes) == faultIndex)
                throw new IOException("simulated crash after empty closure directory delete");
        }
    }
}
