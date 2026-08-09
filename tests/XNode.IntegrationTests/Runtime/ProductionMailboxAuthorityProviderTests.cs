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
    public async Task Pmc2FullTupleCardinality_ExactReplayDistinctRolFetchRestartAndCap()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-cardinality"));
        var material = fixture.CreateDirectClosure();
        var parsedEnvelope = ProductionMailboxClosureEnvelopeCodec.Decode(
            material.CanonicalEnvelope);
        Assert.Equal("PMC2"u8.ToArray(), material.CanonicalEnvelope[..4]);
        Assert.Equal(2, material.CanonicalEnvelope[4]);
        Assert.Equal((byte)parsedEnvelope.AuthorizationKind, material.CanonicalEnvelope[5]);
        Assert.Equal(new byte[2], material.CanonicalEnvelope[6..8]);
        Assert.Equal(parsedEnvelope.CacheSalt.ToArray(), material.CanonicalEnvelope[8..40]);
        Assert.Equal(parsedEnvelope.LineageCommitment.ToArray(),
            material.CanonicalEnvelope[40..72]);
        var expectedLengths = new[]
        {
            parsedEnvelope.Authority.Length, parsedEnvelope.Revocations.Length,
            parsedEnvelope.Topology.Length, parsedEnvelope.CurrentSelection.Length,
            parsedEnvelope.NextSelection.Length, parsedEnvelope.SelectionSuccessorV2.Length,
            parsedEnvelope.RouteCertificate.Length, parsedEnvelope.TransitionContext.Length,
            parsedEnvelope.RevocationCheckpoint.Length, parsedEnvelope.RouteAuthorization.Length
        };
        Assert.Equal(expectedLengths, Enumerable.Range(0, 10).Select(index => checked((int)
            BinaryPrimitives.ReadUInt32BigEndian(
                material.CanonicalEnvelope.AsSpan(72 + index * 4, 4)))).ToArray());
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var hostileFields = new[]
        {
            parsedEnvelope.Authority, parsedEnvelope.Revocations, parsedEnvelope.Topology,
            parsedEnvelope.CurrentSelection, parsedEnvelope.NextSelection,
            parsedEnvelope.SelectionSuccessorV2, parsedEnvelope.RouteCertificate,
            parsedEnvelope.TransitionContext, parsedEnvelope.RevocationCheckpoint,
            parsedEnvelope.RouteAuthorization
        };
        var paddedPmtLength = ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes;
        var hostileEnvelopeLength = ProductionMailboxClosureEnvelopeCodec.HeaderLength
            + hostileFields.Where((_, index) => index != 2).Sum(static field => field.Length)
            + paddedPmtLength;
        var hostile = new byte[ProductionMailboxPrepositionCommandCodec.HeaderLength
            + hostileEnvelopeLength];
        "PMP2"u8.CopyTo(hostile); hostile[4] = 2;
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(272),
            checked((uint)hostileEnvelopeLength));
        var hostileEnvelope = hostile.AsSpan(
            ProductionMailboxPrepositionCommandCodec.HeaderLength);
        material.CanonicalEnvelope.AsSpan(0, 72).CopyTo(hostileEnvelope);
        var hostileLengths = hostileFields.Select(static field => field.Length).ToArray();
        hostileLengths[2] = paddedPmtLength;
        for (var index = 0; index < hostileLengths.Length; index++)
            BinaryPrimitives.WriteUInt32BigEndian(hostileEnvelope[(72 + index * 4)..],
                checked((uint)hostileLengths[index]));
        var hostileOffset = ProductionMailboxClosureEnvelopeCodec.HeaderLength;
        for (var index = 0; index < hostileFields.Length; index++)
        {
            hostileFields[index].Span.CopyTo(hostileEnvelope[hostileOffset..]);
            hostileOffset += hostileLengths[index];
        }
        var beforeHostile = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<InvalidDataException>(() => store.PrepositionAsync(
            hostile, CancellationToken.None).AsTask().GetAwaiter().GetResult());
        var hostileAllocated = GC.GetAllocatedBytesForCurrentThread() - beforeHostile;
        Assert.True(hostileAllocated < 128 * 1024,
            $"PMP2 store ingress allocated {hostileAllocated} bytes before late rejection.");
        var command = fixture.PrepositionCommand(material);
        Assert.Equal(0, command[5]);
        Assert.Equal(new byte[64], command[112..176]);
        var legacyCountMutation = command.ToArray();
        legacyCountMutation[5] = 1;
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxPrepositionCommandCodec.Decode(legacyCountMutation));
        var legacySlotMutation = command.ToArray();
        legacySlotMutation[112] = 1;
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxPrepositionCommandCodec.Decode(legacySlotMutation));
        var mutableCommand = command.ToArray();
        var pmtOffset = ProductionMailboxPrepositionCommandCodec.HeaderLength
            + ProductionMailboxClosureEnvelopeCodec.HeaderLength
            + parsedEnvelope.Authority.Length + parsedEnvelope.Revocations.Length;
        var mutateAfterPreflight = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier(),
            new ProductionMailboxClosureStoreTestHooks(
                AfterPrepositionStructuralPreflight: () => mutableCommand[pmtOffset] ^= 0x80));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await mutateAfterPreflight.PrepositionAsync(mutableCommand, CancellationToken.None));
        Assert.Equal((0, 0L), mutateAfterPreflight.StorageAccounting);

        await store.PrepositionAsync(command, CancellationToken.None);
        var afterFirst = store.StorageAccounting;
        await store.PrepositionAsync(command, CancellationToken.None);
        Assert.Equal(afterFirst, store.StorageAccounting);
        Assert.Equal(1, afterFirst.Count);
        Assert.Single(Directory.EnumerateFiles(fixture.Options.ClosureDirectory,
            "*.pmcs2", SearchOption.AllDirectories));
        Assert.Empty(Directory.EnumerateFiles(fixture.Options.ClosureDirectory,
            "*.pmcs1", SearchOption.AllDirectories));
        Assert.Equal(material.CanonicalEnvelope,
            await store.FetchAsync(fixture.Request(material), CancellationToken.None));

        var second = fixture.CreateRolVariant(material, 0x8C);
        Assert.Equal(material.OldSelectionHash, second.OldSelectionHash);
        Assert.NotEqual(material.LineageCommitment, second.LineageCommitment);
        await store.PrepositionAsync(fixture.PrepositionCommand(second, 0x45),
            CancellationToken.None);
        var afterSecond = store.StorageAccounting;
        Assert.Equal(2, afterSecond.Count);
        Assert.Equal(2, Directory.EnumerateFiles(fixture.Options.ClosureDirectory,
            "*.pmcs2", SearchOption.AllDirectories).Count());
        Assert.Equal(second.CanonicalEnvelope,
            await store.FetchAsync(fixture.Request(second, 0x46), CancellationToken.None));

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(afterSecond, restarted.StorageAccounting);
        Assert.Equal(material.CanonicalEnvelope,
            await restarted.FetchAsync(fixture.Request(material), CancellationToken.None));
        Assert.Equal(second.CanonicalEnvelope,
            await restarted.FetchAsync(fixture.Request(second, 0x46), CancellationToken.None));

        fixture.Options.MaximumClosureLineagesPerSelection = 2;
        var overCap = fixture.CreateRolVariant(material, 0x8D);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await restarted.PrepositionAsync(fixture.PrepositionCommand(overCap, 0x47),
                CancellationToken.None));
        Assert.Equal(afterSecond, restarted.StorageAccounting);
    }

    [Fact]
    public async Task Pmc2Delegated_ActiveRchAndRcaRoundTripThroughCacheOnlyVerifier()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-delegated"));
        var material = fixture.CreateDirectClosure(authorizationKind:
            ProductionMailboxRouteAuthorizationKind.DelegatedRCA1);
        var decoded = ProductionMailboxClosureEnvelopeCodec.Decode(material.CanonicalEnvelope);
        Assert.Equal(ProductionMailboxRouteContinuityConstants.CanonicalRevocationCheckpointLength,
            decoded.RevocationCheckpoint.Length);
        Assert.Equal(ProductionMailboxRouteAuthorizationConstants.CanonicalContinuityActivationLength,
            decoded.RouteAuthorization.Length);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(fixture.PrepositionCommand(material),
            CancellationToken.None);
        Assert.Equal(material.CanonicalEnvelope,
            await store.FetchAsync(fixture.Request(material), CancellationToken.None));
    }

    [Fact]
    public async Task Pmc2OfflineCheckpoint_OwnerRoundTripsWithoutRetiredIssuerSignature()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-offline-owner"));
        var material = fixture.CreateDirectClosure(mode:
            ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint);
        var envelope = ProductionMailboxClosureEnvelopeCodec.Decode(material.CanonicalEnvelope);
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            envelope.SelectionSuccessorV2.Span);
        Assert.All(pss.Selection.OldIssuerSignature.ToArray(),
            static value => Assert.Equal(0, value));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(fixture.PrepositionCommand(material),
            CancellationToken.None);
        Assert.Equal(material.CanonicalEnvelope,
            await store.FetchAsync(fixture.Request(material), CancellationToken.None));
    }

    [Fact]
    public async Task Pmc2ExpiredClosure_IsCryptographicallyRevalidatedThenCollectedOnRestart()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-expired-gc"));
        var material = fixture.CreateDirectClosure();
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(fixture.PrepositionCommand(material),
            CancellationToken.None);
        Assert.Equal(1, store.StorageAccounting.Count);
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 100));
        Assert.Equal(material.CanonicalEnvelope, await store.FetchAsync(
            fixture.Request(material, 0x4F, timestampUnixSeconds: Now + 100),
            CancellationToken.None));
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 500));
        Assert.Null(await store.FetchAsync(
            fixture.Request(material, 0x50, timestampUnixSeconds: Now + 500),
            CancellationToken.None));

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((0, 0L), restarted.StorageAccounting);
        Assert.Empty(Directory.EnumerateFiles(fixture.Options.ClosureDirectory,
            "*.pmcs2", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Pmc2AuthorizationExpiryBeforeRtc_IsRejectedAtAdmission()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-hard-auth-expiry"));
        var material = fixture.CreateAuthorizationExpiryVariant(
            fixture.CreateDirectClosure(), Now + 60);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(fixture.PrepositionCommand(material),
                CancellationToken.None));
        Assert.Equal((0, 0L), store.StorageAccounting);
    }

    [Fact]
    public async Task Pmc2NextPmsExpiryBeforePss_IsRejectedAtAdmission()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-next-pms-expiry"));
        var original = fixture.CreateDirectClosure();
        var pss = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            ProductionMailboxClosureEnvelopeCodec.Decode(original.CanonicalEnvelope)
                .SelectionSuccessorV2.Span).Selection;
        var malformed = fixture.CreateNextSelectionExpiryVariant(
            original, pss.ExpiresAtUnixSeconds - 1);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(fixture.PrepositionCommand(malformed),
                CancellationToken.None));
        Assert.Equal((0, 0L), store.StorageAccounting);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pmc2GlobalGc_ReclaimsCrossSelectionCountOrBytesAcrossRestart(
        bool constrainBytes)
    {
        var fixture = Fixture.Create(Path.Combine(_root,
            $"pmc2-global-gc-{(constrainBytes ? "bytes" : "count")}"));
        var replacementFixture = Fixture.Create(Path.Combine(_root,
            $"pmc2-global-gc-replacement-{(constrainBytes ? "bytes" : "count")}"),
            1_000, readinessPlacementSeed: 0x25);
        var expired = fixture.CreateDirectClosure();
        var replacement = replacementFixture.CreateDirectClosure();
        replacementFixture.Node.RouterId = fixture.Node.RouterId;
        replacementFixture.Node.Ed25519PrivateKey = fixture.Node.Ed25519PrivateKey;
        var expiredCharge = expired.CanonicalEnvelope.Length
            + fixture.Options.ClosureAccountingOverheadBytes;
        var replacementCharge = replacement.CanonicalEnvelope.Length
            + fixture.Options.ClosureAccountingOverheadBytes;
        fixture.Options.MaximumStoredClosures = constrainBytes ? 8 : 1;
        fixture.Options.MaximumClosureStoreBytes = constrainBytes
            ? Math.Max(expiredCharge, replacementCharge)
            : 32L * 1024 * 1024;
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await initial.PrepositionAsync(fixture.PrepositionCommand(expired, 0x61),
            CancellationToken.None);

        var afterExpiry = checked(Now + 250);
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterExpiry)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((0, 0L), restarted.StorageAccounting);
        await restarted.PrepositionAsync(
            replacementFixture.PrepositionCommand(replacement, 0x62,
                timestampUnixSeconds: afterExpiry),
            CancellationToken.None);
        Assert.Equal((1, (long)replacementCharge), restarted.StorageAccounting);
        Assert.Equal(replacement.CanonicalEnvelope, await restarted.FetchAsync(
            replacementFixture.Request(replacement, 0x63,
                timestampUnixSeconds: afterExpiry), CancellationToken.None));
    }

    [Fact]
    public async Task Pmc2CapacityPressure_PrunesExpiredTargetAndUnrelatedWithoutStaleAccounting()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-gc-target"));
        var unrelatedFixture = Fixture.Create(
            Path.Combine(_root, "pmc2-gc-unrelated"), readinessPlacementSeed: 0x26);
        var liveFixture = Fixture.Create(Path.Combine(_root, "pmc2-gc-target-live"), 1_000);
        var targetExpired = fixture.CreateDirectClosure();
        var targetLive = liveFixture.CreateDirectClosure();
        var unrelatedExpired = unrelatedFixture.CreateDirectClosure();
        unrelatedFixture.Node.RouterId = fixture.Node.RouterId;
        unrelatedFixture.Node.Ed25519PrivateKey = fixture.Node.Ed25519PrivateKey;
        liveFixture.Node.RouterId = fixture.Node.RouterId;
        liveFixture.Node.Ed25519PrivateKey = fixture.Node.Ed25519PrivateKey;
        fixture.Options.MaximumStoredClosures = 2;
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(fixture.PrepositionCommand(targetExpired, 0x64),
            CancellationToken.None);
        await store.PrepositionAsync(
            unrelatedFixture.PrepositionCommand(unrelatedExpired, 0x65),
            CancellationToken.None);
        Assert.Equal(2, store.StorageAccounting.Count);

        fixture.Options.MaximumStoredClosures = 1;
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 250));
        await store.PrepositionAsync(liveFixture.PrepositionCommand(targetLive, 0x66,
                timestampUnixSeconds: Now + 250),
            CancellationToken.None);
        Assert.Equal(1, store.StorageAccounting.Count);
        Assert.Single(Directory.EnumerateFiles(fixture.Options.ClosureDirectory,
            "*.pmcs2", SearchOption.AllDirectories));
        Assert.Equal(targetLive.CanonicalEnvelope, await store.FetchAsync(
            liveFixture.Request(targetLive, 0x67, timestampUnixSeconds: Now + 250),
            CancellationToken.None));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pmc2GlobalGc_AmbiguousDeleteOrFlushReconcilesAndNeverEvictsLive(
        bool failOnFlush)
    {
        var fixture = Fixture.Create(Path.Combine(_root,
            $"pmc2-gc-ambiguous-{failOnFlush}"));
        var expired = fixture.CreateDirectClosure();
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await initial.PrepositionAsync(fixture.PrepositionCommand(expired, 0x68),
            CancellationToken.None);
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

        var liveFixture = Fixture.Create(Path.Combine(_root,
            $"pmc2-gc-live-{failOnFlush}"));
        var live = liveFixture.CreateDirectClosure();
        liveFixture.Options.MaximumStoredClosures = 1;
        var liveStore = new ProductionMailboxClosureStore(
            liveFixture.Options, liveFixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await liveStore.PrepositionAsync(liveFixture.PrepositionCommand(live, 0x69),
            CancellationToken.None);
        var another = liveFixture.CreateRolVariant(live, 0x8D);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await liveStore.PrepositionAsync(liveFixture.PrepositionCommand(another, 0x6A),
                CancellationToken.None));
        Assert.Equal(live.CanonicalEnvelope, await liveStore.FetchAsync(
            liveFixture.Request(live, 0x6B), CancellationToken.None));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Pmc2EmptyDirectoryDeleteAmbiguity_ReconcilesEveryLevel(int faultIndex)
    {
        var fixture = Fixture.Create(Path.Combine(_root,
            $"pmc2-empty-directory-{faultIndex}"));
        var expired = fixture.CreateDirectClosure();
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await initial.PrepositionAsync(fixture.PrepositionCommand(expired, 0x6C),
            CancellationToken.None);
        Assert.Throws<IOException>(() => new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 250))),
            new MailboxStorageSecurity(), new ThrowOnNthDirectoryDeleteBarrier(faultIndex)));
        var recovered = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 250))),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal((0, 0L), recovered.StorageAccounting);
        Assert.Empty(Directory.EnumerateDirectories(fixture.Options.ClosureDirectory,
            "*", SearchOption.AllDirectories));
    }

    [Fact]
    public void Pmc2StartupEmptyDirectorySweep_IsBoundedAndFailClosed()
    {
        var cleanup = Fixture.Create(Path.Combine(_root, "pmc2-empty-cleanup"));
        Directory.CreateDirectory(Path.Combine(cleanup.Options.ClosureDirectory,
            "aa", "selection", "lineage"));
        _ = new ProductionMailboxClosureStore(
            cleanup.Options, cleanup.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Empty(Directory.EnumerateDirectories(cleanup.Options.ClosureDirectory,
            "*", SearchOption.AllDirectories));

        var overflow = Fixture.Create(Path.Combine(_root, "pmc2-empty-overflow"));
        overflow.Options.MaximumStoredClosures = 1;
        for (var index = 0; index < 260; index++)
            Directory.CreateDirectory(Path.Combine(overflow.Options.ClosureDirectory,
                $"empty-{index:D3}"));
        var before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<InvalidOperationException>(() => new ProductionMailboxClosureStore(
            overflow.Options, overflow.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier()));
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 2 * 1024 * 1024);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task Pmc2CapacityJournal_RecoversCardinalityOneAcrossCrash(int crashPhase)
    {
        var fixture = Fixture.Create(Path.Combine(_root, $"pmc2-crash-{crashPhase}"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x94, 32);
        var charge = checked((ulong)(material.CanonicalEnvelope.Length
            + fixture.Options.ClosureAccountingOverheadBytes));
        var armed = 1;
        Action crash = () =>
        {
            if (Interlocked.Exchange(ref armed, 0) == 1)
                throw new IOException("Injected PMC2 transfer termination.");
        };
        var hooks = new ProductionMailboxClosureStoreTestHooks(
            AfterCapacityTransferJournal: crashPhase == 0 ? crash : null,
            AfterCapacityTransferClosure: crashPhase == 1 ? crash : null,
            SimulateCapacityTransferProcessTermination: true);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), hooks);
        await store.ReserveCapacityAsync(fixture.CapacityCommand(cohort, 1, charge),
            CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(async () => await store.PrepositionAsync(
            fixture.PrepositionCommand(material, reservationCohortId: cohort),
            CancellationToken.None));
        Assert.True(File.Exists(Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity-transfer.pbt2")));

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        Assert.False(File.Exists(Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity-transfer.pbt2")));
        Assert.Equal(crashPhase == 0 ? 0 : 1, restarted.StorageAccounting.Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Pmc2FetchWaitsAcrossEveryCapacityTransferDurabilityPhase(int phase)
    {
        var fixture = Fixture.Create(Path.Combine(_root, $"pmc2-fetch-phase-{phase}"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x95, 32);
        var charge = checked((ulong)(material.CanonicalEnvelope.Length
            + fixture.Options.ClosureAccountingOverheadBytes));
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Action pause = () => { entered.Set(); release.Wait(TimeSpan.FromSeconds(10)); };
        var hooks = new ProductionMailboxClosureStoreTestHooks(
            AfterCapacityTransferJournal: phase == 0 ? pause : null,
            AfterCapacityTransferClosure: phase == 1 ? pause : null,
            AfterCapacityTransferFloor: phase == 2 ? pause : null,
            AfterCapacityTransferLedger: phase == 3 ? pause : null);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier(), hooks);
        await writer.ReserveCapacityAsync(fixture.CapacityCommand(cohort, 1, charge),
            CancellationToken.None);
        var reader = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var write = Task.Run(async () => await writer.PrepositionAsync(
            fixture.PrepositionCommand(material, reservationCohortId: cohort),
            CancellationToken.None));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        var fetch = reader.FetchAsync(
            fixture.Request(material, 0x96), CancellationToken.None).AsTask();
        await Task.Delay(50);
        Assert.False(fetch.IsCompleted);
        release.Set();
        await write;
        Assert.Equal(material.CanonicalEnvelope, await fetch);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Pmc2FetchRechecksFreshnessAndHardExpiryAfterParentFlush(
        bool crossCacheExpiry)
    {
        var fixture = Fixture.Create(Path.Combine(_root,
            $"pmc2-fetch-parent-flush-{crossCacheExpiry}"),
            crossCacheExpiry ? 0UL : 1_000UL);
        var material = fixture.CreateDirectClosure();
        fixture.Options.ClockSkewSeconds = 60;
        var pssExpiry = ProductionMailboxSelectionSuccessorV2Codec.Decode(
            ProductionMailboxClosureEnvelopeCodec.Decode(material.CanonicalEnvelope)
                .SelectionSuccessorV2.Span).Selection.ExpiresAtUnixSeconds;
        using var durability = new BlockingClosureFlushBarrier();
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), durability);
        var reader = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var write = Task.Run(async () => await writer.PrepositionAsync(
            fixture.PrepositionCommand(material), CancellationToken.None));
        Assert.True(durability.Entered.Wait(TimeSpan.FromSeconds(5)));
        if (crossCacheExpiry)
            clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(pssExpiry + 1));
        var fetch = reader.FetchAsync(
            fixture.Request(material, 0x97, timestampUnixSeconds:
                crossCacheExpiry ? pssExpiry + 61 : Now), CancellationToken.None).AsTask();
        await Task.Delay(50);
        Assert.False(fetch.IsCompleted);
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(
            crossCacheExpiry ? pssExpiry + 61 : Now + 61));
        durability.Release.Set();
        await write;
        Assert.Null(await fetch);
    }

    [Fact]
    public async Task Pmc2ConfiguredFreshness_AcceptsExactBoundaryAndRejectsOnePast()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-freshness-boundary"));
        fixture.Options.ClockSkewSeconds = 60;
        var material = fixture.CreateDirectClosure();
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 60)));
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var command = fixture.PrepositionCommand(material);
        await store.PrepositionAsync(command, CancellationToken.None);
        Assert.Equal(material.CanonicalEnvelope, await store.FetchAsync(
            fixture.Request(material, 0xA7), CancellationToken.None));

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 61));
        Assert.Null(await store.FetchAsync(
            fixture.Request(material, 0xA8), CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.PrepositionAsync(command, CancellationToken.None));
    }

    [Fact]
    public async Task Pmc2FetchFinalFreshnessRecheckRejectsAfterSnapshotDelay()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-final-freshness"));
        fixture.Options.ClockSkewSeconds = 60;
        var material = fixture.CreateDirectClosure();
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await writer.PrepositionAsync(fixture.PrepositionCommand(material),
            CancellationToken.None);
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var reader = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier(),
            new ProductionMailboxClosureStoreTestHooks(
                BeforeCacheClosureVerification: () =>
                {
                    entered.Set();
                    release.Wait(TimeSpan.FromSeconds(10));
                }));
        var fetch = Task.Run(async () => await reader.FetchAsync(
            fixture.Request(material, 0xA9), CancellationToken.None));
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 61));
        release.Set();
        Assert.Null(await fetch);
    }

    [Fact]
    public async Task Pmc2DistinctLineageFetchVerificationOverlapsOutsideGlobalLock()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-fetch-overlap"));
        var first = fixture.CreateDirectClosure();
        var second = fixture.CreateRolVariant(first, 0x8C);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await writer.PrepositionAsync(fixture.PrepositionCommand(first, 0xA1),
            CancellationToken.None);
        await writer.PrepositionAsync(fixture.PrepositionCommand(second, 0xA2),
            CancellationToken.None);

        using var entered = new CountdownEvent(2);
        using var release = new ManualResetEventSlim();
        Action pauseVerification = () =>
        {
            entered.Signal();
            release.Wait(TimeSpan.FromSeconds(10));
        };
        var hook = new ProductionMailboxClosureStoreTestHooks(
            BeforeCacheClosureVerification: pauseVerification);
        var readerOne = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier(), hook);
        var readerTwo = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier(), hook);
        var fetchOne = readerOne.FetchAsync(
            fixture.Request(first, 0xA3), CancellationToken.None).AsTask();
        var fetchTwo = readerTwo.FetchAsync(
            fixture.Request(second, 0xA4), CancellationToken.None).AsTask();
        Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
        release.Set();
        Assert.Equal(first.CanonicalEnvelope, await fetchOne);
        Assert.Equal(second.CanonicalEnvelope, await fetchTwo);
    }

    [Fact]
    public async Task Pmc2FetchLockWaitHonorsCancellationAndFiveSecondDeadline()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-fetch-lock-deadline"));
        var material = fixture.CreateDirectClosure();
        using var durability = new BlockingClosureFlushBarrier();
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var writer = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), durability);
        var reader = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock,
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var write = Task.Run(async () => await writer.PrepositionAsync(
            fixture.PrepositionCommand(material), CancellationToken.None));
        Assert.True(durability.Entered.Wait(TimeSpan.FromSeconds(5)));

        using var cancellation = new CancellationTokenSource(100);
        var cancelled = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await reader.FetchAsync(fixture.Request(material, 0xA5), cancellation.Token));
        Assert.True(cancelled.Elapsed < TimeSpan.FromSeconds(1));

        var deadline = System.Diagnostics.Stopwatch.StartNew();
        Assert.Null(await reader.FetchAsync(
            fixture.Request(material, 0xA6), CancellationToken.None));
        Assert.InRange(deadline.Elapsed, TimeSpan.FromSeconds(4.5), TimeSpan.FromSeconds(7));
        durability.Release.Set();
        await write;
    }


    [Fact]
    public async Task CapacityReservation_TransfersAtomicallyAndExactReplayDoesNotDoubleCharge()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-transfer"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x91, 32);
        var scheduleLength = material.CanonicalEnvelope.Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureAccountingOverheadBytes));
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
    public async Task CapacityExactReceipt_ReplaysAfterExpiryAndRestartWithoutMutation()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-expired-replay"));
        _ = fixture.CreateDirectClosure();
        var cohort = Bytes(0xA1, 32);
        var command = fixture.CapacityCommand(
            cohort, 2, 65_536, lifetimeSeconds: 60, nonce: 0x61);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var acceptedReceipt = await store.ReserveCapacityAsync(
            command, CancellationToken.None);

        fixture.Options.MinimumClosureReservationLifetimeSeconds = 120;
        fixture.Options.MaximumClosureReservationLifetimeSeconds = 3_600;
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 61))),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var before = Directory.EnumerateFiles(fixture.Options.ClosureDirectory, "*",
                SearchOption.AllDirectories)
            .OrderBy(static path => path, StringComparer.Ordinal)
            .ToDictionary(static path => path,
                static path => SHA256.HashData(File.ReadAllBytes(path)),
                StringComparer.Ordinal);
        var recoveredReceipt = await restarted.ReserveCapacityAsync(
            command, CancellationToken.None);
        var after = Directory.EnumerateFiles(fixture.Options.ClosureDirectory, "*",
                SearchOption.AllDirectories)
            .OrderBy(static path => path, StringComparer.Ordinal)
            .ToDictionary(static path => path,
                static path => SHA256.HashData(File.ReadAllBytes(path)),
                StringComparer.Ordinal);

        Assert.Equal(acceptedReceipt, recoveredReceipt);
        Assert.Equal(before.Keys, after.Keys);
        Assert.All(before, pair => Assert.Equal(pair.Value, after[pair.Key]));
        Assert.Equal((0, 0L), restarted.StorageAccounting);
        var fork = fixture.CapacityCommand(
            cohort, 2, 65_536, lifetimeSeconds: 60, nonce: 0x62);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ReserveCapacityAsync(fork, CancellationToken.None));
        Assert.Equal(before.Keys, Directory.EnumerateFiles(
                fixture.Options.ClosureDirectory, "*", SearchOption.AllDirectories)
            .OrderBy(static path => path, StringComparer.Ordinal));
    }

    [Fact]
    public async Task CapacityExpiredReplay_RejectsSupersededForkAndReplaysReleaseOnly()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-expired-release"));
        _ = fixture.CreateDirectClosure();
        var cohort = Bytes(0xA2, 32);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var first = fixture.CapacityCommand(
            cohort, 2, 65_536, lifetimeSeconds: 60, nonce: 0x63);
        _ = await store.ReserveCapacityAsync(first, CancellationToken.None);
        var renewal = fixture.CapacityCommand(
            cohort, 2, 65_536, revision: 2, lifetimeSeconds: 120, nonce: 0x64);
        _ = await store.ReserveCapacityAsync(renewal, CancellationToken.None);
        var release = fixture.CapacityCommand(
            cohort, 0, 0, revision: 3, lifetimeSeconds: 180,
            operation: ProductionMailboxCapacityOperation.Release, nonce: 0x65);
        var releaseReceipt = await store.ReserveCapacityAsync(
            release, CancellationToken.None);

        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 181))),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(releaseReceipt, await restarted.ReserveCapacityAsync(
            release, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ReserveCapacityAsync(first, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ReserveCapacityAsync(renewal, CancellationToken.None));
        Assert.Equal((0, 0L), restarted.StorageAccounting);
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
        var scheduleLength = material.CanonicalEnvelope.Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureAccountingOverheadBytes));
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
        var releaseCommand = fixture.CapacityCommand(
            cohort, 0, 0, revision: 2, lifetimeSeconds: 60,
            operation: ProductionMailboxCapacityOperation.Release, nonce: 0x49,
            timestampUnixSeconds: Now + 61);
        var releaseReceiptBytes = await restarted.ReserveCapacityAsync(
            releaseCommand, CancellationToken.None);
        var releaseReceipt = ProductionMailboxCapacityReceiptCodec.Decode(
            releaseReceiptBytes);
        Assert.Equal(releaseReceipt.ConsumedClosureCount,
            releaseReceipt.ReservedClosureCount);
        Assert.Equal(releaseReceipt.ConsumedBytes, releaseReceipt.ReservedBytes);
        Assert.Equal((uint)1, releaseReceipt.ConsumedClosureCount);
        Assert.Equal(charge, releaseReceipt.ConsumedBytes);
        Assert.Equal((1, (long)charge), restarted.StorageAccounting);

        var releaseRestart = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 62))),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        Assert.Equal(releaseReceiptBytes, await releaseRestart.ReserveCapacityAsync(
            releaseCommand, CancellationToken.None));
        Assert.Equal((1, (long)charge), releaseRestart.StorageAccounting);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await releaseRestart.ReserveCapacityAsync(
                fixture.CapacityCommand(Bytes(0x93, 32), 1, charge,
                    lifetimeSeconds: 60, nonce: 0x48,
                    timestampUnixSeconds: Now + 62),
                CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await releaseRestart.ReserveCapacityAsync(
                fixture.CapacityCommand(cohort, 1, charge,
                    revision: 3, lifetimeSeconds: 120, nonce: 0x4A,
                    timestampUnixSeconds: Now + 62),
                CancellationToken.None));
    }

    [Fact]
    public async Task CapacityReconciliation_AcknowledgesGcAbsentTerminalWithoutMutation()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "capacity-reconcile-absent"));
        _ = fixture.CreateDirectClosure();
        var cohort = Bytes(0xB4, 32);
        var initial = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var reserveReceipt = await initial.ReserveCapacityAsync(
            fixture.CapacityCommand(cohort, 2, 65_536, lifetimeSeconds: 60),
            CancellationToken.None);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await initial.ReconcileAbsentCapacityAsync(
                fixture.CapacityReconciliationCommand(reserveReceipt),
                CancellationToken.None));
        var afterRetention = checked(Now + 61
            + fixture.Options.MaximumClosureReservationLifetimeSeconds
            + (ulong)fixture.Options.ClockSkewSeconds);
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)afterRetention)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var before = Directory.EnumerateFiles(fixture.Options.ClosureDirectory, "*",
                SearchOption.AllDirectories)
            .ToDictionary(path => Path.GetRelativePath(fixture.Options.ClosureDirectory, path),
                path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                StringComparer.Ordinal);

        var command = fixture.CapacityReconciliationCommand(
            reserveReceipt, timestampUnixSeconds: afterRetention);
        var canonicalReceipt = await restarted.ReconcileAbsentCapacityAsync(
            command, CancellationToken.None);
        var receipt = ProductionMailboxCapacityReconciliationReceiptCodec.Decode(
            canonicalReceipt);

        Assert.Equal(ProductionMailboxCapacityReconciliationStatus.AbsentTerminal,
            receipt.Status);
        Assert.Equal(cohort.ToArray(), receipt.CohortId.ToArray());
        Assert.Equal(1UL, receipt.LastKnownRevision);
        Assert.True(ProductionMailboxCapacityReconciliationReceiptCodec.VerifyNode(
            receipt, fixture.Node.GetRouterId().ToBytes()));
        Assert.Equal(canonicalReceipt, await restarted.ReconcileAbsentCapacityAsync(
            command, CancellationToken.None));
        Assert.Equal((0, 0L), restarted.StorageAccounting);
        var after = Directory.EnumerateFiles(fixture.Options.ClosureDirectory, "*",
                SearchOption.AllDirectories)
            .ToDictionary(path => Path.GetRelativePath(fixture.Options.ClosureDirectory, path),
                path => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))),
                StringComparer.Ordinal);
        Assert.Equal(before, after);

        var apiContext = PrepositionContext(command, 7080,
            ProductionMailboxClosureHttpContract.CapacityReconciliationCommandMediaType);
        var apiResult = await ProductionMailboxClosureHttpEndpoint
            .HandleCapacityReconciliationAsync(apiContext, restarted, 7443,
                CancellationToken.None);
        await apiResult.ExecuteAsync(apiContext);
        Assert.Equal(StatusCodes.Status404NotFound, apiContext.Response.StatusCode);
        var peerContext = PrepositionContext(command, 7443,
            ProductionMailboxClosureHttpContract.CapacityReconciliationCommandMediaType);
        var peerResult = await ProductionMailboxClosureHttpEndpoint
            .HandleCapacityReconciliationAsync(peerContext, restarted, 7443,
                CancellationToken.None);
        await peerResult.ExecuteAsync(peerContext);
        Assert.Equal(StatusCodes.Status200OK, peerContext.Response.StatusCode);
        Assert.Equal("no-store", peerContext.Response.Headers.CacheControl);
        Assert.Equal(
            ProductionMailboxClosureHttpContract.CapacityReconciliationReceiptMediaType,
            peerContext.Response.ContentType);

        var fork = command.ToArray();
        fork[408] ^= 0x01;
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ReconcileAbsentCapacityAsync(fork, CancellationToken.None));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task CapacityTransfer_PartialCommitRecoversAcrossRealStoreRestart(
        int crashPhase)
    {
        var fixture = Fixture.Create(Path.Combine(_root, $"capacity-crash-{crashPhase}"));
        var material = fixture.CreateDirectClosure();
        var cohort = Bytes(0x94, 32);
        var scheduleLength = material.CanonicalEnvelope.Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureAccountingOverheadBytes));
        var clock = new MutableClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var armed = 1;
        Action crash = () =>
        {
            if (Interlocked.Exchange(ref armed, 0) == 1)
                throw new IOException("Injected transfer process termination.");
        };
        var hooks = new ProductionMailboxClosureStoreTestHooks(
            AfterCapacityTransferJournal: crashPhase == 0 ? crash : null,
            AfterCapacityTransferClosure: crashPhase == 1 ? crash : null,
            AfterCapacityTransferFloor: crashPhase == 2 ? crash : null,
            AfterCapacityTransferLedger: crashPhase == 3 ? crash : null,
            SimulateCapacityTransferProcessTermination: true);
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier(), hooks);
        var reserve = fixture.CapacityCommand(
            cohort, 1, charge, lifetimeSeconds: 60);
        var reserveReceipt = await store.ReserveCapacityAsync(
            reserve, CancellationToken.None);

        await Assert.ThrowsAsync<IOException>(async () =>
            await store.PrepositionAsync(
                fixture.PrepositionCommand(material, reservationCohortId: cohort),
                CancellationToken.None));
        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds((long)(Now + 61));
        var beforeReplay = Directory.EnumerateFiles(
                fixture.Options.ClosureDirectory, "*", SearchOption.AllDirectories)
            .OrderBy(static path => path, StringComparer.Ordinal)
            .ToDictionary(static path => path,
                static path => SHA256.HashData(File.ReadAllBytes(path)),
                StringComparer.Ordinal);
        var accountingBeforeReplay = store.StorageAccounting;
        Assert.Equal(reserveReceipt, await store.ReserveCapacityAsync(
            reserve, CancellationToken.None));
        var afterReplay = Directory.EnumerateFiles(
                fixture.Options.ClosureDirectory, "*", SearchOption.AllDirectories)
            .OrderBy(static path => path, StringComparer.Ordinal)
            .ToDictionary(static path => path,
                static path => SHA256.HashData(File.ReadAllBytes(path)),
                StringComparer.Ordinal);
        Assert.Equal(beforeReplay.Keys, afterReplay.Keys);
        Assert.All(beforeReplay,
            pair => Assert.Equal(pair.Value, afterReplay[pair.Key]));
        Assert.Equal(accountingBeforeReplay, store.StorageAccounting);
        Assert.True(File.Exists(Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity-transfer.pbt2")));
        var restarted = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
        Assert.False(File.Exists(Path.Combine(fixture.Options.ClosureDirectory,
            ".closure-capacity-transfer.pbt2")));
        if (crashPhase == 0)
        {
            Assert.Equal((0, 0L), restarted.StorageAccounting);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await restarted.PrepositionAsync(
                    fixture.PrepositionCommand(
                        material, reservationCohortId: cohort,
                        timestampUnixSeconds: Now + 61),
                    CancellationToken.None));
        }
        else
        {
            Assert.Equal((1, checked((long)charge)), restarted.StorageAccounting);
            await restarted.PrepositionAsync(
                fixture.PrepositionCommand(material, reservationCohortId: cohort,
                    timestampUnixSeconds: Now + 61),
                CancellationToken.None);
        }
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
                fixture.PrepositionCommand(material, reservationCohortId: cohort,
                    timestampUnixSeconds: Now + 61),
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
        var scheduleLength = material.CanonicalEnvelope.Length;
        var charge = checked((ulong)(scheduleLength
            + fixture.Options.ClosureAccountingOverheadBytes));
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
            "closure.pmcs2.00000000000000000000000000000000.tmp"), [0x01]);

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
        var request = fixture.Request(material, 0x46);

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
        "PMP2"u8.CopyTo(malformed);
        malformed[4] = 2;
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

        var valid = fixture.CreateDirectClosure();
        var formatFailure = fixture.CreateCurrentPssSignatureMutation(valid);
        var formatContext = PrepositionContext(
            fixture.PrepositionCommand(formatFailure, 0x98), peerPort);
        var formatResult = await ProductionMailboxClosureHttpEndpoint.HandlePrepositionAsync(
            formatContext, store, peerPort, CancellationToken.None);
        await formatResult.ExecuteAsync(formatContext);
        Assert.Equal(StatusCodes.Status400BadRequest, formatContext.Response.StatusCode);
        Assert.Equal(string.Empty, await ResponseBody(formatContext));

        var customFailure = fixture.CreateNextSelectionExpiryVariant(valid,
            ProductionMailboxSelectionSuccessorV2Codec.Decode(
                ProductionMailboxClosureEnvelopeCodec.Decode(valid.CanonicalEnvelope)
                    .SelectionSuccessorV2.Span).Selection.ExpiresAtUnixSeconds - 1);
        var customContext = PrepositionContext(
            fixture.PrepositionCommand(customFailure, 0x99), peerPort);
        var customResult = await ProductionMailboxClosureHttpEndpoint.HandlePrepositionAsync(
            customContext, store, peerPort, CancellationToken.None);
        await customResult.ExecuteAsync(customContext);
        Assert.Equal(StatusCodes.Status400BadRequest, customContext.Response.StatusCode);
        Assert.Equal(string.Empty, await ResponseBody(customContext));

        var decodeBoundary = fixture.PrepositionCommand(valid, 0x9B);
        var decoded = ProductionMailboxClosureEnvelopeCodec.Decode(valid.CanonicalEnvelope);
        var rtcOffset = ProductionMailboxPrepositionCommandCodec.HeaderLength
            + ProductionMailboxClosureEnvelopeCodec.HeaderLength
            + decoded.Authority.Length + decoded.Revocations.Length + decoded.Topology.Length
            + decoded.CurrentSelection.Length + decoded.NextSelection.Length
            + decoded.SelectionSuccessorV2.Length + decoded.RouteCertificate.Length;
        decodeBoundary[rtcOffset] ^= 0x80;
        var decodeContext = PrepositionContext(decodeBoundary, peerPort);
        var decodeResult = await ProductionMailboxClosureHttpEndpoint.HandlePrepositionAsync(
            decodeContext, store, peerPort, CancellationToken.None);
        await decodeResult.ExecuteAsync(decodeContext);
        Assert.Equal(StatusCodes.Status400BadRequest, decodeContext.Response.StatusCode);
        Assert.Equal(string.Empty, await ResponseBody(decodeContext));
    }

    [Fact]
    public async Task Pmc2CorruptStoredProtocolArtifact_IsCoarseFetchMiss()
    {
        var fixture = Fixture.Create(Path.Combine(_root, "pmc2-corrupt-fetch"));
        var material = fixture.CreateDirectClosure();
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now)),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        await store.PrepositionAsync(fixture.PrepositionCommand(material),
            CancellationToken.None);
        var path = Assert.Single(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmcs2", SearchOption.AllDirectories));
        File.WriteAllBytes(path,
            fixture.CreateCurrentPssSignatureMutation(material).CanonicalEnvelope);

        Assert.Null(await store.FetchAsync(
            fixture.Request(material, 0x9A), CancellationToken.None));

        var overflow = material.CanonicalEnvelope.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(overflow.AsSpan(72), uint.MaxValue);
        File.WriteAllBytes(path, overflow);
        Assert.Null(await store.FetchAsync(
            fixture.Request(material, 0x9C), CancellationToken.None));
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

        var expiredStore = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node,
            new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)(Now + 3_601))),
            new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        var recoveryContext = PrepositionContext(command, peerPort,
            ProductionMailboxClosureHttpContract.CapacityCommandMediaType);
        var recoveryResult = await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            recoveryContext, expiredStore, peerPort, CancellationToken.None);
        await recoveryResult.ExecuteAsync(recoveryContext);
        Assert.Equal(StatusCodes.Status200OK, recoveryContext.Response.StatusCode);
        Assert.Equal(canonicalReceipt,
            ((MemoryStream)recoveryContext.Response.Body).ToArray());

        var fork = fixture.CapacityCommand(
            Bytes(0x98, 32), 2, 65_536, nonce: 0x66);
        var forkContext = PrepositionContext(fork, peerPort,
            ProductionMailboxClosureHttpContract.CapacityCommandMediaType);
        var forkResult = await ProductionMailboxClosureHttpEndpoint.HandleCapacityAsync(
            forkContext, expiredStore, peerPort, CancellationToken.None);
        await forkResult.ExecuteAsync(forkContext);
        Assert.Equal(StatusCodes.Status400BadRequest, forkContext.Response.StatusCode);
        Assert.DoesNotContain("ProductionMailbox", await ResponseBody(forkContext),
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
        byte[] OwnerPrivateKey)
    {
        public byte[] OldSelectionHash =>
            ProductionMailboxSelectionSuccessorV2Codec.Decode(
                ProductionMailboxClosureEnvelopeCodec.Decode(CanonicalEnvelope)
                    .SelectionSuccessorV2.Span).Selection.OldCanonicalSelectionHash.ToArray();
        public byte[] LineageCommitment => ProductionMailboxClosureEnvelopeCodec
            .Decode(CanonicalEnvelope).LineageCommitment.ToArray();
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

        public static Fixture Create(string root, ulong survivalHorizonSeconds = 0,
            byte readinessPlacementSeed = 0x24)
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
            var authorityUntil = Now + (survivalHorizonSeconds == 0
                ? 300UL : survivalHorizonSeconds + 300);
            var currentDescriptors = Descriptors(20, Now - 60, currentUntil);
            var nextDescriptors = Descriptors(21, Now - 10, nextUntil);
            var readinessPlacementId = Bytes(readinessPlacementSeed, 32);
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
            ulong successorGeneration = 8,
            long nextActivationOffsetSeconds = 120)
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
            var nextNotBefore = nextActivationOffsetSeconds >= 0
                ? checked(activationTime + (ulong)nextActivationOffsetSeconds)
                : checked(activationTime - (ulong)-nextActivationOffsetSeconds);
            var currentDescriptors = successorGeneration == 8
                ? _descriptors[Authority.NextEpoch.Epoch]
                : Descriptors(currentEpochNumber, activationTime - 60, successorUntil);
            var nextDescriptors = Descriptors(
                checked(currentEpochNumber + 1), nextNotBefore, successorUntil);
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
                    nextNotBefore,
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
                    ExpiresAtUnixSeconds = activationTime +
                        (_survivalHorizonSeconds == 0
                            ? 300UL : _survivalHorizonSeconds + 300)
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
            ulong successorGeneration = 8,
            ProductionMailboxRouteAuthorizationKind authorizationKind =
                ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
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
                successorGeneration: successorGeneration,
                nextActivationOffsetSeconds: -10);
            var newAuthorityBytes = ProductionMailboxAuthorityCodec.Encode(newAuthority);
            var newRevocationBytes = File.ReadAllBytes(RevocationArtifactPath);
            var newTopologyBytes = File.ReadAllBytes(TopologyArtifactPath);
            var newTopology = ProductionMailboxTopologyCodec.Decode(newTopologyBytes);
            var newSelectionBytes = File.ReadAllBytes(SelectionPath);
            var newSelection = ProductionMailboxTopologyCodec.DecodeSelection(newSelectionBytes);
            var newVerifiedAuthority = ProductionMailboxAuthorityVerifier.Verify(
                newAuthority,
                new ProductionMailboxAuthorityVerificationContext
                {
                    PinnedMrXPublicKeySha256 = SHA256.HashData(
                        newAuthority.MrXApprovalEd25519PublicKey.Span),
                    ExpectedNetworkId = newAuthority.NetworkId,
                    LastCommittedGeneration = oldAuthority.AuthorityGeneration,
                    LastCommittedAuthorityHash = SHA256.HashData(oldAuthorityBytes),
                    LastCommittedRevocationGeneration = oldAuthority.Revocation.Generation,
                    LastCommittedRevocationHeadHash = oldAuthority.Revocation.HeadHash,
                    LastCommittedRevocationSnapshotHash = oldAuthority.Revocation.SnapshotHash,
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxAuthoritySignatureVerifier());
            var newVerifiedTopology = ProductionMailboxTopologyVerifier.Verify(
                newTopologyBytes, newVerifiedAuthority,
                new ProductionMailboxTopologyVerificationContext
                {
                    LastCommittedTopologyGeneration = oldTopology.TopologyGeneration,
                    LastCommittedTopologyHash = SHA256.HashData(oldTopologyBytes),
                    NowUnixSeconds = Now,
                    ClockSkewSeconds = 0
                }, new SodiumProductionMailboxTopologySignatureVerifier());
            var newNextSelectionBytes = CreateSelectionBytes(
                newTopology, newVerifiedTopology, newTopology.NextEpoch,
                _descriptors[newTopology.NextEpoch.Epoch]);
            var newNextSelection = ProductionMailboxTopologyCodec.DecodeSelection(
                newNextSelectionBytes);
            var owner = PublicKeyAuth.GenerateKeyPair(Bytes(0x2A, 32));
            var placementId = Options.GetReadinessBlindedPlacementId();
            var transitionFrom = Math.Max(newSelection.IssuedAtUnixSeconds,
                newNextSelection.IssuedAtUnixSeconds);
            var transitionUntil = Math.Min(newSelection.ExpiresAtUnixSeconds,
                newNextSelection.ExpiresAtUnixSeconds);
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
                IssuedAtUnixSeconds = transitionFrom,
                ExpiresAtUnixSeconds = transitionUntil,
                CanonicalNewAuthority = newAuthorityBytes,
                OldCanonicalSelection = oldNextSelectionBytes,
                NewCanonicalSelection = newSelectionBytes,
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            var certificate = new ProductionMailboxRouteCertificate
            {
                NetworkId = newAuthority.NetworkId,
                AuthorityGeneration = newAuthority.AuthorityGeneration,
                CanonicalAuthorityHash = SHA256.HashData(newAuthorityBytes),
                IssuerEd25519PublicKey = newAuthority.MailboxIssuerEd25519PublicKey,
                MailboxOwnerEd25519PublicKey = owner.PublicKey,
                BlindedMailboxId = draft.BlindedMailboxId,
                BlindedPlacementId = draft.BlindedPlacementId,
                SelectionInputCommitment = draft.SelectionInputCommitment,
                IssuedAtUnixSeconds = transitionFrom,
                ExpiresAtUnixSeconds = transitionUntil,
                IssuerSignature = new byte[64]
            };
            certificate = certificate with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxRouteAdvertisementCodec.GetCertificateSigningBytes(
                        certificate), _issuerPrivateKey)
            };
            var certificateBytes = ProductionMailboxRouteAdvertisementCodec.EncodeCertificate(
                certificate);
            var routeDomain = ProductionMailboxRouteAdvertisementCodec.ComputeRouteDomainHash(
                certificate);
            var predecessorHash = Bytes(0x8A, 32);
            var transitionSalt = authorizationKind ==
                ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                    ? Bytes(0x8C, 32) : new byte[32];
            var continuityCommitment = authorizationKind ==
                ProductionMailboxRouteAuthorizationKind.DelegatedRCA1
                    ? Bytes(0x8D, 32) : new byte[32];
            byte[] checkpointBytes;
            if (authorizationKind == ProductionMailboxRouteAuthorizationKind.DelegatedRCA1)
            {
                var checkpoint = new ProductionMailboxRouteRevocationCheckpoint
                {
                    NetworkId = newAuthority.NetworkId,
                    RouteDomainHash = routeDomain,
                    CurrentAuthorityGeneration = newAuthority.AuthorityGeneration,
                    CurrentCanonicalAuthorityHash = SHA256.HashData(newAuthorityBytes),
                    CurrentIssuerEd25519PublicKey = newAuthority.MailboxIssuerEd25519PublicKey,
                    CurrentOwnerRevocationGeneration = 0,
                    CurrentOwnerRevocationHeadHash = new byte[32],
                    TransitionSalt = transitionSalt,
                    ContinuityTransitionCommitment = continuityCommitment,
                    Status = ProductionMailboxRouteRevocationStatus.Active,
                    IssuedAtUnixSeconds = transitionFrom,
                    ExpiresAtUnixSeconds = transitionUntil,
                    CurrentIssuerSignature = new byte[64]
                };
                checkpoint = checkpoint with
                {
                    CurrentIssuerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxRouteContinuityCodec),
                            "GetRevocationCheckpointSigningBytes", checkpoint),
                        _issuerPrivateKey)
                };
                checkpointBytes = ProductionMailboxRouteContinuityCodec
                    .EncodeRevocationCheckpoint(checkpoint);
            }
            else if (authorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
                checkpointBytes = [];
            else
                throw new ArgumentOutOfRangeException(nameof(authorizationKind));
            var rtc = new ProductionMailboxRouteTransitionContext
            {
                Mode = mode,
                PredecessorAuthorizationKind = ProductionMailboxRouteAuthorizationKind.OwnerPRA2,
                NewAuthorizationKind = authorizationKind,
                NetworkId = newAuthority.NetworkId,
                RouteDomainHash = routeDomain,
                OldCanonicalSelectionHash = draft.OldCanonicalSelectionHash,
                NewCanonicalSelectionHash = draft.NewCanonicalSelectionHash,
                PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
                PredecessorRouteAuthorizationSequence = 1,
                FreshCanonicalRouteCertificateHash = SHA256.HashData(certificateBytes),
                NewRouteAuthorizationSequence = 2,
                TransitionSalt = transitionSalt,
                ContinuityTransitionCommitment = continuityCommitment,
                CanonicalRevocationCheckpointHash = checkpointBytes.Length == 0
                    ? new byte[32] : SHA256.HashData(checkpointBytes),
                CurrentCanonicalAuthorityHash = SHA256.HashData(newAuthorityBytes),
                CurrentAuthorityGeneration = newAuthority.AuthorityGeneration,
                SealedOldRouteOriginLkgHash = Bytes(0x8B, 32),
                OldRouteVerifiedAtUnixSeconds = transitionFrom - 1,
                OldLocalRouteCommitGeneration = 1,
                NotBeforeUnixSeconds = transitionFrom,
                ExpiresAtUnixSeconds = transitionUntil
            };
            var rtcBytes = ProductionMailboxRouteAuthorizationCodec
                .EncodeTransitionContext(rtc);
            byte[] authorizationBytes;
            if (authorizationKind == ProductionMailboxRouteAuthorizationKind.OwnerPRA2)
            {
                var advertisement = new ProductionMailboxRouteAdvertisementV2
                {
                    Certificate = certificate,
                    PredecessorAuthorizationKind = rtc.PredecessorAuthorizationKind,
                    PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
                    PredecessorRouteAuthorizationSequence = 1,
                    Sequence = 2,
                    PublishedAtUnixSeconds = transitionFrom,
                    ExpiresAtUnixSeconds = transitionUntil,
                    OwnerSignature = new byte[64]
                };
                advertisement = advertisement with
                {
                    OwnerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxRouteAuthorizationCodec),
                            "GetAdvertisementV2SigningBytes", advertisement), owner.PrivateKey)
                };
                authorizationBytes = ProductionMailboxRouteAuthorizationCodec
                    .EncodeAdvertisementV2(advertisement);
            }
            else
            {
                var revocations = ProductionMailboxRevocationSnapshotCodec.Decode(
                    newRevocationBytes);
                var activation = new ProductionMailboxRouteContinuityActivation
                {
                    NetworkId = newAuthority.NetworkId,
                    RouteDomainHash = routeDomain,
                    CurrentAuthorityGeneration = newAuthority.AuthorityGeneration,
                    CurrentCanonicalAuthorityHash = SHA256.HashData(newAuthorityBytes),
                    CurrentIssuerEd25519PublicKey = newAuthority.MailboxIssuerEd25519PublicKey,
                    CurrentRevocationGeneration = revocations.RevocationGeneration,
                    CurrentRevocationHeadHash = revocations.RevocationHeadHash,
                    CurrentRevocationSnapshotHash = SHA256.HashData(newRevocationBytes),
                    TransitionSalt = transitionSalt,
                    ContinuityTransitionCommitment = continuityCommitment,
                    CanonicalRevocationCheckpointHash = SHA256.HashData(checkpointBytes),
                    FreshCanonicalRouteCertificateHash = SHA256.HashData(certificateBytes),
                    CanonicalTransitionContextHash = InvokeProtocolBytes(
                        typeof(ProductionMailboxRouteAuthorizationCodec),
                        "ComputeTransitionContextHash", rtc),
                    PredecessorAuthorizationKind = rtc.PredecessorAuthorizationKind,
                    PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
                    PredecessorRouteAuthorizationSequence = 1,
                    ActivationSequence = 2,
                    IssuedAtUnixSeconds = transitionFrom,
                    ExpiresAtUnixSeconds = transitionUntil,
                    CurrentIssuerSignature = new byte[64]
                };
                activation = activation with
                {
                    CurrentIssuerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxRouteAuthorizationCodec),
                            "GetContinuityActivationSigningBytes", activation),
                        _issuerPrivateKey)
                };
                authorizationBytes = ProductionMailboxRouteAuthorizationCodec
                    .EncodeContinuityActivation(activation);
            }
            var successor = new ProductionMailboxSelectionSuccessorV2Proof
            {
                Selection = draft,
                CanonicalTransitionContextHash =
                    InvokeProtocolBytes(typeof(ProductionMailboxRouteAuthorizationCodec),
                        "ComputeTransitionContextHash", rtc),
                PredecessorAuthorizationKind = rtc.PredecessorAuthorizationKind,
                NewAuthorizationKind = rtc.NewAuthorizationKind,
                PredecessorCanonicalRouteAuthorizationHash = predecessorHash,
                PredecessorRouteAuthorizationSequence = 1,
                FreshCanonicalRouteCertificateHash = SHA256.HashData(certificateBytes),
                NewCanonicalRouteAuthorizationHash = SHA256.HashData(authorizationBytes),
                NewRouteAuthorizationSequence = 2,
                CanonicalRevocationCheckpointHash = rtc.CanonicalRevocationCheckpointHash
            };
            if (mode == ProductionMailboxSelectionSuccessorMode.DirectPromotion)
                successor = successor with
                {
                    Selection = successor.Selection with
                    {
                        OldIssuerSignature = PublicKeyAuth.SignDetached(
                            InvokeProtocolBytes(typeof(ProductionMailboxSelectionSuccessorV2Codec),
                                "GetOldIssuerSigningBytes", successor), _issuerPrivateKey)
                    }
                };
            successor = successor with
            {
                Selection = successor.Selection with
                {
                    NewIssuerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxSelectionSuccessorV2Codec),
                            "GetCurrentIssuerSigningBytes", successor), _issuerPrivateKey)
                }
            };
            var canonicalSuccessor = ProductionMailboxSelectionSuccessorV2Codec.Encode(successor);
            Node.RouterId = Hex(oldNextSelection.Replicas[0].ReplicaId.ToArray());
            Node.Ed25519PrivateKey = Hex(SeedFor(
                oldNextSelection.Replicas[0].ReplicaId.Span,
                oldNextSelection.Epoch));
            var salt = RandomNumberGenerator.GetBytes(32);
            var unsignedEnvelope = new ProductionMailboxClosureEnvelope(
                authorizationKind, salt, new byte[32],
                newAuthorityBytes, newRevocationBytes, newTopologyBytes,
                newSelectionBytes, newNextSelectionBytes, canonicalSuccessor,
                certificateBytes, rtcBytes, authorizationBytes, checkpointBytes);
            var envelope = ProductionMailboxClosureEnvelopeCodec.Encode(unsignedEnvelope with
            {
                LineageCommitment = ProductionMailboxClosureEnvelopeCodec
                    .ComputeLineageCommitment(unsignedEnvelope)
            });
            return new(envelope, Options.GetReadinessSelectionInputCommitment(),
                owner.PublicKey, owner.PrivateKey);
        }

        public ClosureMaterial CreateRolVariant(ClosureMaterial source, byte sealedRolSeed)
        {
            var original = ProductionMailboxClosureEnvelopeCodec.Decode(
                source.CanonicalEnvelope);
            var rtc = ProductionMailboxRouteAuthorizationCodec.DecodeTransitionContext(
                original.TransitionContext.Span) with
            {
                SealedOldRouteOriginLkgHash = Bytes(sealedRolSeed, 32)
            };
            var rtcBytes = ProductionMailboxRouteAuthorizationCodec
                .EncodeTransitionContext(rtc);
            var successor = ProductionMailboxSelectionSuccessorV2Codec.Decode(
                original.SelectionSuccessorV2.Span) with
            {
                CanonicalTransitionContextHash = InvokeProtocolBytes(
                    typeof(ProductionMailboxRouteAuthorizationCodec),
                    "ComputeTransitionContextHash", rtc)
            };
            successor = successor with
            {
                Selection = successor.Selection with
                {
                    OldIssuerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxSelectionSuccessorV2Codec),
                            "GetOldIssuerSigningBytes", successor), _issuerPrivateKey)
                }
            };
            successor = successor with
            {
                Selection = successor.Selection with
                {
                    NewIssuerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxSelectionSuccessorV2Codec),
                            "GetCurrentIssuerSigningBytes", successor), _issuerPrivateKey)
                }
            };
            var draft = original with
            {
                CacheSalt = RandomNumberGenerator.GetBytes(32),
                LineageCommitment = new byte[32],
                TransitionContext = rtcBytes,
                SelectionSuccessorV2 = ProductionMailboxSelectionSuccessorV2Codec.Encode(successor)
            };
            var envelope = ProductionMailboxClosureEnvelopeCodec.Encode(draft with
            {
                LineageCommitment = ProductionMailboxClosureEnvelopeCodec
                    .ComputeLineageCommitment(draft)
            });
            return source with { CanonicalEnvelope = envelope };
        }

        public ClosureMaterial CreateAuthorizationExpiryVariant(
            ClosureMaterial source, ulong expiresAtUnixSeconds)
        {
            var original = ProductionMailboxClosureEnvelopeCodec.Decode(
                source.CanonicalEnvelope);
            var advertisement = ProductionMailboxRouteAuthorizationCodec.DecodeAdvertisementV2(
                original.RouteAuthorization.Span) with
            {
                ExpiresAtUnixSeconds = expiresAtUnixSeconds,
                OwnerSignature = new byte[64]
            };
            advertisement = advertisement with
            {
                OwnerSignature = PublicKeyAuth.SignDetached(
                    InvokeProtocolBytes(typeof(ProductionMailboxRouteAuthorizationCodec),
                        "GetAdvertisementV2SigningBytes", advertisement),
                    source.OwnerPrivateKey)
            };
            var authorization = ProductionMailboxRouteAuthorizationCodec
                .EncodeAdvertisementV2(advertisement);
            var successor = ProductionMailboxSelectionSuccessorV2Codec.Decode(
                original.SelectionSuccessorV2.Span) with
            {
                NewCanonicalRouteAuthorizationHash = SHA256.HashData(authorization)
            };
            successor = ResignSuccessor(successor);
            return RebuildVariant(source, original, successor,
                routeAuthorization: authorization);
        }

        public ClosureMaterial CreateNextSelectionExpiryVariant(
            ClosureMaterial source, ulong expiresAtUnixSeconds)
        {
            var original = ProductionMailboxClosureEnvelopeCodec.Decode(
                source.CanonicalEnvelope);
            var next = ProductionMailboxTopologyCodec.DecodeSelection(
                original.NextSelection.Span) with
            {
                ExpiresAtUnixSeconds = expiresAtUnixSeconds,
                IssuerSignature = new byte[64]
            };
            next = next with
            {
                IssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxTopologyCodec.GetSelectionSigningBytes(next),
                    _issuerPrivateKey)
            };
            return RebuildVariant(source, original,
                ProductionMailboxSelectionSuccessorV2Codec.Decode(
                    original.SelectionSuccessorV2.Span),
                nextSelection: ProductionMailboxTopologyCodec.EncodeSelection(next));
        }

        public ClosureMaterial CreateCurrentPssSignatureMutation(ClosureMaterial source)
        {
            var original = ProductionMailboxClosureEnvelopeCodec.Decode(
                source.CanonicalEnvelope);
            var successor = ProductionMailboxSelectionSuccessorV2Codec.Decode(
                original.SelectionSuccessorV2.Span);
            var signature = successor.Selection.NewIssuerSignature.ToArray();
            signature[0] ^= 0x80;
            successor = successor with
            {
                Selection = successor.Selection with { NewIssuerSignature = signature }
            };
            return RebuildVariant(source, original, successor);
        }

        private ProductionMailboxSelectionSuccessorV2Proof ResignSuccessor(
            ProductionMailboxSelectionSuccessorV2Proof successor)
        {
            if (successor.Selection.Mode ==
                ProductionMailboxSelectionSuccessorMode.DirectPromotion)
                successor = successor with
                {
                    Selection = successor.Selection with
                    {
                        OldIssuerSignature = PublicKeyAuth.SignDetached(
                            InvokeProtocolBytes(typeof(ProductionMailboxSelectionSuccessorV2Codec),
                                "GetOldIssuerSigningBytes", successor), _issuerPrivateKey)
                    }
                };
            return successor with
            {
                Selection = successor.Selection with
                {
                    NewIssuerSignature = PublicKeyAuth.SignDetached(
                        InvokeProtocolBytes(typeof(ProductionMailboxSelectionSuccessorV2Codec),
                            "GetCurrentIssuerSigningBytes", successor), _issuerPrivateKey)
                }
            };
        }

        private static ClosureMaterial RebuildVariant(
            ClosureMaterial source,
            ProductionMailboxClosureEnvelope original,
            ProductionMailboxSelectionSuccessorV2Proof successor,
            ReadOnlyMemory<byte> routeAuthorization = default,
            ReadOnlyMemory<byte> nextSelection = default)
        {
            var draft = original with
            {
                CacheSalt = RandomNumberGenerator.GetBytes(32),
                LineageCommitment = new byte[32],
                RouteAuthorization = routeAuthorization.IsEmpty
                    ? original.RouteAuthorization : routeAuthorization,
                NextSelection = nextSelection.IsEmpty
                    ? original.NextSelection : nextSelection,
                SelectionSuccessorV2 = ProductionMailboxSelectionSuccessorV2Codec.Encode(successor)
            };
            var envelope = ProductionMailboxClosureEnvelopeCodec.Encode(draft with
            {
                LineageCommitment = ProductionMailboxClosureEnvelopeCodec
                    .ComputeLineageCommitment(draft)
            });
            return source with { CanonicalEnvelope = envelope };
        }

        public byte[] PrepositionCommand(
            ClosureMaterial material,
            byte nonce = 0x44,
            ReadOnlyMemory<byte> reservationCohortId = default,
            ulong? timestampUnixSeconds = null)
        {
            var draft = new ProductionMailboxPrepositionCommand(
                timestampUnixSeconds ?? Now, Bytes(nonce, 32),
                SHA256.HashData(material.CanonicalEnvelope),
                Node.GetRouterId().ToBytes(),
                new byte[64], material.CanonicalEnvelope, reservationCohortId);
            var signed = draft with
            {
                PublisherSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxPrepositionCommandCodec.GetSigningBytes(draft),
                    _issuerPrivateKey)
            };
            return ProductionMailboxPrepositionCommandCodec.Encode(signed);
        }

        public byte[] Request(ClosureMaterial material, byte nonce = 0x43,
            ReadOnlyMemory<byte> targetReplicaId = default,
            ulong? timestampUnixSeconds = null)
        {
            var draft = new ProductionMailboxClosureRequest(
                timestampUnixSeconds ?? Now, Bytes(nonce, 32), material.SelectionInputCommitment,
                material.OldSelectionHash, material.LineageCommitment,
                targetReplicaId.IsEmpty ? Node.GetRouterId().ToBytes() : targetReplicaId,
                material.OwnerPublicKey, new byte[64]);
            return ProductionMailboxClosureRequestCodec.Encode(draft with
            {
                OwnerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxClosureRequestCodec.GetSigningBytes(draft),
                    material.OwnerPrivateKey)
            });
        }

        private static byte[] InvokeProtocolBytes(Type type, string method, object argument) =>
            (byte[])(type.GetMethod(method,
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Static)?.Invoke(null, [argument])
                ?? throw new MissingMethodException(type.FullName, method));

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

        public byte[] CapacityReconciliationCommand(
            ReadOnlyMemory<byte> lastCanonicalReceipt,
            ulong? timestampUnixSeconds = null,
            byte nonce = 0x6E)
        {
            var timestamp = timestampUnixSeconds ?? Now;
            var prior = ProductionMailboxCapacityReceiptCodec.Decode(
                lastCanonicalReceipt.Span);
            var draft = new ProductionMailboxCapacityReconciliationCommand(
                timestamp, checked(timestamp + 60), Bytes(nonce, 32),
                prior.CohortId.ToArray(), prior.TargetReplicaId.ToArray(), prior.Revision,
                lastCanonicalReceipt.ToArray(), SHA256.HashData(lastCanonicalReceipt.Span),
                prior.CommandSha256.ToArray(), new byte[64]);
            var signed = draft with
            {
                PublisherSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReconciliationCommandCodec.GetSigningBytes(draft),
                    _issuerPrivateKey)
            };
            return ProductionMailboxCapacityReconciliationCommandCodec.Encode(signed);
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
                ExpiresAtUnixSeconds = artifactNow + (_survivalHorizonSeconds == 0
                    ? 250UL : _survivalHorizonSeconds + 250),
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
            var selectionIssuedAt = Math.Max(
                topology.IssuedAtUnixSeconds + 3, epoch.NotBeforeUnixSeconds);
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
                IssuedAtUnixSeconds = selectionIssuedAt,
                ExpiresAtUnixSeconds = Math.Min(
                    selectionIssuedAt + (_survivalHorizonSeconds == 0
                        ? 202UL : _survivalHorizonSeconds + 202),
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
            if (path.EndsWith(".pmcs2", StringComparison.OrdinalIgnoreCase)
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
            if (deletedPath.EndsWith(".pmcs2", StringComparison.OrdinalIgnoreCase)
                && Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash while flushing closure directory");
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            _inner.ReplaceFile(temporaryPath, finalPath);

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }

    private sealed class BlockingClosureFlushBarrier : IMailboxDurabilityBarrier, IDisposable
    {
        private readonly MailboxDurabilityBarrier _inner = new();
        public ManualResetEventSlim Entered { get; } = new();
        public ManualResetEventSlim Release { get; } = new();

        public void FlushFileAndParentDirectory(string path) =>
            _inner.FlushFileAndParentDirectory(path);

        public void FlushParentDirectory(string deletedPath)
        {
            if (deletedPath.EndsWith(".pmcs2", StringComparison.OrdinalIgnoreCase))
            {
                Entered.Set();
                Release.Wait(TimeSpan.FromSeconds(10));
            }
            _inner.FlushParentDirectory(deletedPath);
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            _inner.ReplaceFile(temporaryPath, finalPath);

        public void DeleteFile(string path) => _inner.DeleteFile(path);

        public void Dispose()
        {
            Release.Set();
            Entered.Dispose();
            Release.Dispose();
        }
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
