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
            material.OwnerPublicKey, new byte[64]);
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
            fixture.Options.ClosureDirectory, "*.pmc1", SearchOption.TopDirectoryOnly));
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
        fixture.Options.MaximumClosureStoreBytes = material.CanonicalEnvelope.Length;
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds((long)Now));
        var barrier = new ThrowOnceAfterReplaceBarrier();
        var store = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(), barrier);
        var command = fixture.PrepositionCommand(material);

        await Assert.ThrowsAsync<IOException>(async () =>
            await store.PrepositionAsync(command, CancellationToken.None));
        await store.PrepositionAsync(command, CancellationToken.None);

        Assert.Single(Directory.EnumerateFiles(
            fixture.Options.ClosureDirectory, "*.pmc1", SearchOption.TopDirectoryOnly));
        Assert.Equal((1, (long)material.CanonicalEnvelope.Length), store.StorageAccounting);
        _ = new ProductionMailboxClosureStore(
            fixture.Options, fixture.Node, clock, new MailboxStorageSecurity(),
            new MailboxDurabilityBarrier());
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
            "orphan.pmc1.00000000000000000000000000000000.tmp"), [0x01]);

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
            material.OwnerPublicKey, new byte[64]);
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
        BinaryPrimitives.WriteUInt32BigEndian(malformed.AsSpan(176), uint.MaxValue);

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

    private static DefaultHttpContext PrepositionContext(byte[] body, int localPort)
    {
        var context = new DefaultHttpContext();
        context.Connection.LocalPort = localPort;
        context.Request.ContentLength = body.Length;
        context.Request.ContentType = ProductionMailboxClosureHttpContract.PrepositionMediaType;
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
        byte[] OwnerPrivateKey);

    private sealed class Fixture
    {
        private readonly byte[] _privateKey;
        private readonly byte[] _issuerPrivateKey;
        private readonly IReadOnlyDictionary<ulong, MembershipRouteDescriptor[]> _descriptors;

        private Fixture(
            RouterNodeOptions node,
            ProductionMailboxAuthorityOptions options,
            ProductionMailboxAuthority authority,
            byte[] privateKey,
            byte[] issuerPrivateKey,
            IReadOnlyDictionary<ulong, MembershipRouteDescriptor[]> descriptors)
        {
            Node = node;
            Options = options;
            Authority = authority;
            _privateKey = privateKey;
            _issuerPrivateKey = issuerPrivateKey;
            _descriptors = descriptors;
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

        public static Fixture Create(string root)
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
            var currentDescriptors = Descriptors(20, Now - 60, Now + 600);
            var nextDescriptors = Descriptors(21, Now - 10, Now + 1200);
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
                    Now + 600,
                    MembershipRouteDescriptorCodec.ComputeRoot(currentDescriptors),
                    MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(readinessPlacementId))),
                NextEpoch = Epoch(
                    21,
                    71,
                    Now - 10,
                    Now + 1200,
                    MembershipRouteDescriptorCodec.ComputeRoot(nextDescriptors),
                    Bytes(0x92, 32)),
                Revocation = new()
                {
                    SnapshotHash = Bytes(0xA1, 32),
                    HeadHash = Bytes(0xB1, 32),
                    PreviousHeadHash = Bytes(0xC1, 32),
                    Generation = 6,
                    IssuedAtUnixSeconds = Now - 30,
                    ExpiresAtUnixSeconds = Now + 300
                },
                MrXApproval = Approval(Now - 30, Now + 300),
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
                });
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

        public ProductionMailboxAuthority Successor(byte[]? previousAuthorityHash = null)
        {
            var currentHash = ProductionMailboxAuthorityCodec.ComputeCanonicalHash(Authority);
            var successor = BindAndSignPair(Authority with
            {
                AuthorityGeneration = 8,
                PreviousAuthorityHash = previousAuthorityHash ?? currentHash,
                CurrentEpoch = Authority.NextEpoch,
                NextEpoch = Epoch(
                    22,
                    72,
                    Now + 120,
                    Now + 1800,
                    Bytes(0xD2, 32),
                    Bytes(0xD3, 32)),
                Revocation = Authority.Revocation with
                {
                    SnapshotHash = Bytes(0xE2, 32),
                    PreviousHeadHash = Authority.Revocation.HeadHash,
                    HeadHash = Bytes(0xF2, 32),
                    Generation = 7
                },
                MrXApproval = Approval(Now - 5, Now + 600)
            });
            return successor;
        }

        public ClosureMaterial CreateDirectClosure()
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
            var oldNextSelectionBytes = CreateSelectionBytes(
                oldTopology, oldVerifiedTopology, oldTopology.NextEpoch,
                _descriptors[oldTopology.NextEpoch.Epoch]);
            var oldNextSelection = ProductionMailboxTopologyCodec.DecodeSelection(
                oldNextSelectionBytes);

            var newAuthority = Successor();
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
                Mode = ProductionMailboxSelectionSuccessorMode.DirectPromotion,
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
                IssuedAtUnixSeconds = Now,
                ExpiresAtUnixSeconds = Now + 200,
                CanonicalNewAuthority = newAuthorityBytes,
                OldCanonicalSelection = oldNextSelectionBytes,
                NewCanonicalSelection = newSelectionBytes,
                OldIssuerSignature = new byte[64],
                NewIssuerSignature = new byte[64]
            };
            var withOld = draft with
            {
                OldIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetOldIssuerSigningBytes(draft),
                    _issuerPrivateKey)
            };
            var successor = withOld with
            {
                NewIssuerSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxSelectionSuccessorCodec.GetNewIssuerSigningBytes(withOld),
                    _issuerPrivateKey)
            };
            var canonicalSuccessor = ProductionMailboxSelectionSuccessorCodec.Encode(successor);
            Node.RouterId = Hex(oldNextSelection.Replicas[0].ReplicaId.ToArray());
            var envelope = ProductionMailboxClosureEnvelopeCodec.Encode(new(
                newAuthorityBytes, newRevocationBytes, newTopologyBytes,
                newSelectionBytes, canonicalSuccessor));
            return new(envelope, Options.GetReadinessSelectionInputCommitment(),
                owner.PublicKey, owner.PrivateKey);
        }

        public byte[] PrepositionCommand(ClosureMaterial material, byte nonce = 0x44)
        {
            var draft = new ProductionMailboxPrepositionCommand(
                Now, Bytes(nonce, 32), SHA256.HashData(material.CanonicalEnvelope),
                Node.GetRouterId().ToBytes(), new byte[64], material.CanonicalEnvelope);
            var signed = draft with
            {
                PublisherSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxPrepositionCommandCodec.GetSigningBytes(draft),
                    _issuerPrivateKey)
            };
            return ProductionMailboxPrepositionCommandCodec.Encode(signed);
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
                TopologyGeneration = (previousTopology?.TopologyGeneration ?? 0) + 1,
                PreviousTopologyHash = previousTopology is null
                    ? new byte[32]
                    : ProductionMailboxTopologyCodec.ComputeCanonicalHash(previousTopology),
                IssuedAtUnixSeconds = Now - 5,
                ExpiresAtUnixSeconds = Now + 250,
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
                        NowUnixSeconds = Now,
                        ClockSkewSeconds = 0
                    },
                    new SodiumProductionMailboxAuthoritySignatureVerifier()),
                new ProductionMailboxTopologyVerificationContext
                {
                    LastCommittedTopologyGeneration = topology.TopologyGeneration - 1,
                    LastCommittedTopologyHash = topology.PreviousTopologyHash,
                    NowUnixSeconds = Now,
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
                IssuedAtUnixSeconds = Now - 2,
                ExpiresAtUnixSeconds = Math.Min(Now + 200, epoch.NotAfterUnixSeconds),
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
            if (path.EndsWith(".pmc1", StringComparison.OrdinalIgnoreCase)
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
            if (deletedPath.EndsWith(".pmc1", StringComparison.OrdinalIgnoreCase)
                && Interlocked.Exchange(ref _armed, 0) == 1)
                throw new IOException("simulated crash while flushing closure directory");
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            _inner.ReplaceFile(temporaryPath, finalPath);

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }
}
