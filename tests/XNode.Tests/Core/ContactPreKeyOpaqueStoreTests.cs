using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ContactV1;
using Deep.Protocol.MessagingWire;
using XNode.Core.ContactPreKey;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ContactPreKeyOpaqueStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 7, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void BoundedPublicationStagesCanonicalReceiptsAndResumesReadyCommitAfterRestart()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("bounded-restart", fixture.Clock);
        var viewHash = Hash("bounded-restart/view");
        var placementHash = Hash("bounded-restart/placement");
        var logical = Xpp1Codec.Decode(Xpp1Codec.Encode(
            inventory.NetworkId,
            inventory.PublicationOperationId,
            placementHash,
            Xpi1Codec.Decode(inventory.ExactXpi1),
            inventory.OneTimeOfferings
                .Select(static value => (ReadOnlyMemory<byte>)value.ExactDpk2.ToArray())
                .ToArray(),
            inventory.LastResortOffering.ExactDpk2));
        var publication = BoundedPreKeyInventoryPublication.Create(
            logical,
            viewHash,
            checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds()),
            inventory.ServiceExpiresAtUnixSeconds);
        using var authority = new LocalContactServiceReplicaReceiptAuthority(
            Hash("bounded-restart/replica-seed"));
        var receiptAt = checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds());

        byte[] manifestReceipt;
        using (var store = fixture.Open())
        {
            var manifest = store.ApplyPublicationStage(
                publication.ManifestRequest,
                authority.ReplicaId.Span,
                receiptAt,
                authority.SignBoundedPreKeyReceipt);
            Assert.Equal(PreKeyPublicationReplicaDisposition.ManifestAccepted, manifest.Transition.Disposition);
            Assert.NotNull(manifest.StoredReceipt);
            Assert.Equal(Xic1BoundedStatus.ManifestStaged, manifest.StoredReceipt!.Status);
            manifestReceipt = manifest.StoredReceipt.CanonicalBytes.ToArray();

            foreach (var chunk in publication.ChunkRequests)
            {
                Assert.True(chunk.CanonicalBytes.Length <= Xpp1BoundedCodec.MaximumCanonicalRequestBytes);
                var staged = store.ApplyPublicationStage(
                    chunk,
                    authority.ReplicaId.Span,
                    receiptAt,
                    authority.SignBoundedPreKeyReceipt);
                Assert.Equal(PreKeyPublicationReplicaDisposition.ChunkAccepted, staged.Transition.Disposition);
                Assert.Equal(Xic1BoundedStatus.ChunkStaged, staged.StoredReceipt!.Status);
            }
        }

        using (var store = fixture.Open())
        {
            var replay = store.ApplyPublicationStage(
                publication.ManifestRequest,
                authority.ReplicaId.Span,
                receiptAt,
                authority.SignBoundedPreKeyReceipt);
            Assert.Equal(manifestReceipt, replay.StoredReceipt!.CanonicalBytes.ToArray());
            Assert.Equal(Xic1BoundedStatus.ManifestStaged, replay.StoredReceipt.Status);

            var ready = store.ApplyPublicationStage(
                publication.CommitRequest,
                authority.ReplicaId.Span,
                receiptAt,
                authority.SignBoundedPreKeyReceipt);
            Assert.Equal(PreKeyPublicationReplicaDisposition.ReadyToVerify, ready.Transition.Disposition);
            Assert.Null(ready.StoredReceipt);
            Assert.Null(ready.UnsignedReceipt);
            Assert.Equal(
                PreKeyPublicationReplicaDisposition.ReadyToVerify,
                store.ReadPublicationCommit(publication.CommitRequest).Transition.Disposition);
        }
    }

    [Fact]
    public void BoundedPublicationSameEpochForkLatchesAndExactConflictReceiptSurvivesRestart()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("bounded-fork", fixture.Clock);
        var view = Hash("bounded-fork/view");
        var placement = Hash("bounded-fork/placement");
        BoundedPreKeyInventoryPublication Publication(byte[] operation)
        {
            var logical = Xpp1Codec.Decode(Xpp1Codec.Encode(
                inventory.NetworkId,
                operation,
                placement,
                Xpi1Codec.Decode(inventory.ExactXpi1),
                inventory.OneTimeOfferings
                    .Select(static value => (ReadOnlyMemory<byte>)value.ExactDpk2.ToArray())
                    .ToArray(),
                inventory.LastResortOffering.ExactDpk2));
            return BoundedPreKeyInventoryPublication.Create(
                logical,
                view,
                checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds()),
                inventory.ServiceExpiresAtUnixSeconds);
        }
        var first = Publication(Hash("bounded-fork/operation/first"));
        var conflicting = Publication(Hash("bounded-fork/operation/second"));
        using var authority = new LocalContactServiceReplicaReceiptAuthority(
            Hash("bounded-fork/replica-seed"));
        var receiptAt = checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds());
        byte[] conflictReceipt;

        using (var store = fixture.Open())
        {
            Assert.Equal(
                PreKeyPublicationReplicaDisposition.ManifestAccepted,
                store.ApplyPublicationStage(
                    first.ManifestRequest,
                    authority.ReplicaId.Span,
                    receiptAt,
                    authority.SignBoundedPreKeyReceipt).Transition.Disposition);
            var conflict = store.ApplyPublicationStage(
                conflicting.ManifestRequest,
                authority.ReplicaId.Span,
                receiptAt,
                authority.SignBoundedPreKeyReceipt);
            Assert.Equal(PreKeyPublicationReplicaDisposition.ForkLatched, conflict.Transition.Disposition);
            Assert.Equal(Xic1BoundedStatus.Conflict, conflict.StoredReceipt!.Status);
            Assert.Equal(
                Xic1BoundedMutationOutcome.DurablyForkLatched,
                conflict.StoredReceipt.MutationOutcome);
            conflictReceipt = conflict.StoredReceipt.CanonicalBytes.ToArray();
        }

        using (var store = fixture.Open())
        {
            var replay = store.ApplyPublicationStage(
                conflicting.ManifestRequest,
                authority.ReplicaId.Span,
                receiptAt,
                authority.SignBoundedPreKeyReceipt);
            Assert.Equal(conflictReceipt, replay.StoredReceipt!.CanonicalBytes.ToArray());
            Assert.Equal(Xic1BoundedStatus.Conflict, replay.StoredReceipt.Status);
        }
    }

    [Fact]
    public void OneTimeClaimAndExactReplaySurviveRestart()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("restart", fixture.Clock, lastResortLimit: 2);
        var request = ClaimRequest(inventory, "restart/claim", fixture.Clock);
        ContactPreKeyClaimResult claimed;

        using (var store = fixture.Open())
        {
            Assert.Equal(
                ContactPreKeyInventoryDisposition.Installed,
                store.InstallVerifiedInventory(inventory).Disposition);
            claimed = store.Claim(request);
            Assert.Equal(ContactPreKeyClaimDisposition.Claimed, claimed.Disposition);
            Assert.False(ContactPreKeyOpaqueValue.IsZero32(claimed.OneTimePreKeyId));
            Assert.Equal<ulong>(1, claimed.ClaimCommitGeneration);
            Assert.Equal<ushort>(0, claimed.LastResortUseCounter);
            Assert.Equal(inventory.ExactXpi1.ToArray(), claimed.ExactXpi1.ToArray());
            Assert.Equal(inventory.Xpi1Hash.ToArray(), claimed.Xpi1Hash.ToArray());
            Assert.Equal(inventory.InventoryEpoch, claimed.InventoryEpoch);
            Assert.Equal<ushort>(0, claimed.InventoryIndex);
            Assert.Equal(160, claimed.InclusionProof.Length);
            Assert.Equal(inventory.ReplicaNodeIds.Select(static value => value.ToArray()),
                claimed.ReplicaNodeIds.Select(static value => value.ToArray()));
        }

        using (var store = fixture.Open())
        {
            var replay = store.Claim(request);
            Assert.Equal(ContactPreKeyClaimDisposition.ExactReplay, replay.Disposition);
            Assert.Equal(claimed.OneTimePreKeyId.ToArray(), replay.OneTimePreKeyId.ToArray());
            Assert.Equal(claimed.ExactDpk2.ToArray(), replay.ExactDpk2.ToArray());
            Assert.Equal(claimed.ClaimCommitGeneration, replay.ClaimCommitGeneration);
            Assert.Equal(claimed.ExactXpi1.ToArray(), replay.ExactXpi1.ToArray());
            Assert.Equal(claimed.InclusionProof.ToArray(), replay.InclusionProof.ToArray());
        }
    }

    [Fact]
    public void SameOperationChangedRequestConflictsAndCannotConsumeAnotherPreKey()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("operation-conflict", fixture.Clock);
        using var store = fixture.Open();
        Assert.Equal(
            ContactPreKeyInventoryDisposition.Installed,
            store.InstallVerifiedInventory(inventory).Disposition);
        var firstRequest = ClaimRequest(inventory, "operation-conflict/one", fixture.Clock);
        var first = store.Claim(firstRequest);
        Assert.Equal(ContactPreKeyClaimDisposition.Claimed, first.Disposition);

        var changed = new OpaquePreKeyClaimRequest(
            inventory.NetworkId,
            inventory.ServiceCapability,
            inventory.ResponderDeviceId,
            inventory.SupportedSuite,
            firstRequest.OperationId,
            Hash("changed request hash"),
            Hash("operation-conflict/dcb"),
            Hash("stale/different-xps"),
            firstRequest.RequestExpiresAtUnixSeconds);
        Assert.Equal(ContactPreKeyClaimDisposition.Conflict, store.Claim(changed).Disposition);

        var second = store.Claim(ClaimRequest(inventory, "operation-conflict/two", fixture.Clock));
        Assert.Equal(ContactPreKeyClaimDisposition.Claimed, second.Disposition);
        Assert.NotEqual(first.OneTimePreKeyId.ToArray(), second.OneTimePreKeyId.ToArray());
        Assert.Equal<ulong>(2, second.ClaimCommitGeneration);
    }

    [Fact]
    public async Task ConcurrentOperationsNeverReceiveTheSameOneTimePreKey()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("unique", fixture.Clock);
        using var store = fixture.Open();
        store.InstallVerifiedInventory(inventory);
        var tasks = Enumerable.Range(0, ContactPreKeyStoreOptions.MinimumOneTimeOfferings)
            .Select(index => Task.Run(() =>
                store.Claim(ClaimRequest(inventory, "unique/" + index, fixture.Clock))))
            .ToArray();
        var results = await Task.WhenAll(tasks);
        Assert.All(results, result => Assert.Equal(ContactPreKeyClaimDisposition.Claimed, result.Disposition));
        Assert.All(results, result => Assert.Equal<ushort>(0, result.LastResortUseCounter));
        Assert.Equal(
            ContactPreKeyStoreOptions.MinimumOneTimeOfferings,
            results.Select(result => Convert.ToHexString(result.OneTimePreKeyId)).Distinct().Count());
    }

    [Fact]
    public void ExhaustionUsesLastResortOnlyWithinSignedCounterLimit()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("last-resort", fixture.Clock, lastResortLimit: 2);
        using var store = fixture.Open();
        store.InstallVerifiedInventory(inventory);
        for (var index = 0; index < ContactPreKeyStoreOptions.MinimumOneTimeOfferings; index++)
        {
            Assert.Equal(
                ContactPreKeyClaimDisposition.Claimed,
                store.Claim(ClaimRequest(inventory, "last-resort/one-time/" + index, fixture.Clock)).Disposition);
        }

        var firstFallback = store.Claim(ClaimRequest(inventory, "last-resort/fallback/1", fixture.Clock));
        var secondFallback = store.Claim(ClaimRequest(inventory, "last-resort/fallback/2", fixture.Clock));
        Assert.True(ContactPreKeyOpaqueValue.IsZero32(firstFallback.OneTimePreKeyId));
        Assert.True(ContactPreKeyOpaqueValue.IsZero32(secondFallback.OneTimePreKeyId));
        Assert.Equal<ushort>(1, firstFallback.LastResortUseCounter);
        Assert.Equal<ushort>(2, secondFallback.LastResortUseCounter);
        Assert.Equal(
            ContactPreKeyClaimDisposition.PreKeysUnavailable,
            store.Claim(ClaimRequest(inventory, "last-resort/exhausted", fixture.Clock)).Disposition);
    }

    [Fact]
    public void StaleBundleAndExpiryAreExplicitAndDoNotConsumeInventory()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("stale", fixture.Clock);
        using var store = fixture.Open();
        store.InstallVerifiedInventory(inventory);
        var stale = new OpaquePreKeyClaimRequest(
            inventory.NetworkId,
            inventory.ServiceCapability,
            inventory.ResponderDeviceId,
            inventory.SupportedSuite,
            Hash("stale/op"),
            Hash("stale/request"),
            Hash("stale/different-dcb"),
            Hash("stale/different-xps"),
            checked((ulong)fixture.Clock.UtcNow.AddMinutes(1).ToUnixTimeSeconds()));
        var staleResult = store.Claim(stale);
        Assert.Equal(ContactPreKeyClaimDisposition.StaleBundle, staleResult.Disposition);
        Assert.Equal(Hash("stale/different-dcb"), staleResult.RequiredDcb1Hash.ToArray());
        Assert.Equal(inventory.ExactXps1Hash.ToArray(), staleResult.RequiredXps1Hash.ToArray());
        Assert.Equal(inventory.Xpi1Hash.ToArray(), staleResult.RequiredXpi1Hash.ToArray());

        var expired = ClaimRequest(
            inventory,
            "stale/expired",
            fixture.Clock,
            fixture.Clock.UtcNow);
        Assert.Equal(ContactPreKeyClaimDisposition.Expired, store.Claim(expired).Disposition);
        Assert.Equal(
            ContactPreKeyClaimDisposition.Claimed,
            store.Claim(ClaimRequest(inventory, "stale/fresh", fixture.Clock)).Disposition);
    }

    [Fact]
    public void ExactBundleHashesCannotBeReusedForAnotherNetworkDeviceOrSuite()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("selector-binding", fixture.Clock);
        using var store = fixture.Open();
        store.InstallVerifiedInventory(inventory);

        OpaquePreKeyClaimRequest Changed(
            ReadOnlySpan<byte> network,
            ReadOnlySpan<byte> device,
            ushort suite,
            string label) => new(
                network,
                inventory.ServiceCapability,
                device,
                suite,
                Hash(label + "/operation"),
                Hash(label + "/request"),
                Hash(label + "/dcb"),
                inventory.ExactXps1Hash,
                checked((ulong)fixture.Clock.UtcNow.AddMinutes(5).ToUnixTimeSeconds()));

        Assert.Equal(ContactPreKeyClaimDisposition.Conflict,
            store.Claim(Changed(Hash("wrong-network").AsSpan(0, 16),
                inventory.ResponderDeviceId, inventory.SupportedSuite, "network")).Disposition);
        Assert.Equal(ContactPreKeyClaimDisposition.Conflict,
            store.Claim(Changed(inventory.NetworkId, Hash("wrong-device"),
                inventory.SupportedSuite, "device")).Disposition);
        Assert.Equal(ContactPreKeyClaimDisposition.Conflict,
            store.Claim(Changed(inventory.NetworkId, inventory.ResponderDeviceId,
                checked((ushort)(inventory.SupportedSuite + 1)), "suite")).Disposition);

        Assert.Equal(ContactPreKeyClaimDisposition.Claimed,
            store.Claim(ClaimRequest(inventory, "selector-binding/valid", fixture.Clock)).Disposition);
    }

    [Fact]
    public void SuccessorRequiresMonotonicEpochAndExactXpi1Predecessor()
    {
        using var fixture = new StoreFixture();
        var first = Inventory("rotation/first", fixture.Clock, serviceGeneration: 7);
        using var store = fixture.Open();
        Assert.Equal(
            ContactPreKeyInventoryDisposition.Installed,
            store.InstallVerifiedInventory(first).Disposition);
        Assert.Equal(
            ContactPreKeyInventoryDisposition.ExactReplay,
            store.InstallVerifiedInventory(first).Disposition);

        var skipped = Inventory(
            "rotation/skipped",
            fixture.Clock,
            serviceGeneration: 7,
            inventoryEpoch: 3,
            capability: first.ServiceCapability.ToArray(),
            xps: first.ExactXps1Hash.ToArray(),
            predecessorXpi1: first.Xpi1Hash.ToArray());
        Assert.Equal(
            ContactPreKeyInventoryDisposition.StaleGeneration,
            store.InstallVerifiedInventory(skipped).Disposition);

        var wrongPredecessor = Inventory(
            "rotation/wrong",
            fixture.Clock,
            serviceGeneration: 7,
            inventoryEpoch: 2,
            capability: first.ServiceCapability.ToArray(),
            xps: first.ExactXps1Hash.ToArray(),
            predecessorXpi1: Hash("wrong predecessor"));
        Assert.Equal(
            ContactPreKeyInventoryDisposition.Conflict,
            store.InstallVerifiedInventory(wrongPredecessor).Disposition);
        Assert.Equal(
            ContactPreKeyClaimDisposition.ForkLatched,
            store.Claim(ClaimRequest(first, "rotation/claim", fixture.Clock)).Disposition);
    }

    [Fact]
    public void SameEpochOrPublicationOperationWithChangedInventoryForkLatches()
    {
        using (var fixture = new StoreFixture())
        {
            var first = Inventory("fork/first", fixture.Clock);
            using var store = fixture.Open();
            Assert.Equal(ContactPreKeyInventoryDisposition.Installed,
                store.InstallVerifiedInventory(first).Disposition);
            var changedSameEpoch = Inventory(
                "fork/changed", fixture.Clock,
                capability: first.ServiceCapability.ToArray(),
                xps: first.ExactXps1Hash.ToArray());
            Assert.Equal(ContactPreKeyInventoryDisposition.Conflict,
                store.InstallVerifiedInventory(changedSameEpoch).Disposition);
            Assert.Equal(ContactPreKeyClaimDisposition.ForkLatched,
                store.Claim(ClaimRequest(first, "fork/claim", fixture.Clock)).Disposition);
        }

        using (var fixture = new StoreFixture())
        {
            var operation = Hash("fork/reused-publication-operation");
            var first = Inventory("fork/op/first", fixture.Clock, publicationOperation: operation);
            using var store = fixture.Open();
            store.InstallVerifiedInventory(first);
            var successor = Inventory(
                "fork/op/successor", fixture.Clock,
                serviceGeneration: first.ServiceGeneration,
                inventoryEpoch: 2,
                capability: first.ServiceCapability.ToArray(),
                xps: first.ExactXps1Hash.ToArray(),
                predecessorXpi1: first.Xpi1Hash.ToArray(),
                publicationOperation: operation);
            Assert.Equal(ContactPreKeyInventoryDisposition.Conflict,
                store.InstallVerifiedInventory(successor).Disposition);
            Assert.Equal(ContactPreKeyClaimDisposition.ForkLatched,
                store.Claim(ClaimRequest(first, "fork/op/claim", fixture.Clock)).Disposition);
        }
    }

    [Fact]
    public void LastResortClaimPersistsCanonicalXpi1SentinelAcrossRestart()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("last-resort-restart", fixture.Clock, lastResortLimit: 1);
        OpaquePreKeyClaimRequest? fallbackRequest = null;
        using (var store = fixture.Open())
        {
            store.InstallVerifiedInventory(inventory);
            for (var index = 0; index < ContactPreKeyStoreOptions.MinimumOneTimeOfferings; index++)
            {
                store.Claim(ClaimRequest(inventory, $"last-resort-restart/{index}", fixture.Clock));
            }
            fallbackRequest = ClaimRequest(inventory, "last-resort-restart/fallback", fixture.Clock);
            var fallback = store.Claim(fallbackRequest);
            Assert.Equal(ushort.MaxValue, fallback.InventoryIndex);
            Assert.Empty(fallback.InclusionProof.ToArray());
        }
        using var restarted = fixture.Open();
        var replay = restarted.Claim(fallbackRequest!);
        Assert.Equal(ContactPreKeyClaimDisposition.ExactReplay, replay.Disposition);
        Assert.Equal(ushort.MaxValue, replay.InventoryIndex);
        Assert.Empty(replay.InclusionProof.ToArray());
        Assert.Equal(inventory.ExactXpi1.ToArray(), replay.ExactXpi1.ToArray());
    }

    [Fact]
    public void ReplayRetentionIsLaterOfPreKeyExpiryOrThirtyDaysAfterClaim()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("retention", fixture.Clock);
        var request = ClaimRequest(inventory, "retention/claim", fixture.Clock);
        using var store = fixture.Open();
        store.InstallVerifiedInventory(inventory);
        Assert.Equal(ContactPreKeyClaimDisposition.Claimed, store.Claim(request).Disposition);

        fixture.Clock.UtcNow = Start.AddDays(30).AddSeconds(-1);
        Assert.Equal(0, store.CollectGarbage());
        Assert.Equal(ContactPreKeyClaimDisposition.ExactReplay, store.Claim(request).Disposition);

        fixture.Clock.UtcNow = Start.AddDays(30);
        Assert.True(store.CollectGarbage() >= 2);
        Assert.Equal(
            ContactPreKeyClaimDisposition.PreKeysUnavailable,
            store.Claim(ClaimRequest(inventory, "retention/after-gc", fixture.Clock)).Disposition);
        var successor = Inventory(
            "retention/successor",
            fixture.Clock,
            serviceGeneration: inventory.ServiceGeneration,
            inventoryEpoch: 2,
            capability: inventory.ServiceCapability.ToArray(),
            xps: inventory.ExactXps1Hash.ToArray(),
            predecessorXpi1: inventory.Xpi1Hash.ToArray());
        Assert.Equal(
            ContactPreKeyInventoryDisposition.Installed,
            store.InstallVerifiedInventory(successor).Disposition);
        Assert.Equal<ulong>(
            2,
            store.Claim(ClaimRequest(successor, "retention/successor/claim", fixture.Clock))
                .ClaimCommitGeneration);
    }

    [Fact]
    public void ServiceAuthorizationMaySpanFourHundredDaysButDpkEpochMayNotExceedThirty()
    {
        using var fixture = new StoreFixture();
        using var store = fixture.Open();
        var valid = Inventory(
            "lifetime/valid",
            fixture.Clock,
            serviceLifetime: TimeSpan.FromDays(400),
            preKeyLifetime: TimeSpan.FromDays(30));
        Assert.Equal(
            ContactPreKeyInventoryDisposition.Installed,
            store.InstallVerifiedInventory(valid).Disposition);

        var invalid = Inventory(
            "lifetime/invalid-template",
            fixture.Clock,
            serviceLifetime: TimeSpan.FromDays(400),
            preKeyLifetime: TimeSpan.FromDays(30));
        Assert.NotNull(invalid);
        Assert.ThrowsAny<Exception>(() => Inventory(
            "lifetime/invalid",
            fixture.Clock,
            serviceLifetime: TimeSpan.FromDays(400),
            preKeyLifetime: TimeSpan.FromDays(30).Add(TimeSpan.FromSeconds(1))));
    }

    [Fact]
    public void OpaqueByteQuotaRejectsClaimBeforeMutation()
    {
        const long inventoryBytes =
            ContactPreKeyStoreOptions.MinimumOneTimeOfferings * ContactPreKeyStoreOptions.OneTimeDpk2Bytes
            + ContactPreKeyStoreOptions.LastResortDpk2Bytes
            + (ContactPreKeyStoreOptions.MinimumOneTimeOfferings * 160L)
            + 560L;
        using var fixture = new StoreFixture(new ContactPreKeyStoreOptions
        {
            MaximumCapabilities = 1,
            MaximumClaimsPerCapability = 8_256,
            MaximumOpaqueBytes = inventoryBytes,
            MaximumPersistedBytes = 1_000_000
        });
        var inventory = Inventory("quota", fixture.Clock);
        using var store = fixture.Open();
        Assert.Equal(
            ContactPreKeyInventoryDisposition.Installed,
            store.InstallVerifiedInventory(inventory).Disposition);
        var request = ClaimRequest(inventory, "quota/claim", fixture.Clock);
        Assert.Equal(ContactPreKeyClaimDisposition.QuotaExceeded, store.Claim(request).Disposition);
        Assert.Equal(ContactPreKeyClaimDisposition.QuotaExceeded, store.Claim(request).Disposition);
    }

    [Fact]
    public void CorruptionIsQuarantinedAndNeverSilentlyReset()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("corrupt", fixture.Clock);
        using (var store = fixture.Open())
        {
            store.InstallVerifiedInventory(inventory);
            Assert.Equal(
                ContactPreKeyClaimDisposition.Claimed,
                store.Claim(ClaimRequest(inventory, "corrupt/claim", fixture.Clock)).Disposition);
        }

        var bytes = File.ReadAllBytes(fixture.StatePath);
        bytes[^1] ^= 0xff;
        File.WriteAllBytes(fixture.StatePath, bytes);
        Assert.Throws<ContactPreKeyStoreCorruptException>(() => fixture.Open());
        Assert.False(File.Exists(fixture.StatePath));
        Assert.Single(Directory.GetFiles(fixture.DirectoryPath, "*.quarantine.*"));
    }

    [Fact]
    public void ExclusiveLeasePreventsTwoProcessesFromOpeningTheSameState()
    {
        using var fixture = new StoreFixture();
        using var first = fixture.Open();
        Assert.Throws<IOException>(() => fixture.Open());
    }

    [Fact]
    public void FailedAtomicReplaceFaultsTheProcessAndRestartNeverObservesHalfClaim()
    {
        using var fixture = new StoreFixture();
        var inventory = Inventory("durability", fixture.Clock);
        var request = ClaimRequest(inventory, "durability/claim", fixture.Clock);
        var barrier = new SwitchableDurabilityBarrier();
        using (var store = fixture.Open(barrier))
        {
            store.InstallVerifiedInventory(inventory);
            barrier.FailReplace = true;
            Assert.Throws<IOException>(() => store.Claim(request));
            Assert.Throws<InvalidOperationException>(() => store.Claim(request));
        }

        using (var restarted = fixture.Open())
        {
            var claimed = restarted.Claim(request);
            Assert.Equal(ContactPreKeyClaimDisposition.Claimed, claimed.Disposition);
            Assert.Equal<ulong>(1, claimed.ClaimCommitGeneration);
        }
    }

    [Fact]
    public async Task TwoReplicaApplicationReconcilesLostAcknowledgementExactly()
    {
        using var fixture = new ReplicaFixture("application");
        var inventory = Inventory("application", fixture.Clock);
        fixture.FirstStore.InstallVerifiedInventory(inventory);
        fixture.SecondStore.InstallVerifiedInventory(inventory);
        var second = new SwitchableReplica(fixture.SecondReplica) { FailAfterMutation = true };
        using var coordinator = fixture.Coordinator(fixture.FirstReplica, second);
        var service = new ContactPreKeyApplicationService(coordinator);
        var request = ClaimRequest(inventory, "application/claim", fixture.Clock);

        var unknown = await service.ClaimAsync(request);
        Assert.Equal(ContactPreKeyApplicationStatus.OutcomeUnknown, unknown.Status);
        Assert.Equal(ContactPreKeyMutationOutcome.OutcomeUnknown, unknown.MutationOutcome);
        Assert.Equal(1, unknown.DurableReplicaCount);

        second.FailAfterMutation = false;
        var replay = await service.ReconcileAsync(request);
        Assert.Equal(ContactPreKeyApplicationStatus.Replay, replay.Status);
        Assert.Equal(ContactPreKeyMutationOutcome.DurablyCommitted, replay.MutationOutcome);
        Assert.Equal(2, replay.DurableReplicaCount);
        Assert.False(ContactPreKeyOpaqueValue.IsZero32(replay.Claim.OneTimePreKeyId));
    }

    [Fact]
    public async Task ReplicaSelectionDivergenceForkLatchesBothStores()
    {
        using var fixture = new ReplicaFixture("divergence");
        var leftInventory = Inventory("divergence/left", fixture.Clock);
        var rightInventory = Inventory(
            "divergence/right",
            fixture.Clock,
            capability: leftInventory.ServiceCapability.ToArray(),
            xps: leftInventory.ExactXps1Hash.ToArray());
        fixture.FirstStore.InstallVerifiedInventory(leftInventory);
        fixture.SecondStore.InstallVerifiedInventory(rightInventory);
        using var coordinator = fixture.Coordinator();
        var service = new ContactPreKeyApplicationService(coordinator);
        var request = ClaimRequest(leftInventory, "divergence/claim", fixture.Clock);

        var conflict = await service.ClaimAsync(request);
        Assert.Equal(ContactPreKeyApplicationStatus.Conflict, conflict.Status);
        Assert.Equal(
            ContactPreKeyClaimDisposition.ForkLatched,
            fixture.FirstStore.Claim(ClaimRequest(leftInventory, "divergence/after/left", fixture.Clock)).Disposition);
        Assert.Equal(
            ContactPreKeyClaimDisposition.ForkLatched,
            fixture.SecondStore.Claim(ClaimRequest(rightInventory, "divergence/after/right", fixture.Clock)).Disposition);
    }

    private static VerifiedOpaquePreKeyInventory Inventory(
        string label,
        FixedClock clock,
        ushort lastResortLimit = 2,
        ulong serviceGeneration = 1,
        ulong inventoryEpoch = 1,
        byte[]? capability = null,
        byte[]? xps = null,
        byte[]? predecessorXpi1 = null,
        byte[]? publicationOperation = null,
        TimeSpan? serviceLifetime = null,
        TimeSpan? preKeyLifetime = null)
    {
        _ = serviceLifetime;
        var issuedAt = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        var preKeyExpiry = checked((ulong)(clock.UtcNow
            + (preKeyLifetime ?? TimeSpan.FromDays(30))).ToUnixTimeSeconds());
        var network = Hash(label + "/network").AsSpan(0, 16).ToArray();
        var serviceCapability = capability ?? Hash(label + "/capability");
        var device = Hash(label + "/device");
        var dmd = Hash(label + "/dmd");
        var oneTime = Enumerable.Range(0, ContactPreKeyStoreOptions.MinimumOneTimeOfferings)
            .Select(index => (ReadOnlyMemory<byte>)BuildDpk2(
                network, device, dmd, serviceGeneration, inventoryEpoch,
                issuedAt, preKeyExpiry, index, lastResort: false, 0))
            .ToArray();
        var replicas = new[]
        {
            (ReadOnlyMemory<byte>)Hash(label + "/replica/first"),
            (ReadOnlyMemory<byte>)Hash(label + "/replica/second")
        };
        return PreKeyInventoryTestCapability.Create(
            network, serviceCapability, device, Reference("DPD1", Bytes(32, 0x92)), serviceGeneration,
            xps ?? Hash(label + "/xps"), dmd, Reference("DRS1", Hash(label + "/drs")),
            issuedAt, preKeyExpiry, oneTime,
            BuildDpk2(network, device, dmd, serviceGeneration, inventoryEpoch,
                issuedAt, preKeyExpiry, 0xff, lastResort: true, lastResortLimit),
            replicas, inventoryEpoch, predecessorXpi1 ?? Zero32(),
            publicationOperation ?? Hash(label + "/publication"));
    }

    private static byte[] BuildDpk2(
        byte[] network,
        byte[] device,
        byte[] dmd,
        ulong serviceGeneration,
        ulong inventoryEpoch,
        ulong issuedAt,
        ulong expiry,
        int index,
        bool lastResort,
        ushort reuseLimit)
    {
        var marker = checked((byte)((index % 32) + 1));
        var record = new Dpk2Record(
            network, Hash("account"), device, 1, Reference("DPD1", Bytes(32, 0x92)),
            1, dmd, serviceGeneration, inventoryEpoch, Bytes(32, 0x21), 1,
            issuedAt, issuedAt, expiry, Bytes(32, 0x22), Bytes(32, 0x23), Bytes(32, 0x24),
            Bytes(64, 0x25), lastResort ? [] : Bytes(32, marker),
            lastResort ? [] : Bytes(32, checked((byte)(0x40 + marker))),
            Bytes(32, checked((byte)(0x60 + marker))), Bytes(1184, checked((byte)(0x80 + marker))),
            lastResort ? Dpk2PrekeyKind.LastResort : Dpk2PrekeyKind.OneTime,
            lastResort ? reuseLimit : (ushort)0, Bytes(64, 0x26), Bytes(64, 0x27));
        return Dpk2Codec.Encode(record);
    }

    private static OpaquePreKeyClaimRequest ClaimRequest(
        VerifiedOpaquePreKeyInventory inventory,
        string label,
        FixedClock clock,
        DateTimeOffset? expiry = null) =>
        new(
            inventory.NetworkId,
            inventory.ServiceCapability,
            inventory.ResponderDeviceId,
            inventory.SupportedSuite,
            Hash(label + "/operation"),
            Hash(label + "/request"),
            Hash(label + "/dcb"),
            inventory.ExactXps1Hash,
            checked((ulong)(expiry ?? clock.UtcNow.AddMinutes(5)).ToUnixTimeSeconds()));

    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private static byte[] Bytes(string value, int length)
    {
        var seed = Hash(value);
        var bytes = new byte[length];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = seed[index % seed.Length];
        }
        return bytes;
    }

    private static byte[] Zero32() => new byte[32];

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var output = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        hash.CopyTo(output.AsSpan(6));
        return output;
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();

    private sealed class StoreFixture : IDisposable
    {
        private readonly ContactPreKeyStoreOptions? options;

        internal StoreFixture(ContactPreKeyStoreOptions? options = null)
        {
            this.options = options;
            DirectoryPath = Path.Combine(Path.GetTempPath(), "xnode-contact-prekey-tests-" + Guid.NewGuid().ToString("N"));
            StatePath = Path.Combine(DirectoryPath, "prekey.state");
            Clock = new FixedClock(Start);
        }

        internal string DirectoryPath { get; }
        internal string StatePath { get; }
        internal FixedClock Clock { get; }
        internal ContactPreKeyOpaqueStore Open(IMailboxDurabilityBarrier? durability = null) =>
            new(
                StatePath,
                options,
                Clock,
                new TestStorageSecurity(),
                durability ?? new MailboxDurabilityBarrier());

        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath))
            {
                Directory.Delete(DirectoryPath, recursive: true);
            }
        }
    }

    private sealed class ReplicaFixture : IDisposable
    {
        private readonly string directory;

        internal ReplicaFixture(string label)
        {
            directory = Path.Combine(Path.GetTempPath(), "xnode-contact-prekey-replicas-" + Guid.NewGuid().ToString("N"));
            Clock = new FixedClock(Start);
            FirstStore = Open(label + ".first");
            SecondStore = Open(label + ".second");
            FirstReplica = new ContactPreKeyStoreReplica(Hash(label + "/replica/first"), FirstStore);
            SecondReplica = new ContactPreKeyStoreReplica(Hash(label + "/replica/second"), SecondStore);
        }

        internal FixedClock Clock { get; }
        internal ContactPreKeyOpaqueStore FirstStore { get; }
        internal ContactPreKeyOpaqueStore SecondStore { get; }
        internal IContactPreKeyReplica FirstReplica { get; }
        internal IContactPreKeyReplica SecondReplica { get; }
        internal ContactPreKeyTwoReplicaCoordinator Coordinator(
            IContactPreKeyReplica? first = null,
            IContactPreKeyReplica? second = null) =>
            new(first ?? FirstReplica, second ?? SecondReplica);

        public void Dispose()
        {
            FirstStore.Dispose();
            SecondStore.Dispose();
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        private ContactPreKeyOpaqueStore Open(string name) =>
            new(
                Path.Combine(directory, name + ".state"),
                clock: Clock,
                storageSecurity: new TestStorageSecurity(),
                durability: new MailboxDurabilityBarrier());
    }

    private sealed class SwitchableReplica(IContactPreKeyReplica inner) : IContactPreKeyReplica
    {
        internal bool FailAfterMutation { get; set; }
        public ReadOnlyMemory<byte> ReplicaId => inner.ReplicaId;

        public async ValueTask<ContactPreKeyClaimResult> ClaimAsync(
            OpaquePreKeyClaimRequest request,
            CancellationToken cancellationToken)
        {
            var result = await inner.ClaimAsync(request, cancellationToken);
            if (FailAfterMutation)
            {
                throw new IOException("Injected lost acknowledgement.");
            }
            return result;
        }

        public ValueTask LatchForkAsync(
            ReadOnlyMemory<byte> serviceCapability32,
            CancellationToken cancellationToken) =>
            inner.LatchForkAsync(serviceCapability32, cancellationToken);
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }

    private sealed class SwitchableDurabilityBarrier : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier inner = new();
        internal bool FailReplace { get; set; }

        public void FlushFileAndParentDirectory(string path) => inner.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string deletedPath) => inner.FlushParentDirectory(deletedPath);
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (FailReplace)
            {
                throw new IOException("Injected atomic replace failure.");
            }
            inner.ReplaceFile(temporaryPath, finalPath);
        }
        public void DeleteFile(string path) => inner.DeleteFile(path);
        public void DeleteDirectory(string path) => inner.DeleteDirectory(path);
    }
}
