using System.Security.Cryptography;
using System.Text.Json.Nodes;
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
            "39461df7e18ee0bb6997cc544a579789faaf6cbee5fb7a552725942c8d09efa2",
            Convert.ToHexString(SHA256.HashData(fixture.CanonicalStore)).ToLowerInvariant());
        Assert.Equal(
            "f2f32707f3ae606ee59d160e0942b2baa2eb8c7eb7c161fc8eecf9e0b4c4c172",
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
    public async Task RouterIdsSigningKeysProofsAndSelectedPair_AreIndependentlyBound()
    {
        var fixture = new PeerFixture(_root);
        using (var runtime = await fixture.OpenRecipientAsync())
        {
            var sameRouter = fixture.StoreRequest with
            {
                SenderRouterId = fixture.RecipientId.ToBytes(),
                Signature = ReadOnlyMemory<byte>.Empty
            };
            var sameSigningKey = fixture.StoreRequest.SenderMembershipProof with
            {
                SigningPublicKey =
                    fixture.StoreRequest.RecipientMembershipProof.SigningPublicKey
            };
            var sameKey = fixture.StoreRequest with
            {
                SenderMembershipProof = sameSigningKey,
                Signature = ReadOnlyMemory<byte>.Empty
            };

            Assert.Null(runtime.Policy.Resolve(
                sameRouter,
                MailboxPeerReplicationOperation.Store,
                fixture.NowUnixSeconds));
            Assert.Null(runtime.Policy.Resolve(
                sameKey,
                MailboxPeerReplicationOperation.Store,
                fixture.NowUnixSeconds));
        }

        var unselected = new MailboxPeerAuthorityOptions
        {
            CurrentEpoch = fixture.Authority.CurrentEpoch,
            CurrentMembershipCommitment = fixture.Authority.CurrentMembershipCommitment,
            CurrentEpochExpiresAtUnixSeconds =
                fixture.Authority.CurrentEpochExpiresAtUnixSeconds,
            PlacementSelections =
            [
                new()
                {
                    Epoch = fixture.Authority.CurrentEpoch,
                    PlacementCommitment = Convert.ToHexString(
                        fixture.StoreRequest.PlacementCommitment.Span).ToLowerInvariant(),
                    FirstRouterId = RouterId.FromBytes(PeerFixture.Range(0x02, 32)).Value,
                    SecondRouterId = fixture.RecipientId.Value
                }
            ]
        };
        using var wrongPlacement = await fixture.OpenRecipientAsync(authority: unselected);
        Assert.Equal(
            MailboxPeerReceiveStatus.AuthorizationFailed,
            (await wrongPlacement.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
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
        var invalidTimeout = PeerFixture.Options();
        invalidTimeout.PeerTimeout = TimeSpan.FromSeconds(16);
        Assert.Throws<InvalidOperationException>(invalidTimeout.Validate);
        var collidingDirectories = PeerFixture.Options();
        collidingDirectories.PeerReplayDirectoryName =
            collidingDirectories.PeerMutationDirectoryName.ToUpperInvariant();
        Assert.Throws<InvalidOperationException>(collidingDirectories.Validate);

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
        MailboxPeerReplayClaim originalClaim;
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
            originalClaim = verified.ReplayClaim;
        }

        fixture.Clock.UtcNow += TimeSpan.FromSeconds(
            MailboxPeerWireV2Limits.MaximumPastAgeSeconds + 1);
        using (var journal = new DurableMailboxPeerReplayJournal(
                   _root,
                   PeerFixture.Options(),
                   fixture.Clock))
        {
            var existing = Assert.IsType<MailboxPeerReplayEvaluation>(
                journal.EvaluateExisting(originalClaim with
                {
                    ReservedAtUnixSeconds = fixture.NowUnixSeconds
                }));
            Assert.Equal(MailboxPeerReplayState.PendingSame, existing.State);
            Assert.Equal(
                originalClaim.ReservedAtUnixSeconds,
                existing.EffectiveReservedAtUnixSeconds);
        }

        ReadOnlyMemory<byte> recoveredResponse;
        using (var recovered = await fixture.OpenRecipientAsync())
        {
            var result = await recovered.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store);
            Assert.Equal(MailboxPeerReceiveStatus.Accepted, result.Status);
            recoveredResponse = result.CanonicalResponse.ToArray();
            var receipt = MailboxReceiptV2Codec.DecodeReplica(
                recoveredResponse.Span);
            Assert.Equal(
                originalClaim.ReservedAtUnixSeconds,
                receipt.AcceptedAtUnixSeconds);
            Assert.Equal(
                originalClaim.ReservedAtUnixSeconds,
                receipt.DurableAtUnixSeconds);
        }

        using var final = await fixture.OpenRecipientAsync();
        var firstRetry = await final.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        var secondRetry = await final.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        Assert.True(firstRetry.WasCached);
        Assert.True(secondRetry.WasCached);
        Assert.Equal(recoveredResponse.ToArray(), firstRetry.CanonicalResponse.ToArray());
        Assert.Equal(recoveredResponse.ToArray(), secondRetry.CanonicalResponse.ToArray());
    }

    [Fact]
    public async Task CompletedExactRetry_AfterRestartAndPastFreshness_IsByteIdentical()
    {
        var fixture = new PeerFixture(_root);
        byte[] canonicalMrr2;
        ulong acceptedAt;
        using (var initial = await fixture.OpenRecipientAsync())
        {
            var first = await initial.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store);
            Assert.Equal(MailboxPeerReceiveStatus.Accepted, first.Status);
            canonicalMrr2 = first.CanonicalResponse.ToArray();
            acceptedAt = MailboxReceiptV2Codec.DecodeReplica(
                canonicalMrr2).AcceptedAtUnixSeconds;
        }

        fixture.Clock.UtcNow += TimeSpan.FromSeconds(
            MailboxPeerWireV2Limits.MaximumPastAgeSeconds + 1);
        using (var restarted = await fixture.OpenRecipientAsync())
        {
            for (var attempt = 0; attempt < 3; attempt++)
            {
                var retry = await restarted.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store);
                Assert.Equal(MailboxPeerReceiveStatus.Accepted, retry.Status);
                Assert.True(retry.WasCached);
                Assert.Equal(canonicalMrr2, retry.CanonicalResponse.ToArray());
                Assert.Equal(
                    acceptedAt,
                    MailboxReceiptV2Codec.DecodeReplica(
                        retry.CanonicalResponse.Span).AcceptedAtUnixSeconds);
            }
        }

        using var secondRestart = await fixture.OpenRecipientAsync();
        var afterSecondRestart = await secondRestart.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        Assert.True(afterSecondRestart.WasCached);
        Assert.Equal(canonicalMrr2, afterSecondRestart.CanonicalResponse.ToArray());
    }

    [Fact]
    public async Task UnknownStaleRequest_IsRejectedWithoutReplayAllocation()
    {
        var fixture = new PeerFixture(_root);
        fixture.Clock.UtcNow += TimeSpan.FromSeconds(
            MailboxPeerWireV2Limits.MaximumPastAgeSeconds + 1);

        using var recipient = await fixture.OpenRecipientAsync();
        var result = await recipient.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);

        Assert.Equal(MailboxPeerReceiveStatus.Conflict, result.Status);
        Assert.Empty(Directory.EnumerateFiles(
            Path.Combine(_root, PeerFixture.Options().PeerReplayDirectoryName),
            "*.json"));
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
    public async Task PendingStore_IsOwnedByExactReplayIdentityAcrossCrash()
    {
        var fixture = new PeerFixture(_root);
        using (var crashed = await fixture.OpenRecipientAsync(
                   faults: new OneShotMutationFault(MailboxPeerMutationFaultPoint.StoreReserved)))
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.DependencyUnavailable,
                (await crashed.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        var differentNonce = fixture.CanonicalStoreWithReplayNonce(PeerFixture.Range(0xe0, 32));
        using var recovered = await fixture.OpenRecipientAsync();
        Assert.Equal(
            MailboxPeerReceiveStatus.AuthorizationFailed,
            (await recovered.Receiver.ReceiveAsync(
                differentNonce,
                MailboxPeerReplicationOperation.Store)).Status);
        var exact = await recovered.Receiver.ReceiveAsync(
            fixture.CanonicalStore,
            MailboxPeerReplicationOperation.Store);
        Assert.Equal(MailboxPeerReceiveStatus.Accepted, exact.Status);
        Assert.Equal(
            MailboxReplicaDisposition.Stored,
            MailboxReceiptV2Codec.DecodeReplica(exact.CanonicalResponse.Span).Disposition);
    }

    [Theory]
    [InlineData(MailboxPeerMutationFaultPoint.TombstoneReserved)]
    [InlineData(MailboxPeerMutationFaultPoint.TombstoneBlobDeleted)]
    public async Task TombstoneCrash_ReconcilesSingleRecordWithoutStoreGap(
        MailboxPeerMutationFaultPoint faultPoint)
    {
        var fixture = new PeerFixture(_root);
        using (var initial = await fixture.OpenRecipientAsync())
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.Accepted,
                (await initial.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        var tombstone = fixture.CanonicalTombstone();
        using (var crashed = await fixture.OpenRecipientAsync(
                   faults: new OneShotMutationFault(faultPoint)))
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.DependencyUnavailable,
                (await crashed.Receiver.ReceiveAsync(
                    tombstone,
                    MailboxPeerReplicationOperation.Tombstone)).Status);
        }

        using var recovered = await fixture.OpenRecipientAsync();
        var duplicateStore = fixture.CanonicalStoreWithReplayNonce(PeerFixture.Range(0xe1, 32));
        Assert.Equal(
            MailboxPeerReceiveStatus.AuthorizationFailed,
            (await recovered.Receiver.ReceiveAsync(
                duplicateStore,
                MailboxPeerReplicationOperation.Store)).Status);
        var result = await recovered.Receiver.ReceiveAsync(
            tombstone,
            MailboxPeerReplicationOperation.Tombstone);
        Assert.Equal(MailboxPeerReceiveStatus.Accepted, result.Status);
        Assert.Empty(await recovered.Blobs.ReadAsync(
            Convert.ToHexString(fixture.Envelope.MailboxId.Bytes.Span).ToLowerInvariant(),
            10));
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
    public async Task FullReplayAndMutationJournals_ReclaimRetiredStateAfterRestart()
    {
        var fixture = new PeerFixture(_root);
        using (var runtime = await fixture.OpenRecipientAsync())
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.Accepted,
                (await runtime.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        var retiredAt = fixture.Authority.CurrentEpochExpiresAtUnixSeconds
            + MailboxPeerWireV2Limits.ReplayRetentionSeconds;
        fixture.Clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(checked((long)retiredAt));
        var options = PeerFixture.Options();
        options.MaxPeerReplayRecords = 1;
        options.MaxPeerReplayRecordsPerRouterPairEpoch = 1;
        options.MaxPeerReplayGcBatch = 1;
        options.MaxPeerMutationRecords = 1;
        options.MaxPeerMutationGcBatch = 1;
        var blobs = new ReplicatedMailboxStore(_root, options, fixture.Clock);
        await blobs.InitializeAsync();
        using (var mutations = new MailboxPeerMutationStore(
                   _root,
                   options,
                   blobs,
                   fixture.Clock))
        {
            await mutations.InitializeAsync();
            Assert.Empty(Directory.EnumerateFiles(
                Path.Combine(_root, options.PeerMutationDirectoryName),
                "*.json"));
        }

        using var journal = new DurableMailboxPeerReplayJournal(
            _root,
            options,
            fixture.Clock);
        var now = checked((ulong)fixture.Clock.UtcNow.ToUnixTimeSeconds());
        var claim = new MailboxPeerReplayClaim
        {
            ScopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(
                PeerFixture.Range(2, 32),
                PeerFixture.Range(42, 32),
                9,
                PeerFixture.Range(82, 32)),
            RequestDigest = PeerFixture.Range(122, 32),
            SenderRouterId = PeerFixture.Range(2, 32),
            RecipientRouterId = PeerFixture.Range(42, 32),
            ReplayNonce = PeerFixture.Range(82, 32),
            OperationId = PeerFixture.Range(162, 16),
            Operation = MailboxPeerReplicationOperation.Store,
            Epoch = 9,
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = now + 60,
            ReservedAtUnixSeconds = now,
            EpochExpiresAtUnixSeconds = now + 120,
            RetainUntilUnixSeconds =
                now + 120 + MailboxPeerWireV2Limits.ReplayRetentionSeconds
        };
        Assert.Equal(
            MailboxPeerReplayState.NewReserved,
            journal.EvaluateAndReserve(claim).State);
    }

    [Fact]
    public async Task ReplayReserve_CollectsEligibleCompletedEntryBeforeCapacity()
    {
        var fixture = new PeerFixture(_root);
        var options = PeerFixture.Options();
        options.MaxPeerReplayRecords = 1;
        options.MaxPeerReplayRecordsPerRouterPairEpoch = 1;
        options.MaxPeerReplayGcBatch = 1;
        using var runtime = await fixture.OpenRecipientAsync(options: options);
        Assert.Equal(
            MailboxPeerReceiveStatus.Accepted,
            (await runtime.Receiver.ReceiveAsync(
                fixture.CanonicalStore,
                MailboxPeerReplicationOperation.Store)).Status);

        var now = fixture.Authority.CurrentEpochExpiresAtUnixSeconds
            + MailboxPeerWireV2Limits.ReplayRetentionSeconds;
        fixture.Clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(checked((long)now));
        var next = new MailboxPeerReplayClaim
        {
            ScopeKey = MailboxPeerReplayStateMachine.ComputeScopeKey(
                PeerFixture.Range(3, 32),
                PeerFixture.Range(43, 32),
                10,
                PeerFixture.Range(83, 32)),
            RequestDigest = PeerFixture.Range(123, 32),
            SenderRouterId = PeerFixture.Range(3, 32),
            RecipientRouterId = PeerFixture.Range(43, 32),
            ReplayNonce = PeerFixture.Range(83, 32),
            OperationId = PeerFixture.Range(163, 16),
            Operation = MailboxPeerReplicationOperation.Store,
            Epoch = 10,
            CreatedAtUnixSeconds = now,
            ExpiresAtUnixSeconds = now + 60,
            ReservedAtUnixSeconds = now,
            EpochExpiresAtUnixSeconds = now + 120,
            RetainUntilUnixSeconds =
                now + 120 + MailboxPeerWireV2Limits.ReplayRetentionSeconds
        };

        Assert.Equal(
            MailboxPeerReplayState.NewReserved,
            runtime.Journal.EvaluateAndReserve(next).State);
    }

    [Theory]
    [InlineData("status")]
    [InlineData("response-domain")]
    [InlineData("timestamp-order")]
    [InlineData("retention")]
    public async Task FutureRetainedReplayCorruption_FailsConstructor(
        string corruption)
    {
        var fixture = new PeerFixture(_root);
        using (var runtime = await fixture.OpenRecipientAsync())
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.Accepted,
                (await runtime.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        var options = PeerFixture.Options();
        var path = Assert.Single(Directory.EnumerateFiles(
            Path.Combine(_root, options.PeerReplayDirectoryName),
            "*.json"));
        var record = Assert.IsType<JsonObject>(JsonNode.Parse(await File.ReadAllTextAsync(path)));
        switch (corruption)
        {
            case "status":
                record["status"] = 99;
                break;
            case "response-domain":
                record["canonicalResponse"] = Convert.ToBase64String(
                    new byte[MailboxPeerWireV2Limits.Ed25519ReplicaResponseLength]);
                break;
            case "timestamp-order":
                record["expiresAtUnixSeconds"] =
                    record["createdAtUnixSeconds"]!.GetValue<ulong>();
                break;
            case "retention":
                record["retainUntilUnixSeconds"] =
                    record["retainUntilUnixSeconds"]!.GetValue<ulong>() + 1;
                break;
            default:
                throw new InvalidOperationException("Unknown corruption.");
        }

        await File.WriteAllTextAsync(path, record.ToJsonString());
        Assert.Throws<InvalidDataException>(() =>
            new DurableMailboxPeerReplayJournal(
                _root,
                options,
                fixture.Clock));
    }

    [Theory]
    [InlineData("epoch-lifetime")]
    [InlineData("retention")]
    [InlineData("state-fields")]
    [InlineData("timestamp-order")]
    public async Task FutureRetainedMutationCorruption_FailsConstructor(
        string corruption)
    {
        var fixture = new PeerFixture(_root);
        using (var runtime = await fixture.OpenRecipientAsync())
        {
            Assert.Equal(
                MailboxPeerReceiveStatus.Accepted,
                (await runtime.Receiver.ReceiveAsync(
                    fixture.CanonicalStore,
                    MailboxPeerReplicationOperation.Store)).Status);
        }

        var options = PeerFixture.Options();
        var path = Assert.Single(Directory.EnumerateFiles(
            Path.Combine(_root, options.PeerMutationDirectoryName),
            "*.json"));
        var record = Assert.IsType<JsonObject>(JsonNode.Parse(await File.ReadAllTextAsync(path)));
        switch (corruption)
        {
            case "epoch-lifetime":
                record["expiresAtUnixSeconds"] =
                    record["epochExpiresAtUnixSeconds"]!.GetValue<ulong>() + 1;
                break;
            case "retention":
                record["retainUntilUnixSeconds"] =
                    record["retainUntilUnixSeconds"]!.GetValue<ulong>() + 1;
                break;
            case "state-fields":
                record["tombstoneReplayNonce"] =
                    Convert.ToHexString(PeerFixture.Range(0x91, 32)).ToLowerInvariant();
                break;
            case "timestamp-order":
                record["storeReservedAtUnixSeconds"] =
                    record["expiresAtUnixSeconds"]!.GetValue<ulong>();
                break;
            default:
                throw new InvalidOperationException("Unknown corruption.");
        }

        await File.WriteAllTextAsync(path, record.ToJsonString());
        var blobs = new ReplicatedMailboxStore(_root, options, fixture.Clock);
        Assert.Throws<InvalidDataException>(() =>
            new MailboxPeerMutationStore(
                _root,
                options,
                blobs,
                fixture.Clock));
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
            SenderId = RouterId.FromBytes(Range(0x01, 32));
            RecipientId = RouterId.FromBytes(Range(0x41, 32));
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
                CurrentEpochExpiresAtUnixSeconds = NowUnixSeconds + 7200,
                PlacementSelections =
                [
                    new()
                    {
                        Epoch = 7,
                        PlacementCommitment = Convert.ToHexString(
                            StoreRequest.PlacementCommitment.Span).ToLowerInvariant(),
                        FirstRouterId = SenderId.Value,
                        SecondRouterId = RecipientId.Value
                    }
                ]
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
        public FixedClock Clock => _clock;
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

        public byte[] CanonicalStoreWithReplayNonce(byte[] replayNonce) =>
            MailboxPeerWireV2Codec.Encode(Sign(StoreRequest with
            {
                ReplayNonce = replayNonce,
                Signature = ReadOnlyMemory<byte>.Empty
            }));

        public async Task<PeerRuntime> OpenRecipientAsync(
            bool failReplayCompletion = false,
            IMailboxPeerMutationFaultInjector? faults = null,
            MailboxPeerAuthorityOptions? authority = null,
            ReplicatedMailboxOptions? options = null)
        {
            Directory.CreateDirectory(_root);
            options ??= Options();
            var blobs = new ReplicatedMailboxStore(_root, options, _clock);
            await blobs.InitializeAsync();
            var mutations = new MailboxPeerMutationStore(
                _root,
                options,
                blobs,
                _clock,
                faults: faults);
            await mutations.InitializeAsync();
            var journal = new DurableMailboxPeerReplayJournal(_root, options, _clock);
            var verifier = new MembershipRoutesMailboxReplicaProofVerifier();
            var policy = new MailboxPeerRequestPolicyResolver(
                RecipientId,
                Convert.ToHexString(_recipientSeed),
                authority ?? Authority,
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

    private sealed class OneShotMutationFault(MailboxPeerMutationFaultPoint expected)
        : IMailboxPeerMutationFaultInjector
    {
        private int _fired;

        public void Inject(MailboxPeerMutationFaultPoint point)
        {
            if (point == expected && Interlocked.Exchange(ref _fired, 1) == 0)
            {
                throw new IOException($"simulated-{point}");
            }
        }
    }

    private sealed class FailCompletionReplayJournal(IMailboxPeerReplayJournal inner)
        : IMailboxPeerReplayJournal
    {
        public MailboxPeerReplayEvaluation EvaluateAndReserve(MailboxPeerReplayClaim claim) =>
            inner.EvaluateAndReserve(claim);

        public MailboxPeerReplayEvaluation? EvaluateExisting(MailboxPeerReplayClaim claim) =>
            inner.EvaluateExisting(claim);

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
