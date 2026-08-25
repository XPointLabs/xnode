using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class MailboxNativeMau2BusinessInvariantTests : IDisposable
{
    public enum StoreReceiptFault
    {
        MismatchedCursor,
        ForgedSignature,
        StaleAcceptedTime
    }

    private static readonly DateTimeOffset Now =
        DateTimeOffset.FromUnixTimeSeconds(1_010);
    private static readonly byte[] MailboxId = Range(0x20, 32);
    private static readonly byte[] PlacementId = Range(0x50, 32);
    private static readonly byte[] MembershipCommitment = Range(0x90, 32);
    private static readonly byte[] NextMembershipCommitment = Range(0xb0, 32);
    private static readonly byte[] NetworkId = Range(0xd0, 16);
    private static readonly byte[] IssuerSeed = Range(0x10, 32);
    private static readonly byte[] HolderSeed = Range(0x40, 32);

    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-native-mau2-business-{Guid.NewGuid():N}");

    [Fact]
    public async Task InvalidFanoutReceiptStaysPending_AndExactRestartCompletesDurably()
    {
        var envelope = Envelope(ciphertextLength: 64);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var canonicalMau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 11,
            serial: 0x71);

        using (var first = new NativeEnvironment(
                   _root,
                   storeFanoutFactory: remote =>
                       new SigningStoreFanout(remote, mutateCursor: true)))
        {
            await first.Adapter.InitializeAsync();
            var authenticated = first.Runtime.Verify(canonicalMau2);
            Assert.True(first.Runtime.TryAcquireExecution(authenticated));
            first.Runtime.ReserveOutcomeCapacity(
                authenticated,
                MailboxWireHttpContract.Store.MaximumResponseBytes);

            var rejected = await first.Adapter.StoreVerifiedAsync(
                authenticated,
                envelope);

            Assert.Equal(
                MailboxClientStoreStatus.QuorumUnavailable,
                rejected.Status);
            Assert.True(authenticated.SideEffectsStarted);
            first.Runtime.AbortIfNew(authenticated);
            var pending = first.Runtime.Verify(canonicalMau2);
            Assert.Equal(
                MailboxAuthenticatedReplayDisposition.InFlight,
                pending.ReplayDisposition);
        }

        byte[] canonicalReceipt;
        using (var recovered = new NativeEnvironment(_root))
        {
            await recovered.Adapter.InitializeAsync();
            var authenticated = recovered.Runtime.Verify(canonicalMau2);
            Assert.Equal(
                MailboxAuthenticatedReplayDisposition.InFlight,
                authenticated.ReplayDisposition);
            Assert.True(recovered.Runtime.TryAcquireExecution(authenticated));
            recovered.Runtime.ReserveOutcomeCapacity(
                authenticated,
                MailboxWireHttpContract.Store.MaximumResponseBytes);

            var result = await recovered.Adapter.StoreVerifiedAsync(
                authenticated,
                envelope);
            Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
            canonicalReceipt = recovered.Runtime.PersistSuccess(
                    authenticated,
                    result.DurableQuorumReceipt,
                    MailboxWireHttpContract.Store.MaximumResponseBytes)
                .CanonicalBytes
                .ToArray();
            _ = MailboxReceiptV3Codec.DecodeDurableQuorum(canonicalReceipt);

            var exactReplay = recovered.Runtime.Verify(canonicalMau2);
            Assert.Equal(
                MailboxAuthenticatedReplayDisposition.IdempotentCompleted,
                exactReplay.ReplayDisposition);
            Assert.Equal(
                canonicalReceipt,
                exactReplay.RecoveredOutcome?.CanonicalBytes.ToArray());
        }

        using var restarted = new NativeEnvironment(
            _root,
            storeFanoutFactory: _ => new ThrowingStoreFanout());
        await restarted.Adapter.InitializeAsync();
        var afterSecondRestart = restarted.Runtime.Verify(canonicalMau2);
        Assert.Equal(
            canonicalReceipt,
            afterSecondRestart.RecoveredOutcome?.CanonicalBytes.ToArray());
    }

    [Fact]
    public void PreSideAbortReleasesReservation_ButPendingPriorRejectsHigherExecution()
    {
        var envelope = Envelope(ciphertextLength: 64);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var lower = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 20,
            serial: 0x72);
        var higher = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 21,
            serial: 0x72);
        using var environment = new NativeEnvironment(_root);

        var safeAbort = environment.Runtime.Verify(lower);
        Assert.True(environment.Runtime.TryAcquireExecution(safeAbort));
        environment.Runtime.ReserveOutcomeCapacity(
            safeAbort,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        environment.Runtime.AbortIfNew(safeAbort);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            environment.Runtime.Verify(lower).ReplayDisposition);

        var pendingOwner = environment.Runtime.Verify(lower);
        Assert.True(environment.Runtime.TryAcquireExecution(pendingOwner));
        pendingOwner.MarkSideEffectsStarted();
        environment.Runtime.AbortIfNew(pendingOwner);

        var pendingPrior = environment.Runtime.Verify(higher);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            pendingPrior.ReplayDisposition);
        Assert.False(environment.Runtime.TryAcquireExecution(pendingPrior));

        var exactPending = environment.Runtime.Verify(lower);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            exactPending.ReplayDisposition);
        Assert.True(environment.Runtime.TryAcquireExecution(exactPending));
        environment.Runtime.EndExecution(exactPending);
    }

    [Fact]
    public async Task OutcomeCapacityIsRejectedBeforeAnyWorkerObserverMutation()
    {
        var envelope = Envelope(ciphertextLength: 64);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var firstMau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 30,
            serial: 0x73);
        var secondMau2 = Sign(
            MailboxAuthenticatedRequestTranscript.ForStore(
                envelope with
                {
                    OperationId = Range(0x31, 16),
                    DeduplicationDigest = Range(0x41, 32)
                }),
            MailboxCapabilityDomain.Deposit,
            replayCounter: 31,
            serial: 0x73);
        var outcomeOptions = new MailboxClientCanonicalOutcomeStoreOptions
        {
            MaximumEntries = 1,
            MaximumBytes =
                MailboxClientCanonicalOutcomeStore.HeaderLength
                + MailboxWireHttpContract.Store.MaximumResponseBytes
        };
        using var environment = new NativeEnvironment(
            _root,
            outcomeOptions: outcomeOptions);
        await environment.Adapter.InitializeAsync();

        var first = environment.Runtime.Verify(firstMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(first));
        environment.Runtime.ReserveOutcomeCapacity(
            first,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        environment.Runtime.PersistTerminal(
            first,
            MailboxClientTerminalOutcome.DurableStateRejected);

        var observer = new RecordingObserver();
        environment.Adapter.RequestObserver = observer;
        var second = environment.Runtime.Verify(secondMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(second));
        Assert.Throws<MailboxClientCanonicalOutcomeCapacityException>(() =>
            environment.Runtime.ReserveOutcomeCapacity(
                second,
                MailboxWireHttpContract.Store.MaximumResponseBytes));

        Assert.False(second.SideEffectsStarted);
        Assert.Empty(observer.Accesses);
        environment.Runtime.AbortIfNew(second);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            environment.Runtime.Verify(secondMau2).ReplayDisposition);
    }

    [Fact]
    public async Task NativeStoreRetrieveAck_RoundTripsLargeMrp1AndDurableOutcomes()
    {
        using var environment = new NativeEnvironment(_root);
        await environment.Adapter.InitializeAsync();
        var envelope = Envelope(MailboxClientLimits.MaximumCiphertextLength);

        var storeBinding =
            MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var storeMau2 = Sign(
            storeBinding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 40,
            serial: 0x74);
        var storeAuthenticated = environment.Runtime.Verify(storeMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(storeAuthenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            storeAuthenticated,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        var stored = await environment.Adapter.StoreVerifiedAsync(
            storeAuthenticated,
            envelope);
        Assert.Equal(MailboxClientStoreStatus.Durable, stored.Status);
        environment.Runtime.PersistSuccess(
            storeAuthenticated,
            stored.DurableQuorumReceipt,
            MailboxWireHttpContract.Store.MaximumResponseBytes);

        var retrieveBinding =
            MailboxAuthenticatedRequestTranscript.ForRetrieve(
                epoch: 7,
                operationId: Range(0x51, 16),
                mailboxId: envelope.MailboxId,
                placementId: envelope.PlacementId,
                afterCursor: 0,
                maximumItems: 1,
                continuationToken: []);
        var retrieveMau2 = Sign(
            retrieveBinding,
            MailboxCapabilityDomain.Retrieve,
            replayCounter: 41,
            serial: 0x75);
        var retrieveAuthenticated = environment.Runtime.Verify(retrieveMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(retrieveAuthenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            retrieveAuthenticated,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        var retrieveBody =
            MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                retrieveBinding.CanonicalRequest.Span);
        var retrieved = await environment.Adapter.RetrieveVerifiedAsync(
            retrieveAuthenticated,
            retrieveBody);
        Assert.Equal(MailboxClientRetrieveStatus.Success, retrieved.Status);
        Assert.True(retrieved.CanonicalPage.Length > 64 * 1024);
        var page = MailboxClientCodec.DecodeRetrievePage(
            retrieved.CanonicalPage.Span,
            DecodePolicy());
        var item = Assert.Single(page.Items);
        Assert.Equal(
            MailboxClientLimits.MaximumEncryptedEnvelopeLength,
            MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope).Length);
        var persistedPage = environment.Runtime.PersistSuccess(
            retrieveAuthenticated,
            retrieved.CanonicalPage,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        Assert.Equal(
            retrieved.CanonicalPage.ToArray(),
            persistedPage.CanonicalBytes.ToArray());
        Assert.Equal(
            retrieved.CanonicalPage.ToArray(),
            environment.Runtime.Verify(retrieveMau2)
                .RecoveredOutcome?.CanonicalBytes.ToArray());

        var acknowledgement = item.ToAcknowledgement();
        var ackBinding = MailboxAuthenticatedRequestTranscript.ForAck(
            epoch: 7,
            operationId: Range(0x61, 16),
            mailboxId: envelope.MailboxId,
            placementId: envelope.PlacementId,
            isFinalPage: true,
            continuationToken: [],
            acknowledgements: [acknowledgement]);
        var ackMau2 = Sign(
            ackBinding,
            MailboxCapabilityDomain.Retrieve,
            replayCounter: 42,
            serial: 0x76);
        var ackAuthenticated = environment.Runtime.Verify(ackMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(ackAuthenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            ackAuthenticated,
            MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
        var ackBody = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
            ackBinding.CanonicalRequest.Span);
        var acknowledged = await environment.Adapter.AcknowledgeVerifiedAsync(
            ackAuthenticated,
            ackBody);
        Assert.Equal(MailboxClientAckStatus.Durable, acknowledged.Status);
        var aggregate = MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = ackBody.Epoch,
                OperationId = ackBody.OperationId.ToArray(),
                TombstoneQuorums = acknowledged.Receipts
                    .Select(static receipt =>
                        (ReadOnlyMemory<byte>)receipt.DurableQuorumReceipt.ToArray())
                    .ToArray()
            });
        environment.Runtime.PersistSuccess(
            ackAuthenticated,
            aggregate,
            MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
        Assert.Single(MailboxAggregateAckCodec.DecodeMqr3(aggregate).TombstoneQuorums);
        Assert.Equal(
            aggregate,
            environment.Runtime.Verify(ackMau2)
                .RecoveredOutcome?.CanonicalBytes.ToArray());

        var emptyBinding =
            MailboxAuthenticatedRequestTranscript.ForRetrieve(
                epoch: 7,
                operationId: Range(0x71, 16),
                mailboxId: envelope.MailboxId,
                placementId: envelope.PlacementId,
                afterCursor: 0,
                maximumItems: 1,
                continuationToken: []);
        var emptyMau2 = Sign(
            emptyBinding,
            MailboxCapabilityDomain.Retrieve,
            replayCounter: 43,
            serial: 0x77);
        var emptyAuthenticated = environment.Runtime.Verify(emptyMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(emptyAuthenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            emptyAuthenticated,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        var empty = await environment.Adapter.RetrieveVerifiedAsync(
            emptyAuthenticated,
            MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                emptyBinding.CanonicalRequest.Span));
        Assert.Equal(MailboxClientRetrieveStatus.Success, empty.Status);
        Assert.Empty(MailboxClientCodec.DecodeRetrievePage(
            empty.CanonicalPage.Span,
            DecodePolicy()).Items);
        environment.Runtime.PersistSuccess(
            emptyAuthenticated,
            empty.CanonicalPage,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
    }

    [Fact]
    public async Task SameOperationWithDifferentCanonicalBody_IsDurableConflict()
    {
        using var environment = new NativeEnvironment(_root);
        await environment.Adapter.InitializeAsync();
        var original = Envelope(64);
        var first = await ExecuteStoreAsync(
            environment,
            original,
            replayCounter: 50,
            serial: 0x78);
        Assert.Equal(MailboxClientStoreStatus.Durable, first.Status);

        var changed = original with
        {
            DeduplicationDigest = Range(0x81, 32),
            Ciphertext = Filled(0x6b, 64)
        };
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(changed);
        var authenticated = environment.Runtime.Verify(Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 51,
            serial: 0x79));
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Store.MaximumResponseBytes);

        var conflict = await environment.Adapter.StoreVerifiedAsync(
            authenticated,
            changed);

        Assert.Equal(MailboxClientStoreStatus.Conflict, conflict.Status);
        environment.Runtime.PersistTerminal(
            authenticated,
            MailboxClientTerminalOutcome.OperationConflict);
    }

    [Fact]
    public async Task ExactLedgerRetryKeepsCachedQuorumAndCursorWithoutSecondFanout()
    {
        ToggleStoreFanout? fanout = null;
        using var environment = new NativeEnvironment(
            _root,
            storeFanoutFactory: remote =>
                fanout = new ToggleStoreFanout(remote));
        await environment.Adapter.InitializeAsync();
        var envelope = Envelope(64);

        var first = await ExecuteStoreAsync(
            environment,
            envelope,
            replayCounter: 60,
            serial: 0x7a);
        fanout!.Throw = true;
        var retry = await ExecuteStoreAsync(
            environment,
            envelope,
            replayCounter: 61,
            serial: 0x7b);

        Assert.Equal(MailboxClientStoreStatus.Durable, first.Status);
        Assert.Equal(MailboxClientStoreStatus.Durable, retry.Status);
        Assert.Equal(
            first.DurableQuorumReceipt.ToArray(),
            retry.DurableQuorumReceipt.ToArray());
        Assert.Equal(1, fanout.CallCount);
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(
            retry.DurableQuorumReceipt.Span);
        Assert.Equal(1UL, quorum.FirstReplica.Cursor);
        Assert.Equal(1UL, quorum.SecondReplica.Cursor);
    }

    [Fact]
    public async Task ConcurrentNativeClaimsShareOneStoreSingleFlight()
    {
        ToggleStoreFanout? fanout = null;
        using var environment = new NativeEnvironment(
            _root,
            storeFanoutFactory: remote =>
                fanout = new ToggleStoreFanout(
                    remote,
                    delay: TimeSpan.FromMilliseconds(75)));
        await environment.Adapter.InitializeAsync();
        var envelope = Envelope(64);

        var first = ExecuteStoreAsync(
            environment,
            envelope,
            replayCounter: 70,
            serial: 0x7c);
        var second = ExecuteStoreAsync(
            environment,
            envelope,
            replayCounter: 71,
            serial: 0x7d);
        var results = await Task.WhenAll(first, second);

        Assert.All(results, result =>
            Assert.Equal(MailboxClientStoreStatus.Durable, result.Status));
        Assert.Equal(
            results[0].DurableQuorumReceipt.ToArray(),
            results[1].DurableQuorumReceipt.ToArray());
        Assert.Equal(1, fanout!.CallCount);
    }

    [Fact]
    public async Task LedgerLeaseAndCorruptionRemainFailClosed()
    {
        MailboxClientAdapterOptions options;
        using (var environment = new NativeEnvironment(_root))
        {
            await environment.Adapter.InitializeAsync();
            options = environment.AdapterOptions;
            Assert.Throws<InvalidOperationException>(() =>
                new MailboxClientOperationLedger(
                    _root,
                    options,
                    new FixedClock(Now)));
        }

        var path = Path.Combine(
            _root,
            options.DirectoryName,
            "operations.json");
        File.WriteAllText(path, """{"schemaVersion":999}""");
        using var corrupted = new NativeEnvironment(_root);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            corrupted.Adapter.InitializeAsync());
    }

    [Fact]
    public async Task ExpiredLedgerEntryCompactsWithoutCursorReuse()
    {
        var clock = new FixedClock(Now);
        Action<MailboxClientAdapterOptions> constrained = options =>
        {
            options.MaxOperationEntries = 1;
            options.MaxCursorAuthorities = 1;
            options.MaxConcurrentSingleFlights = 1;
        };
        using (var first = new NativeEnvironment(
                   _root,
                   configureOptions: constrained,
                   clock: clock))
        {
            await first.Adapter.InitializeAsync();
            var stored = await ExecuteStoreAsync(
                first,
                Envelope(
                    64,
                    operationStart: 0x21,
                    digestStart: 0x31,
                    expiresAt: 1_080),
                replayCounter: 80,
                serial: 0x7e);
            Assert.Equal(1UL, MailboxReceiptV3Codec.DecodeDurableQuorum(
                stored.DurableQuorumReceipt.Span).FirstReplica.Cursor);
        }

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1_090);
        using var restarted = new NativeEnvironment(
            _root,
            configureOptions: constrained,
            clock: clock);
        await restarted.Adapter.InitializeAsync();
        var replacement = await ExecuteStoreAsync(
            restarted,
            Envelope(
                64,
                operationStart: 0x41,
                digestStart: 0x51,
                createdAt: 1_090,
                expiresAt: 1_170),
            replayCounter: 81,
            serial: 0x7f);
        Assert.Equal(MailboxClientStoreStatus.Durable, replacement.Status);
        Assert.Equal(2UL, MailboxReceiptV3Codec.DecodeDurableQuorum(
            replacement.DurableQuorumReceipt.Span).FirstReplica.Cursor);
    }

    [Fact]
    public async Task EpochsUseDistinctConfiguredMembershipCommitments()
    {
        RecordingAuthorizer? authorizer = null;
        using var environment = new NativeEnvironment(
            _root,
            authorizerFactory: replicas =>
                authorizer = new RecordingAuthorizer(replicas));
        await environment.Adapter.InitializeAsync();

        var current = await ExecuteStoreAsync(
            environment,
            Envelope(
                64,
                epoch: 7,
                operationStart: 0x61,
                digestStart: 0x71),
            replayCounter: 90,
            serial: 0x81);
        var next = await ExecuteStoreAsync(
            environment,
            Envelope(
                64,
                epoch: 8,
                operationStart: 0x71,
                digestStart: 0x81),
            replayCounter: 91,
            serial: 0x82);

        Assert.Equal(MailboxClientStoreStatus.Durable, current.Status);
        Assert.Equal(MailboxClientStoreStatus.Durable, next.Status);
        Assert.Contains(authorizer!.SeenMemberships, value =>
            value.AsSpan().SequenceEqual(MembershipCommitment));
        Assert.Contains(authorizer.SeenMemberships, value =>
            value.AsSpan().SequenceEqual(NextMembershipCommitment));
        Assert.False(MembershipCommitment.AsSpan().SequenceEqual(
            NextMembershipCommitment));
    }

    [Fact]
    public async Task ContinuationRejectsWrongMailboxTamperPageDigestAndExpiry()
    {
        var clock = new FixedClock(Now);
        using var environment = new NativeEnvironment(
            _root,
            configureOptions: options =>
                options.ContinuationTokenLifetime = TimeSpan.FromMinutes(1),
            clock: clock);
        await environment.Adapter.InitializeAsync();
        _ = await ExecuteStoreAsync(
            environment,
            Envelope(64, operationStart: 0x91, digestStart: 0xa1),
            replayCounter: 100,
            serial: 0x83);
        _ = await ExecuteStoreAsync(
            environment,
            Envelope(64, operationStart: 0xa1, digestStart: 0xb1),
            replayCounter: 101,
            serial: 0x84);

        var firstBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0xb1, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            0,
            1,
            []);
        var firstAuthenticated = environment.Runtime.Verify(Sign(
            firstBinding,
            MailboxCapabilityDomain.Retrieve,
            102,
            0x85));
        Assert.True(environment.Runtime.TryAcquireExecution(firstAuthenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            firstAuthenticated,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        var firstResult = await environment.Adapter.RetrieveVerifiedAsync(
            firstAuthenticated,
            MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                firstBinding.CanonicalRequest.Span));
        Assert.Equal(MailboxClientRetrieveStatus.Success, firstResult.Status);
        var firstPage = MailboxClientCodec.DecodeRetrievePage(
            firstResult.CanonicalPage.Span,
            DecodePolicy());
        Assert.True(firstPage.HasMore);
        var firstItem = Assert.Single(firstPage.Items);
        environment.Runtime.PersistSuccess(
            firstAuthenticated,
            firstResult.CanonicalPage,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);

        var wrongMailboxBinding =
            MailboxAuthenticatedRequestTranscript.ForRetrieve(
                7,
                Range(0xc1, 16),
                new BlindedMailboxId(Range(0xe0, 32)),
                new BlindedPlacementId(PlacementId),
                firstPage.NextCursor,
                1,
                firstPage.ContinuationToken.Span);
        var wrongMailbox = await ExecuteRetrieveFailureAsync(
            environment,
            wrongMailboxBinding,
            replayCounter: 103,
            serial: 0x86);
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, wrongMailbox.Status);

        var tamperedToken = firstPage.ContinuationToken.ToArray();
        tamperedToken[^1] ^= 0xff;
        var tamperedBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0xd1, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            firstPage.NextCursor,
            1,
            tamperedToken);
        var tampered = await ExecuteRetrieveFailureAsync(
            environment,
            tamperedBinding,
            replayCounter: 104,
            serial: 0x87);
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, tampered.Status);

        var wrongAcknowledgement = firstItem.ToAcknowledgement() with
        {
            EnvelopeDigest = Range(0xf0, 32)
        };
        var ackBinding = MailboxAuthenticatedRequestTranscript.ForAck(
            7,
            Range(0xe1, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            isFinalPage: false,
            firstPage.ContinuationToken.Span,
            [wrongAcknowledgement]);
        var ackAuthenticated = environment.Runtime.Verify(Sign(
            ackBinding,
            MailboxCapabilityDomain.Retrieve,
            105,
            0x88));
        Assert.True(environment.Runtime.TryAcquireExecution(ackAuthenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            ackAuthenticated,
            MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
        var wrongPageDigest =
            await environment.Adapter.AcknowledgeVerifiedAsync(
                ackAuthenticated,
                MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                    ackBinding.CanonicalRequest.Span));
        Assert.Equal(
            MailboxClientAckStatus.Unauthorized,
            wrongPageDigest.Status);
        environment.Runtime.PersistTerminal(
            ackAuthenticated,
            MailboxClientTerminalOutcome.AuthorizationRejected);

        clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1_071);
        var expiredBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0xf1, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            firstPage.NextCursor,
            1,
            firstPage.ContinuationToken.Span);
        var expired = await ExecuteRetrieveFailureAsync(
            environment,
            expiredBinding,
            replayCounter: 106,
            serial: 0x89);
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, expired.Status);
    }

    [Fact]
    public async Task MaximumPageByteBoundCreatesCanonicalContinuation()
    {
        using var environment = new NativeEnvironment(_root);
        await environment.Adapter.InitializeAsync();
        for (var index = 0; index < 13; index++)
        {
            var stored = await ExecuteStoreAsync(
                environment,
                Envelope(
                    MailboxClientLimits.MaximumCiphertextLength,
                    operationStart: checked((byte)(0x10 + index)),
                    digestStart: checked((byte)(0x40 + index))),
                replayCounter: checked((ulong)(120 + index)),
                serial: checked((byte)(0x90 + index)));
            Assert.Equal(MailboxClientStoreStatus.Durable, stored.Status);
        }

        var firstBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0x60, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            0,
            MailboxClientLimits.MaximumPageItems,
            []);
        var first = await ExecuteRetrieveSuccessAsync(
            environment,
            firstBinding,
            replayCounter: 140,
            serial: 0xa0);
        Assert.InRange(
            first.CanonicalPage.Length,
            64 * 1024 + 1,
            MailboxClientLimits.MaximumPageBytes);
        var firstPage = MailboxClientCodec.DecodeRetrievePage(
            first.CanonicalPage.Span,
            DecodePolicy());
        Assert.True(firstPage.HasMore);
        Assert.InRange(firstPage.Items.Count, 1, 12);

        var nextBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0x70, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            firstPage.NextCursor,
            MailboxClientLimits.MaximumPageItems,
            firstPage.ContinuationToken.Span);
        var next = await ExecuteRetrieveSuccessAsync(
            environment,
            nextBinding,
            replayCounter: 141,
            serial: 0xa1);
        var nextPage = MailboxClientCodec.DecodeRetrievePage(
            next.CanonicalPage.Span,
            DecodePolicy());
        Assert.False(nextPage.HasMore);
        Assert.Equal(13, firstPage.Items.Count + nextPage.Items.Count);
        Assert.True(firstPage.Items
            .Concat(nextPage.Items)
            .Select(static item => item.Cursor)
            .SequenceEqual(Enumerable.Range(1, 13)
                .Select(static value => (ulong)value)));
    }

    [Fact]
    public async Task AckCapacityRejectsBeforeAnyTargetBecomesHidden()
    {
        using var environment = new NativeEnvironment(
            _root,
            configureOptions: options =>
            {
                options.MaxOperationEntries = 4;
                options.MaxCursorAuthorities = 4;
                options.MaxConcurrentSingleFlights = 4;
            });
        await environment.Adapter.InitializeAsync();
        _ = await ExecuteStoreAsync(
            environment,
            Envelope(64, operationStart: 0x21, digestStart: 0x31),
            replayCounter: 150,
            serial: 0xb0);
        _ = await ExecuteStoreAsync(
            environment,
            Envelope(64, operationStart: 0x31, digestStart: 0x41),
            replayCounter: 151,
            serial: 0xb1);
        var retrieveBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0x41, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            0,
            10,
            []);
        var retrieved = await ExecuteRetrieveSuccessAsync(
            environment,
            retrieveBinding,
            replayCounter: 152,
            serial: 0xb2);
        var page = MailboxClientCodec.DecodeRetrievePage(
            retrieved.CanonicalPage.Span,
            DecodePolicy());
        Assert.Equal(2, page.Items.Count);

        var ackBinding = MailboxAuthenticatedRequestTranscript.ForAck(
            7,
            Range(0x51, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            true,
            [],
            page.Items.Select(static item => item.ToAcknowledgement()).ToArray());
        var authenticated = environment.Runtime.Verify(Sign(
            ackBinding,
            MailboxCapabilityDomain.Retrieve,
            153,
            0xb3));
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
        var rejected = await environment.Adapter.AcknowledgeVerifiedAsync(
            authenticated,
            MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                ackBinding.CanonicalRequest.Span));
        Assert.Equal(MailboxClientAckStatus.Rejected, rejected.Status);
        Assert.Equal("operation-ledger-capacity", rejected.Error);
        environment.Runtime.PersistTerminal(
            authenticated,
            MailboxClientTerminalOutcome.DurableStateRejected);

        var retryBinding = MailboxAuthenticatedRequestTranscript.ForRetrieve(
            7,
            Range(0x61, 16),
            new BlindedMailboxId(MailboxId),
            new BlindedPlacementId(PlacementId),
            0,
            10,
            []);
        var stillVisible = await ExecuteRetrieveSuccessAsync(
            environment,
            retryBinding,
            replayCounter: 154,
            serial: 0xb4);
        Assert.Equal(2, MailboxClientCodec.DecodeRetrievePage(
            stillVisible.CanonicalPage.Span,
            DecodePolicy()).Items.Count);
    }

    [Fact]
    public async Task PartialAckFailureHidesTargets_ThenRestartCompletesExactMar1()
    {
        PartialFailureTombstoneFanout? partial = null;
        byte[] ackMau2;
        using (var first = new NativeEnvironment(
                   _root,
                   tombstoneFanoutFactory: remote =>
                       partial = new PartialFailureTombstoneFanout(
                           remote,
                           failOnCall: 2)))
        {
            await first.Adapter.InitializeAsync();
            _ = await ExecuteStoreAsync(
                first,
                Envelope(64, operationStart: 0x71, digestStart: 0x81),
                replayCounter: 160,
                serial: 0xb5);
            _ = await ExecuteStoreAsync(
                first,
                Envelope(64, operationStart: 0x81, digestStart: 0x91),
                replayCounter: 161,
                serial: 0xb6);
            var retrieveBinding =
                MailboxAuthenticatedRequestTranscript.ForRetrieve(
                    7,
                    Range(0x91, 16),
                    new BlindedMailboxId(MailboxId),
                    new BlindedPlacementId(PlacementId),
                    0,
                    10,
                    []);
            var retrieved = await ExecuteRetrieveSuccessAsync(
                first,
                retrieveBinding,
                replayCounter: 162,
                serial: 0xb7);
            var page = MailboxClientCodec.DecodeRetrievePage(
                retrieved.CanonicalPage.Span,
                DecodePolicy());
            var ackBinding = MailboxAuthenticatedRequestTranscript.ForAck(
                7,
                Range(0xa1, 16),
                new BlindedMailboxId(MailboxId),
                new BlindedPlacementId(PlacementId),
                true,
                [],
                page.Items.Select(static item => item.ToAcknowledgement()).ToArray());
            ackMau2 = Sign(
                ackBinding,
                MailboxCapabilityDomain.Retrieve,
                163,
                0xb8);
            var authenticated = first.Runtime.Verify(ackMau2);
            Assert.True(first.Runtime.TryAcquireExecution(authenticated));
            first.Runtime.ReserveOutcomeCapacity(
                authenticated,
                MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
            var interrupted = await first.Adapter.AcknowledgeVerifiedAsync(
                authenticated,
                MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                    ackBinding.CanonicalRequest.Span));
            Assert.Equal(
                MailboxClientAckStatus.QuorumUnavailable,
                interrupted.Status);
            Assert.Equal(2, partial!.CallCount);
            first.Runtime.AbortIfNew(authenticated);

            var afterFailureBinding =
                MailboxAuthenticatedRequestTranscript.ForRetrieve(
                    7,
                    Range(0xb1, 16),
                    new BlindedMailboxId(MailboxId),
                    new BlindedPlacementId(PlacementId),
                    0,
                    10,
                    []);
            var hidden = await ExecuteRetrieveSuccessAsync(
                first,
                afterFailureBinding,
                replayCounter: 164,
                serial: 0xb9);
            Assert.Empty(MailboxClientCodec.DecodeRetrievePage(
                hidden.CanonicalPage.Span,
                DecodePolicy()).Items);
        }

        byte[] aggregate;
        using (var recovered = new NativeEnvironment(_root))
        {
            await recovered.Adapter.InitializeAsync();
            var authenticated = recovered.Runtime.Verify(ackMau2);
            Assert.Equal(
                MailboxAuthenticatedReplayDisposition.InFlight,
                authenticated.ReplayDisposition);
            Assert.True(recovered.Runtime.TryAcquireExecution(authenticated));
            recovered.Runtime.ReserveOutcomeCapacity(
                authenticated,
                MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
            var ackBody = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                authenticated.Verified.Binding.CanonicalRequest.Span);
            var completed =
                await recovered.Adapter.AcknowledgeVerifiedAsync(
                    authenticated,
                    ackBody);
            Assert.Equal(MailboxClientAckStatus.Durable, completed.Status);
            Assert.Equal(2, completed.Receipts.Count);
            aggregate = MailboxAggregateAckCodec.EncodeMqr3(
                new MailboxAggregateAckResponse
                {
                    Epoch = ackBody.Epoch,
                    OperationId = ackBody.OperationId.ToArray(),
                    TombstoneQuorums = completed.Receipts
                        .Select(static receipt =>
                            (ReadOnlyMemory<byte>)receipt
                                .DurableQuorumReceipt.ToArray())
                        .ToArray()
                });
            recovered.Runtime.PersistSuccess(
                authenticated,
                aggregate,
                MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
            Assert.Equal(
                aggregate,
                recovered.Runtime.Verify(ackMau2)
                    .RecoveredOutcome?.CanonicalBytes.ToArray());
        }

        using var restarted = new NativeEnvironment(_root);
        await restarted.Adapter.InitializeAsync();
        Assert.Equal(
            aggregate,
            restarted.Runtime.Verify(ackMau2)
                .RecoveredOutcome?.CanonicalBytes.ToArray());
    }

    [Theory]
    [InlineData(StoreReceiptFault.MismatchedCursor)]
    [InlineData(StoreReceiptFault.ForgedSignature)]
    [InlineData(StoreReceiptFault.StaleAcceptedTime)]
    public async Task ForgedMismatchedOrStaleReceiptNeverCountsTowardQuorum(
        StoreReceiptFault fault)
    {
        using var environment = new NativeEnvironment(
            _root,
            storeFanoutFactory: remote =>
                new FaultyStoreFanout(remote, fault));
        await environment.Adapter.InitializeAsync();

        var result = await ExecuteStoreAsync(
            environment,
            Envelope(64),
            replayCounter: 170,
            serial: 0xba);

        Assert.Equal(MailboxClientStoreStatus.QuorumUnavailable, result.Status);
        Assert.True(result.DurableQuorumReceipt.IsEmpty);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task AckLedgerCrashBoundaryRestartsWithoutResurrection(
        int crashAt)
    {
        MailboxAuthenticatedRequestBinding ackBinding;
        byte[] ackMau2;
        using (var setup = new NativeEnvironment(_root))
        {
            await setup.Adapter.InitializeAsync();
            _ = await ExecuteStoreAsync(
                setup,
                Envelope(64),
                replayCounter: 180,
                serial: 0xbb);
            var retrieveBinding =
                MailboxAuthenticatedRequestTranscript.ForRetrieve(
                    7,
                    Range(0x31, 16),
                    new BlindedMailboxId(MailboxId),
                    new BlindedPlacementId(PlacementId),
                    0,
                    1,
                    []);
            var retrieved = await ExecuteRetrieveSuccessAsync(
                setup,
                retrieveBinding,
                replayCounter: 181,
                serial: 0xbc);
            var item = Assert.Single(MailboxClientCodec.DecodeRetrievePage(
                retrieved.CanonicalPage.Span,
                DecodePolicy()).Items);
            ackBinding = MailboxAuthenticatedRequestTranscript.ForAck(
                7,
                Range(0x41, 16),
                new BlindedMailboxId(MailboxId),
                new BlindedPlacementId(PlacementId),
                true,
                [],
                [item.ToAcknowledgement()]);
            ackMau2 = Sign(
                ackBinding,
                MailboxCapabilityDomain.Retrieve,
                182,
                0xbd);
        }

        var crash = new ArmedCrashDurability();
        using (var interrupted = new NativeEnvironment(
                   _root,
                   ledgerDurability: crash))
        {
            await interrupted.Adapter.InitializeAsync();
            var authenticated = interrupted.Runtime.Verify(ackMau2);
            Assert.True(interrupted.Runtime.TryAcquireExecution(authenticated));
            interrupted.Runtime.ReserveOutcomeCapacity(
                authenticated,
                MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
            crash.Arm(crashAt);
            await Assert.ThrowsAsync<SyntheticCrashException>(() =>
                interrupted.Adapter.AcknowledgeVerifiedAsync(
                    authenticated,
                    MailboxAuthenticatedRequestTranscript.DecodeAckBody(
                        ackBinding.CanonicalRequest.Span)));
        }

        using var recovered = new NativeEnvironment(_root);
        await recovered.Adapter.InitializeAsync();
        var retry = recovered.Runtime.Verify(ackMau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            retry.ReplayDisposition);
        Assert.True(recovered.Runtime.TryAcquireExecution(retry));
        recovered.Runtime.ReserveOutcomeCapacity(
            retry,
            MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);
        var ackBody = MailboxAuthenticatedRequestTranscript.DecodeAckBody(
            ackBinding.CanonicalRequest.Span);
        var completed = await recovered.Adapter.AcknowledgeVerifiedAsync(
            retry,
            ackBody);
        Assert.Equal(MailboxClientAckStatus.Durable, completed.Status);
        var aggregate = MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = ackBody.Epoch,
                OperationId = ackBody.OperationId.ToArray(),
                TombstoneQuorums = completed.Receipts
                    .Select(static receipt =>
                        (ReadOnlyMemory<byte>)receipt
                            .DurableQuorumReceipt.ToArray())
                    .ToArray()
            });
        recovered.Runtime.PersistSuccess(
            retry,
            aggregate,
            MailboxWireHttpContract.Acknowledge.MaximumResponseBytes);

        var retrieveAfterBinding =
            MailboxAuthenticatedRequestTranscript.ForRetrieve(
                7,
                Range(0x51, 16),
                new BlindedMailboxId(MailboxId),
                new BlindedPlacementId(PlacementId),
                0,
                1,
                []);
        var after = await ExecuteRetrieveSuccessAsync(
            recovered,
            retrieveAfterBinding,
            replayCounter: 183,
            serial: 0xbe);
        Assert.Empty(MailboxClientCodec.DecodeRetrievePage(
            after.CanonicalPage.Span,
            DecodePolicy()).Items);
    }

    [Fact]
    public void UnexpectedArgumentExceptionBeforeSideEffects_ReleasesEverything()
    {
        using var environment = new NativeEnvironment(_root);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(
            Envelope(64));
        var mau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 190,
            serial: 0xbf);
        var authenticated = environment.Runtime.Verify(mau2);
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Store.MaximumResponseBytes);

        var exception = Assert.Throws<ArgumentException>((Action)(() =>
        {
            try
            {
                throw new ArgumentException("Synthetic pre-side failure.");
            }
            finally
            {
                environment.Runtime.CleanupRequest(authenticated);
            }
        }));
        Assert.Contains("pre-side", exception.Message);
        environment.Runtime.CleanupRequest(authenticated);

        Assert.False(authenticated.SideEffectsStarted);
        Assert.Equal(0, environment.OutcomeDiagnostics.ReservedEntries);
        var released = environment.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            released.ReplayDisposition);
        Assert.True(environment.Runtime.TryAcquireExecution(released));
        environment.Runtime.CleanupRequest(released);
        Assert.Equal(0, environment.OutcomeDiagnostics.ReservedEntries);
    }

    [Fact]
    public async Task UnexpectedPeerExceptionAfterSideEffects_StaysExactlyRecoverable()
    {
        var envelope = Envelope(64);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var mau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 191,
            serial: 0xc0);
        using (var interrupted = new NativeEnvironment(
                   _root,
                   storeFanoutFactory: _ =>
                       new ThrowingPeerReplicationStoreFanout()))
        {
            await interrupted.Adapter.InitializeAsync();
            var authenticated = interrupted.Runtime.Verify(mau2);
            Assert.True(interrupted.Runtime.TryAcquireExecution(authenticated));
            interrupted.Runtime.ReserveOutcomeCapacity(
                authenticated,
                MailboxWireHttpContract.Store.MaximumResponseBytes);

            await Assert.ThrowsAsync<MailboxPeerReplicationException>(
                async () =>
                {
                    try
                    {
                        _ = await interrupted.Adapter.StoreVerifiedAsync(
                            authenticated,
                            envelope);
                    }
                    finally
                    {
                        interrupted.Runtime.CleanupRequest(authenticated);
                    }
                });
            interrupted.Runtime.CleanupRequest(authenticated);

            Assert.True(authenticated.SideEffectsStarted);
            Assert.Equal(0, interrupted.OutcomeDiagnostics.ReservedEntries);
            var exactPending = interrupted.Runtime.Verify(mau2);
            Assert.Equal(
                MailboxAuthenticatedReplayDisposition.InFlight,
                exactPending.ReplayDisposition);
            Assert.True(interrupted.Runtime.TryAcquireExecution(exactPending));
            interrupted.Runtime.CleanupRequest(exactPending);
        }

        using var recovered = new NativeEnvironment(_root);
        await recovered.Adapter.InitializeAsync();
        var retry = recovered.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            retry.ReplayDisposition);
        Assert.True(recovered.Runtime.TryAcquireExecution(retry));
        recovered.Runtime.ReserveOutcomeCapacity(
            retry,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        var result = await recovered.Adapter.StoreVerifiedAsync(
            retry,
            envelope);
        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        var exact = recovered.Runtime.PersistSuccess(
            retry,
            result.DurableQuorumReceipt,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        Assert.Equal(
            exact.CanonicalBytes.ToArray(),
            recovered.Runtime.Verify(mau2)
                .RecoveredOutcome?.CanonicalBytes.ToArray());
        Assert.Equal(0, recovered.OutcomeDiagnostics.ReservedEntries);
    }

    [Fact]
    public void CleanupAbortPersistenceFaultStillReleasesQuotaAndExecution()
    {
        var durability = new FailReplayReplaceDurability();
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(
            Envelope(64));
        var mau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 192,
            serial: 0xc4);
        using var interrupted = new NativeEnvironment(
            _root,
            replayDurability: durability);
        var authenticated = interrupted.Runtime.Verify(mau2);
        Assert.True(interrupted.Runtime.TryAcquireExecution(authenticated));
        interrupted.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        durability.Arm();

        Assert.Throws<IOException>(() =>
            interrupted.Runtime.CleanupRequest(authenticated));
        Assert.Equal(0, interrupted.OutcomeDiagnostics.ReservedEntries);

        var afterFailure = interrupted.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            afterFailure.ReplayDisposition);
        Assert.True(interrupted.Runtime.TryAcquireExecution(afterFailure));
        interrupted.Runtime.CleanupRequest(afterFailure);
        Assert.Equal(0, interrupted.OutcomeDiagnostics.ReservedEntries);
        interrupted.Dispose();

        using var recovered = new NativeEnvironment(_root);
        var afterRestart = recovered.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            afterRestart.ReplayDisposition);
        Assert.True(recovered.Runtime.TryAcquireExecution(afterRestart));
        recovered.Runtime.CleanupRequest(afterRestart);
    }

    [Fact]
    public void DelayedNewCannotExecuteOrAbortAfterExactInFlightCompletes()
    {
        using var environment = new NativeEnvironment(_root);
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(
            Envelope(64));
        var mau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter: 193,
            serial: 0xc5);

        var delayedNew = environment.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.NewReserved,
            delayedNew.ReplayDisposition);
        var exactInFlight = environment.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.InFlight,
            exactInFlight.ReplayDisposition);

        Assert.True(environment.Runtime.TryAcquireExecution(exactInFlight));
        environment.Runtime.ReserveOutcomeCapacity(
            exactInFlight,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        var persisted = environment.Runtime.PersistTerminal(
            exactInFlight,
            MailboxClientTerminalOutcome.DurableStateRejected);
        environment.Runtime.CleanupRequest(exactInFlight);

        Assert.False(environment.Runtime.TryAcquireExecution(delayedNew));
        environment.Runtime.CleanupRequest(delayedNew);

        var completed = environment.Runtime.Verify(mau2);
        Assert.Equal(
            MailboxAuthenticatedReplayDisposition.IdempotentCompleted,
            completed.ReplayDisposition);
        Assert.NotNull(completed.RecoveredOutcome);
        Assert.Equal(
            persisted.CanonicalBytes.ToArray(),
            completed.RecoveredOutcome.CanonicalBytes.ToArray());
        Assert.Equal(
            MailboxClientTerminalOutcome.DurableStateRejected,
            completed.RecoveredOutcome.Terminal);
        Assert.Equal(0, environment.OutcomeDiagnostics.ReservedEntries);
    }

    [Fact]
    public void CoordinatedGcUsesStrictEqualityBoundedBatchAndRestartCapacity()
    {
        var outcomeOptions = new MailboxClientCanonicalOutcomeStoreOptions
        {
            MaximumEntries = 2,
            MaximumBytes = 2L * (
                MailboxClientCanonicalOutcomeStore.HeaderLength
                + MailboxWireHttpContract.Store.MaximumResponseBytes)
        };
        var replayOptions = new DurableMailboxCapabilityReplayJournalOptions
        {
            MaximumScopes = 2
        };
        ulong retainUntil;
        using (var first = new NativeEnvironment(
                   _root,
                   outcomeOptions: outcomeOptions,
                   replayOptions: replayOptions))
        {
            retainUntil = PersistTerminalClaim(
                first,
                replayCounter: 200,
                serial: 0xc1,
                operationStart: 0x61,
                digestStart: 0x71);
            Assert.Equal(
                retainUntil,
                PersistTerminalClaim(
                    first,
                    replayCounter: 201,
                    serial: 0xc2,
                    operationStart: 0x71,
                    digestStart: 0x81));
            Assert.Equal(2, first.ReplayDiagnostics.ScopeCount);
            Assert.Equal(2, first.OutcomeDiagnostics.EntryCount);

            Assert.Equal(0, first.Runtime.CollectExpired(retainUntil, 1));
            Assert.Equal(2, first.ReplayDiagnostics.ScopeCount);
            Assert.Equal(2, first.OutcomeDiagnostics.EntryCount);

            Assert.Equal(
                1,
                first.Runtime.CollectExpired(retainUntil + 1, 1));
            Assert.Equal(1, first.ReplayDiagnostics.ScopeCount);
            Assert.Equal(1, first.OutcomeDiagnostics.EntryCount);
        }

        using var restarted = new NativeEnvironment(
            _root,
            outcomeOptions: outcomeOptions,
            replayOptions: replayOptions);
        Assert.Equal(1, restarted.ReplayDiagnostics.ScopeCount);
        Assert.Equal(1, restarted.OutcomeDiagnostics.EntryCount);
        Assert.Equal(
            1,
            restarted.Runtime.CollectExpired(retainUntil, 1));
        Assert.Equal(0, restarted.ReplayDiagnostics.ScopeCount);
        Assert.Equal(0, restarted.OutcomeDiagnostics.EntryCount);
        Assert.Equal(2, restarted.ReplayDiagnostics.CapacityRemaining);
        Assert.Equal(2, restarted.OutcomeDiagnostics.EntryCapacityRemaining);
        Assert.Equal(
            0,
            restarted.Runtime.CollectExpired(retainUntil + 1, 1));
    }

    [Fact]
    public void CoordinatedGcDurablyMarksReplayBeforeOutcomeDeletion()
    {
        var deletion = new FailDeleteDurability();
        ulong retainUntil;
        using (var interrupted = new NativeEnvironment(
                   _root,
                   outcomeDurability: deletion))
        {
            retainUntil = PersistTerminalClaim(
                interrupted,
                replayCounter: 210,
                serial: 0xc3,
                operationStart: 0x81,
                digestStart: 0x91);
            deletion.Arm();

            Assert.Throws<MailboxClientCanonicalOutcomePersistenceException>(
                () => interrupted.Runtime.CollectExpired(
                    retainUntil + 1,
                    1));
            Assert.Equal(1, interrupted.ReplayDiagnostics.ScopeCount);
            Assert.Equal(0, interrupted.ReplayDiagnostics.CompletedCount);
            Assert.Equal(1, interrupted.OutcomeDiagnostics.EntryCount);
        }

        using var recovered = new NativeEnvironment(_root);
        Assert.Equal(1, recovered.ReplayDiagnostics.ScopeCount);
        Assert.Equal(1, recovered.OutcomeDiagnostics.EntryCount);
        Assert.Equal(
            1,
            recovered.Runtime.CollectExpired(retainUntil + 1, 1));
        Assert.Equal(0, recovered.ReplayDiagnostics.ScopeCount);
        Assert.Equal(0, recovered.OutcomeDiagnostics.EntryCount);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static MailboxEncryptedEnvelope Envelope(
        int ciphertextLength,
        ulong epoch = 7,
        byte operationStart = 0x01,
        byte digestStart = 0x11,
        ulong createdAt = 1_000,
        ulong expiresAt = 1_120) =>
        new()
        {
            Epoch = epoch,
            MailboxId = new BlindedMailboxId(MailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            OperationId = Range(operationStart, 16),
            DeduplicationDigest = Range(digestStart, 32),
            CreatedAtUnixSeconds = createdAt,
            ExpiresAtUnixSeconds = expiresAt,
            Ciphertext = Filled(0x5a, ciphertextLength)
        };

    private static byte[] Sign(
        MailboxAuthenticatedRequestBinding binding,
        MailboxCapabilityDomain domain,
        ulong replayCounter,
        byte serial,
        ulong epoch = 7,
        byte[]? membershipCommitment = null)
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        membershipCommitment ??= epoch == 7
            ? MembershipCommitment
            : NextMembershipCommitment;
        var grant = crypto.SignGrant(
            new MailboxAuthenticatedGrant
            {
                Domain = domain,
                Lifecycle = MailboxCapabilityLifecycle.Active,
                NetworkId = NetworkId,
                Epoch = epoch,
                Generation = 9,
                Serial = Filled(serial, 16),
                NotBeforeUnixSeconds = 900,
                ExpiresAtUnixSeconds = 1_100,
                OverlapUntilUnixSeconds = 0,
                PlacementCommitment = MailboxPlacementCommitment.Compute(
                    new BlindedPlacementId(PlacementId)),
                MembershipCommitment = membershipCommitment,
                IssuerPublicKey = crypto.GetPublicKey(IssuerSeed),
                HolderPublicKey = crypto.GetPublicKey(HolderSeed),
                IssuerSignature = ReadOnlyMemory<byte>.Empty
            },
            IssuerSeed);
        var presentation = crypto.SignPresentation(
            grant,
            binding,
            replayCounter,
            HolderSeed);
        return MailboxAuthenticatedClientRequestCodec.Encode(
            new MailboxAuthenticatedClientRequest
            {
                Binding = binding,
                Presentation = presentation
            });
    }

    private static MailboxClientDecodePolicy DecodePolicy() =>
        new()
        {
            NowUnixSeconds = checked((ulong)Now.ToUnixTimeSeconds()),
            EpochWindow = new()
            {
                CurrentEpoch = 7,
                NextEpoch = 8,
                CurrentNotBeforeUnixSeconds = 900,
                NextNotBeforeUnixSeconds = 950,
                CurrentExpiresAtUnixSeconds = 1_150,
                NextExpiresAtUnixSeconds = 1_250
            },
            CapabilityPolicy = new()
            {
                CurrentBucket = 1_010,
                MinimumGeneration = 7,
                AllowLegacyMirrorOverlap = false,
                AllowRevoked = false,
                AllowRecovery = false
            },
            AllowLegacyMirrorOverlap = false
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length)
            .Select(static value => unchecked((byte)value))
            .ToArray();

    private static byte[] Filled(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            "XNode repository root was not found.");
    }

    private static async Task<MailboxClientStoreResult> ExecuteStoreAsync(
        NativeEnvironment environment,
        MailboxEncryptedEnvelope envelope,
        ulong replayCounter,
        byte serial)
    {
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(envelope);
        var canonicalMau2 = Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter,
            serial,
            envelope.Epoch);
        var authenticated = environment.Runtime.Verify(canonicalMau2);
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        var result = await environment.Adapter.StoreVerifiedAsync(
            authenticated,
            envelope);
        if (result.Status == MailboxClientStoreStatus.Durable)
        {
            environment.Runtime.PersistSuccess(
                authenticated,
                result.DurableQuorumReceipt,
                MailboxWireHttpContract.Store.MaximumResponseBytes);
        }
        else
        {
            environment.Runtime.AbortIfNew(authenticated);
        }

        return result;
    }

    private static ulong PersistTerminalClaim(
        NativeEnvironment environment,
        ulong replayCounter,
        byte serial,
        byte operationStart,
        byte digestStart)
    {
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(
            Envelope(
                64,
                operationStart: operationStart,
                digestStart: digestStart));
        var authenticated = environment.Runtime.Verify(Sign(
            binding,
            MailboxCapabilityDomain.Deposit,
            replayCounter,
            serial));
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Store.MaximumResponseBytes);
        environment.Runtime.PersistTerminal(
            authenticated,
            MailboxClientTerminalOutcome.DurableStateRejected);
        return authenticated.RetainUntilUnixSeconds;
    }

    private static async Task<MailboxClientRetrieveResult>
        ExecuteRetrieveSuccessAsync(
            NativeEnvironment environment,
            MailboxAuthenticatedRequestBinding binding,
            ulong replayCounter,
            byte serial)
    {
        var authenticated = environment.Runtime.Verify(Sign(
            binding,
            MailboxCapabilityDomain.Retrieve,
            replayCounter,
            serial));
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        var result = await environment.Adapter.RetrieveVerifiedAsync(
            authenticated,
            MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                binding.CanonicalRequest.Span));
        Assert.Equal(MailboxClientRetrieveStatus.Success, result.Status);
        environment.Runtime.PersistSuccess(
            authenticated,
            result.CanonicalPage,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        return result;
    }

    private static async Task<MailboxClientRetrieveResult>
        ExecuteRetrieveFailureAsync(
            NativeEnvironment environment,
            MailboxAuthenticatedRequestBinding binding,
            ulong replayCounter,
            byte serial)
    {
        var authenticated = environment.Runtime.Verify(Sign(
            binding,
            MailboxCapabilityDomain.Retrieve,
            replayCounter,
            serial));
        Assert.True(environment.Runtime.TryAcquireExecution(authenticated));
        environment.Runtime.ReserveOutcomeCapacity(
            authenticated,
            MailboxWireHttpContract.Retrieve.MaximumResponseBytes);
        var result = await environment.Adapter.RetrieveVerifiedAsync(
            authenticated,
            MailboxAuthenticatedRequestTranscript.DecodeRetrieveBody(
                binding.CanonicalRequest.Span));
        Assert.NotEqual(MailboxClientRetrieveStatus.Success, result.Status);
        environment.Runtime.PersistTerminal(
            authenticated,
            MailboxClientTerminalOutcome.AuthorizationRejected);
        return result;
    }

    private sealed class NativeEnvironment : IDisposable
    {
        private readonly DurableMailboxCapabilityReplayJournal _journal;
        private readonly MailboxClientCanonicalOutcomeStore _outcomes;
        private readonly MailboxClientOperationLedger _ledger;

        public NativeEnvironment(
            string root,
            Func<MailboxClientReceiptCrypto, IMailboxClientReplicaFanout>?
                storeFanoutFactory = null,
            MailboxClientCanonicalOutcomeStoreOptions? outcomeOptions = null,
            Func<MailboxClientReceiptCrypto, IMailboxClientTombstoneFanout>?
                tombstoneFanoutFactory = null,
            Func<IReadOnlyList<ReadOnlyMemory<byte>>, IMailboxClientReplicaAuthorizer>?
                authorizerFactory = null,
            Action<MailboxClientAdapterOptions>? configureOptions = null,
            FixedClock? clock = null,
            IMailboxDurabilityBarrier? ledgerDurability = null,
            DurableMailboxCapabilityReplayJournalOptions? replayOptions = null,
            IMailboxDurabilityBarrier? outcomeDurability = null,
            IMailboxDurabilityBarrier? replayDurability = null)
        {
            Clock = clock ?? new FixedClock(Now);
            var adapterOptions = new MailboxClientAdapterOptions
            {
                Enabled = true,
                CurrentMembershipCommitment = Convert
                    .ToHexString(MembershipCommitment)
                    .ToLowerInvariant(),
                NextMembershipCommitment = Convert
                    .ToHexString(NextMembershipCommitment)
                    .ToLowerInvariant(),
                CurrentEpoch = 7,
                NextEpoch = 8,
                CurrentNotBeforeUnixSeconds = 900,
                NextNotBeforeUnixSeconds = 950,
                CurrentExpiresAtUnixSeconds = 1_150,
                NextExpiresAtUnixSeconds = 1_250
            };
            configureOptions?.Invoke(adapterOptions);
            AdapterOptions = adapterOptions;
            var mailboxOptions = new ReplicatedMailboxOptions
            {
                Enabled = true
            };
            var localSeed = Convert.ToHexString(Filled(0x11, 32));
            var remoteSeed = Convert.ToHexString(Filled(0x22, 32));
            var publicKeyCrypto = new SodiumMailboxCapabilityCrypto();
            var localCrypto = new MailboxClientReceiptCrypto(
                RouterId.FromBytes(publicKeyCrypto.GetPublicKey(
                    Convert.FromHexString(localSeed))),
                localSeed);
            var remoteCrypto = new MailboxClientReceiptCrypto(
                RouterId.FromBytes(publicKeyCrypto.GetPublicKey(
                    Convert.FromHexString(remoteSeed))),
                remoteSeed);
            var store = new ReplicatedMailboxStore(
                root,
                mailboxOptions,
                Clock);
            _ledger = new MailboxClientOperationLedger(
                root,
                adapterOptions,
                Clock,
                durability: ledgerDurability);
            _journal = new DurableMailboxCapabilityReplayJournal(
                root,
                replayOptions,
                durability: replayDurability,
                clock: Clock);
            _outcomes = new MailboxClientCanonicalOutcomeStore(
                root,
                outcomeOptions,
                durability: outcomeDurability);
            Runtime = new MailboxAuthenticatedCapabilityRuntime(
                new FixedAuthority(),
                new FixedRevocations(),
                _journal,
                _outcomes,
                Clock);
            var replicas = new[]
            {
                (ReadOnlyMemory<byte>)localCrypto.LocalRouterId.ToArray(),
                remoteCrypto.LocalRouterId.ToArray()
            };
            Adapter = new MailboxClientStoreAdapter(
                adapterOptions,
                mailboxOptions,
                store,
                _ledger,
                authorizerFactory?.Invoke(replicas)
                    ?? new FixedAuthorizer(replicas),
                storeFanoutFactory?.Invoke(remoteCrypto)
                    ?? new SigningStoreFanout(remoteCrypto),
                localCrypto,
                Clock,
                tombstoneFanoutFactory?.Invoke(remoteCrypto)
                    ?? new SigningTombstoneFanout(remoteCrypto));
        }

        public MailboxAuthenticatedCapabilityRuntime Runtime { get; }

        public MailboxClientStoreAdapter Adapter { get; }

        public MailboxClientAdapterOptions AdapterOptions { get; }

        public FixedClock Clock { get; }

        public MailboxClientCanonicalOutcomeStoreDiagnostics OutcomeDiagnostics =>
            _outcomes.Diagnostics;

        public MailboxCapabilityReplayJournalDiagnostics ReplayDiagnostics =>
            _journal.Diagnostics;

        public void Dispose()
        {
            Adapter.Dispose();
            _ledger.Dispose();
            _journal.Dispose();
            _outcomes.Dispose();
        }
    }

    private sealed class FixedAuthority : IMailboxCapabilityAuthoritySource
    {
        private static readonly byte[] IssuerPublicKey =
            new SodiumMailboxCapabilityCrypto().GetPublicKey(IssuerSeed);

        public bool IsConfigured => true;

        public bool TryResolve(
            MailboxCapabilityAuthorityQuery query,
            out MailboxAuthenticatedVerificationPolicy? policy)
        {
            if (!query.NetworkId.Span.SequenceEqual(NetworkId)
                || !query.PlacementCommitment.Span.SequenceEqual(
                    MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(PlacementId)))
                || query.Epoch is not (7 or 8)
                || !query.MembershipCommitment.Span.SequenceEqual(
                    query.Epoch == 7
                        ? MembershipCommitment
                        : NextMembershipCommitment)
                || !query.IssuerPublicKey.Span.SequenceEqual(IssuerPublicKey))
            {
                policy = null;
                return false;
            }

            policy = new MailboxAuthenticatedVerificationPolicy
            {
                NetworkId = NetworkId,
                Epoch = query.Epoch,
                PlacementCommitment = query.PlacementCommitment.ToArray(),
                MembershipCommitment = query.MembershipCommitment.ToArray(),
                NowUnixSeconds = 0,
                MinimumGeneration = 9,
                TrustedIssuers =
                [
                    new MailboxCapabilityIssuerAuthority
                    {
                        PublicKey = IssuerPublicKey,
                        Domain = query.Domain,
                        AllowedLifecycle = MailboxCapabilityLifecycle.Active,
                        MinimumGeneration = 9,
                        MaximumGeneration = 9,
                        ValidFromUnixSeconds = 800,
                        ValidUntilUnixSeconds = 1_200
                    }
                ]
            };
            return true;
        }
    }

    private sealed class FixedRevocations : IMailboxCapabilityRevocationPolicy
    {
        public bool IsConfigured => true;

        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class FixedAuthorizer(
        IReadOnlyList<ReadOnlyMemory<byte>> replicas)
        : IMailboxClientReplicaAuthorizer
    {
        public bool IsConfigured => true;

        public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
            ulong epoch,
            ReadOnlyMemory<byte> membershipCommitment,
            ReadOnlyMemory<byte> placementCommitment,
            ReadOnlyMemory<byte> blindedPlacementId,
            ReadOnlyMemory<byte> selectionInputCommitment,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(replicas);
    }

    private sealed class RecordingAuthorizer(
        IReadOnlyList<ReadOnlyMemory<byte>> replicas)
        : IMailboxClientReplicaAuthorizer
    {
        public bool IsConfigured => true;

        public List<byte[]> SeenMemberships { get; } = [];

        public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
            ulong epoch,
            ReadOnlyMemory<byte> membershipCommitment,
            ReadOnlyMemory<byte> placementCommitment,
            ReadOnlyMemory<byte> blindedPlacementId,
            ReadOnlyMemory<byte> selectionInputCommitment,
            CancellationToken cancellationToken)
        {
            SeenMemberships.Add(membershipCommitment.ToArray());
            return ValueTask.FromResult(replicas);
        }
    }

    private sealed class SigningStoreFanout(
        MailboxClientReceiptCrypto crypto,
        bool mutateCursor = false)
        : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken)
        {
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = context.Disposition,
                ReplicaId = crypto.LocalRouterId,
                OperationId = context.OperationId,
                Epoch = context.Epoch,
                Cursor = mutateCursor ? context.Cursor + 1 : context.Cursor,
                AcceptedAtUnixSeconds = context.AcceptedAtUnixSeconds,
                DurableAtUnixSeconds = context.AcceptedAtUnixSeconds,
                ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds,
                BlindedMailboxId = context.BlindedMailboxId,
                PlacementCommitment = context.PlacementCommitment,
                MembershipCommitment = context.MembershipCommitment,
                EnvelopeDigest = context.EnvelopeDigest,
                Signature = new byte[64]
            };
            var signed = unsigned with
            {
                Signature = crypto.SignLocal(
                    MailboxReceiptV2Codec.GetReplicaSigningBytes(unsigned))
            };
            return Task.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>(
                [MailboxReceiptV2Codec.EncodeReplica(signed)]);
        }
    }

    private sealed class FaultyStoreFanout(
        MailboxClientReceiptCrypto crypto,
        StoreReceiptFault fault)
        : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public async Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken)
        {
            if (fault == StoreReceiptFault.MismatchedCursor)
            {
                return await new SigningStoreFanout(
                    crypto,
                    mutateCursor: true).StoreAsync(
                    context,
                    cancellationToken);
            }

            var acceptedAt = fault == StoreReceiptFault.StaleAcceptedTime
                ? context.AcceptedAtUnixSeconds - 1
                : context.AcceptedAtUnixSeconds;
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = context.Disposition,
                ReplicaId = crypto.LocalRouterId,
                OperationId = context.OperationId,
                Epoch = context.Epoch,
                Cursor = context.Cursor,
                AcceptedAtUnixSeconds = acceptedAt,
                DurableAtUnixSeconds = acceptedAt,
                ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds,
                BlindedMailboxId = context.BlindedMailboxId,
                PlacementCommitment = context.PlacementCommitment,
                MembershipCommitment = context.MembershipCommitment,
                EnvelopeDigest = context.EnvelopeDigest,
                Signature = new byte[64]
            };
            var signed = unsigned with
            {
                Signature = crypto.SignLocal(
                    MailboxReceiptV2Codec.GetReplicaSigningBytes(unsigned))
            };
            var encoded = MailboxReceiptV2Codec.EncodeReplica(signed);
            if (fault == StoreReceiptFault.ForgedSignature)
            {
                encoded[^1] ^= 0xff;
            }

            return [encoded];
        }
    }

    private sealed class SigningTombstoneFanout(
        MailboxClientReceiptCrypto crypto)
        : IMailboxClientTombstoneFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
            MailboxReplicaTombstoneContext context,
            CancellationToken cancellationToken)
        {
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = MailboxReplicaDisposition.Tombstone,
                ReplicaId = crypto.LocalRouterId,
                OperationId = context.OperationId,
                Epoch = context.Epoch,
                Cursor = context.Cursor,
                AcceptedAtUnixSeconds = context.AcceptedAtUnixSeconds,
                DurableAtUnixSeconds = context.AcceptedAtUnixSeconds,
                ExpiresAtUnixSeconds = context.ExpiresAtUnixSeconds,
                BlindedMailboxId = context.BlindedMailboxId,
                PlacementCommitment = context.PlacementCommitment,
                MembershipCommitment = context.MembershipCommitment,
                EnvelopeDigest = context.EnvelopeDigest,
                Signature = new byte[64]
            };
            var signed = unsigned with
            {
                Signature = crypto.SignLocal(
                    MailboxReceiptV2Codec.GetReplicaSigningBytes(unsigned))
            };
            return Task.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>(
                [MailboxReceiptV2Codec.EncodeReplica(signed)]);
        }
    }

    private sealed class PartialFailureTombstoneFanout(
        MailboxClientReceiptCrypto crypto,
        int failOnCall)
        : IMailboxClientTombstoneFanout
    {
        private int _calls;

        public bool IsConfigured => true;

        public int CallCount => Volatile.Read(ref _calls);

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
            MailboxReplicaTombstoneContext context,
            CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls);
            if (call == failOnCall)
            {
                throw new IOException("Synthetic partial ACK fanout failure.");
            }

            return new SigningTombstoneFanout(crypto).TombstoneAsync(
                context,
                cancellationToken);
        }
    }

    private sealed class ToggleStoreFanout(
        MailboxClientReceiptCrypto crypto,
        TimeSpan? delay = null)
        : IMailboxClientReplicaFanout
    {
        private int _calls;

        public bool IsConfigured => true;

        public bool Throw { get; set; }

        public int CallCount => Volatile.Read(ref _calls);

        public async Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            if (Throw)
            {
                throw new InvalidOperationException(
                    "Cached store retry unexpectedly reached fanout.");
            }

            if (delay is not null)
            {
                await Task.Delay(delay.Value, cancellationToken);
            }

            return await new SigningStoreFanout(crypto).StoreAsync(
                context,
                cancellationToken);
        }
    }

    private sealed class ThrowingStoreFanout : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException(
                "A completed ledger retry must not invoke replica fanout.");
    }

    private sealed class ThrowingPeerReplicationStoreFanout
        : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken) =>
            throw new MailboxPeerReplicationException(
                MailboxPeerReplicationError.InvalidPayload,
                "Synthetic unexpected peer replication failure.");
    }

    private sealed class RecordingObserver : IMailboxClientRequestObserver
    {
        public List<(
            MailboxClientOperation Operation,
            MailboxClientObservedAccess Access)> Accesses { get; } = [];

        public void OnAccess(
            MailboxClientOperation operation,
            MailboxClientObservedAccess access) =>
            Accesses.Add((operation, access));
    }

    private sealed class ArmedCrashDurability : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier _inner = new();
        private int _armed;
        private int _crashAt;
        private int _flushes;

        public void Arm(int crashAt)
        {
            _crashAt = crashAt;
            Volatile.Write(ref _flushes, 0);
            Volatile.Write(ref _armed, 1);
        }

        public void FlushFileAndParentDirectory(string path)
        {
            if (Volatile.Read(ref _armed) != 0
                && Interlocked.Increment(ref _flushes) == _crashAt)
            {
                throw new SyntheticCrashException();
            }

            _inner.FlushFileAndParentDirectory(path);
        }

        public void FlushParentDirectory(string deletedPath) =>
            _inner.FlushParentDirectory(deletedPath);

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            _inner.ReplaceFile(temporaryPath, finalPath);

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }

    private sealed class FailDeleteDurability : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier _inner = new();
        private int _armed;

        public void Arm() => Volatile.Write(ref _armed, 1);

        public void FlushFileAndParentDirectory(string path) =>
            _inner.FlushFileAndParentDirectory(path);

        public void FlushParentDirectory(string deletedPath) =>
            _inner.FlushParentDirectory(deletedPath);

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            _inner.ReplaceFile(temporaryPath, finalPath);

        public void DeleteFile(string path)
        {
            if (Volatile.Read(ref _armed) != 0)
            {
                throw new IOException(
                    "Synthetic outcome deletion failure.");
            }

            _inner.DeleteFile(path);
        }
    }

    private sealed class FailReplayReplaceDurability
        : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier _inner = new();
        private int _armed;

        public void Arm() => Volatile.Write(ref _armed, 1);

        public void FlushFileAndParentDirectory(string path) =>
            _inner.FlushFileAndParentDirectory(path);

        public void FlushParentDirectory(string deletedPath) =>
            _inner.FlushParentDirectory(deletedPath);

        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            if (Volatile.Read(ref _armed) != 0)
            {
                throw new IOException(
                    "Synthetic replay abort persistence failure.");
            }

            _inner.ReplaceFile(temporaryPath, finalPath);
        }

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }

    private sealed class SyntheticCrashException : Exception;
}
