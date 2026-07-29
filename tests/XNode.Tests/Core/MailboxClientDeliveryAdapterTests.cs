using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class MailboxClientDeliveryAdapterTests : IDisposable
{
    private static readonly byte[] MailboxId = Range(0x30, 32);
    private static readonly byte[] OtherMailboxId = Range(0x60, 32);
    private static readonly byte[] PlacementId = Range(0x90, 32);
    private static readonly byte[] Membership = Range(0xc0, 32);
    private static readonly byte[] NextMembership = Range(0xe0, 32);
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-mailbox-delivery-{Guid.NewGuid():N}");
    private readonly FixedClock _clock =
        new(DateTimeOffset.FromUnixTimeSeconds(1010));
    private readonly List<IDisposable> _resources = [];

    [Fact]
    public async Task Retrieve_UsesStableCursorSnapshotAndCannotEnumerateAnotherMailbox()
    {
        var fixture = CreateFixture();
        var adapter = fixture.Adapter;
        await StoreAsync(adapter, Envelope(1, MailboxId));
        await StoreAsync(adapter, Envelope(2, OtherMailboxId));
        await StoreAsync(adapter, Envelope(3, MailboxId));
        await StoreAsync(adapter, Envelope(4, MailboxId));

        var firstRequest = RetrieveRequest(
            operation: 40,
            mailboxId: MailboxId,
            maximumItems: 2);
        var first = await adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(firstRequest));
        Assert.Equal(MailboxClientRetrieveStatus.Success, first.Status);
        var firstPage = MailboxClientCodec.DecodeRetrievePage(first.CanonicalPage.Span, Policy());
        Assert.Equal(new ulong[] { 1, 2 }, firstPage.Items.Select(static item => item.Cursor));
        Assert.All(firstPage.Items, item =>
            Assert.Equal(MailboxId, item.Envelope.MailboxId.Bytes.ToArray()));
        Assert.True(firstPage.HasMore);

        // This store is newer than the first page snapshot and cannot make that pagination endless.
        await StoreAsync(adapter, Envelope(5, MailboxId));
        var secondRequest = RetrieveRequest(
            operation: 41,
            mailboxId: MailboxId,
            maximumItems: 1,
            afterCursor: firstPage.NextCursor,
            token: firstPage.ContinuationToken);
        var second = await adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(secondRequest));
        var secondPage = MailboxClientCodec.DecodeRetrievePage(second.CanonicalPage.Span, Policy());

        Assert.Equal(new ulong[] { 3 }, secondPage.Items.Select(static item => item.Cursor));
        Assert.False(secondPage.HasMore);

        var fresh = await adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(42, MailboxId, 100)));
        var freshPage = MailboxClientCodec.DecodeRetrievePage(fresh.CanonicalPage.Span, Policy());
        Assert.Equal(new ulong[] { 1, 2, 3, 4 }, freshPage.Items.Select(static item => item.Cursor));
    }

    [Fact]
    public async Task Ack_AtomicallyHidesAllTargetsBeforeQuorum_ThenRetriesDurably()
    {
        var tombstones = new ToggleTombstoneFanout();
        var fixture = CreateFixture(tombstones);
        tombstones.Crypto = fixture.RemoteCrypto;
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);
        var ack = AckRequest(
            50,
            MailboxId,
            page.Items.Select(static item => item.ToAcknowledgement()).ToArray());
        var encodedAck = MailboxClientCodec.EncodeAck(ack);

        tombstones.Fail = true;
        var unavailable = await fixture.Adapter.AcknowledgeAsync(encodedAck);
        Assert.Equal(MailboxClientAckStatus.QuorumUnavailable, unavailable.Status);
        var hidden = await RetrievePageAsync(fixture.Adapter, MailboxId);
        Assert.Empty(hidden.Items);

        tombstones.Fail = false;
        var durable = await fixture.Adapter.AcknowledgeAsync(encodedAck);
        Assert.Equal(MailboxClientAckStatus.Durable, durable.Status);
        Assert.Equal(2, durable.Receipts.Count);
        var sequences = durable.Receipts.Select(receipt =>
        {
            var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(
                receipt.DurableQuorumReceipt.Span);
            Assert.Equal(MailboxReplicaDisposition.Tombstone, quorum.FirstReplica.Disposition);
            Assert.Equal(receipt.Cursor, quorum.FirstReplica.Cursor);
            return quorum.CoordinatorSequence;
        }).ToArray();
        Assert.Equal(2, sequences.Distinct().Count());
        foreach (var item in page.Items)
        {
            var canonical = MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope);
            Assert.Null(await fixture.Store.ReadExactAsync(
                Convert.ToHexString(MailboxId).ToLowerInvariant(),
                Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()));
        }

        var fanoutCalls = tombstones.CallCount;
        var retry = await fixture.Adapter.AcknowledgeAsync(encodedAck);
        Assert.Equal(MailboxClientAckStatus.Durable, retry.Status);
        Assert.Equal(fanoutCalls, tombstones.CallCount);
        Assert.Equal(
            durable.Receipts.Select(static receipt => receipt.DurableQuorumReceipt.ToArray()),
            retry.Receipts.Select(static receipt => receipt.DurableQuorumReceipt.ToArray()),
            ByteArrayComparer.Instance);

        fixture.Adapter.Dispose();
        fixture.Ledger.Dispose();
        var restartedLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        tombstones.Fail = true;
        var restarted = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            restartedLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new StoreSigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock,
            tombstones));
        await restarted.InitializeAsync();
        var callsBeforeRestartRetry = tombstones.CallCount;
        var cachedAfterRestart = await restarted.AcknowledgeAsync(encodedAck);
        Assert.True(
            cachedAfterRestart.Status == MailboxClientAckStatus.Durable,
            $"{cachedAfterRestart.Status}:{cachedAfterRestart.Error}");
        Assert.Equal(callsBeforeRestartRetry, tombstones.CallCount);
        foreach (var item in page.Items)
        {
            var canonical = MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope);
            Assert.Null(await fixture.Store.ReadExactAsync(
                Convert.ToHexString(MailboxId).ToLowerInvariant(),
                Convert.ToHexString(SHA256.HashData(canonical)).ToLowerInvariant()));
        }

        tombstones.Fail = false;
        var duplicateRequest = MailboxClientCodec.EncodeAck(AckRequest(
            51,
            MailboxId,
            page.Items.Select(static item => item.ToAcknowledgement()).ToArray()));
        var callsBeforeDuplicate = tombstones.CallCount;
        var duplicateOperation = await restarted.AcknowledgeAsync(duplicateRequest);
        Assert.Equal(MailboxClientAckStatus.Rejected, duplicateOperation.Status);
        Assert.Equal("ack-target-mismatch", duplicateOperation.Error);
        Assert.Equal(callsBeforeDuplicate, tombstones.CallCount);
        Assert.Null(await restartedLedger.TryReadAckReservationAsync(
            7,
            MailboxId,
            Filled(51, 16),
            SHA256.HashData(duplicateRequest),
            CancellationToken.None));
    }

    [Fact]
    public async Task Ack_DeleteFlushFailurePreservesDurabilityAndInitializeRetriesCleanup()
    {
        var durability = new FailFirstDeleteFlush();
        var fixture = CreateFixture(durability: durability);
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        var foreignEnvelope = Envelope(2, OtherMailboxId);
        await StoreAsync(fixture.Adapter, foreignEnvelope);
        var foreignCanonical = MailboxClientCodec.EncodeEncryptedEnvelope(foreignEnvelope);
        var foreignMailbox = Convert.ToHexString(OtherMailboxId).ToLowerInvariant();
        var foreignBlob = Convert.ToHexString(
            SHA256.HashData(foreignCanonical)).ToLowerInvariant();
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);

        var durable = await fixture.Adapter.AcknowledgeAsync(
            MailboxClientCodec.EncodeAck(AckRequest(
                52,
                MailboxId,
                [page.Items[0].ToAcknowledgement()])));

        Assert.Equal(MailboxClientAckStatus.Durable, durable.Status);
        Assert.Single(await fixture.Ledger.ReadTombstoneCleanupBatchAsync(
            10,
            CancellationToken.None));
        Assert.Equal(1, durability.DeleteFlushAttempts);
        Assert.NotNull(await fixture.Store.ReadExactAsync(foreignMailbox, foreignBlob));

        await fixture.Adapter.InitializeAsync();

        Assert.Empty(await fixture.Ledger.ReadTombstoneCleanupBatchAsync(
            10,
            CancellationToken.None));
        Assert.Equal(2, durability.DeleteFlushAttempts);
        Assert.NotNull(await fixture.Store.ReadExactAsync(foreignMailbox, foreignBlob));
    }

    [Fact]
    public async Task Ack_WrongMixedTargetIsAtomic_PartialAndExactDuplicateAreIdempotent()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(3, MailboxId));
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);
        var wrong = new[]
        {
            page.Items[0].ToAcknowledgement(),
            page.Items[1].ToAcknowledgement() with { EnvelopeDigest = Range(0x11, 32) }
        };
        var rejected = await fixture.Adapter.AcknowledgeAsync(
            MailboxClientCodec.EncodeAck(AckRequest(60, MailboxId, wrong)));
        Assert.Equal(MailboxClientAckStatus.Rejected, rejected.Status);
        Assert.Equal(3, (await RetrievePageAsync(fixture.Adapter, MailboxId)).Items.Count);

        var partialRequest = MailboxClientCodec.EncodeAck(
            AckRequest(61, MailboxId, [page.Items[1].ToAcknowledgement()]));
        var partial = await fixture.Adapter.AcknowledgeAsync(partialRequest);
        Assert.Equal(MailboxClientAckStatus.Durable, partial.Status);
        var remaining = await RetrievePageAsync(fixture.Adapter, MailboxId);
        Assert.Equal(new ulong[] { 1, 3 }, remaining.Items.Select(static item => item.Cursor));

        var duplicate = await fixture.Adapter.AcknowledgeAsync(partialRequest);
        Assert.Equal(
            partial.Receipts[0].DurableQuorumReceipt.ToArray(),
            duplicate.Receipts[0].DurableQuorumReceipt.ToArray());
    }

    [Fact]
    public async Task CapabilityAndContinuation_AreBoundToExactRequestAndMailbox()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        var first = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(70, MailboxId, 1)));
        var page = MailboxClientCodec.DecodeRetrievePage(first.CanonicalPage.Span, Policy());
        Assert.True(page.HasMore);

        var crossMailbox = RetrieveRequest(
            71,
            OtherMailboxId,
            1,
            page.NextCursor,
            page.ContinuationToken);
        var rejected = await fixture.Adapter.RetrieveAsync(
            MailboxClientCodec.EncodeRetrieve(crossMailbox));
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, rejected.Status);

        var tampered = MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(72, MailboxId, 1, page.NextCursor, page.ContinuationToken));
        tampered[^1] ^= 1;
        var tamperedResult = await fixture.Adapter.RetrieveAsync(tampered);
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, tamperedResult.Status);
    }

    [Fact]
    public async Task ContinuationToken_IsVerifiableByAnotherAuthorizedReplica()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        var first = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(73, MailboxId, 1)));
        var page = MailboxClientCodec.DecodeRetrievePage(first.CanonicalPage.Span, Policy());
        fixture.Adapter.Dispose();
        fixture.Ledger.Dispose();

        var ledger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        var failover = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            ledger,
            fixture.Verifier,
            fixture.Authorizer,
            new StoreSigningFanout(fixture.LocalCrypto),
            fixture.RemoteCrypto,
            _clock,
            new ToggleTombstoneFanout { Crypto = fixture.LocalCrypto }));
        var continued = await failover.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(
                74,
                MailboxId,
                1,
                page.NextCursor,
                page.ContinuationToken)));
        var continuedPage = MailboxClientCodec.DecodeRetrievePage(
            continued.CanonicalPage.Span,
            Policy());
        Assert.Single(continuedPage.Items);
        Assert.Equal(2UL, continuedPage.Items[0].Cursor);
    }

    [Fact]
    public async Task ContinuationToken_ExpiresBeforeMailboxAndCapabilityAuthority()
    {
        var fixture = CreateFixture(configure: options =>
            options.ContinuationTokenLifetime = TimeSpan.FromMinutes(1));
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        var first = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(75, MailboxId, 1)));
        var page = MailboxClientCodec.DecodeRetrievePage(first.CanonicalPage.Span, Policy());

        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1071);
        var expired = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(
                76,
                MailboxId,
                1,
                page.NextCursor,
                page.ContinuationToken,
                capabilityExpires: 1090)));

        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, expired.Status);
        Assert.Equal("continuation-token-rejected", expired.Error);
    }

    [Fact]
    public async Task Retrieve_MaximumEnvelopesStaysBelowOneMiBAndContinues()
    {
        var fixture = CreateFixture();
        for (var index = 1; index <= 15; index++)
        {
            await StoreAsync(fixture.Adapter, Envelope(
                index,
                MailboxId,
                MailboxClientLimits.MaximumCiphertextLength));
        }

        var result = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(75, MailboxId, 100)));
        Assert.Equal(MailboxClientRetrieveStatus.Success, result.Status);
        Assert.True(result.CanonicalPage.Length <= MailboxClientLimits.MaximumPageBytes);
        var page = MailboxClientCodec.DecodeRetrievePage(result.CanonicalPage.Span, Policy());
        Assert.NotEmpty(page.Items);
        Assert.True(page.HasMore);
        Assert.True(page.Items.Count < 15);
        Assert.Equal(page.Items[^1].Cursor, page.NextCursor);
    }

    [Fact]
    public async Task ExpiredAndCorruptTombstoneState_FailClosed()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1081);
        var expired = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(76, MailboxId, 100, capabilityExpires: 1090)));
        Assert.Empty(MailboxClientCodec.DecodeRetrievePage(
            expired.CanonicalPage.Span,
            Policy(1081)).Items);

        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1010);
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        fixture.Adapter.Dispose();
        fixture.Ledger.Dispose();
        var path = Path.Combine(
            _root,
            fixture.AdapterOptions.DirectoryName,
            "operations.json");
        var json = await File.ReadAllTextAsync(path);
        json = json.Replace(
            "\"tombstoned\":false",
            "\"tombstoned\":true",
            StringComparison.Ordinal);
        await File.WriteAllTextAsync(path, json);
        var corrupt = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        await Assert.ThrowsAsync<InvalidDataException>(() => corrupt.InitializeAsync());
    }

    [Fact]
    public async Task SameRetrieveCapabilityUnderFreshOuterOperation_IsReplayRejected()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        var first = RetrieveRequest(77, MailboxId, 1);
        Assert.Equal(
            MailboxClientRetrieveStatus.Success,
            (await fixture.Adapter.RetrieveAsync(
                MailboxClientCodec.EncodeRetrieve(first))).Status);
        var substituted = first with { OperationId = Filled(78, 16) };
        var replay = await fixture.Adapter.RetrieveAsync(
            MailboxClientCodec.EncodeRetrieve(substituted));
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, replay.Status);
        Assert.Equal("capability-binding-rejected", replay.Error);
    }

    [Fact]
    public async Task NonFinalAckToken_BindsExactRetrievedPageDigest()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        var retrieved = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(79, MailboxId, 1)));
        var page = MailboxClientCodec.DecodeRetrievePage(retrieved.CanonicalPage.Span, Policy());
        var acknowledgement = page.Items[0].ToAcknowledgement();
        var valid = AckRequest(81, MailboxId, [acknowledgement]) with
        {
            IsFinalPage = false,
            ContinuationToken = page.ContinuationToken
        };
        Assert.Equal(
            MailboxClientAckStatus.Durable,
            (await fixture.Adapter.AcknowledgeAsync(
                MailboxClientCodec.EncodeAck(valid))).Status);

        var wrong = AckRequest(82, MailboxId,
            [acknowledgement with { EnvelopeDigest = Range(0x11, 32) }]) with
        {
            IsFinalPage = false,
            ContinuationToken = page.ContinuationToken
        };
        var rejected = await fixture.Adapter.AcknowledgeAsync(
            MailboxClientCodec.EncodeAck(wrong));
        Assert.Equal(MailboxClientAckStatus.Unauthorized, rejected.Status);
        Assert.Equal("continuation-token-rejected", rejected.Error);
    }

    [Fact]
    public async Task AckCapacity_IsChargedPerItemBeforeAnyTombstoneMutation()
    {
        var fixture = CreateFixture(configure: options =>
        {
            options.MaxOperationEntries = 4;
            options.MaxCursorAuthorities = 4;
            options.MaxConcurrentSingleFlights = 4;
        });
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId));
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);
        var ack = AckRequest(
            83,
            MailboxId,
            page.Items.Select(static item => item.ToAcknowledgement()).ToArray());
        var result = await fixture.Adapter.AcknowledgeAsync(
            MailboxClientCodec.EncodeAck(ack));
        Assert.Equal(MailboxClientAckStatus.Rejected, result.Status);
        Assert.Equal("operation-ledger-capacity", result.Error);
        Assert.Equal(2, (await RetrievePageAsync(fixture.Adapter, MailboxId)).Items.Count);
    }

    [Fact]
    public async Task RetrieveAndAck_UseExactEAndEPlusOneMembershipCommitments()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(fixture.Adapter, Envelope(2, MailboxId, epoch: 8));
        var retrieved = await fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(84, MailboxId, 10, epoch: 8)));
        var page = MailboxClientCodec.DecodeRetrievePage(retrieved.CanonicalPage.Span, Policy());
        var item = Assert.Single(page.Items);
        Assert.Equal(8UL, item.Envelope.Epoch);
        Assert.Equal(1UL, item.Cursor);

        var acknowledged = await fixture.Adapter.AcknowledgeAsync(
            MailboxClientCodec.EncodeAck(AckRequest(
                85,
                MailboxId,
                [item.ToAcknowledgement()],
                epoch: 8)));
        Assert.Equal(MailboxClientAckStatus.Durable, acknowledged.Status);
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(
            acknowledged.Receipts[0].DurableQuorumReceipt.Span);
        Assert.Equal(NextMembership, quorum.FirstReplica.MembershipCommitment.ToArray());
    }

    [Fact]
    public async Task ConcurrentStoreRetrieveAck_RemainsCanonicalAndConverges()
    {
        var fixture = CreateFixture();
        for (var index = 1; index <= 10; index++)
        {
            await StoreAsync(fixture.Adapter, Envelope(index, MailboxId));
        }

        var before = await RetrievePageAsync(fixture.Adapter, MailboxId);
        var ack = fixture.Adapter.AcknowledgeAsync(MailboxClientCodec.EncodeAck(
            AckRequest(
                86,
                MailboxId,
                before.Items.Take(5)
                    .Select(static item => item.ToAcknowledgement())
                    .ToArray())));
        var store = StoreAsync(fixture.Adapter, Envelope(11, MailboxId));
        var concurrentRetrieve = fixture.Adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(87, MailboxId, 100)));
        await Task.WhenAll(ack, store, concurrentRetrieve);
        var ackResult = await ack;
        var concurrentRetrieveResult = await concurrentRetrieve;
        Assert.Equal(MailboxClientAckStatus.Durable, ackResult.Status);
        var concurrentPage = MailboxClientCodec.DecodeRetrievePage(
            concurrentRetrieveResult.CanonicalPage.Span,
            Policy());
        Assert.True(concurrentPage.Items
            .Select(static item => item.Cursor)
            .SequenceEqual(concurrentPage.Items
                .Select(static item => item.Cursor)
                .Order()));

        var converged = await RetrievePageAsync(fixture.Adapter, MailboxId);
        Assert.Equal(
            Enumerable.Range(6, 6).Select(static value => (ulong)value),
            converged.Items.Select(static item => item.Cursor));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task AckCrashBoundaries_ResumeFromDurableJournalWithoutResurrection(int crashAt)
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);
        var encodedAck = MailboxClientCodec.EncodeAck(AckRequest(
            88,
            MailboxId,
            [page.Items[0].ToAcknowledgement()]));
        fixture.Adapter.Dispose();
        fixture.Ledger.Dispose();

        var crashLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock,
            durability: new ThrowOnFlush(crashAt)));
        var crashing = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            crashLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new StoreSigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock,
            fixture.Tombstones));
        await Assert.ThrowsAsync<SimulatedCrashException>(() =>
            crashing.AcknowledgeAsync(encodedAck));
        var fanoutCallsAtCrash = fixture.Tombstones.CallCount;
        crashing.Dispose();
        crashLedger.Dispose();

        var recoveredLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        var recovered = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            recoveredLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new StoreSigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock,
            fixture.Tombstones));
        await recovered.InitializeAsync();
        Assert.Empty((await RetrievePageAsync(recovered, MailboxId)).Items);
        var result = await recovered.AcknowledgeAsync(encodedAck);
        Assert.Equal(MailboxClientAckStatus.Durable, result.Status);
        Assert.Equal(
            crashAt == 2 ? fanoutCallsAtCrash : fanoutCallsAtCrash + 1,
            fixture.Tombstones.CallCount);
    }

    [Fact]
    public async Task ExpiredAckCompaction_ReleasesChargedCapacityWithoutCursorReuse()
    {
        var fixture = CreateFixture(configure: options =>
        {
            options.MaxOperationEntries = 3;
            options.MaxCursorAuthorities = 3;
            options.MaxConcurrentSingleFlights = 3;
        });
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);
        Assert.Equal(
            MailboxClientAckStatus.Durable,
            (await fixture.Adapter.AcknowledgeAsync(MailboxClientCodec.EncodeAck(
                AckRequest(89, MailboxId, [page.Items[0].ToAcknowledgement()])))).Status);

        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1081);
        await fixture.Adapter.InitializeAsync();
        var later = Envelope(2, MailboxId) with
        {
            CreatedAtUnixSeconds = 1081,
            ExpiresAtUnixSeconds = 1161
        };
        var stored = await StoreAsync(fixture.Adapter, later);
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(
            stored.DurableQuorumReceipt.Span);
        Assert.Equal(2UL, quorum.FirstReplica.Cursor);
    }

    [Fact]
    public async Task StaggeredAckExpiry_RestartAndRetrieveCompactWithoutDanglingTargets()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        await StoreAsync(
            fixture.Adapter,
            Envelope(2, MailboxId) with { ExpiresAtUnixSeconds = 1095 });
        var page = await RetrievePageAsync(fixture.Adapter, MailboxId);
        var encodedAck = MailboxClientCodec.EncodeAck(AckRequest(
            90,
            MailboxId,
            page.Items.Select(static item => item.ToAcknowledgement()).ToArray()));
        Assert.Equal(
            MailboxClientAckStatus.Durable,
            (await fixture.Adapter.AcknowledgeAsync(encodedAck)).Status);

        fixture.Adapter.Dispose();
        fixture.Ledger.Dispose();
        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1081);
        var restartedLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        var restarted = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            restartedLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new StoreSigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock,
            fixture.Tombstones));

        await restarted.InitializeAsync();
        Assert.NotNull(await restartedLedger.TryReadAckReservationAsync(
            7,
            MailboxId,
            Filled(90, 16),
            SHA256.HashData(encodedAck),
            CancellationToken.None));
        Assert.Equal(
            MailboxClientAckStatus.Durable,
            (await restarted.AcknowledgeAsync(encodedAck)).Status);
        var afterRestart = await restarted.RetrieveAsync(
            MailboxClientCodec.EncodeRetrieve(RetrieveRequest(
                91,
                MailboxId,
                100,
                capabilityExpires: 1090)));
        Assert.Equal(MailboxClientRetrieveStatus.Success, afterRestart.Status);
        Assert.Empty(MailboxClientCodec.DecodeRetrievePage(
            afterRestart.CanonicalPage.Span,
            Policy(1081)).Items);

        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1096);
        await restarted.InitializeAsync();
        Assert.Null(await restartedLedger.TryReadAckReservationAsync(
            7,
            MailboxId,
            Filled(90, 16),
            SHA256.HashData(encodedAck),
            CancellationToken.None));
    }

    [Fact]
    public async Task VerifierAttestationWithWrongCanonicalDigest_IsRejected()
    {
        var fixture = CreateFixture();
        await StoreAsync(fixture.Adapter, Envelope(1, MailboxId));
        fixture.Adapter.Dispose();
        var wrong = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            new WrongDigestVerifier(fixture.Verifier),
            fixture.Authorizer,
            new StoreSigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock,
            fixture.Tombstones));
        var result = await wrong.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(90, MailboxId, 10)));
        Assert.Equal(MailboxClientRetrieveStatus.Unauthorized, result.Status);
        Assert.Equal("capability-binding-rejected", result.Error);
    }

    [Fact]
    public async Task VerifierWithoutDurableAtomicReplay_KeepsEveryOperationNotReady()
    {
        var fixture = CreateFixture();
        fixture.Adapter.Dispose();
        var unsafeAdapter = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            new ReplayUnsafeVerifier(fixture.Verifier),
            fixture.Authorizer,
            new StoreSigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock,
            fixture.Tombstones));

        Assert.Equal("capability-verifier-replay-unsafe", unsafeAdapter.Status.Reason);
        Assert.False(
            unsafeAdapter.Status.CapabilityVerifierProvidesDurableAtomicReplay);
        Assert.False(unsafeAdapter.Status.StoreReady);
        Assert.False(unsafeAdapter.Status.RetrieveReady);
        Assert.False(unsafeAdapter.Status.AcknowledgeReady);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await unsafeAdapter.StoreAsync(new byte[] { 1, 2, 3, 4 })).Status);
        Assert.Equal(
            MailboxClientRetrieveStatus.NotReady,
            (await unsafeAdapter.RetrieveAsync(new byte[] { 1, 2, 3, 4 })).Status);
        Assert.Equal(
            MailboxClientAckStatus.NotReady,
            (await unsafeAdapter.AcknowledgeAsync(new byte[] { 1, 2, 3, 4 })).Status);
    }

    private Fixture CreateFixture(
        ToggleTombstoneFanout? tombstones = null,
        Action<MailboxClientAdapterOptions>? configure = null,
        IMailboxDurabilityBarrier? durability = null)
    {
        var adapterOptions = new MailboxClientAdapterOptions
        {
            Enabled = true,
            CurrentMembershipCommitment = Convert.ToHexString(Membership).ToLowerInvariant(),
            NextMembershipCommitment = Convert.ToHexString(NextMembership).ToLowerInvariant(),
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentNotBeforeUnixSeconds = 900,
            NextNotBeforeUnixSeconds = 950,
            CurrentExpiresAtUnixSeconds = 1100,
            NextExpiresAtUnixSeconds = 1200
        };
        configure?.Invoke(adapterOptions);
        var storeOptions = new ReplicatedMailboxOptions { Enabled = true };
        var localSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x11, 32).ToArray());
        var remoteSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x22, 32).ToArray());
        var localCrypto = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(localSeed),
            localSeed);
        var remoteCrypto = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(remoteSeed),
            remoteSeed);
        var store = new ReplicatedMailboxStore(
            _root,
            storeOptions,
            _clock,
            durability: durability);
        var ledger = Track(new MailboxClientOperationLedger(_root, adapterOptions, _clock));
        tombstones ??= new ToggleTombstoneFanout { Crypto = remoteCrypto };
        var verifier = new AttestingVerifier(adapterOptions, _clock);
        var replicas = new FixedAuthorizer(
            [localCrypto.LocalRouterId, remoteCrypto.LocalRouterId]);
        var adapter = Track(new MailboxClientStoreAdapter(
            adapterOptions,
            storeOptions,
            store,
            ledger,
            verifier,
            replicas,
            new StoreSigningFanout(remoteCrypto),
            localCrypto,
            _clock,
            tombstones));
        return new(
            adapterOptions,
            storeOptions,
            store,
            ledger,
            adapter,
            localCrypto,
            remoteCrypto,
            verifier,
            replicas,
            tombstones);
    }

    private static async Task<MailboxClientStoreResult> StoreAsync(
        MailboxClientStoreAdapter adapter,
        MailboxEncryptedEnvelope envelope)
    {
        var result = await adapter.StoreAsync(MailboxClientCodec.EncodeStore(new()
        {
            Epoch = envelope.Epoch,
            OperationId = envelope.OperationId,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            DepositCapability = Capability(
                new RotatingDepositCapability(Range(0x10 + envelope.OperationId.Span[0], 32)),
                envelope.Epoch,
                envelope.OperationId.Span[0]),
            Envelope = envelope
        }));
        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        return result;
    }

    private async Task<MailboxRetrievePage> RetrievePageAsync(
        MailboxClientStoreAdapter adapter,
        byte[] mailboxId)
    {
        var result = await adapter.RetrieveAsync(MailboxClientCodec.EncodeRetrieve(
            RetrieveRequest(80, mailboxId, 100)));
        Assert.Equal(MailboxClientRetrieveStatus.Success, result.Status);
        return MailboxClientCodec.DecodeRetrievePage(result.CanonicalPage.Span, Policy());
    }

    private static MailboxEncryptedEnvelope Envelope(
        int value,
        byte[] mailboxId,
        int ciphertextLength = 32,
        ulong epoch = 7) =>
        new()
        {
            Epoch = epoch,
            MailboxId = new BlindedMailboxId(mailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            OperationId = Filled(checked((byte)value), 16),
            DeduplicationDigest = Filled(checked((byte)(0x20 + value)), 32),
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1080,
            Ciphertext = Filled(checked((byte)(0x40 + value)), ciphertextLength)
        };

    private static MailboxRetrieveRequest RetrieveRequest(
        int operation,
        byte[] mailboxId,
        ushort maximumItems,
        ulong afterCursor = 0,
        ReadOnlyMemory<byte> token = default,
        uint capabilityExpires = 1090,
        ulong epoch = 7) =>
        new()
        {
            Epoch = epoch,
            OperationId = Filled(checked((byte)operation), 16),
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            RetrieveCapability = Capability(
                new RotatingRetrieveCapability(Filled(checked((byte)(0x80 + operation)), 32)),
                epoch,
                checked((byte)operation),
                capabilityExpires),
            MailboxId = new BlindedMailboxId(mailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            AfterCursor = afterCursor,
            MaximumItems = maximumItems,
            ContinuationToken = token
        };

    private static MailboxAckRequest AckRequest(
        int operation,
        byte[] mailboxId,
        IReadOnlyList<MailboxAcknowledgement> acknowledgements,
        ulong epoch = 7) =>
        new()
        {
            Epoch = epoch,
            OperationId = Filled(checked((byte)operation), 16),
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            RetrieveCapability = Capability(
                new RotatingRetrieveCapability(Filled(checked((byte)(0xa0 + operation)), 32)),
                epoch,
                checked((byte)operation)),
            MailboxId = new BlindedMailboxId(mailboxId),
            PlacementId = new BlindedPlacementId(PlacementId),
            IsFinalPage = true,
            ContinuationToken = ReadOnlyMemory<byte>.Empty,
            Acknowledgements = acknowledgements
        };

    private static MailboxCapabilityPresentation Capability(
        MailboxDomainValue value,
        ulong epoch,
        byte discriminator,
        uint expiresAt = 1090) =>
        new()
        {
            DomainValue = value,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = epoch,
            NotBeforeBucket = 1000,
            ExpiresAtBucket = expiresAt,
            OverlapUntilBucket = 0,
            ReplayCounter = discriminator == 0 ? 1UL : discriminator,
            IdempotencyKey = Filled(discriminator == 0 ? (byte)1 : discriminator, 16)
        };

    private static MailboxClientDecodePolicy Policy(ulong now = 1010) =>
        new()
        {
            NowUnixSeconds = now,
            EpochWindow = new()
            {
                CurrentEpoch = 7,
                NextEpoch = 8,
                CurrentNotBeforeUnixSeconds = 900,
                NextNotBeforeUnixSeconds = 950,
                CurrentExpiresAtUnixSeconds = 1100,
                NextExpiresAtUnixSeconds = 1200
            },
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

    private T Track<T>(T resource) where T : IDisposable
    {
        _resources.Add(resource);
        return resource;
    }

    public void Dispose()
    {
        foreach (var resource in _resources.AsEnumerable().Reverse())
        {
            resource.Dispose();
        }

        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private static byte[] Filled(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed record Fixture(
        MailboxClientAdapterOptions AdapterOptions,
        ReplicatedMailboxOptions StoreOptions,
        ReplicatedMailboxStore Store,
        MailboxClientOperationLedger Ledger,
        MailboxClientStoreAdapter Adapter,
        MailboxClientReceiptCrypto LocalCrypto,
        MailboxClientReceiptCrypto RemoteCrypto,
        AttestingVerifier Verifier,
        FixedAuthorizer Authorizer,
        ToggleTombstoneFanout Tombstones);

    private sealed class AttestingVerifier(
        MailboxClientAdapterOptions options,
        IClock clock)
        : IMailboxClientCapabilityVerifier
    {
        private readonly Dictionary<string, string> _replays = new(StringComparer.Ordinal);
        private readonly object _gate = new();
        public bool IsConfigured => true;
        public bool ProvidesDurableAtomicReplay => true;

        public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
            ReadOnlyMemory<byte> canonicalRequest,
            MailboxClientOperation operation,
            CancellationToken cancellationToken)
        {
            var request = canonicalRequest.Span;
            var epoch = BinaryPrimitives.ReadUInt64BigEndian(request.Slice(8, 8));
            var operationId = request.Slice(16, 16).ToArray();
            var (offset, length, domain, mailboxOffset, placementOffset) = operation switch
            {
                MailboxClientOperation.Store => (
                    48,
                    BinaryPrimitives.ReadUInt16BigEndian(request.Slice(32, 2)),
                    MailboxCapabilityDomain.Deposit,
                    -1,
                    -1),
                MailboxClientOperation.Retrieve => (
                    120,
                    BinaryPrimitives.ReadUInt16BigEndian(request.Slice(42, 2)),
                    MailboxCapabilityDomain.Retrieve,
                    48,
                    80),
                MailboxClientOperation.Acknowledge => (
                    120,
                    BinaryPrimitives.ReadUInt16BigEndian(request.Slice(34, 2)),
                    MailboxCapabilityDomain.Retrieve,
                    40,
                    72),
                _ => throw new InvalidOperationException()
            };
            var capabilityBytes = request.Slice(offset, length).ToArray();
            var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
            var capability = MailboxCapabilityCodec.Decode(
                capabilityBytes,
                domain,
                Policy(now).CapabilityPolicy,
                new AcceptingReplayGuard()).Presentation;
            byte[] mailbox;
            byte[] placement;
            if (operation == MailboxClientOperation.Store)
            {
                var envelopeLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                    request.Slice(36, 4)));
                var envelope = MailboxClientCodec.DecodeEncryptedEnvelope(
                    request.Slice(offset + length, envelopeLength),
                    Policy(now));
                mailbox = envelope.MailboxId.Bytes.ToArray();
                placement = envelope.PlacementId.Bytes.ToArray();
            }
            else
            {
                mailbox = request.Slice(mailboxOffset, 32).ToArray();
                placement = request.Slice(placementOffset, 32).ToArray();
            }

            var capabilityDigest = SHA256.HashData(capabilityBytes);
            var requestDigest = SHA256.HashData(request);
            var replayKey =
                $"{domain}:{epoch}:{capability.ReplayCounter}:" +
                $"{Convert.ToHexString(capability.IdempotencyKey.Span)}";
            MailboxCapabilityReplayDisposition disposition;
            lock (_gate)
            {
                var requestKey = Convert.ToHexString(requestDigest);
                if (_replays.TryGetValue(replayKey, out var prior)
                    && !string.Equals(prior, requestKey, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<MailboxCapabilityBinding?>(null);
                }

                disposition = _replays.ContainsKey(replayKey)
                    ? MailboxCapabilityReplayDisposition.IdempotentReplay
                    : MailboxCapabilityReplayDisposition.New;
                _replays[replayKey] = requestKey;
            }

            return ValueTask.FromResult<MailboxCapabilityBinding?>(new(
                epoch,
                mailbox,
                SHA256.HashData(placement),
                options.GetMembershipCommitment(epoch),
                operation)
            {
                OuterOperationId = operationId,
                CanonicalRequestDigest = requestDigest,
                CanonicalCapabilityDigest = capabilityDigest,
                ReplayCounter = capability.ReplayCounter,
                IdempotencyKey = capability.IdempotencyKey.ToArray(),
                ReplayDisposition = disposition
            });
        }
    }

    private sealed class AcceptingReplayGuard : IMailboxCapabilityReplayGuard
    {
        public MailboxCapabilityReplayEvaluation Evaluate(MailboxCapabilityReplayScope scope) =>
            new()
            {
                Decision = MailboxCapabilityReplayDecision.AcceptedNew,
                CachedOutcome = ReadOnlyMemory<byte>.Empty
            };
    }

    private sealed class FixedAuthorizer(IReadOnlyList<ReadOnlyMemory<byte>> replicas)
        : IMailboxClientReplicaAuthorizer
    {
        public bool IsConfigured => true;

        public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
            ulong epoch,
            ReadOnlyMemory<byte> membershipCommitment,
            ReadOnlyMemory<byte> placementCommitment,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(replicas);
    }

    private sealed class WrongDigestVerifier(IMailboxClientCapabilityVerifier inner)
        : IMailboxClientCapabilityVerifier
    {
        public bool IsConfigured => inner.IsConfigured;
        public bool ProvidesDurableAtomicReplay => inner.ProvidesDurableAtomicReplay;

        public async ValueTask<MailboxCapabilityBinding?> VerifyAsync(
            ReadOnlyMemory<byte> canonicalRequest,
            MailboxClientOperation operation,
            CancellationToken cancellationToken)
        {
            var binding = await inner.VerifyAsync(
                canonicalRequest,
                operation,
                cancellationToken);
            return binding is null
                ? null
                : binding with { CanonicalRequestDigest = Range(0x01, 32) };
        }
    }

    private sealed class ReplayUnsafeVerifier(IMailboxClientCapabilityVerifier inner)
        : IMailboxClientCapabilityVerifier
    {
        public bool IsConfigured => inner.IsConfigured;
        public bool ProvidesDurableAtomicReplay => false;

        public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
            ReadOnlyMemory<byte> canonicalRequest,
            MailboxClientOperation operation,
            CancellationToken cancellationToken) =>
            inner.VerifyAsync(canonicalRequest, operation, cancellationToken);
    }

    private sealed class StoreSigningFanout(MailboxClientReceiptCrypto crypto)
        : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>(
                [MailboxReceiptV2Codec.EncodeReplica(Sign(context))]);

        private MailboxReplicaReceiptV2 Sign(MailboxReplicaStoreContext context)
        {
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = context.Disposition,
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
            return unsigned with
            {
                Signature = crypto.SignLocal(
                    MailboxReceiptV2Codec.GetReplicaSigningBytes(unsigned))
            };
        }
    }

    private sealed class ToggleTombstoneFanout : IMailboxClientTombstoneFanout
    {
        private int _calls;
        public bool IsConfigured => true;
        public bool Fail { get; set; }
        public MailboxClientReceiptCrypto? Crypto { get; set; }
        public int CallCount => Volatile.Read(ref _calls);

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> TombstoneAsync(
            MailboxReplicaTombstoneContext context,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            if (Fail)
            {
                throw new IOException("simulated tombstone fanout outage");
            }

            var crypto = Crypto ?? throw new InvalidOperationException();
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

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static ByteArrayComparer Instance { get; } = new();
        public bool Equals(byte[]? x, byte[]? y) =>
            x is not null && y is not null && x.AsSpan().SequenceEqual(y);
        public int GetHashCode(byte[] obj) => 0;
    }

    private sealed class ThrowOnFlush(int crashAt) : IMailboxDurabilityBarrier
    {
        private int _flushes;

        public void FlushFileAndParentDirectory(string path)
        {
            if (Interlocked.Increment(ref _flushes) == crashAt)
            {
                throw new SimulatedCrashException();
            }
        }

        public void FlushParentDirectory(string deletedPath)
        {
        }
    }

    private sealed class FailFirstDeleteFlush : IMailboxDurabilityBarrier
    {
        private int _deleteFlushAttempts;
        public int DeleteFlushAttempts => Volatile.Read(ref _deleteFlushAttempts);

        public void FlushFileAndParentDirectory(string path)
        {
        }

        public void FlushParentDirectory(string deletedPath)
        {
            if (Interlocked.Increment(ref _deleteFlushAttempts) == 1)
            {
                throw new IOException("simulated-delete-flush-failure");
            }
        }
    }

    private sealed class SimulatedCrashException : Exception;
}
