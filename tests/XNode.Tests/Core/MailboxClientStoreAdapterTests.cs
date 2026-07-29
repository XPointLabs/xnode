using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class MailboxClientStoreAdapterTests : IDisposable
{
    private readonly List<IDisposable> _resources = [];
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"xnode-mailbox-client-{Guid.NewGuid():N}");
    private readonly FixedClock _clock =
        new(DateTimeOffset.FromUnixTimeSeconds(1010));

    [Fact]
    public async Task Store_PersistsCanonicalEnvelopeAndDurableContext_BeforeFanout()
    {
        var fixture = CreateFixture();
        var envelope = Envelope();
        var encodedEnvelope = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        var encodedStore = MailboxClientCodec.EncodeStore(Store(envelope));
        var fanout = new SigningFanout(
            fixture.RemoteCrypto,
            () =>
            {
                var ledger = File.ReadAllText(
                    Path.Combine(_root, "mailbox-client-adapter-v1", "operations.json"));
                Assert.Contains("\"state\":\"reserved\"", ledger, StringComparison.Ordinal);
            });
        var adapter = CreateAdapter(fixture, fanout);
        await adapter.InitializeAsync();

        var result = await adapter.StoreAsync(encodedStore);

        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(result.DurableQuorumReceipt.Span);
        Assert.Equal(1UL, quorum.FirstReplica.Cursor);
        Assert.Equal(1UL, quorum.SecondReplica.Cursor);
        Assert.False(quorum.FirstReplica.ReplicaId.Span.SequenceEqual(quorum.SecondReplica.ReplicaId.Span));
        var stored = Assert.Single(await fixture.Store.ReadAsync(
            Convert.ToHexString(MailboxId).ToLowerInvariant(),
            10));
        Assert.Equal(encodedEnvelope, Convert.FromBase64String(stored.Ciphertext));
        Assert.DoesNotContain(
            "seed",
            await File.ReadAllTextAsync(
                Path.Combine(_root, "mailbox-client-adapter-v1", "operations.json")),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ExactRetryAfterRestart_ReturnsCachedQuorumAndKeepsCursor()
    {
        var fixture = CreateFixture();
        var encoded = MailboxClientCodec.EncodeStore(Store(Envelope()));
        var first = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await first.InitializeAsync();
        var firstResult = await first.StoreAsync(encoded);
        Assert.Equal(MailboxClientStoreStatus.Durable, firstResult.Status);

        first.Dispose();
        fixture.Ledger.Dispose();
        var reopenedLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        var reopened = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            reopenedLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new ThrowingFanout(),
            fixture.LocalCrypto,
            _clock));
        await reopened.InitializeAsync();
        var retry = await reopened.StoreAsync(encoded);

        Assert.Equal(MailboxClientStoreStatus.Durable, retry.Status);
        Assert.Equal(firstResult.DurableQuorumReceipt.ToArray(), retry.DurableQuorumReceipt.ToArray());
    }

    [Fact]
    public async Task ExactRetryAfterUnavailablePeer_AcceptsLaterRemoteDurabilityAndCachesMqr3()
    {
        var fixture = CreateFixture();
        var encoded = MailboxClientCodec.EncodeStore(Store(Envelope()));
        var unavailable = CreateAdapter(fixture, new UnavailableFanout());
        await unavailable.InitializeAsync();

        var first = await unavailable.StoreAsync(encoded);

        Assert.Equal(MailboxClientStoreStatus.QuorumUnavailable, first.Status);
        Assert.True(first.DurableQuorumReceipt.IsEmpty);

        unavailable.Dispose();
        fixture.Ledger.Dispose();
        var recoveryLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock));
        var recovery = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            recoveryLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new SigningFanout(
                fixture.RemoteCrypto,
                acceptedAtOffsetSeconds: 15,
                durableAtOffsetSeconds: 17),
            fixture.LocalCrypto,
            _clock));
        await recovery.InitializeAsync();

        var recovered = await recovery.StoreAsync(encoded);
        var cached = await recovery.StoreAsync(encoded);

        Assert.Equal(MailboxClientStoreStatus.Durable, recovered.Status);
        Assert.Equal(recovered.DurableQuorumReceipt.ToArray(), cached.DurableQuorumReceipt.ToArray());
        var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(
            recovered.DurableQuorumReceipt.Span);
        var receipts = new[] { quorum.FirstReplica, quorum.SecondReplica };
        Assert.Contains(receipts, receipt =>
            receipt.AcceptedAtUnixSeconds == 1010
            && receipt.DurableAtUnixSeconds == 1010);
        Assert.Contains(receipts, receipt =>
            receipt.AcceptedAtUnixSeconds == 1025
            && receipt.DurableAtUnixSeconds == 1027);
    }

    [Fact]
    public async Task SameOperationWithDifferentCanonicalRequest_IsDurableConflict()
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await adapter.InitializeAsync();
        var first = MailboxClientCodec.EncodeStore(Store(Envelope()));
        Assert.Equal(MailboxClientStoreStatus.Durable, (await adapter.StoreAsync(first)).Status);
        var changedEnvelope = Envelope() with
        {
            DeduplicationDigest = Range(0x80, 32),
            Ciphertext = Range(0xc0, 32)
        };
        var conflict = MailboxClientCodec.EncodeStore(Store(changedEnvelope));

        var result = await adapter.StoreAsync(conflict);

        Assert.Equal(MailboxClientStoreStatus.Conflict, result.Status);
    }

    [Fact]
    public async Task DisabledMissingVerifierAndMissingFanout_AreDistinctFailClosedStates()
    {
        var disabledFixture = CreateFixture(enabled: false);
        var disabled = CreateAdapter(disabledFixture, new DisabledMailboxClientReplicaFanout());
        Assert.Equal(
            MailboxClientStoreStatus.Disabled,
            (await disabled.StoreAsync(new byte[] { 1, 2, 3 })).Status);

        disabled.Dispose();
        disabledFixture.Ledger.Dispose();
        var fixture = CreateFixture();
        var noVerifier = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            new RejectAllMailboxClientCapabilityVerifier(),
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        Assert.Equal("capability-verifier-missing", noVerifier.Status.Reason);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await noVerifier.StoreAsync(new byte[] { 1, 2, 3 })).Status);

        noVerifier.Dispose();
        var noAuthorizer = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            new RejectAllMailboxClientReplicaAuthorizer(),
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        Assert.Equal("replica-authorizer-missing", noAuthorizer.Status.Reason);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await noAuthorizer.StoreAsync(new byte[] { 1, 2, 3 })).Status);

        noAuthorizer.Dispose();
        var noFanout = CreateAdapter(fixture, new DisabledMailboxClientReplicaFanout());
        Assert.Equal("replica-fanout-missing", noFanout.Status.Reason);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await noFanout.StoreAsync(new byte[] { 1, 2, 3 })).Status);
    }

    [Fact]
    public async Task NonCanonicalAndCapabilityBindingMismatch_NeverReachStorage()
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await adapter.InitializeAsync();
        var malformed = MailboxClientCodec.EncodeStore(Store(Envelope()));
        malformed[0] = (byte)'X';

        Assert.Equal(
            MailboxClientStoreStatus.Malformed,
            (await adapter.StoreAsync(malformed)).Status);

        var badVerifier = new FixedVerifier(
            new MailboxCapabilityBinding(
                7,
                MailboxId,
                Range(0xff, 32),
                MembershipCommitment,
                MailboxClientOperation.Store));
        adapter.Dispose();
        var unauthorized = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            badVerifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        Assert.Equal(
            MailboxClientStoreStatus.Unauthorized,
            (await unauthorized.StoreAsync(
                MailboxClientCodec.EncodeStore(Store(Envelope())))).Status);
        Assert.Empty(Directory.Exists(_root)
            ? Directory.GetFiles(_root, "*.json", SearchOption.AllDirectories)
            : []);
    }

    [Fact]
    public async Task InvalidOrContextMismatchedReplicaReceipt_DoesNotCountTowardQuorum()
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(
            fixture,
            new SigningFanout(fixture.RemoteCrypto, mutateCursor: true));
        await adapter.InitializeAsync();

        var result = await adapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(Envelope())));

        Assert.Equal(MailboxClientStoreStatus.QuorumUnavailable, result.Status);
        Assert.True(result.DurableQuorumReceipt.IsEmpty);
    }

    [Theory]
    [InlineData(15, 18, MailboxClientStoreStatus.Durable)]
    [InlineData(-1, 0, MailboxClientStoreStatus.QuorumUnavailable)]
    [InlineData(10, 9, MailboxClientStoreStatus.QuorumUnavailable)]
    [InlineData(109, 110, MailboxClientStoreStatus.QuorumUnavailable)]
    public async Task ReplicaDurabilityTimes_AreIndependentAndBounded(
        long acceptedAtOffsetSeconds,
        long durableAtOffsetSeconds,
        MailboxClientStoreStatus expected)
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(
            fixture,
            new SigningFanout(
                fixture.RemoteCrypto,
                acceptedAtOffsetSeconds: acceptedAtOffsetSeconds,
                durableAtOffsetSeconds: durableAtOffsetSeconds));
        await adapter.InitializeAsync();

        var result = await adapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(Envelope())));

        Assert.Equal(expected, result.Status);
        Assert.Equal(
            expected == MailboxClientStoreStatus.Durable,
            !result.DurableQuorumReceipt.IsEmpty);
    }

    [Fact]
    public async Task MaximumCanonicalMeo1_IsStoredWithoutTruncation()
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await adapter.InitializeAsync();
        var envelope = Envelope() with
        {
            Ciphertext = Enumerable.Repeat(
                (byte)0xa5,
                MailboxClientLimits.MaximumCiphertextLength).ToArray()
        };
        var canonicalEnvelope = MailboxClientCodec.EncodeEncryptedEnvelope(envelope);
        Assert.Equal(MailboxClientLimits.MaximumEncryptedEnvelopeLength, canonicalEnvelope.Length);

        var result = await adapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(envelope)));

        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        var stored = Assert.Single(await fixture.Store.ReadAsync(
            Convert.ToHexString(MailboxId).ToLowerInvariant(),
            1));
        Assert.Equal(canonicalEnvelope, Convert.FromBase64String(stored.Ciphertext));
    }

    [Fact]
    public async Task ForgedSelfSignedNonMemberReceipt_DoesNotCount()
    {
        var fixture = CreateFixture();
        var attackerSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x44, 32).ToArray());
        var attacker = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(attackerSeed),
            attackerSeed);
        var adapter = CreateAdapter(fixture, new SigningFanout(attacker));
        await adapter.InitializeAsync();

        var result = await adapter.StoreAsync(MailboxClientCodec.EncodeStore(Store(Envelope())));

        Assert.Equal(MailboxClientStoreStatus.QuorumUnavailable, result.Status);
    }

    [Fact]
    public async Task SimultaneousIdenticalCalls_AreSingleFlightWithOneCoordinatorSequence()
    {
        var fixture = CreateFixture();
        var fanout = new CountingFanout(fixture.RemoteCrypto);
        var adapter = CreateAdapter(fixture, fanout);
        await adapter.InitializeAsync();
        var request = MailboxClientCodec.EncodeStore(Store(Envelope()));

        var results = await Task.WhenAll(
            Enumerable.Range(0, 12).Select(_ => adapter.StoreAsync(request)));

        Assert.All(results, result => Assert.Equal(MailboxClientStoreStatus.Durable, result.Status));
        Assert.Equal(1, fanout.CallCount);
        Assert.Single(results.Select(result =>
            Convert.ToHexString(SHA256.HashData(result.DurableQuorumReceipt.Span))).Distinct());
        Assert.All(results, result => Assert.Equal(
            1UL,
            MailboxReceiptV3Codec.DecodeDurableQuorum(
                result.DurableQuorumReceipt.Span).CoordinatorSequence));
    }

    [Fact]
    public async Task CrashAfterCompletionReservation_RestartSignsExactPersistedStatement()
    {
        var fixture = CreateFixture();
        fixture.Ledger.Dispose();
        var crash = new CrashOnFlush(3);
        var crashLedger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock,
            durability: crash));
        var crashing = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            crashLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        await crashing.InitializeAsync();
        var request = MailboxClientCodec.EncodeStore(Store(Envelope()));
        await Assert.ThrowsAsync<SimulatedCrashException>(() => crashing.StoreAsync(request));

        crashing.Dispose();
        crashLedger.Dispose();
        var recoveryLedger = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        var reopened = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            recoveryLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new ThrowingFanout(),
            fixture.LocalCrypto,
            _clock));
        await reopened.InitializeAsync();
        var recovered = await reopened.StoreAsync(request);

        Assert.Equal(MailboxClientStoreStatus.Durable, recovered.Status);
        Assert.Equal(
            1UL,
            MailboxReceiptV3Codec.DecodeDurableQuorum(
                recovered.DurableQuorumReceipt.Span).CoordinatorSequence);
    }

    [Theory]
    [InlineData("\"nextCursorByMailbox\":{\"0000000000000007:", "\"nextCursorByMailbox\":{\"0000000000000007:", "rewind")]
    [InlineData("\"schemaVersion\":3", "\"schemaVersion\":1", "schema")]
    public async Task LedgerCorruption_FailsClosedOnRestart(
        string find,
        string replace,
        string scenario)
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await adapter.InitializeAsync();
        Assert.Equal(
            MailboxClientStoreStatus.Durable,
            (await adapter.StoreAsync(MailboxClientCodec.EncodeStore(Store(Envelope())))).Status);
        var path = Path.Combine(_root, "mailbox-client-adapter-v1", "operations.json");
        var json = await File.ReadAllTextAsync(path);
        if (scenario == "rewind")
        {
            var cursorMarker = "\":1}";
            json = json.Replace(cursorMarker, "\":0}", StringComparison.Ordinal);
        }
        else
        {
            json = json.Replace(find, replace, StringComparison.Ordinal);
        }
        await File.WriteAllTextAsync(path, json);

        adapter.Dispose();
        fixture.Ledger.Dispose();
        var reopened = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.InitializeAsync());
    }

    [Fact]
    public async Task PerMailboxCursorAndGlobalCoordinatorSequence_AreIndependent()
    {
        var fixture = CreateFixture();
        var adapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await adapter.InitializeAsync();
        var first = await adapter.StoreAsync(MailboxClientCodec.EncodeStore(Store(Envelope())));
        var otherMailbox = Range(0xf0, 32);
        var otherOperation = Range(0x01, 16);
        var secondEnvelope = Envelope(otherMailbox, otherOperation);
        var secondVerifier = new FixedVerifier(new(
            7,
            otherMailbox,
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId)),
            MembershipCommitment,
            MailboxClientOperation.Store));
        adapter.Dispose();
        var secondAdapter = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            secondVerifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        var second = await secondAdapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(secondEnvelope)));

        var firstReceipt = MailboxReceiptV3Codec.DecodeDurableQuorum(first.DurableQuorumReceipt.Span);
        var secondReceipt = MailboxReceiptV3Codec.DecodeDurableQuorum(second.DurableQuorumReceipt.Span);
        Assert.Equal(1UL, firstReceipt.FirstReplica.Cursor);
        Assert.Equal(1UL, secondReceipt.FirstReplica.Cursor);
        Assert.Equal(1UL, firstReceipt.CoordinatorSequence);
        Assert.Equal(2UL, secondReceipt.CoordinatorSequence);
    }

    [Fact]
    public async Task NearExpiryRejection_DoesNotConsumeLedgerCapacity()
    {
        var fixture = CreateFixture();
        fixture.AdapterOptions.MaxOperationEntries = 1;
        fixture.AdapterOptions.MaxCursorAuthorities = 1;
        fixture.AdapterOptions.MaxConcurrentSingleFlights = 1;
        var adapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await adapter.InitializeAsync();
        var nearExpiry = Envelope() with
        {
            CreatedAtUnixSeconds = 950,
            ExpiresAtUnixSeconds = 1069
        };
        Assert.Equal(
            MailboxClientStoreStatus.Rejected,
            (await adapter.StoreAsync(
                MailboxClientCodec.EncodeStore(Store(nearExpiry)))).Status);

        var valid = await adapter.StoreAsync(MailboxClientCodec.EncodeStore(Store(Envelope())));
        Assert.Equal(MailboxClientStoreStatus.Durable, valid.Status);
    }

    [Fact]
    public async Task ExpiredLedgerCleanup_ReleasesCapacityWithoutCursorReuse()
    {
        var fixture = CreateFixture();
        fixture.AdapterOptions.MaxOperationEntries = 1;
        fixture.AdapterOptions.MaxCursorAuthorities = 1;
        fixture.AdapterOptions.MaxConcurrentSingleFlights = 1;
        fixture.Ledger.Dispose();
        var ledger = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        var replicas = new ReadOnlyMemory<byte>[]
        {
            fixture.LocalCrypto.LocalRouterId,
            fixture.RemoteCrypto.LocalRouterId
        };
        var first = await ledger.ReserveStoreAsync(
            7,
            OperationId,
            Range(0x91, 32),
            MailboxId,
            EnvelopeDigest,
            Range(0xa1, 32),
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId)),
            MembershipCommitment,
            replicas,
            1011,
            CancellationToken.None);
        Assert.Equal(1UL, first.Cursor);

        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1012);
        await ledger.InitializeAsync();
        var second = await ledger.ReserveStoreAsync(
            7,
            Range(0x61, 16),
            Range(0x92, 32),
            MailboxId,
            Range(0x93, 32),
            Range(0x94, 32),
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId)),
            MembershipCommitment,
            replicas,
            1200,
            CancellationToken.None);

        Assert.Equal(2UL, second.Cursor);
    }

    [Fact]
    public async Task CachedReceipt_IsRejectedAfterMembershipOrCoordinatorKeyRotation()
    {
        var fixture = CreateFixture();
        var request = MailboxClientCodec.EncodeStore(Store(Envelope()));
        var first = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await first.InitializeAsync();
        Assert.Equal(MailboxClientStoreStatus.Durable, (await first.StoreAsync(request)).Status);

        first.Dispose();
        fixture.AdapterOptions.CurrentMembershipCommitment =
            Convert.ToHexString(Range(0x81, 32)).ToLowerInvariant();
        var rotatedMembership = CreateAdapter(fixture, new ThrowingFanout());
        Assert.Equal(
            "capability-binding-rejected",
            (await rotatedMembership.StoreAsync(request)).Error);

        rotatedMembership.Dispose();
        fixture.AdapterOptions.CurrentMembershipCommitment =
            Convert.ToHexString(MembershipCommitment).ToLowerInvariant();
        var newSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x55, 32).ToArray());
        var newLocal = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(newSeed),
            newSeed);
        var rotatedKey = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            new FixedAuthorizer([newLocal.LocalRouterId, fixture.RemoteCrypto.LocalRouterId]),
            new ThrowingFanout(),
            newLocal,
            _clock));
        Assert.Equal(
            "replica-authority-rotated",
            (await rotatedKey.StoreAsync(request)).Error);
    }

    [Fact]
    public async Task CachedReceiptWithStaleSignature_IsReverifiedAndRejected()
    {
        var fixture = CreateFixture();
        var request = MailboxClientCodec.EncodeStore(Store(Envelope()));
        var first = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        await first.InitializeAsync();
        Assert.Equal(MailboxClientStoreStatus.Durable, (await first.StoreAsync(request)).Status);
        var path = Path.Combine(_root, "mailbox-client-adapter-v1", "operations.json");
        var document = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        var operation = document["operations"]!.AsObject().First().Value!.AsObject();
        var receipt = Convert.FromBase64String(operation["receipt"]!.GetValue<string>());
        receipt[^1] ^= 0x01;
        operation["receipt"] = Convert.ToBase64String(receipt);
        await File.WriteAllTextAsync(path, document.ToJsonString());

        first.Dispose();
        var reopened = CreateAdapter(fixture, new ThrowingFanout());
        await reopened.InitializeAsync();
        var result = await reopened.StoreAsync(request);

        Assert.Equal(MailboxClientStoreStatus.Rejected, result.Status);
        Assert.Equal("cached-quorum-invalid", result.Error);
    }

    [Fact]
    public async Task EAndEPlusOne_UseDistinctMembershipCommitments()
    {
        var fixture = CreateFixture();
        var nextOperation = Range(0x60, 16);
        var nextEnvelope = Envelope(MailboxId, nextOperation) with
        {
            Epoch = 8,
            CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1130
        };
        var nextVerifier = new FixedVerifier(new(
            8,
            MailboxId,
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId)),
            NextMembershipCommitment,
            MailboxClientOperation.Store));
        var authorizer = new RecordingAuthorizer(
            [fixture.LocalCrypto.LocalRouterId, fixture.RemoteCrypto.LocalRouterId]);
        var adapter = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            nextVerifier,
            authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));

        var result = await adapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(nextEnvelope, 8)));

        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        Assert.Equal(NextMembershipCommitment, authorizer.SeenMembership);
        var receipt = MailboxReceiptV3Codec.DecodeDurableQuorum(result.DurableQuorumReceipt.Span);
        Assert.Equal(NextMembershipCommitment, receipt.FirstReplica.MembershipCommitment.ToArray());
    }

    [Fact]
    public void PublicAdapterContracts_DoNotExposeNodeSeedOrClientSecrets()
    {
        var forbidden = new[] { "Seed", "PrivateKey", "Master", "RetrieveCapability", "Plaintext" };
        var publicProperties = typeof(MailboxClientStoreAdapter).Assembly.GetTypes()
            .Where(type => type.IsPublic
                && type.Namespace == "XNode.Core.Mailbox.Client")
            .SelectMany(static type => type.GetProperties())
            .Select(static property => property.Name)
            .ToArray();
        Assert.All(forbidden, value => Assert.DoesNotContain(
            publicProperties,
            property => property.Contains(value, StringComparison.OrdinalIgnoreCase)));
    }

    [Fact]
    public void EqualEAndEPlusOneMembershipCommitments_FailClosed()
    {
        var fixture = CreateFixture();
        fixture.AdapterOptions.NextMembershipCommitment =
            fixture.AdapterOptions.CurrentMembershipCommitment;
        Assert.Throws<InvalidOperationException>(() => fixture.AdapterOptions.Validate());
    }

    [Fact]
    public async Task DirectoryLeaseAndAdapterClaim_AreExclusiveAndReleasable()
    {
        var fixture = CreateFixture();
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        var firstAdapter = CreateAdapter(fixture, new SigningFanout(fixture.RemoteCrypto));
        Assert.Throws<InvalidOperationException>(() =>
            new MailboxClientStoreAdapter(
                fixture.AdapterOptions,
                fixture.StoreOptions,
                fixture.Store,
                fixture.Ledger,
                fixture.Verifier,
                fixture.Authorizer,
                new SigningFanout(fixture.RemoteCrypto),
                fixture.LocalCrypto,
                _clock));

        firstAdapter.Dispose();
        var replacementAdapter = CreateAdapter(
            fixture,
            new SigningFanout(fixture.RemoteCrypto));
        replacementAdapter.Dispose();
        fixture.Ledger.Dispose();

        var restartedLedger = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        await restartedLedger.InitializeAsync();
    }

    [Theory]
    [InlineData("reserved-raw")]
    [InlineData("retryable-empty-error")]
    [InlineData("terminal-invalid-disposition")]
    [InlineData("reserved-noncanonical-error")]
    [InlineData("terminal-raw")]
    [InlineData("completing-zero-sequence")]
    [InlineData("durable-empty-receipt")]
    [InlineData("reserved-malformed-receipt")]
    [InlineData("null-operation")]
    [InlineData("null-mailbox")]
    [InlineData("null-replica")]
    public async Task LedgerStateMatrixCorruption_FailsClosed(string mutation)
    {
        var fixture = CreateFixture();
        var replicas = new ReadOnlyMemory<byte>[]
        {
            fixture.LocalCrypto.LocalRouterId,
            fixture.RemoteCrypto.LocalRouterId
        };
        await fixture.Ledger.ReserveStoreAsync(
            7,
            OperationId,
            Range(0x91, 32),
            MailboxId,
            EnvelopeDigest,
            Range(0xa1, 32),
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId)),
            MembershipCommitment,
            replicas,
            1120,
            CancellationToken.None);
        fixture.Ledger.Dispose();
        var path = Path.Combine(_root, "mailbox-client-adapter-v1", "operations.json");
        var document = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        var operation = document["operations"]!.AsObject().First().Value!.AsObject();
        switch (mutation)
        {
            case "reserved-raw":
                operation["firstReplicaReceipt"] = "AQ==";
                break;
            case "retryable-empty-error":
                operation["state"] = "retryable";
                operation["disposition"] = "stored";
                operation["acceptedAtUnixSeconds"] = 1010;
                break;
            case "terminal-invalid-disposition":
                operation["state"] = "terminal";
                operation["disposition"] = "forged";
                operation["error"] = "terminal-error";
                break;
            case "reserved-noncanonical-error":
                operation["error"] = "BAD error!";
                break;
            case "terminal-raw":
                operation["state"] = "terminal";
                operation["error"] = "terminal-error";
                operation["secondReplicaReceipt"] = "AQ==";
                break;
            case "completing-zero-sequence":
                operation["state"] = "completing";
                operation["disposition"] = "stored";
                operation["acceptedAtUnixSeconds"] = 1010;
                operation["firstReplicaReceipt"] = "AQ==";
                operation["secondReplicaReceipt"] = "Ag==";
                break;
            case "durable-empty-receipt":
                operation["state"] = "durable";
                operation["disposition"] = "stored";
                operation["acceptedAtUnixSeconds"] = 1010;
                operation["coordinatorSequence"] = 1;
                operation["firstReplicaReceipt"] = "AQ==";
                operation["secondReplicaReceipt"] = "Ag==";
                break;
            case "reserved-malformed-receipt":
                operation["receipt"] = "!";
                break;
            case "null-operation":
                var operationKey = document["operations"]!.AsObject().First().Key;
                document["operations"]![operationKey] = null;
                break;
            case "null-mailbox":
                operation["mailboxId"] = null;
                break;
            case "null-replica":
                operation["expectedReplicaIds"]!.AsArray()[0] = null;
                break;
        }
        await File.WriteAllTextAsync(path, document.ToJsonString());

        var reopened = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.InitializeAsync());
    }

    [Fact]
    public async Task AuthenticatedMailboxChurn_CompactsAuthoritiesAcrossRestartWithoutReuse()
    {
        var fixture = CreateFixture();
        fixture.AdapterOptions.MaxOperationEntries = 2;
        fixture.AdapterOptions.MaxCursorAuthorities = 2;
        fixture.AdapterOptions.MaxConcurrentSingleFlights = 1;
        fixture.AdapterOptions.CurrentExpiresAtUnixSeconds = 2000;
        fixture.AdapterOptions.NextExpiresAtUnixSeconds = 2100;
        fixture.Ledger.Dispose();
        var firstMailbox = MailboxId;
        var secondMailbox = Range(0x81, 32);
        var thirdMailbox = Range(0xa1, 32);
        var firstRequest = MailboxClientCodec.EncodeStore(Store(Envelope(
            firstMailbox,
            OperationId)));
        var secondRequest = MailboxClientCodec.EncodeStore(Store(Envelope(
            secondMailbox,
            Range(0x41, 16))));
        var earlyThird = MailboxClientCodec.EncodeStore(Store(Envelope(
            thirdMailbox,
            Range(0x51, 16))));
        var verifier = new RequestMapVerifier(
            (firstRequest, Binding(firstMailbox)),
            (secondRequest, Binding(secondMailbox)),
            (earlyThird, Binding(thirdMailbox)));
        var firstLedger = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        var adapter = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            firstLedger,
            verifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        Assert.Equal(
            MailboxClientStoreStatus.Durable,
            (await adapter.StoreAsync(firstRequest)).Status);
        Assert.Equal(
            MailboxClientStoreStatus.Durable,
            (await adapter.StoreAsync(secondRequest)).Status);
        Assert.Equal(
            "operation-ledger-capacity",
            (await adapter.StoreAsync(earlyThird)).Error);

        adapter.Dispose();
        firstLedger.Dispose();
        _clock.UtcNow = DateTimeOffset.FromUnixTimeSeconds(1121);
        var lateEnvelope = Envelope(thirdMailbox, Range(0x51, 16)) with
        {
            CreatedAtUnixSeconds = 1121,
            ExpiresAtUnixSeconds = 1200
        };
        var lateThird = MailboxClientCodec.EncodeStore(
            Store(lateEnvelope, capabilityExpires: 1500));
        verifier.Add(lateThird, Binding(thirdMailbox));
        var restartedLedger = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        var restarted = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            restartedLedger,
            verifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        await restarted.InitializeAsync();

        var result = await restarted.StoreAsync(lateThird);

        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        Assert.Equal(
            2UL,
            MailboxReceiptV3Codec.DecodeDurableQuorum(
                result.DurableQuorumReceipt.Span).FirstReplica.Cursor);
        var ledgerJson = JsonNode.Parse(await File.ReadAllTextAsync(
            Path.Combine(_root, "mailbox-client-adapter-v1", "operations.json")))!.AsObject();
        Assert.True(ledgerJson["nextCursorByMailbox"]!.AsObject().Count <= 2);
        Assert.Equal(1UL, ledgerJson["retiredCursorFloor"]!.GetValue<ulong>());
    }

    [Fact]
    public async Task UniqueOperationSingleFlightCapacity_IsBoundedAndReleased()
    {
        var fixture = CreateFixture();
        fixture.AdapterOptions.MaxConcurrentSingleFlights = 1;
        var secondMailbox = Range(0x81, 32);
        var firstRequest = MailboxClientCodec.EncodeStore(Store(Envelope()));
        var secondRequest = MailboxClientCodec.EncodeStore(Store(Envelope(
            secondMailbox,
            Range(0x41, 16))));
        var verifier = new RequestMapVerifier(
            (firstRequest, Binding(MailboxId)),
            (secondRequest, Binding(secondMailbox)));
        fixture.Ledger.Dispose();
        var ledger = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        var fanout = new CountingFanout(fixture.RemoteCrypto, 200);
        var adapter = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            ledger,
            verifier,
            fixture.Authorizer,
            fanout,
            fixture.LocalCrypto,
            _clock));
        var first = adapter.StoreAsync(firstRequest);
        for (var attempt = 0; attempt < 50 && fanout.CallCount == 0; attempt++)
        {
            await Task.Delay(5);
        }

        var bounded = await adapter.StoreAsync(secondRequest);
        var firstResult = await first;
        var afterRelease = await adapter.StoreAsync(secondRequest);

        Assert.Equal(MailboxClientStoreStatus.Durable, firstResult.Status);
        Assert.Equal("single-flight-capacity", bounded.Error);
        Assert.Equal(MailboxClientStoreStatus.Durable, afterRelease.Status);
    }

    [Fact]
    public async Task InitializeLifecycle_PreventsConcurrentLeaseRelease()
    {
        var fixture = CreateFixture();
        fixture.Ledger.Dispose();
        var security = new BlockingInitializationSecurity();
        var ledger = Track(new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock,
            security));
        var adapter = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            ledger,
            fixture.Verifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock));
        var initialize = Task.Run(async () => await adapter.InitializeAsync());
        try
        {
            Assert.True(security.WaitUntilInitializeEntered(TimeSpan.FromSeconds(5)));
            Assert.Throws<InvalidOperationException>(() => adapter.Dispose());
            Assert.Throws<InvalidOperationException>(() => ledger.Dispose());
        }
        finally
        {
            security.ReleaseInitialization();
        }

        await initialize;
        adapter.Dispose();
        ledger.Dispose();
        var restarted = Track(
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock));
        await restarted.InitializeAsync();
    }

    [Fact]
    public async Task CancelledSameOperationWaiter_ReleasesFinalSingleFlightReference()
    {
        var fixture = CreateFixture();
        var request = MailboxClientCodec.EncodeStore(Store(Envelope()));
        var fanout = new CountingFanout(fixture.RemoteCrypto, 500);
        var adapter = CreateAdapter(fixture, fanout);
        var first = adapter.StoreAsync(request);
        for (var attempt = 0; attempt < 100 && fanout.CallCount == 0; attempt++)
        {
            await Task.Delay(5);
        }

        Assert.Equal(1, fanout.CallCount);
        using var cancellation = new CancellationTokenSource();
        var waiter = adapter.StoreAsync(request, cancellation.Token);
        await Task.Delay(20);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);
        Assert.Equal(MailboxClientStoreStatus.Durable, (await first).Status);
        Assert.Equal(
            MailboxClientStoreStatus.Durable,
            (await adapter.StoreAsync(request)).Status);
        adapter.Dispose();
        var replacement = Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            fixture.Authorizer,
            new ThrowingFanout(),
            fixture.LocalCrypto,
            _clock));
        Assert.True(replacement.Status.StoreReady);
        Assert.True(replacement.Status.RetrieveReady);
        Assert.False(replacement.Status.AcknowledgeReady);
        Assert.False(replacement.Status.Ready);
        Assert.Equal(
            "tombstone-fanout-missing",
            replacement.Status.AcknowledgeReason);
    }

    private Fixture CreateFixture(bool enabled = true)
    {
        var mailboxOptions = new ReplicatedMailboxOptions { Enabled = true };
        var adapterOptions = new MailboxClientAdapterOptions
        {
            Enabled = enabled,
            CurrentMembershipCommitment =
                Convert.ToHexString(MembershipCommitment).ToLowerInvariant(),
            NextMembershipCommitment =
                Convert.ToHexString(NextMembershipCommitment).ToLowerInvariant(),
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentNotBeforeUnixSeconds = 900,
            NextNotBeforeUnixSeconds = 950,
            CurrentExpiresAtUnixSeconds = 1100,
            NextExpiresAtUnixSeconds = 1200
        };
        var localSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x11, 32).ToArray());
        var remoteSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x22, 32).ToArray());
        var localCrypto = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(localSeed),
            localSeed);
        var remoteCrypto = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(remoteSeed),
            remoteSeed);
        var store = new ReplicatedMailboxStore(_root, mailboxOptions, _clock);
        var placementCommitment =
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId));
        var ledger = Track(new MailboxClientOperationLedger(
            _root,
            adapterOptions,
            _clock));
        return new(
            adapterOptions,
            mailboxOptions,
            store,
            ledger,
            new FixedVerifier(new(
                7,
                MailboxId,
                placementCommitment,
                MembershipCommitment,
                MailboxClientOperation.Store)),
            new FixedAuthorizer([localCrypto.LocalRouterId, remoteCrypto.LocalRouterId]),
            localCrypto,
            remoteCrypto);
    }

    private MailboxClientStoreAdapter CreateAdapter(
        Fixture fixture,
        IMailboxClientReplicaFanout fanout) =>
        Track(new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            fixture.Authorizer,
            fanout,
            fixture.LocalCrypto,
            _clock));

    private T Track<T>(T resource) where T : IDisposable
    {
        _resources.Add(resource);
        return resource;
    }

    private static readonly byte[] OperationId = Range(0x10, 16);
    private static readonly byte[] MailboxId = Range(0x30, 32);
    private static readonly byte[] PlacementId = Range(0x50, 32);
    private static readonly byte[] EnvelopeDigest = Range(0x70, 32);
    private static readonly byte[] MembershipCommitment = Range(0xd0, 32);
    private static readonly byte[] NextMembershipCommitment = Range(0xe0, 32);

    private static MailboxEncryptedEnvelope Envelope() => Envelope(MailboxId, OperationId);

    private static MailboxEncryptedEnvelope Envelope(byte[] mailboxId, byte[] operationId) => new()
    {
        Epoch = 7,
        MailboxId = new BlindedMailboxId(mailboxId),
        PlacementId = new BlindedPlacementId(PlacementId),
        OperationId = operationId,
        DeduplicationDigest = EnvelopeDigest,
        CreatedAtUnixSeconds = 1000,
        ExpiresAtUnixSeconds = 1120,
        Ciphertext = Range(0xa0, 32)
    };

    private static MailboxStoreRequest Store(
        MailboxEncryptedEnvelope envelope,
        ulong epoch = 7,
        uint capabilityNotBefore = 1000,
        uint capabilityExpires = 1100) => new()
    {
        Epoch = epoch,
        OperationId = envelope.OperationId,
        MixedVersion = MailboxMixedVersionMarker.StrictV1,
        DepositCapability = new MailboxCapabilityPresentation
        {
            DomainValue = new RotatingDepositCapability(Range(0x90, 32)),
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = epoch,
            NotBeforeBucket = capabilityNotBefore,
            ExpiresAtBucket = capabilityExpires,
            OverlapUntilBucket = 0,
            ReplayCounter = 9,
            IdempotencyKey = Range(0x20, 16)
        },
        Envelope = envelope
    };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private static MailboxCapabilityBinding Binding(byte[] mailboxId) =>
        new(
            7,
            mailboxId,
            MailboxPlacementCommitment.Compute(new BlindedPlacementId(PlacementId)),
            MembershipCommitment,
            MailboxClientOperation.Store);

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

        GC.SuppressFinalize(this);
    }

    private sealed record Fixture(
        MailboxClientAdapterOptions AdapterOptions,
        ReplicatedMailboxOptions StoreOptions,
        ReplicatedMailboxStore Store,
        MailboxClientOperationLedger Ledger,
        IMailboxClientCapabilityVerifier Verifier,
        IMailboxClientReplicaAuthorizer Authorizer,
        MailboxClientReceiptCrypto LocalCrypto,
        MailboxClientReceiptCrypto RemoteCrypto);

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

    private sealed class RecordingAuthorizer(IReadOnlyList<ReadOnlyMemory<byte>> replicas)
        : IMailboxClientReplicaAuthorizer
    {
        public bool IsConfigured => true;
        public byte[] SeenMembership { get; private set; } = [];

        public ValueTask<IReadOnlyList<ReadOnlyMemory<byte>>> SelectReplicaIdsAsync(
            ulong epoch,
            ReadOnlyMemory<byte> membershipCommitment,
            ReadOnlyMemory<byte> placementCommitment,
            CancellationToken cancellationToken)
        {
            SeenMembership = membershipCommitment.ToArray();
            return ValueTask.FromResult(replicas);
        }
    }

    private sealed class FixedVerifier(MailboxCapabilityBinding binding)
        : IMailboxClientCapabilityVerifier
    {
        public bool IsConfigured => true;
        public bool ProvidesDurableAtomicReplay => true;

        public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
            ReadOnlyMemory<byte> canonicalRequest,
            MailboxClientOperation operation,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<MailboxCapabilityBinding?>(
                Attest(binding, canonicalRequest, operation));
    }

    private sealed class RequestMapVerifier : IMailboxClientCapabilityVerifier
    {
        private readonly Dictionary<string, MailboxCapabilityBinding> _bindings =
            new(StringComparer.Ordinal);

        public RequestMapVerifier(
            params (byte[] Request, MailboxCapabilityBinding Binding)[] bindings)
        {
            foreach (var binding in bindings)
            {
                Add(binding.Request, binding.Binding);
            }
        }

        public bool IsConfigured => true;
        public bool ProvidesDurableAtomicReplay => true;

        public void Add(byte[] request, MailboxCapabilityBinding binding) =>
            _bindings[Convert.ToHexString(SHA256.HashData(request))] = binding;

        public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
            ReadOnlyMemory<byte> canonicalRequest,
            MailboxClientOperation operation,
            CancellationToken cancellationToken)
        {
            _bindings.TryGetValue(
                Convert.ToHexString(SHA256.HashData(canonicalRequest.Span)),
                out var binding);
            return ValueTask.FromResult<MailboxCapabilityBinding?>(
                binding is null ? null : Attest(binding, canonicalRequest, operation));
        }
    }

    private static MailboxCapabilityBinding Attest(
        MailboxCapabilityBinding binding,
        ReadOnlyMemory<byte> canonicalRequest,
        MailboxClientOperation operation)
    {
        var policy = new MailboxClientDecodePolicy
        {
            NowUnixSeconds = 1010,
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
                CurrentBucket = 1010,
                MinimumGeneration = 7,
                AllowLegacyMirrorOverlap = false,
                AllowRevoked = false,
                AllowRecovery = false
            },
            AllowLegacyMirrorOverlap = false
        };
        var replay = new AcceptingReplayGuard();
        var request = canonicalRequest.Span;
        var (capabilityOffset, capabilityLength, domain) = operation switch
        {
            MailboxClientOperation.Store => (
                48,
                BinaryPrimitives.ReadUInt16BigEndian(request.Slice(32, 2)),
                MailboxCapabilityDomain.Deposit),
            MailboxClientOperation.Retrieve => (
                120,
                BinaryPrimitives.ReadUInt16BigEndian(request.Slice(42, 2)),
                MailboxCapabilityDomain.Retrieve),
            MailboxClientOperation.Acknowledge => (
                120,
                BinaryPrimitives.ReadUInt16BigEndian(request.Slice(34, 2)),
                MailboxCapabilityDomain.Retrieve),
            _ => throw new InvalidOperationException()
        };
        var operationId = request.Slice(16, 16).ToArray();
        var capability = MailboxCapabilityCodec.Decode(
            request.Slice(capabilityOffset, capabilityLength),
            domain,
            policy.CapabilityPolicy,
            replay).Presentation;
        return binding with
        {
            OuterOperationId = operationId.ToArray(),
            CanonicalRequestDigest = SHA256.HashData(canonicalRequest.Span),
            CanonicalCapabilityDigest =
                SHA256.HashData(MailboxCapabilityCodec.Encode(capability)),
            ReplayCounter = capability.ReplayCounter,
            IdempotencyKey = capability.IdempotencyKey.ToArray(),
            ReplayDisposition = MailboxCapabilityReplayDisposition.New
        };
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

    private sealed class SigningFanout(
        MailboxClientReceiptCrypto crypto,
        Action? beforeSign = null,
        bool mutateCursor = false,
        long acceptedAtOffsetSeconds = 0,
        long durableAtOffsetSeconds = 0)
        : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken)
        {
            beforeSign?.Invoke();
            var acceptedAt = AddOffset(
                context.AcceptedAtUnixSeconds,
                acceptedAtOffsetSeconds);
            var durableAt = AddOffset(
                context.AcceptedAtUnixSeconds,
                durableAtOffsetSeconds);
            var encodableDurableAt =
                durableAt >= acceptedAt && durableAt < context.ExpiresAtUnixSeconds
                    ? durableAt
                    : acceptedAt;
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = context.Disposition,
                ReplicaId = crypto.LocalRouterId,
                OperationId = context.OperationId,
                Epoch = context.Epoch,
                Cursor = mutateCursor ? context.Cursor + 1 : context.Cursor,
                AcceptedAtUnixSeconds = acceptedAt,
                DurableAtUnixSeconds = encodableDurableAt,
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
            BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(72, 8), acceptedAt);
            BinaryPrimitives.WriteUInt64BigEndian(encoded.AsSpan(80, 8), durableAt);
            return Task.FromResult<IReadOnlyList<ReadOnlyMemory<byte>>>(
                [encoded]);
        }

        private static ulong AddOffset(ulong value, long offset) =>
            offset >= 0
                ? checked(value + (ulong)offset)
                : checked(value - (ulong)(-offset));
    }

    private sealed class UnavailableFanout : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken) =>
            throw new IOException("simulated peer outage");
    }

    private sealed class ThrowingFanout : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Cached retries must not fan out.");
    }

    private sealed class CountingFanout(
        MailboxClientReceiptCrypto crypto,
        int delayMilliseconds = 40)
        : IMailboxClientReplicaFanout
    {
        private int _calls;
        public bool IsConfigured => true;
        public int CallCount => Volatile.Read(ref _calls);

        public async Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            await Task.Delay(delayMilliseconds, cancellationToken);
            return await new SigningFanout(crypto).StoreAsync(context, cancellationToken);
        }
    }

    private sealed class BlockingInitializationSecurity : IMailboxStorageSecurity
    {
        private readonly ManualResetEventSlim _initializeEntered = new();
        private readonly ManualResetEventSlim _releaseInitialize = new();
        private int _secureDirectoryCalls;

        public void SecureDirectory(string path)
        {
            Directory.CreateDirectory(path);
            if (Interlocked.Increment(ref _secureDirectoryCalls) == 2)
            {
                _initializeEntered.Set();
                _releaseInitialize.Wait();
            }
        }

        public void SecureFile(string path)
        {
        }

        public bool WaitUntilInitializeEntered(TimeSpan timeout) =>
            _initializeEntered.Wait(timeout);

        public void ReleaseInitialization() => _releaseInitialize.Set();
    }

    private sealed class CrashOnFlush(int crashAt) : IMailboxDurabilityBarrier
    {
        private int _flushes;

        public void FlushFileAndParentDirectory(string path)
        {
            if (Interlocked.Increment(ref _flushes) == crashAt)
            {
                throw new SimulatedCrashException();
            }
        }

        public void FlushParentDirectory(string deletedPath) =>
            FlushFileAndParentDirectory(deletedPath);
    }

    private sealed class SimulatedCrashException : Exception;
}
