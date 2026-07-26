using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class MailboxClientStoreAdapterTests : IDisposable
{
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
        var quorum = MailboxReceiptV2Codec.DecodeDurableQuorum(result.DurableQuorumReceipt.Span);
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

        var reopenedLedger = new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock);
        var reopened = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            reopenedLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new ThrowingFanout(),
            fixture.LocalCrypto,
            _clock);
        await reopened.InitializeAsync();
        var retry = await reopened.StoreAsync(encoded);

        Assert.Equal(MailboxClientStoreStatus.Durable, retry.Status);
        Assert.Equal(firstResult.DurableQuorumReceipt.ToArray(), retry.DurableQuorumReceipt.ToArray());
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

        var fixture = CreateFixture();
        var noVerifier = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            new RejectAllMailboxClientCapabilityVerifier(),
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);
        Assert.Equal("capability-verifier-missing", noVerifier.Status.Reason);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await noVerifier.StoreAsync(new byte[] { 1, 2, 3 })).Status);

        var noAuthorizer = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            new RejectAllMailboxClientReplicaAuthorizer(),
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);
        Assert.Equal("replica-authorizer-missing", noAuthorizer.Status.Reason);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await noAuthorizer.StoreAsync(new byte[] { 1, 2, 3 })).Status);

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
                MailboxClientOperation.Store));
        var unauthorized = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            badVerifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);
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
            MailboxReceiptV2Codec.DecodeDurableQuorum(
                result.DurableQuorumReceipt.Span).CoordinatorSequence));
    }

    [Fact]
    public async Task CrashAfterCompletionReservation_RestartSignsExactPersistedStatement()
    {
        var fixture = CreateFixture();
        var crash = new CrashOnFlush(3);
        var crashLedger = new MailboxClientOperationLedger(
            _root,
            fixture.AdapterOptions,
            _clock,
            durability: crash);
        var crashing = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            crashLedger,
            fixture.Verifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);
        await crashing.InitializeAsync();
        var request = MailboxClientCodec.EncodeStore(Store(Envelope()));
        await Assert.ThrowsAsync<SimulatedCrashException>(() => crashing.StoreAsync(request));

        var reopened = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock),
            fixture.Verifier,
            fixture.Authorizer,
            new ThrowingFanout(),
            fixture.LocalCrypto,
            _clock);
        await reopened.InitializeAsync();
        var recovered = await reopened.StoreAsync(request);

        Assert.Equal(MailboxClientStoreStatus.Durable, recovered.Status);
        Assert.Equal(
            1UL,
            MailboxReceiptV2Codec.DecodeDurableQuorum(
                recovered.DurableQuorumReceipt.Span).CoordinatorSequence);
    }

    [Theory]
    [InlineData("\"nextCursorByMailbox\":{\"0000000000000007:", "\"nextCursorByMailbox\":{\"0000000000000007:", "rewind")]
    [InlineData("\"schemaVersion\":2", "\"schemaVersion\":1", "schema")]
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

        var reopened = new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock);
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
            SHA256.HashData(PlacementId),
            MailboxClientOperation.Store));
        var secondAdapter = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            secondVerifier,
            fixture.Authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);
        var second = await secondAdapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(secondEnvelope)));

        var firstReceipt = MailboxReceiptV2Codec.DecodeDurableQuorum(first.DurableQuorumReceipt.Span);
        var secondReceipt = MailboxReceiptV2Codec.DecodeDurableQuorum(second.DurableQuorumReceipt.Span);
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
        var ledger = new MailboxClientOperationLedger(_root, fixture.AdapterOptions, _clock);
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

        fixture.AdapterOptions.CurrentMembershipCommitment =
            Convert.ToHexString(Range(0x81, 32)).ToLowerInvariant();
        var rotatedMembership = CreateAdapter(fixture, new ThrowingFanout());
        Assert.Equal(
            "cached-quorum-invalid",
            (await rotatedMembership.StoreAsync(request)).Error);

        fixture.AdapterOptions.CurrentMembershipCommitment =
            Convert.ToHexString(MembershipCommitment).ToLowerInvariant();
        var newSeed = Convert.ToHexString(Enumerable.Repeat((byte)0x55, 32).ToArray());
        var newLocal = new MailboxClientReceiptCrypto(
            RelayContactSigner.DeriveRouterId(newSeed),
            newSeed);
        var rotatedKey = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            new FixedAuthorizer([newLocal.LocalRouterId, fixture.RemoteCrypto.LocalRouterId]),
            new ThrowingFanout(),
            newLocal,
            _clock);
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
            SHA256.HashData(PlacementId),
            MailboxClientOperation.Store));
        var authorizer = new RecordingAuthorizer(
            [fixture.LocalCrypto.LocalRouterId, fixture.RemoteCrypto.LocalRouterId]);
        var adapter = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            nextVerifier,
            authorizer,
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);

        var result = await adapter.StoreAsync(
            MailboxClientCodec.EncodeStore(Store(nextEnvelope, 8)));

        Assert.Equal(MailboxClientStoreStatus.Durable, result.Status);
        Assert.Equal(NextMembershipCommitment, authorizer.SeenMembership);
        var receipt = MailboxReceiptV2Codec.DecodeDurableQuorum(result.DurableQuorumReceipt.Span);
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
        var placementCommitment = SHA256.HashData(PlacementId);
        return new(
            adapterOptions,
            mailboxOptions,
            store,
            new MailboxClientOperationLedger(_root, adapterOptions, _clock),
            new FixedVerifier(new(
                7,
                MailboxId,
                placementCommitment,
                MailboxClientOperation.Store)),
            new FixedAuthorizer([localCrypto.LocalRouterId, remoteCrypto.LocalRouterId]),
            localCrypto,
            remoteCrypto);
    }

    private MailboxClientStoreAdapter CreateAdapter(
        Fixture fixture,
        IMailboxClientReplicaFanout fanout) =>
        new(
            fixture.AdapterOptions,
            fixture.StoreOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            fixture.Authorizer,
            fanout,
            fixture.LocalCrypto,
            _clock);

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
        ulong epoch = 7) => new()
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
            NotBeforeBucket = 1000,
            ExpiresAtBucket = 1100,
            OverlapUntilBucket = 0,
            ReplayCounter = 9,
            IdempotencyKey = Range(0x20, 16)
        },
        Envelope = envelope
    };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    public void Dispose()
    {
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

        public ValueTask<MailboxCapabilityBinding?> VerifyAsync(
            ReadOnlyMemory<byte> canonicalRequest,
            MailboxClientOperation operation,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult<MailboxCapabilityBinding?>(binding);
    }

    private sealed class SigningFanout(
        MailboxClientReceiptCrypto crypto,
        Action? beforeSign = null,
        bool mutateCursor = false)
        : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken)
        {
            beforeSign?.Invoke();
            var now = context.AcceptedAtUnixSeconds;
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = context.Disposition,
                ReplicaId = crypto.LocalRouterId,
                OperationId = context.OperationId,
                Epoch = context.Epoch,
                Cursor = mutateCursor ? context.Cursor + 1 : context.Cursor,
                AcceptedAtUnixSeconds = now,
                DurableAtUnixSeconds = now,
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

    private sealed class ThrowingFanout : IMailboxClientReplicaFanout
    {
        public bool IsConfigured => true;

        public Task<IReadOnlyList<ReadOnlyMemory<byte>>> StoreAsync(
            MailboxReplicaStoreContext context,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Cached retries must not fan out.");
    }

    private sealed class CountingFanout(MailboxClientReceiptCrypto crypto)
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
            await Task.Delay(40, cancellationToken);
            return await new SigningFanout(crypto).StoreAsync(context, cancellationToken);
        }
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
    }

    private sealed class SimulatedCrashException : Exception;
}
