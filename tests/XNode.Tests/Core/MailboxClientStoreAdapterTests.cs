using System.Security.Cryptography;
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

        var reopenedLedger = new MailboxClientOperationLedger(_root, fixture.AdapterOptions);
        var reopened = new MailboxClientStoreAdapter(
            fixture.AdapterOptions,
            fixture.Store,
            reopenedLedger,
            fixture.Verifier,
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
            fixture.Store,
            fixture.Ledger,
            new RejectAllMailboxClientCapabilityVerifier(),
            new SigningFanout(fixture.RemoteCrypto),
            fixture.LocalCrypto,
            _clock);
        Assert.Equal("capability-verifier-missing", noVerifier.Status.Reason);
        Assert.Equal(
            MailboxClientStoreStatus.NotReady,
            (await noVerifier.StoreAsync(new byte[] { 1, 2, 3 })).Status);

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
            fixture.Store,
            fixture.Ledger,
            badVerifier,
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

    private Fixture CreateFixture(bool enabled = true)
    {
        var mailboxOptions = new ReplicatedMailboxOptions { Enabled = true };
        var adapterOptions = new MailboxClientAdapterOptions
        {
            Enabled = enabled,
            MembershipCommitment = Convert.ToHexString(MembershipCommitment).ToLowerInvariant(),
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
            store,
            new MailboxClientOperationLedger(_root, adapterOptions),
            new FixedVerifier(new(
                7,
                MailboxId,
                placementCommitment,
                MailboxClientOperation.Store)),
            localCrypto,
            remoteCrypto);
    }

    private MailboxClientStoreAdapter CreateAdapter(
        Fixture fixture,
        IMailboxClientReplicaFanout fanout) =>
        new(
            fixture.AdapterOptions,
            fixture.Store,
            fixture.Ledger,
            fixture.Verifier,
            fanout,
            fixture.LocalCrypto,
            _clock);

    private static readonly byte[] OperationId = Range(0x10, 16);
    private static readonly byte[] MailboxId = Range(0x30, 32);
    private static readonly byte[] PlacementId = Range(0x50, 32);
    private static readonly byte[] EnvelopeDigest = Range(0x70, 32);
    private static readonly byte[] MembershipCommitment = Range(0xd0, 32);

    private static MailboxEncryptedEnvelope Envelope() => new()
    {
        Epoch = 7,
        MailboxId = new BlindedMailboxId(MailboxId),
        PlacementId = new BlindedPlacementId(PlacementId),
        OperationId = OperationId,
        DeduplicationDigest = EnvelopeDigest,
        CreatedAtUnixSeconds = 1000,
        ExpiresAtUnixSeconds = 1120,
        Ciphertext = Range(0xa0, 32)
    };

    private static MailboxStoreRequest Store(MailboxEncryptedEnvelope envelope) => new()
    {
        Epoch = 7,
        OperationId = OperationId,
        MixedVersion = MailboxMixedVersionMarker.StrictV1,
        DepositCapability = new MailboxCapabilityPresentation
        {
            DomainValue = new RotatingDepositCapability(Range(0x90, 32)),
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 7,
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
        ReplicatedMailboxStore Store,
        MailboxClientOperationLedger Ledger,
        IMailboxClientCapabilityVerifier Verifier,
        MailboxClientReceiptCrypto LocalCrypto,
        MailboxClientReceiptCrypto RemoteCrypto);

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
            var now = 1010UL;
            var unsigned = new MailboxReplicaReceiptV2
            {
                Status = MailboxReceiptStatus.Durable,
                Disposition = MailboxReplicaDisposition.Stored,
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
}
