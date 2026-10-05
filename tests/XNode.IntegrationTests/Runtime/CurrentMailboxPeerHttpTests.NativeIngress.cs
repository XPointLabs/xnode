using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Retrieve)]
    public async Task NativeIngressWrongOuterOperationRejectsBeforeAuthorityOrDurableReplay(
        OnionOperation outer, MailboxAuthenticatedOperation inner)
    {
        await using var f = await Fixture.CreateAsync();
        using var services = NativeServices(f);
        var reads = f.Signed.PublicationReads; var replay = f.Sender.Node.Replay.Diagnostics;
        var ledger = File.ReadAllBytes(f.LedgerFile);
        var result = await NativeDispatcher(services).DispatchAsync(outer, NativeFrame(f, inner), default);
        Assert.Equal(400, result.StatusCode); Assert.Empty(result.CanonicalBody.ToArray());
        Assert.Equal(reads, f.Signed.PublicationReads); Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics);
        Assert.Equal(ledger, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(0, f.AllHttpRequests);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
    }

    [Theory]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Ack)]
    public async Task NativeIngressMatchingOperationStillRequiresCurrentAuthority(
        OnionOperation outer, MailboxAuthenticatedOperation inner)
    {
        await using var f = await Fixture.CreateAsync();
        using var services = NativeServices(f);
        var reads = f.Signed.PublicationReads; var replay = f.Sender.Node.Replay.Diagnostics;
        var ledger = File.ReadAllBytes(f.LedgerFile); f.Signed.RejectProof = true;
        var result = await NativeDispatcher(services).DispatchAsync(outer, NativeFrame(f, inner), default);
        AssertUnknown(result); Assert.Equal(reads + 1, f.Signed.PublicationReads);
        Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics); Assert.Equal(ledger, File.ReadAllBytes(f.LedgerFile));
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(OnionOperation.Store, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Retrieve, MailboxAuthenticatedOperation.Ack)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Store)]
    [InlineData(OnionOperation.Acknowledge, MailboxAuthenticatedOperation.Retrieve)]
    public async Task NativeIngressWrongOuterOperationCannotReserveAnOtherwiseValidSignedRequest(
        OnionOperation outer, MailboxAuthenticatedOperation inner)
    {
        await using var f = await Fixture.CreateAsync();
        await StoreItem(f, 1);
        var page = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f))).Span, f);
        var exact = inner switch
        {
            MailboxAuthenticatedOperation.Store => StoreItemFrame(f, 2),
            MailboxAuthenticatedOperation.Retrieve => RetrieveFrame(f, counter: 2, operation: 0x72),
            MailboxAuthenticatedOperation.Ack => AckFrame(f, page),
            _ => throw new ArgumentOutOfRangeException(nameof(inner))
        };
        using var services = NativeServices(f);
        var dispatcher = NativeDispatcher(services);
        var reads = f.Signed.PublicationReads; var replay = f.Sender.Node.Replay.Diagnostics;
        var outcomes = f.Sender.Node.OutcomeCount;
        var ledger = File.ReadAllBytes(f.LedgerFile);
        Assert.Equal(400, (await dispatcher.DispatchAsync(outer, exact, default)).StatusCode);
        Assert.Equal(reads, f.Signed.PublicationReads); Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics);
        Assert.Equal(ledger, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(1, f.AllHttpRequests);
        Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
        // The exact current issuer/holder-signed counter is still admissible to
        // its real native operation, not just a raw codec/source fixture.
        var accepted = await dispatcher.DispatchAsync(NativeOperation(inner), exact, default);
        Assert.True(accepted.Success); Assert.NotEmpty(accepted.CanonicalBody.ToArray());
        Assert.True(f.Signed.PublicationReads > reads);
        // A later counter in the same grant reuses one replay scope. Scope
        // counts can stay equal: its new durable exact outcome proves acceptance.
        Assert.Equal(outcomes + 1, f.Sender.Node.OutcomeCount);
    }

    [Fact]
    public async Task NativeIngressMalformedRequestsConsumeBudgetWithoutTouchingCurrentOwners()
    {
        await using var f = await Fixture.CreateAsync(); using var services = NativeServices(f);
        var dispatcher = NativeDispatcher(services); var malformed = f.ClientStoreFrame(); malformed[6] = 1;
        var reads = f.Signed.PublicationReads; var replay = f.Sender.Node.Replay.Diagnostics;
        for (var index = 0; index < MailboxWireHttpContract.Store.RequestsPerMinute; index++)
            Assert.Equal(400, (await dispatcher.DispatchAsync(OnionOperation.Store, malformed, default)).StatusCode);
        var throttled = await dispatcher.DispatchAsync(OnionOperation.Store, malformed, default);
        Assert.Equal(429, throttled.StatusCode); Assert.Empty(throttled.CanonicalBody.ToArray());
        Assert.Equal(reads, f.Signed.PublicationReads); Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics);
        Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public async Task NativeIngressCapturesCallerBufferBeforeDependencyCallbacks()
    {
        await using var f = await Fixture.CreateAsync(); var original = f.ClientStoreFrame();
        var exact = original.ToArray();
        using var services = NativeServices(f, () => Array.Clear(original));
        var result = await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, original, default);
        Assert.True(result.Success); Assert.All(original, value => Assert.Equal((byte)0, value));
        var peer = MailboxPeerWireV2Codec.Decode(Assert.Single(f.ExactIntents));
        Assert.Equal(MailboxAuthenticatedClientRequestCodec.Decode(exact).Binding.CanonicalRequest.ToArray(), peer.Payload.ToArray());
        Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync());
        Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync()); Assert.Equal(1, f.AllHttpRequests);
    }

    [Fact]
    public async Task NativeIngressCurrentStoreRetrieveAckRoundTripsBothOwnersAndExactReopen()
    {
        await using var f = await Fixture.CreateAsync();
        byte[] stored, retrieved, acked, ackRequest;
        var storeRequest = f.ClientStoreFrame(); var retrieveRequest = RetrieveFrame(f);
        using (var services = NativeServices(f))
        {
            var dispatcher = NativeDispatcher(services);
            var store = await dispatcher.DispatchAsync(OnionOperation.Store, storeRequest, default);
            Assert.True(store.Success); stored = store.CanonicalBody.ToArray();
            var retrieve = await dispatcher.DispatchAsync(OnionOperation.Retrieve, retrieveRequest, default);
            Assert.True(retrieve.Success); retrieved = retrieve.CanonicalBody.ToArray();
            var page = DecodePage(retrieved, f); Assert.Single(page.Items);
            Assert.Equal(f.Recipient.Envelope, MailboxClientCodec.EncodeEncryptedEnvelope(page.Items[0].Envelope));
            ackRequest = AckFrame(f, page);
            var ack = await dispatcher.DispatchAsync(OnionOperation.Acknowledge, ackRequest, default);
            Assert.True(ack.Success); acked = ack.CanonicalBody.ToArray(); AssertAck(acked, page, 0x74);
        }
        AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests); var intents = f.ExactIntents;
        f.Reopen(); f.Signed.Sample = 101;
        using var reopenedServices = NativeServices(f); var reopened = NativeDispatcher(reopenedServices);
        foreach (var item in new[] { (OnionOperation.Store, storeRequest, stored),
            (OnionOperation.Retrieve, retrieveRequest, retrieved), (OnionOperation.Acknowledge, ackRequest, acked) })
        {
            var replay = await reopened.DispatchAsync(item.Item1, item.Item2, default);
            Assert.True(replay.Success); Assert.Equal(item.Item3, replay.CanonicalBody.ToArray());
        }
        Assert.Equal(intents, f.ExactIntents); Assert.Equal(2, f.AllHttpRequests); AssertTombstones(f, 1);
        Assert.Null(await f.Sender.ReadBlobAsync()); Assert.Null(await f.Recipient.ReadBlobAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeIngressLostStoreOrAckResponseRemainsUnknownAndExactReopenReconciles(bool ack)
    {
        await using var f = await Fixture.CreateAsync(); var operation = OnionOperation.Store; var exact = f.ClientStoreFrame();
        if (ack)
        {
            await StoreItem(f, 1);
            var page = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f))).Span, f);
            operation = OnionOperation.Acknowledge; exact = AckFrame(f, page);
        }
        f.RemoteHost.DropNext = true;
        using (var services = NativeServices(f)) AssertUnknown(await NativeDispatcher(services).DispatchAsync(operation, exact, default));
        var intents = ack ? AckIntents(f) : f.ExactIntents;
        Assert.Single(intents); Assert.Equal(ack ? 2 : 1, f.AllHttpRequests);
        f.Reopen();
        using var reopenedServices = NativeServices(f);
        var resumed = await NativeDispatcher(reopenedServices).DispatchAsync(operation, exact, default);
        Assert.True(resumed.Success); Assert.NotEmpty(resumed.CanonicalBody.ToArray());
        Assert.Equal(intents, ack ? AckIntents(f) : f.ExactIntents); Assert.Equal(ack ? 3 : 2, f.AllHttpRequests);
        if (ack) AssertTombstones(f, 1);
        else { Assert.Equal(f.Recipient.Envelope, await f.Sender.ReadBlobAsync()); Assert.Equal(f.Recipient.Envelope, await f.Recipient.ReadBlobAsync()); }
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public async Task NativeIngressWrongHolderRejectsBeforeReplayOrIntent(MailboxAuthenticatedOperation operation)
    {
        await using var f = await Fixture.CreateAsync(); var decoded = MailboxAuthenticatedClientRequestCodec.Decode(NativeFrame(f, operation));
        var signature = decoded.Presentation.HolderSignature.ToArray(); signature[0] ^= 1;
        var wrong = MailboxAuthenticatedClientRequestCodec.Encode(decoded with { Presentation = decoded.Presentation with { HolderSignature = signature } });
        var replay = f.Sender.Node.Replay.Diagnostics; var ledger = File.ReadAllBytes(f.LedgerFile);
        using var services = NativeServices(f);
        var result = await NativeDispatcher(services).DispatchAsync(NativeOperation(operation), wrong, default);
        Assert.Equal(401, result.StatusCode); Assert.Empty(result.CanonicalBody.ToArray());
        Assert.Equal(replay, f.Sender.Node.Replay.Diagnostics); Assert.Equal(ledger, File.ReadAllBytes(f.LedgerFile));
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public async Task NativeIngressExpiryInsidePeerCallbackSuppressesSuccessAndKeepsExactPending()
    {
        await using var f = await Fixture.CreateAsync(); var exact = f.ClientStoreFrame();
        f.RemoteHost.AfterReceive = receipt => { f.Signed.Sample = 105; return receipt; };
        using (var services = NativeServices(f)) AssertUnknown(await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, exact, default));
        var intents = f.ExactIntents; Assert.Single(intents); Assert.Equal(1, f.AllHttpRequests);
        Assert.Equal(1, f.Sender.Node.Replay.Diagnostics.PendingCount); Assert.Equal(0, f.Sender.Node.OutcomeCount);
        f.Signed.Sample = 100; f.RemoteHost.AfterReceive = null; f.Reopen();
        using var reopenedServices = NativeServices(f);
        Assert.True((await NativeDispatcher(reopenedServices).DispatchAsync(OnionOperation.Store, exact, default)).Success);
        Assert.Equal(intents, f.ExactIntents); Assert.Equal(2, f.AllHttpRequests);
    }

    [Fact]
    public async Task NativeIngressMissingCurrentCompositionNeverResolvesRawAuthorityRuntime()
    {
        await using var f = await Fixture.CreateAsync(); var resolved = 0;
        using var services = new ServiceCollection()
            .AddSingleton<MailboxAuthenticatedCapabilityRuntime>(_ => { resolved++; throw new InvalidOperationException("Raw authority runtime must not be resolved."); })
            .BuildServiceProvider();
        var result = await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, f.ClientStoreFrame(), default);
        Assert.Equal(503, result.StatusCode); Assert.Equal(NativeMailboxDispatchCertainty.RejectedBeforeForward, result.Certainty);
        Assert.Equal(0, resolved); Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.AllHttpRequests);
    }

    [Fact]
    public async Task NativeIngressSplitCoordinatorAndReceiverCannotMutateEitherOwner()
    {
        await using var f = await Fixture.CreateAsync();
        using var services = new ServiceCollection().AddSingleton(f.Recipient.Receiver).AddSingleton(f.Coordinator).BuildServiceProvider();
        AssertUnknown(await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, f.ClientStoreFrame(), default));
        Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount); Assert.Equal(0, f.Recipient.Node.Replay.Diagnostics.ScopeCount);
        Assert.Empty(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    public async Task NativeIngressRetiredOrUnknownRequestVersionRejectsBeforeAuthority(byte version)
    {
        await using var f = await Fixture.CreateAsync(); using var services = NativeServices(f);
        var request = f.ClientStoreFrame(); request[4] = version; var reads = f.Signed.PublicationReads;
        Assert.Equal(400, (await NativeDispatcher(services).DispatchAsync(OnionOperation.Store, request, default)).StatusCode);
        Assert.Equal(reads, f.Signed.PublicationReads); Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.ScopeCount);
        Assert.Empty(f.Sender.MutationFiles); Assert.Equal(0, f.AllHttpRequests);
    }

    private static byte[] NativeFrame(Fixture f, MailboxAuthenticatedOperation operation) => operation switch
    {
        MailboxAuthenticatedOperation.Store => f.ClientStoreFrame(),
        MailboxAuthenticatedOperation.Retrieve => RetrieveFrame(f),
        // This request is canonical and holder-signed; matching positive ACK
        // tests above derive real targets from a native page first.
        MailboxAuthenticatedOperation.Ack => NativeAckFrame(f),
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };
    private static byte[] StoreItemFrame(Fixture f, int index)
    {
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        {
            OperationId = Enumerable.Repeat(checked((byte)(0x80 + index)), 16).ToArray(),
            DeduplicationDigest = Enumerable.Repeat(checked((byte)(0x90 + index)), 32).ToArray(),
            Ciphertext = Enumerable.Repeat(checked((byte)(0xA0 + index)), 64).ToArray()
        };
        return f.ClientStoreFrame(MailboxClientCodec.EncodeEncryptedEnvelope(body), checked((ulong)index));
    }
    private static byte[] NativeAckFrame(Fixture f)
    {
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope);
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(envelope.Epoch,
            Enumerable.Repeat((byte)0x74, 16).ToArray(), envelope.MailboxId, envelope.PlacementId, true, [],
            [new() { Cursor = 1, EnvelopeDigest = envelope.DeduplicationDigest }]);
        var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host, MailboxCapabilityDomain.Retrieve, 0x52);
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant),
                binding, 1, Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
    }
    private static OnionOperation NativeOperation(MailboxAuthenticatedOperation operation) => operation switch
    {
        MailboxAuthenticatedOperation.Store => OnionOperation.Store,
        MailboxAuthenticatedOperation.Retrieve => OnionOperation.Retrieve,
        MailboxAuthenticatedOperation.Ack => OnionOperation.Acknowledge,
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };
    private static ServiceProvider NativeServices(Fixture f, Action? resolving = null) => new ServiceCollection()
        .AddSingleton(f.Sender.Receiver).AddSingleton<CurrentMailboxReplicationCoordinator>(_ =>
        { resolving?.Invoke(); return f.Coordinator; }).BuildServiceProvider();
    private static ILocalNativeMailboxExitDispatcher NativeDispatcher(IServiceProvider services) => new NativeMailboxExitDispatcher(services);
    private static void AssertUnknown(NativeMailboxDispatchResult result)
    {
        Assert.False(result.Success); Assert.Equal(504, result.StatusCode);
        Assert.Equal(NativeMailboxDispatchCertainty.OutcomeUnknownAfterForward, result.Certainty);
        Assert.Empty(result.CanonicalBody.ToArray());
    }
}
