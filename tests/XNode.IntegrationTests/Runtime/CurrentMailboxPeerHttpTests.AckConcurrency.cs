using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Retrieve, true)]
    [InlineData(MailboxCapabilityDomain.Retrieve, false)]
    [InlineData(MailboxCapabilityDomain.Deposit, false)]
    public async Task InstalledFloorDuringFirstHttpWaitSuppressesOutcomeAndLaterCursorAndColdRetryKeepsExactBatch(
        MailboxCapabilityDomain changedRole, bool revoke)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); f.OpenRecipientLedger();
        await StoreItem(f, 1, diagnostics: output); await StoreItem(f, 2, diagnostics: output); await StoreItem(f, 3, diagnostics: output);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 2))).Span, f);
        var probe = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2,
            operation: 0x72, after: page.NextCursor, maximum: 2, continuation: page.ContinuationToken))).Span, f);
        Assert.Equal(new ulong[] { 1, 2 }, page.Items.Select(item => item.Cursor));
        Assert.Equal(3UL, Assert.Single(probe.Items).Cursor);
        var exact = AckFrame(f, page); var outcomes = f.Sender.Node.OutcomeCount;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var heldHost = f.RemoteHost;
        heldHost.BeforeResponseAsync = async token => { ready.TrySetResult(); await release.Task.WaitAsync(token); };
        var original = f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask();
        byte[][] intents = [];
        var expectedHttp = 4;
        try
        {
            // The real recipient deleted cursor1 and signed its private reply.
            // Cursor2 has only its original reserved batch intent.
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var store = changedRole == MailboxCapabilityDomain.Deposit ? f.Sender.Node.Deposit : f.Sender.Node.Retrieve;
            var initial = MailboxGrantRevocationStoreTests.Snapshot(f.Signed, changedRole);
            var serials = revoke ? new[] { Repeat(0x52, 16), Repeat(0x53, 16) } : new[] { Repeat(0x53, 16) };
            await store.CatchUpAsync(f.Sender.Node.Host,
                MailboxGrantRevocationStoreTests.Snapshot(f.Signed, changedRole, generation: 2, prior: initial, serials: serials))
                .AsTask().WaitAsync(TimeSpan.FromSeconds(10));
            Assert.Equal(2UL, MailboxGrantRevocationV1Codec.Decode((await store.ReadProtectedAsync()).Span).Generation);
            Assert.False(original.IsCompleted); Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
            Assert.Equal("completed", MutationState(f.Sender, 2)); Assert.Equal("completed", MutationState(f.Recipient, 2));
            intents = AckIntents(f); Assert.Equal(2, intents.Length);
            if (changedRole == MailboxCapabilityDomain.Retrieve)
            {
                // Independent recipient admission may still use its local old
                // floor. The new HTTP forward must respect the installed floor
                // at its actual target before replay reservation or deletion.
                var replayFiles = f.Sender.ReplayFiles.Length;
                f.Bind(true);
                await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(
                    AckFrame(f, probe, operation: 0x75, grantSerial: 0x53, holderSeed: 0x58), f.AckLedger).AsTask());
                Assert.Equal(403, f.RemoteHost.LastStatus); Assert.Equal(replayFiles, f.Sender.ReplayFiles.Length);
                Assert.Equal("completed", MutationState(f.Sender, 3)); expectedHttp++;
            }
        }
        finally { heldHost.BeforeResponseAsync = null; release.TrySetResult(); }
        await Assert.ThrowsAnyAsync<CryptographicException>(() => original);
        Assert.Equal(expectedHttp, f.AllHttpRequests); Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
        Assert.Equal("completed", MutationState(f.Sender, 2)); Assert.Equal("completed", MutationState(f.Recipient, 2));
        f.Bind(false); Assert.Equal(intents, AckIntents(f));
        Assert.All(JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!["ackOperations"]!.AsObject()
            .Single().Value!["items"]!.AsArray(), item => Assert.Equal("", item!["receipt"]!.GetValue<string>()));
        byte[]? warm = null;
        if (!revoke && changedRole == MailboxCapabilityDomain.Retrieve)
        {
            // This same runtime must release exactly its own execution/budget
            // after stale rejection; a cold reopen must not hide a leaked owner.
            warm = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
            AssertAck(warm, page, 0x74); Assert.Equal(expectedHttp + 2, f.AllHttpRequests);
            Assert.Equal(intents, AckIntents(f));
        }
        f.Reopen(); f.Signed.Sample = 101; f.Bind(false);
        if (revoke)
        {
            await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
            Assert.Equal(expectedHttp, f.AllHttpRequests);
            Assert.Equal("completed", MutationState(f.Sender, 2)); Assert.Equal("completed", MutationState(f.Recipient, 2));
        }
        else
        {
            var reply = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
            AssertAck(reply, page, 0x74);
            if (warm is not null) Assert.Equal(warm, reply);
            Assert.Equal(expectedHttp + 2, f.AllHttpRequests);
            Assert.Equal("tombstoned", MutationState(f.Sender, 2)); Assert.Equal("tombstoned", MutationState(f.Recipient, 2));
        }
        Assert.Equal(intents, AckIntents(f));
        output.WriteLine($"Changed {changedRole}; revoked={revoke}; generation2 installed during first response wait; later cursor suppressed; exact intents={intents.Length}.");
    }

    [Fact]
    public async Task CallerCancellationDuringPeerWaitReleasesMemoryAndPinsWithoutErasingExactIntent()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1, diagnostics: output);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).Span, f);
        var exact = AckFrame(f, page); var outcomes = f.Sender.Node.OutcomeCount;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.RemoteHost.BeforeResponseAsync = async token => { ready.TrySetResult(); await release.Task.WaitAsync(token); };
        using var cancellation = new CancellationTokenSource();
        var pending = f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger, cancellation.Token).AsTask();
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10)); cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending).WaitAsync(TimeSpan.FromSeconds(10));
        }
        finally { f.RemoteHost.BeforeResponseAsync = null; release.TrySetResult(); }
        var intents = AckIntents(f); Assert.Single(intents); Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
        var initial = MailboxGrantRevocationStoreTests.Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve);
        await f.Sender.Node.Retrieve.CatchUpAsync(f.Sender.Node.Host,
            MailboxGrantRevocationStoreTests.Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve, generation: 2, prior: initial))
            .AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).Span, page, 0x74);
        Assert.Equal(intents, AckIntents(f)); AssertTombstones(f, 1); Assert.Equal(3, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentLocalEffectsStayExclusiveAndSuspendedScopeCannotAuthorizeLocalWork()
    {
        await using var f = await Fixture.CreateAsync();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var lend = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var waiting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = f.Sender.Node.Admission.WithHostAsync(async (scope, token) =>
        {
            entered.TrySetResult(); await lend.Task.WaitAsync(token);
            return await scope.Lease.AwaitPeerAsync(async peerToken =>
            {
                scope.Lease.RequireActive(); // handoff still owns the original segment
                waiting.TrySetResult(); await release.Task.WaitAsync(peerToken);
                Assert.Throws<InvalidOperationException>(() => scope.Lease.RequireActive());
                return true;
            }, token);
        }).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var second = f.Sender.Node.Admission.WithHostAsync((scope, _) =>
            { scope.Lease.RequireActive(); return ValueTask.FromResult(true); }).AsTask();
            Assert.False(second.IsCompleted);
            lend.TrySetResult(); await waiting.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Assert.True(await second.WaitAsync(TimeSpan.FromSeconds(10))); Assert.False(first.IsCompleted);
        }
        finally { lend.TrySetResult(); release.TrySetResult(); }
        Assert.True(await first.WaitAsync(TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public Task OppositeOriginAcksCompleteThroughRealHttpAndColdRetryIsExact() => OppositeOriginAcksAsync(false);

    [Fact]
    public Task UnchangedPeriodicRefreshDoesNotBlockOppositeHttpAcks() => OppositeOriginAcksAsync(true);

    private async Task OppositeOriginAcksAsync(bool refresh)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); f.OpenRecipientLedger();
        await StoreItem(f, 1, diagnostics: output); await StoreItem(f, 2, diagnostics: output);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).Span, f);
        var second = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2,
            operation: 0x72, after: first.NextCursor, maximum: 1, continuation: first.ContinuationToken))).Span, f);
        Assert.Equal(1UL, Assert.Single(first.Items).Cursor); Assert.Equal(2UL, Assert.Single(second.Items).Cursor);
        var firstRequest = AckFrame(f, first);
        var secondRequest = AckFrame(f, second, operation: 0x75, grantSerial: 0x53, holderSeed: 0x58);
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var arrivals = 0;
        async ValueTask Rendezvous(CancellationToken token)
        {
            if (Interlocked.Increment(ref arrivals) == 2) ready.TrySetResult();
            await release.Task.WaitAsync(token);
        }
        f.PeerClient = new() { BeforeSendAsync = Rendezvous }; f.Bind(false);
        var firstCoordinator = f.Coordinator; var firstLedger = f.AckLedger; var firstClient = f.PeerClient;
        f.PeerClient = new() { BeforeSendAsync = Rendezvous }; f.Bind(true);
        var secondCoordinator = f.Coordinator; var secondLedger = f.AckLedger;
        var firstTask = firstCoordinator.AcknowledgeClientAsync(firstRequest, firstLedger).AsTask();
        var secondTask = secondCoordinator.AcknowledgeClientAsync(secondRequest, secondLedger).AsTask();
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(30));
            if (refresh)
            {
                var artifacts = new ExactRefreshArtifacts(f.Signed);
                await Task.WhenAll(f.Sender.Node.Admission.RefreshRevocationsAsync(artifacts, default).AsTask(),
                    f.Recipient.Node.Admission.RefreshRevocationsAsync(artifacts, default).AsTask()).WaitAsync(TimeSpan.FromSeconds(10));
                Assert.Equal(4, artifacts.Calls);
            }
        }
        finally { release.TrySetResult(); }
        var errors = await Task.WhenAll(Record.ExceptionAsync(async () => { _ = await firstTask; }),
            Record.ExceptionAsync(async () => { _ = await secondTask; }));
        output.WriteLine($"Opposite ACKs: forwards={firstClient.Calls + f.PeerClient.Calls}; HTTP={f.AllHttpRequests}; failures={errors.Count(error => error is not null)}.");
        Assert.All(errors, error => Assert.Null(error));
        var firstReply = (await firstTask).ToArray(); var secondReply = (await secondTask).ToArray();
        AssertAck(firstReply, first, 0x74); AssertAck(secondReply, second, 0x75);
        Assert.Equal(4, f.AllHttpRequests); AssertTombstones(f, 2);
        f.Bind(false); var firstIntents = AckIntents(f); f.Bind(true); var secondIntents = AckIntents(f);
        Assert.Single(firstIntents); Assert.Single(secondIntents);
        f.Reopen(); f.Signed.Sample = 101;
        f.Bind(false);
        Assert.Equal(firstReply, (await f.Coordinator.AcknowledgeClientAsync(firstRequest, f.AckLedger)).ToArray());
        Assert.Equal(firstIntents, AckIntents(f)); f.Bind(true);
        Assert.Equal(secondReply, (await f.Coordinator.AcknowledgeClientAsync(secondRequest, f.AckLedger)).ToArray());
        Assert.Equal(secondIntents, AckIntents(f)); Assert.Equal(4, f.AllHttpRequests); AssertTombstones(f, 2);
    }

    private static byte[] Repeat(byte marker, int count) => Enumerable.Repeat(marker, count).ToArray();

    private static string MutationState(CurrentMailboxReplicaReceiverTests.Fixture peer, ulong cursor) =>
        peer.MutationFiles.Select(path => JsonNode.Parse(File.ReadAllBytes(path))!)
            .Single(record => record["cursor"]!.GetValue<ulong>() == cursor)["state"]!.GetValue<string>();

    private sealed class ExactRefreshArtifacts(DeepIdV2PublicationAuthorityFixture signed) : IMailboxGrantRevocationArtifactSource
    {
        internal int Calls;
        public ValueTask<ReadOnlyMemory<byte>> FetchAsync(ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> policyReference,
            MailboxCapabilityDomain role, ulong? generation, CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Interlocked.Increment(ref Calls);
            var bytes = MailboxGrantRevocationStoreTests.Snapshot(signed, role);
            var parsed = MailboxGrantRevocationV1Codec.Decode(bytes);
            Assert.True(network.Span.SequenceEqual(parsed.Field(1).Span));
            Assert.True(policyReference.Span.SequenceEqual(parsed.Field(2).Span));
            Assert.True(generation is null || generation == parsed.Generation);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(bytes);
        }
    }
}
