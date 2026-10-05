using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentClientRetrieveUsesEitherReplicaMutationCustodyAndExactOutcomeAfterReopen(bool remote)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!)).Status);
        var node = remote ? f.Recipient : f.Sender; var frame = RetrieveFrame(f);
        var first = (await node.Receiver.RetrieveClientAsync(frame)).ToArray();
        var page = DecodePage(first, f); var item = Assert.Single(page.Items);
        Assert.Equal(1UL, item.Cursor); Assert.Equal(f.Recipient.Envelope, MailboxClientCodec.EncodeEncryptedEnvelope(item.Envelope));
        Assert.False(page.HasMore); Assert.Empty(page.ContinuationToken.ToArray());
        f.Reopen(); f.Signed.Sample = 101; node = remote ? f.Recipient : f.Sender;
        Assert.Equal(first, (await node.Receiver.RetrieveClientAsync(frame)).ToArray());
        Assert.Single(f.Sender.MutationFiles); Assert.Single(f.Recipient.MutationFiles); Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentRetrieveContinuationCanChangeReplicaAndExcludesLaterStores()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        await StoreItem(f, 1); await StoreItem(f, 2);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        Assert.True(first.HasMore); Assert.Equal(1UL, Assert.Single(first.Items).Cursor);
        Assert.Equal(232, first.ContinuationToken.Length);
        await StoreItem(f, 3); f.Reopen(); f.Signed.Sample = 101;
        var frame = RetrieveFrame(f, counter: 2, operation: 0x72, after: first.NextCursor, maximum: 1, continuation: first.ContinuationToken);
        var second = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(frame)).ToArray(), f);
        Assert.Equal(2UL, Assert.Single(second.Items).Cursor); Assert.False(second.HasMore);
        var fresh = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 3, operation: 0x73))).ToArray(), f);
        Assert.Equal(new ulong[] { 1, 2, 3 }, fresh.Items.Select(item => item.Cursor));
        Assert.Equal(3, f.RemoteHost.Requests);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("cursor")]
    [InlineData("limit")]
    [InlineData("trailing")]
    public async Task CurrentRetrieveRejectsInvalidContinuationWithoutProducingOutcome(string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        var continuation = first.ContinuationToken.ToArray();
        if (defect == "signature") continuation[^1] ^= 1;
        if (defect == "trailing") continuation = [.. continuation, 1];
        var frame = RetrieveFrame(f, counter: 2, operation: 0x72, after: defect == "cursor" ? 2UL : first.NextCursor,
            maximum: defect == "limit" ? (ushort)2 : (ushort)1, continuation: continuation);
        var outcomes = f.Sender.Node.OutcomeCount;
        Assert.NotNull(await Record.ExceptionAsync(() => f.Sender.Receiver.RetrieveClientAsync(frame).AsTask()));
        Assert.Equal(outcomes, f.Sender.Node.OutcomeCount); Assert.Equal(2, f.RemoteHost.Requests);
        Assert.Equal(2, f.Sender.MutationFiles.Length); Assert.Equal(2, f.Recipient.MutationFiles.Length);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentRetrieveCannotSkipLivePendingCustodyBelowCrossReplicaContinuation(bool reopen)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        var pending = f.ClientStoreFrame();
        f.Sender.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.StoreReserved) throw new IOException("Test-owned interruption after native Store reservation."); };
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(pending, f.Ledger!).AsTask());
        f.Sender.Fault.Action = null;
        Assert.Single(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles);
        Assert.Equal(0, f.RemoteHost.Requests);

        // Exercise the native Retrieve guard independently of the new writer
        // intent barrier. The internal explicit producer admits real signed
        // peer requests; shipping client Store uses the durable ledger overload.
        // No mutation JSON is forged and both grants remain authenticated.
        var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x62);
        for (var index = 2; index <= 3; index++)
        {
            var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
            {
                OperationId = Enumerable.Repeat(checked((byte)(0x80 + index)), 16).ToArray(),
                DeduplicationDigest = Enumerable.Repeat(checked((byte)(0x90 + index)), 32).ToArray()
            };
            var binding = MailboxAuthenticatedRequestTranscript.ForStore(body);
            var client = MailboxAuthenticatedClientRequestCodec.Encode(new()
            {
                Binding = binding,
                Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                    MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant), binding, checked((ulong)index - 1),
                    Enumerable.Repeat((byte)0x57, 32).ToArray())
            });
            var peer = PeerForClient(f, client, checked((ulong)index));
            Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(client, peer)).Status);
        }
        var first = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        Assert.Equal(2UL, Assert.Single(first.Items).Cursor); Assert.True(first.HasMore);
        if (reopen) f.Reopen();
        var continuation = RetrieveFrame(f, operation: 0x72, after: first.NextCursor,
            maximum: 1, continuation: first.ContinuationToken);
        var outcomes = f.Sender.Node.OutcomeCount;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.RetrieveClientAsync(continuation).AsTask());
        Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
        Assert.Equal(3, f.Sender.MutationFiles.Length); Assert.Equal(2, f.Recipient.MutationFiles.Length);
        Assert.Equal(2, f.RemoteHost.Requests);

        // Resume the actual original intent, then the unchanged admitted read.
        Assert.Equal(MailboxPeerQuorumStatus.Durable, (await f.Coordinator.StoreClientAsync(pending, f.Ledger!)).Status);
        var next = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(continuation)).ToArray(), f);
        Assert.Equal(3UL, Assert.Single(next.Items).Cursor); Assert.False(next.HasMore);
        var fresh = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(
            RetrieveFrame(f, counter: 2, operation: 0x73))).ToArray(), f);
        Assert.Equal(new ulong[] { 1, 2, 3 }, fresh.Items.Select(item => item.Cursor));
        Assert.Equal(3, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentRetrieveWrongHolderRejectsBeforeReservation()
    {
        await using var f = await Fixture.CreateAsync();
        var frame = MailboxAuthenticatedClientRequestCodec.Decode(RetrieveFrame(f));
        var signature = frame.Presentation.HolderSignature.ToArray(); signature[0] ^= 1;
        var invalid = MailboxAuthenticatedClientRequestCodec.Encode(frame with
        { Presentation = frame.Presentation with { HolderSignature = signature } });
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.RetrieveClientAsync(invalid).AsTask()));
        Assert.Equal(0, f.Recipient.Node.Replay.Diagnostics.PendingCount); Assert.Equal(0, f.Recipient.Node.OutcomeCount);
        Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentRetrieveLostBlobFailsInsteadOfSilentlyAdvancingPastMessage()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var blobPath = BlobPath(f);
        Assert.True(File.Exists(blobPath)); File.Delete(blobPath); f.Reopen();
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f)).AsTask()));
        Assert.Equal(0, f.Recipient.Node.OutcomeCount); Assert.Single(f.Recipient.MutationFiles); Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentRetrieveSourceExpiryAfterActualBlobReadDoesNotReleasePageAndCanRetry()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var reads = 0;
        f.Recipient.Fault.Action = point =>
        { if (point == MailboxPeerMutationFaultPoint.RetrieveBlobRead) { reads++; f.Signed.Sample = 105; } };
        var exact = RetrieveFrame(f);
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.RetrieveClientAsync(exact).AsTask()));
        Assert.Equal(1, reads); Assert.Equal(0, f.Recipient.Node.OutcomeCount);
        Assert.Equal(1, f.Recipient.Node.Replay.Diagnostics.PendingCount);
        f.Signed.Sample = 100; f.Recipient.Fault.Action = null; f.Reopen();
        var recovered = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(exact)).ToArray(), f);
        Assert.Equal(1UL, Assert.Single(recovered.Items).Cursor); Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentRetrieveRevokedRoleCannotReleaseCachedPage()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var exact = RetrieveFrame(f); _ = await f.Recipient.Receiver.RetrieveClientAsync(exact);
        var prior = MailboxGrantRevocationStoreTests.Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve);
        await f.Recipient.Node.Retrieve.AdvanceAsync(f.Recipient.Node.Host,
            MailboxGrantRevocationStoreTests.Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve, generation: 2,
                prior: prior, serials: [Enumerable.Repeat((byte)0x52, 16).ToArray()]));
        f.Reopen();
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.RetrieveClientAsync(exact).AsTask()));
        Assert.Equal(1, f.Recipient.Node.OutcomeCount); Assert.Single(f.Recipient.MutationFiles); Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentRetrieveTamperedOrOversizedBlobCannotBecomeSuccessfulPage(bool oversized)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); var path = BlobPath(f);
        if (oversized) File.WriteAllText(path, new string('x', new ReplicatedMailboxOptions().MaxBlobBytes * 8 + 1025));
        else
        {
            var blob = JsonNode.Parse(File.ReadAllBytes(path))!;
            var bytes = Convert.FromBase64String(blob["ciphertext"]!.GetValue<string>()); bytes[^1] ^= 1;
            blob["ciphertext"] = Convert.ToBase64String(bytes); File.WriteAllText(path, blob.ToJsonString());
        }
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f)).AsTask()));
        Assert.Equal(0, f.Recipient.Node.OutcomeCount); Assert.Single(f.Recipient.MutationFiles); Assert.Equal(1, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentRetrievePageByteBoundPaginatesWithoutDroppingMaximalEnvelopes()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        for (var index = 1; index <= 16; index++) await StoreItem(f, index, MailboxClientLimits.MaximumCiphertextLength);
        var firstBytes = (await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 100))).ToArray();
        Assert.True(firstBytes.Length <= MailboxClientLimits.MaximumPageBytes);
        var first = DecodePage(firstBytes, f); Assert.True(first.HasMore); Assert.Equal(12, first.Items.Count);
        var secondBytes = (await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2, operation: 0x72,
            after: first.NextCursor, maximum: 100, continuation: first.ContinuationToken))).ToArray();
        Assert.True(secondBytes.Length <= MailboxClientLimits.MaximumPageBytes);
        var second = DecodePage(secondBytes, f); Assert.False(second.HasMore);
        Assert.Equal(Enumerable.Range(1, 16).Select(index => (ulong)index), first.Items.Concat(second.Items).Select(item => item.Cursor));
        Assert.Equal(16, f.RemoteHost.Requests);
    }

    [Fact]
    public async Task CurrentMutationCapacityIncludesActualFileAfterFailedDurableFlushWithoutReopen()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        f.Sender.Reopen(new MutationFlushFaultOnce(), maximumMutations: 1); f.Bind();
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.StoreClientAsync(f.ClientStoreFrame(), f.Ledger!).AsTask());
        Assert.Single(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.RemoteHost.Requests);
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        {
            OperationId = Enumerable.Repeat((byte)0x81, 16).ToArray(),
            DeduplicationDigest = Enumerable.Repeat((byte)0x91, 32).ToArray()
        };
        // A prior Pending claim serializes later counters within the same
        // actual grant. Use a separately signed grant scope so this test reaches
        // the native mutation capacity boundary instead of that admission rule.
        var binding = MailboxAuthenticatedRequestTranscript.ForStore(body);
        var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Sender.Node.Host,
            MailboxCapabilityDomain.Deposit, 0x62);
        var next = MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant), binding, 1,
                Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
        // Test the native quota below the independently checked intent barrier.
        // No native owner reopen: its cache/count must already reflect the
        // durable pending file, rather than accepting a second record over quota.
        await Assert.ThrowsAsync<MailboxPeerMutationCapacityException>(() => f.Coordinator.StoreClientAsync(
            next, PeerForClient(f, next, 2)).AsTask());
        Assert.Single(f.Sender.MutationFiles); Assert.Empty(f.Recipient.MutationFiles); Assert.Equal(0, f.RemoteHost.Requests);
    }

    private sealed class MutationFlushFaultOnce : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier native = new(); private int armed = 1;
        public void FlushFileAndParentDirectory(string path)
        {
            native.FlushFileAndParentDirectory(path);
            if (Interlocked.Exchange(ref armed, 0) == 1) throw new IOException("Test-owned failure after durable mutation flush.");
        }
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath) => native.ReplaceFile(temporaryPath, finalPath);
    }

    [Fact]
    public async Task CurrentRetrieveAmbiguousCursorCustodyIsNotSortedOrOmitted()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2);
        var path = f.Recipient.MutationFiles.Single(path => JsonNode.Parse(File.ReadAllBytes(path))!["cursor"]!.GetValue<ulong>() == 2);
        var record = JsonNode.Parse(File.ReadAllBytes(path))!; record["cursor"] = 1;
        File.WriteAllText(path, record.ToJsonString()); f.Reopen();
        Assert.NotNull(await Record.ExceptionAsync(() => f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f)).AsTask()));
        Assert.Equal(0, f.Recipient.Node.OutcomeCount); Assert.Equal(2, f.Recipient.MutationFiles.Length);
    }

    private static byte[] RetrieveFrame(Fixture f, ulong counter = 1, byte operation = 0x71, ulong after = 0,
        ushort maximum = 10, ReadOnlyMemory<byte> continuation = default)
    {
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope);
        var binding = MailboxAuthenticatedRequestTranscript.ForRetrieve(envelope.Epoch,
            Enumerable.Repeat(operation, 16).ToArray(), envelope.MailboxId, envelope.PlacementId, after, maximum, continuation.Span);
        var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Recipient.Node.Host, MailboxCapabilityDomain.Retrieve, 0x52);
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant), binding, counter, Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
    }
    private static string BlobPath(Fixture f)
    {
        var mutation = JsonNode.Parse(File.ReadAllBytes(Assert.Single(f.Recipient.MutationFiles)))!;
        return Path.Combine(f.Recipient.Node.DataRoot, new ReplicatedMailboxOptions().DirectoryName,
            mutation["mailboxId"]!.GetValue<string>(), $"{mutation["blobId"]!.GetValue<string>()}.json");
    }
    private static async Task StoreItem(Fixture f, int index, int size = 64,
        Xunit.Abstractions.ITestOutputHelper? diagnostics = null)
    {
        var body = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope) with
        {
            OperationId = Enumerable.Repeat(checked((byte)(0x80 + index)), 16).ToArray(),
            DeduplicationDigest = Enumerable.Repeat(checked((byte)(0x90 + index)), 32).ToArray(),
            Ciphertext = Enumerable.Repeat(checked((byte)(0xA0 + index)), size).ToArray()
        };
        var result = await f.Coordinator.StoreClientAsync(
            f.ClientStoreFrame(MailboxClientCodec.EncodeEncryptedEnvelope(body), checked((ulong)index)), f.Ledger!);
        var observation =
            $"Setup Store={result.Status}; durable replicas={result.DurableReplicaCount}; peer calls={f.PeerClient.Calls}; " +
            $"failure={f.PeerClient.Failure}; peer elapsed-ms={f.PeerClient.ElapsedMilliseconds}; peer cancelled={f.PeerClient.Cancelled}; " +
            $"HTTP requests={f.RemoteHost.Requests}; status={f.RemoteHost.LastStatus}; bytes={f.RemoteHost.LastBytes}; {f.RemoteHost.Diagnostics}.";
        diagnostics?.WriteLine(observation);
        Assert.True(result.Status == MailboxPeerQuorumStatus.Durable, observation);
    }
    private static MailboxRetrievePage DecodePage(ReadOnlySpan<byte> bytes, Fixture f) =>
        MailboxClientCodec.DecodeRetrievePage(bytes, new()
        {
            NowUnixSeconds = 1_091 + f.Signed.Sample - 100,
            EpochWindow = new()
            {
                CurrentEpoch = f.Recipient.Node.Host.SelectionEpoch,
                NextEpoch = 0,
                CurrentNotBeforeUnixSeconds = 1_090,
                CurrentExpiresAtUnixSeconds = 1_110,
                NextNotBeforeUnixSeconds = 0,
                NextExpiresAtUnixSeconds = 0
            },
            CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }
        });
}
