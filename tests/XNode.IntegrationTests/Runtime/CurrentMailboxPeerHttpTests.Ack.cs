using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentClientAckUsesEitherReplicaAndExactReplayDoesNotResurrect(bool onRecipient)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        f.Bind(onRecipient); if (onRecipient) f.OpenRecipientLedger();
        var exact = AckFrame(f, page); var reply = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
        AssertAck(reply, page, 0x74); Assert.Equal(2, f.AllHttpRequests);
        AssertTombstones(f, 1); Assert.False(File.Exists(BlobPath(f)));
        if (onRecipient) Assert.Empty(JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!["operations"]!.AsObject());
        f.Reopen(); f.Signed.Sample = 101;
        Assert.Equal(reply, (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray());
        Assert.Equal(2, f.AllHttpRequests); AssertTombstones(f, 1);
        Assert.Empty(DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2, operation: 0x75))).ToArray(), f).Items);
    }

    [Fact]
    public async Task CurrentClientAckLostPeerResponseKeepsExactIntentAndCompletesAfterReopen()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var exact = AckFrame(f, page); var outcomes = f.Sender.Node.OutcomeCount; f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        var intents = AckIntents(f); Assert.Single(intents); Assert.Equal(outcomes, f.Sender.Node.OutcomeCount);
        AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests);
        f.Reopen(); f.Signed.Sample = 101;
        var reply = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray(); AssertAck(reply, page, 0x74);
        Assert.Equal(intents, AckIntents(f)); Assert.Equal(3, f.AllHttpRequests); AssertTombstones(f, 1);
    }

    [Fact]
    public async Task CurrentClientAckPageTokenWorksAcrossReplicasAndRemainingPageIsStillRetrievable()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2); await StoreItem(f, 3);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        f.Bind(true); f.OpenRecipientLedger();
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, first), f.AckLedger)).Span, first, 0x74);
        var remaining = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 2, operation: 0x76,
            after: first.NextCursor, maximum: 1, continuation: first.ContinuationToken))).ToArray(), f);
        Assert.Equal(2UL, Assert.Single(remaining.Items).Cursor);
        var rest = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f, counter: 3, operation: 0x77))).ToArray(), f);
        Assert.Equal(new ulong[] { 2, 3 }, rest.Items.Select(item => item.Cursor));
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, rest, counter: 2, operation: 0x78), f.AckLedger)).Span, rest, 0x78);
        AssertTombstones(f, 3); Assert.Equal(6, f.AllHttpRequests);
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("page-digest")]
    [InlineData("trailing")]
    public async Task CurrentClientAckRejectsHostileContinuationBeforeIntentOrTombstone(string defect)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2);
        var page = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        var token = page.ContinuationToken.ToArray(); if (defect == "signature") token[^1] ^= 1;
        if (defect == "trailing") token = [.. token, 1];
        var items = page.Items.Select(item => item.ToAcknowledgement()).ToArray();
        if (defect == "page-digest") items[0] = items[0] with { EnvelopeDigest = Enumerable.Repeat((byte)0xDA, 32).ToArray() };
        var exact = AckFrame(f, page, continuation: token, acknowledgements: items);
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        Assert.Empty(AckIntents(f)); Assert.Equal(2, f.AllHttpRequests);
        Assert.All(f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles), path => Assert.Equal("completed", JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>()));
    }

    private static byte[] AckFrame(Fixture f, MailboxRetrievePage page, ulong counter = 1, byte operation = 0x74,
        ReadOnlyMemory<byte>? continuation = null, IReadOnlyList<MailboxAcknowledgement>? acknowledgements = null)
    {
        var envelope = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(f.Recipient.Envelope);
        var binding = MailboxAuthenticatedRequestTranscript.ForAck(envelope.Epoch, Enumerable.Repeat(operation, 16).ToArray(),
            envelope.MailboxId, envelope.PlacementId, !page.HasMore, (continuation ?? page.ContinuationToken).Span,
            acknowledgements ?? page.Items.Select(item => item.ToAcknowledgement()).ToArray());
        var grant = MailboxGrantRevocationStoreTests.Grant(f.Signed, f.Recipient.Node.Host, MailboxCapabilityDomain.Retrieve, 0x52);
        return MailboxAuthenticatedClientRequestCodec.Encode(new()
        {
            Binding = binding,
            Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant),
                binding, counter, Enumerable.Repeat((byte)0x57, 32).ToArray())
        });
    }
    private static byte[][] AckIntents(Fixture f) => !File.Exists(f.AckLedgerFile) ? [] : JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!["ackOperations"]!.AsObject()
        .SelectMany(operation => operation.Value!["items"]!.AsArray()).Select(item => Convert.FromBase64String(item!["peerRequest"]!.GetValue<string>())).ToArray();
    private static void AssertTombstones(Fixture f, int count)
    {
        Assert.Equal(count, f.Sender.MutationFiles.Length); Assert.Equal(count, f.Recipient.MutationFiles.Length);
        Assert.All(f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles), path => Assert.Equal("tombstoned", JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>()));
    }
    private static void AssertAck(ReadOnlySpan<byte> bytes, MailboxRetrievePage page, byte operation)
    {
        var aggregate = MailboxAggregateAckCodec.DecodeMqr3(bytes); Assert.Equal(page.Epoch, aggregate.Epoch);
        Assert.Equal(Enumerable.Repeat(operation, 16), aggregate.OperationId.ToArray());
        Assert.Equal(page.Items.Count, aggregate.TombstoneQuorums.Count);
        for (var index = 0; index < page.Items.Count; index++)
        {
            var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(aggregate.TombstoneQuorums[index].Span);
            Assert.Equal(page.Items[index].Cursor, quorum.FirstReplica.Cursor); Assert.Equal(page.Items[index].Cursor, quorum.SecondReplica.Cursor);
            Assert.Equal(MailboxReplicaDisposition.Tombstone, quorum.FirstReplica.Disposition);
            Assert.Equal(MailboxReplicaDisposition.Tombstone, quorum.SecondReplica.Disposition);
            Assert.False(quorum.FirstReplica.ReplicaId.Span.SequenceEqual(quorum.SecondReplica.ReplicaId.Span));
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task CurrentClientAckIntentWriteFailurePreservesUnknownOrExactRecoveryWithoutPeerEffects(bool beforeReplace)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        f.OpenLedger(new IntentWriteFault(beforeReplace)); var exact = AckFrame(f, page);
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        Assert.Equal(1, f.AllHttpRequests);
        Assert.All(f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles), path => Assert.Equal("completed", JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>()));
        var intents = AckIntents(f); Assert.Equal(beforeReplace ? 0 : 1, intents.Length);
        if (beforeReplace)
        {
            var pending = JsonNode.Parse(File.ReadAllBytes(Assert.Single(Directory.GetFiles(Path.GetDirectoryName(f.AckLedgerFile)!, "operations.json.*.tmp"))))!;
            intents = pending["ackOperations"]!.AsObject().Single().Value!["items"]!.AsArray()
                .Select(item => Convert.FromBase64String(item!["peerRequest"]!.GetValue<string>())).ToArray();
        }
        f.Reopen();
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).Span, page, 0x74);
        Assert.Equal(intents, AckIntents(f)); AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests);
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(f.AckLedgerFile)!, "operations.json.*.tmp"));
    }

    [Fact]
    public async Task CurrentClientAckLostIntentCannotRemintAlreadyReservedTombstone()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var exact = AckFrame(f, page); f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        f.Ledger!.Dispose(); f.Ledger = null;
        var document = JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!; document["ackOperations"]!.AsObject().Clear();
        File.WriteAllText(f.AckLedgerFile, document.ToJsonString()); f.OpenLedger();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        Assert.Empty(AckIntents(f)); AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientAckChangedSavedSignatureRejectsBeforeAnotherPeerEffect()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var exact = AckFrame(f, page); f.RemoteHost.DropNext = true;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        f.Ledger!.Dispose(); f.Ledger = null;
        var document = JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!;
        var item = document["ackOperations"]!.AsObject().First().Value!["items"]!.AsArray()[0]!;
        var bytes = Convert.FromBase64String(item["peerRequest"]!.GetValue<string>()); bytes[^1] ^= 1;
        item["peerRequest"] = Convert.ToBase64String(bytes); f.OpenLedger();
        await f.InstallTestOwnedDocumentAsync(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        var saved = File.ReadAllBytes(f.AckLedgerFile);
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        Assert.Equal(saved, File.ReadAllBytes(f.AckLedgerFile)); Assert.Equal(2, f.AllHttpRequests); AssertTombstones(f, 1);
    }

    [Fact]
    public async Task CurrentClientAckCapacityRejectsWithoutCollectingOrDeletingActualTargets()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        f.Bind(true); f.OpenRecipientLedger(maximumEntries: 1);
        await Assert.ThrowsAsync<XNode.Core.Mailbox.Client.MailboxClientLedgerCapacityException>(() =>
            f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger).AsTask());
        Assert.Empty(AckIntents(f)); Assert.Equal(1, f.AllHttpRequests); Assert.Equal(1, f.Recipient.Node.OutcomeCount);
        Assert.All(f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles), path => Assert.Equal("completed", JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>()));
    }

    [Fact]
    public async Task CurrentClientAckSourceExpiryAfterPeerDeletionKeepsPendingAndRecoversExactIntent()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f); var exact = AckFrame(f, page);
        var outcomes = f.Sender.Node.OutcomeCount;
        f.RemoteHost.AfterReceive = reply => { f.Signed.Sample = 105; return reply; };
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask()));
        var intents = AckIntents(f); Assert.Single(intents); Assert.Equal(outcomes, f.Sender.Node.OutcomeCount); AssertTombstones(f, 1);
        f.RemoteHost.AfterReceive = null; f.Signed.Sample = 100; f.Reopen();
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).Span, page, 0x74);
        Assert.Equal(intents, AckIntents(f)); Assert.Equal(3, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientAckCrashAfterRemoteBlobDeletionResumesPendingNativeTombstone()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f); var exact = AckFrame(f, page);
        var reached = 0; f.Recipient.Fault.Action = point =>
        {
            if (point == XNode.Core.Mailbox.MailboxPeerMutationFaultPoint.TombstoneBlobDeleted)
            { reached++; throw new IOException("Test-owned interruption after native blob deletion."); }
        };
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        Assert.Equal(1, reached); var intents = AckIntents(f);
        Assert.Equal("tombstone-pending", JsonNode.Parse(File.ReadAllBytes(Assert.Single(f.Recipient.MutationFiles)))!["state"]!.GetValue<string>());
        Assert.False(File.Exists(BlobPath(f))); f.Recipient.Fault.Action = null; f.Reopen();
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).Span, page, 0x74);
        Assert.Equal(intents, AckIntents(f)); AssertTombstones(f, 1); Assert.Equal(3, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientAckConcurrentExactRequestsCreateOneIntentAndOnePeerDeletion()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f); var exact = AckFrame(f, page);
        var replies = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
            (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray()));
        Assert.All(replies, reply => Assert.Equal(replies[0], reply)); Assert.Single(AckIntents(f));
        AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientAckNewOperationCannotRebindAlreadyTombstonedTarget()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        _ = await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger); var intents = AckIntents(f);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.AcknowledgeClientAsync(
            AckFrame(f, page, counter: 2, operation: 0x79), f.AckLedger).AsTask());
        Assert.Equal(intents, AckIntents(f)); AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientAckRevokedRoleCannotReleaseCachedAggregate()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f); var exact = AckFrame(f, page);
        _ = await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger); var outcomes = f.Sender.Node.OutcomeCount;
        var prior = MailboxGrantRevocationStoreTests.Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve);
        await f.Sender.Node.Retrieve.AdvanceAsync(f.Sender.Node.Host,
            MailboxGrantRevocationStoreTests.Snapshot(f.Signed, MailboxCapabilityDomain.Retrieve, generation: 2,
                prior: prior, serials: [Enumerable.Repeat((byte)0x52, 16).ToArray()]));
        f.Reopen();
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask()));
        Assert.Equal(outcomes, f.Sender.Node.OutcomeCount); AssertTombstones(f, 1); Assert.Equal(2, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientAckWrongHolderRejectsBeforeIntentAndNativeReplay()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        var decoded = MailboxAuthenticatedClientRequestCodec.Decode(AckFrame(f, page));
        var signature = decoded.Presentation.HolderSignature.ToArray(); signature[^1] ^= 1;
        var invalid = MailboxAuthenticatedClientRequestCodec.Encode(decoded with
        { Presentation = decoded.Presentation with { HolderSignature = signature } });
        Assert.NotNull(await Record.ExceptionAsync(() => f.Coordinator.AcknowledgeClientAsync(invalid, f.AckLedger).AsTask()));
        Assert.Empty(AckIntents(f)); Assert.Equal(0, f.Sender.Node.Replay.Diagnostics.PendingCount); Assert.Equal(1, f.AllHttpRequests);
        Assert.All(f.Sender.MutationFiles.Concat(f.Recipient.MutationFiles), path => Assert.Equal("completed", JsonNode.Parse(File.ReadAllBytes(path))!["state"]!.GetValue<string>()));
    }

    [Fact]
    public async Task CurrentClientAckDurableItemQuorumRecoversWithoutPeerDispatchAfterFlushError()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f); var exact = AckFrame(f, page);
        f.OpenLedger(new AckQuorumFlushFault()); var outcomes = f.Sender.Node.OutcomeCount;
        await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        var operation = JsonNode.Parse(File.ReadAllBytes(f.AckLedgerFile))!["ackOperations"]!.AsObject().Single().Value!;
        var item = operation["items"]!.AsArray().Single()!; Assert.Equal("durable", item["state"]!.GetValue<string>());
        var quorum = Convert.FromBase64String(item["receipt"]!.GetValue<string>()); var intents = AckIntents(f);
        Assert.Equal(outcomes, f.Sender.Node.OutcomeCount); Assert.Equal(2, f.AllHttpRequests); AssertTombstones(f, 1);
        f.Reopen(); f.Signed.Sample = 101;
        var aggregate = MailboxAggregateAckCodec.DecodeMqr3((await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).Span);
        Assert.Equal(quorum, Assert.Single(aggregate.TombstoneQuorums).ToArray()); Assert.Equal(intents, AckIntents(f));
        Assert.Equal(2, f.AllHttpRequests); AssertTombstones(f, 1);
    }

    private sealed class AckQuorumFlushFault : XNode.Core.Mailbox.IMailboxDurabilityBarrier
    {
        private readonly XNode.Core.Mailbox.MailboxDurabilityBarrier native = new(); private int flushes;
        public void FlushFileAndParentDirectory(string path)
        {
            native.FlushFileAndParentDirectory(path);
            if (Interlocked.Increment(ref flushes) == 2) throw new IOException("Test-owned failure after durable item-quorum flush.");
        }
        public void FlushParentDirectory(string path) => native.FlushParentDirectory(path);
        public void ReplaceFile(string temporaryPath, string finalPath) => native.ReplaceFile(temporaryPath, finalPath);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentClientAckExpiredPageTokenDoesNotReplaceSavedIntentOrOutcome(bool pending)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        var page = first with { ContinuationToken = ShortLivedPageToken(f, first) }; var exact = AckFrame(f, page);
        byte[]? completed = null;
        if (pending)
        {
            f.RemoteHost.DropNext = true;
            await Assert.ThrowsAsync<IOException>(() => f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger).AsTask());
        }
        else completed = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
        var intents = AckIntents(f); f.Reopen(); f.Signed.Sample = 102;
        var recovered = (await f.Coordinator.AcknowledgeClientAsync(exact, f.AckLedger)).ToArray();
        AssertAck(recovered, page, 0x74); if (completed is not null) Assert.Equal(completed, recovered);
        Assert.Equal(intents, AckIntents(f)); Assert.Equal(pending ? 4 : 3, f.AllHttpRequests);
        await Assert.ThrowsAsync<CryptographicException>(() => f.Coordinator.AcknowledgeClientAsync(
            AckFrame(f, page, counter: 2, operation: 0x79), f.AckLedger).AsTask());
        Assert.Equal(intents, AckIntents(f)); Assert.Equal(pending ? 4 : 3, f.AllHttpRequests);
    }

    [Fact]
    public async Task CurrentClientRetrieveExpiredPageTokenDoesNotBlockExactSavedOutcome()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1); await StoreItem(f, 2);
        var first = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f, maximum: 1))).ToArray(), f);
        var token = ShortLivedPageToken(f, first);
        var exact = RetrieveFrame(f, counter: 2, operation: 0x72, after: first.NextCursor, maximum: 1, continuation: token);
        var completed = (await f.Sender.Receiver.RetrieveClientAsync(exact)).ToArray(); f.Reopen(); f.Signed.Sample = 102;
        Assert.Equal(completed, (await f.Sender.Receiver.RetrieveClientAsync(exact)).ToArray());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Sender.Receiver.RetrieveClientAsync(
            RetrieveFrame(f, counter: 3, operation: 0x79, after: first.NextCursor, maximum: 1, continuation: token)).AsTask());
        Assert.Equal(2, f.AllHttpRequests);
    }

    private static byte[] ShortLivedPageToken(Fixture f, MailboxRetrievePage page)
    {
        // Same actual fixture descriptor signer and canonical page statement;
        // pagination expires before its independently verified grant/time source.
        var token = page.ContinuationToken.ToArray();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(token.AsSpan(24), checked(f.Signed.Freshness.TrustedUpperUnixSeconds + 1));
        var privateKey = Sodium.PublicKeyAuth.GenerateKeyPair(f.Signed.Node(f.Sender.Node.Node).Seed).PrivateKey;
        try { Sodium.PublicKeyAuth.SignDetached(token.AsSpan(0, 168).ToArray(), privateKey).CopyTo(token, 168); }
        finally { CryptographicOperations.ZeroMemory(privateKey); }
        return token;
    }
}
