using System.Text;
using System.Text.Json.Nodes;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task MutationGrammarPreservesBomWarmReadAndColdOwnerSemantics()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var owner = f.Sender.Mutations;
        var path = Assert.Single(f.Sender.MutationFiles);
        File.WriteAllBytes(path, [0xef, 0xbb, 0xbf, .. File.ReadAllBytes(path)]);
        var lookup = MutationLookupRequest(f);
        var before = owner.MutationGrammarDecodeCount;
        Assert.True(owner.TryResolveTombstonePlacement(lookup, out _));
        Assert.Equal(before + 1, owner.MutationGrammarDecodeCount);
        Assert.True(owner.TryResolveTombstonePlacement(lookup, out _));
        Assert.Equal(before + 1, owner.MutationGrammarDecodeCount);
        await f.Sender.Receiver.InitializeHostAsync();
        Assert.Equal(before + 1, owner.MutationGrammarDecodeCount);
        f.Reopen();
        Assert.Equal((0, 0), owner.MutationGrammarSize);
        Assert.Throws<ObjectDisposedException>((Action)(() => { owner.TryResolveTombstonePlacement(lookup, out _); }));
        Assert.NotSame(owner, f.Sender.Mutations);
        Assert.True(f.Sender.Mutations.MutationGrammarDecodeCount > 0);
        var cold = f.Sender.Mutations.MutationGrammarDecodeCount;
        await f.Sender.Receiver.InitializeHostAsync();
        Assert.True(f.Sender.Mutations.TryResolveTombstonePlacement(lookup, out _));
        Assert.Equal(cold, f.Sender.Mutations.MutationGrammarDecodeCount);
        Assert.Equal(new byte[] { 0xef, 0xbb, 0xbf }, File.ReadAllBytes(path)[..3]);
    }

    [Fact]
    public async Task MutationGrammarWarmSameLengthNativeChangeStillRejectsIndexMismatch()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        await f.Sender.Receiver.InitializeHostAsync();
        var owner = f.Sender.Mutations;
        var before = owner.MutationGrammarDecodeCount;
        var path = Assert.Single(f.Sender.MutationFiles);
        var original = File.ReadAllBytes(path);
        var changed = JsonNode.Parse(original)!; changed["cursor"] = 2UL;
        var damaged = Encoding.UTF8.GetBytes(changed.ToJsonString());
        Assert.Equal(original.Length, damaged.Length);
        var damage = false;
        f.OpenLedger(afterVerifiedRead: () => { if (damage) File.WriteAllBytes(path, damaged); });
        await f.Sender.Receiver.InitializeHostAsync();
        Assert.Equal(before, owner.MutationGrammarDecodeCount);
        damage = true;
        var protectedDocument = File.ReadAllBytes(f.LedgerFile); var requests = f.AllHttpRequests;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.InitializeHostAsync().AsTask());
        Assert.Equal(before + 1, owner.MutationGrammarDecodeCount);
        Assert.Equal(damaged, File.ReadAllBytes(path));
        Assert.Equal(protectedDocument, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(requests, f.AllHttpRequests);
    }

    [Fact]
    public async Task MutationGrammarWarmAuthenticPreAckRollbackStillRejectsProtectedFloor()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        await f.Sender.Receiver.InitializeHostAsync();
        var path = Assert.Single(f.Sender.MutationFiles); var preAck = File.ReadAllBytes(path);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger)).Span, page, 0x74);
        await f.Sender.Receiver.InitializeHostAsync();
        var before = f.Sender.Mutations.MutationGrammarDecodeCount;
        File.WriteAllBytes(path, preAck);
        var protectedDocument = File.ReadAllBytes(f.LedgerFile); var requests = f.AllHttpRequests;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.InitializeHostAsync().AsTask());
        // The old bytes really hit grammar reuse, but not current custody reuse.
        Assert.Equal(before, f.Sender.Mutations.MutationGrammarDecodeCount);
        Assert.Equal(preAck, File.ReadAllBytes(path));
        Assert.Equal(protectedDocument, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(requests, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MutationGrammarEvictsByEntryAndSourceByteBudgetsWithoutAdmittingNativeChanges(bool sourceBudget)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var owner = f.Sender.Mutations; var path = Assert.Single(f.Sender.MutationFiles);
        var original = File.ReadAllBytes(path); var document = JsonNode.Parse(original)!;
        var lookup = MutationLookupRequest(f); var requests = f.AllHttpRequests;
        var protectedDocument = File.ReadAllBytes(f.LedgerFile);
        var count = sourceBudget ? MailboxPeerMutationStore.MaximumMutationGrammarSourceBytes / (16 * 1024) + 1
            : MailboxPeerMutationStore.MaximumMutationGrammarEntries + 1;
        byte[] first = [];
        try
        {
            // Exercise only the existing denial-only native reader with crafted
            // untrusted files, not 1000 real effects or authoritative admissions.
            for (var index = 1; index <= count; index++)
            {
                document["operationId"] = index.ToString("x32");
                var encoded = Encoding.UTF8.GetBytes(document.ToJsonString());
                if (sourceBudget)
                {
                    var padded = new byte[16 * 1024]; padded.AsSpan().Fill((byte)' ');
                    encoded.CopyTo(padded, 0); encoded = padded;
                }
                if (index == 1) first = encoded;
                File.WriteAllBytes(path, encoded);
                Assert.True(owner.TryResolveTombstonePlacement(lookup, out _));
                Assert.InRange(owner.MutationGrammarSize.Entries, 1, MailboxPeerMutationStore.MaximumMutationGrammarEntries);
                Assert.InRange(owner.MutationGrammarSize.SourceBytes, 1, MailboxPeerMutationStore.MaximumMutationGrammarSourceBytes);
            }
            var before = owner.MutationGrammarDecodeCount;
            Assert.True(owner.TryResolveTombstonePlacement(lookup, out _));
            Assert.Equal(before, owner.MutationGrammarDecodeCount);
            File.WriteAllBytes(path, first);
            Assert.True(owner.TryResolveTombstonePlacement(lookup, out _));
            Assert.Equal(before + 1, owner.MutationGrammarDecodeCount);
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.InitializeHostAsync().AsTask());
            Assert.Equal(protectedDocument, File.ReadAllBytes(f.LedgerFile)); Assert.Equal(requests, f.AllHttpRequests);
        }
        finally { File.WriteAllBytes(path, original); }
        await f.Sender.Receiver.InitializeHostAsync();
    }

    private static MailboxPeerWireRequestV2 MutationLookupRequest(Fixture f)
    {
        var store = MailboxPeerWireV2Codec.Decode(Assert.Single(f.ExactIntents));
        return store with
        {
            Operation = MailboxPeerReplicationOperation.Tombstone,
            Payload = MailboxAuthenticatedRequestTranscript.DecodeStoreBody(store.Payload.Span).DeduplicationDigest
        };
    }
}
