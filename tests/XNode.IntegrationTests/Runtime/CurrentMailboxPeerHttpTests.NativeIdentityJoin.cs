using System.Text;
using System.Text.Json.Nodes;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData("storeDigest")]
    [InlineData("tombstoneDigest")]
    public async Task FreshNativeIdentityJoinChecksEveryProtectedFloorAfterWarmJoin(string field)
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger(); await StoreItem(f, 1);
        var page = DecodePage((await f.Recipient.Receiver.RetrieveClientAsync(RetrieveFrame(f))).ToArray(), f);
        AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger)).Span, page, 0x74);
        await f.Sender.Receiver.InitializeHostAsync();
        await f.Sender.Receiver.InitializeHostAsync();

        var document = JsonNode.Parse(File.ReadAllBytes(f.LedgerFile))!;
        var floors = document["peerReplayFloors"]!.AsObject().Select(pair => pair.Value!).ToArray();
        var tombstone = Assert.Single(floors, floor => floor["tombstoneDigest"]!.GetValue<string>().Length != 0);
        Assert.Equal(2, floors.Count(floor => floor["targetKey"]!.GetValue<string>() == tombstone["targetKey"]!.GetValue<string>()));
        var original = tombstone[field]!.GetValue<string>();
        tombstone[field] = new string(original[0] == 'a' ? 'b' : 'a', 64);
        await f.InstallTestOwnedDocumentAsync(Encoding.UTF8.GetBytes(document.ToJsonString()));
        var protectedDocument = File.ReadAllBytes(f.LedgerFile);
        var native = f.Sender.MutationFiles.Concat(f.Sender.ReplayFiles).ToDictionary(path => path, File.ReadAllBytes);
        var requests = f.AllHttpRequests;

        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.InitializeHostAsync().AsTask());
        Assert.Equal(protectedDocument, File.ReadAllBytes(f.LedgerFile));
        foreach (var row in native) Assert.Equal(row.Value, File.ReadAllBytes(row.Key));
        Assert.Equal(requests, f.AllHttpRequests);
    }
}
