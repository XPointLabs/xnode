using XNode.Core.NodeDb;

namespace XNode.Tests.Core;

public sealed class NodeDbPersistenceTests
{
    [Fact]
    public async Task NodeDb_PersistsAndLoadsRelayContacts()
    {
        var root = NewTempDirectory();
        try
        {
            var options = Options(root);
            var db = new XNode.Core.NodeDb.NodeDb(options, new FixedClock(TestData.Now));
            await db.InitializeAsync();

            var result = await db.UpsertAsync(TestData.Contact(1, "10.1.1.1"));
            Assert.True(result.Stored);
            Assert.True(result.ShouldGossip);

            var recovered = new XNode.Core.NodeDb.NodeDb(options, new FixedClock(TestData.Now));
            await recovered.InitializeAsync();

            Assert.NotNull(recovered.GetContact(TestData.Id(1)));
            Assert.Equal(1, recovered.Snapshot().KnownRelayContacts);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task NodeDb_AppliesXNodeGossipUpdateRules()
    {
        var root = NewTempDirectory();
        try
        {
            var db = new XNode.Core.NodeDb.NodeDb(Options(root), new FixedClock(TestData.Now));
            await db.InitializeAsync();

            await db.UpsertAsync(TestData.Contact(1, "10.1.1.1"));

            var tooRecent = await db.UpsertAsync(TestData.Contact(1, "10.1.1.1", signedMinutes: 0));
            Assert.False(tooRecent.Stored);
            Assert.Equal("too-recent", tooRecent.Reason);

            var mundane = await db.UpsertAsync(TestData.Contact(1, "10.1.1.1", signedMinutes: 2));
            Assert.True(mundane.Stored);
            Assert.False(mundane.ShouldGossip);

            var addressChange = await db.UpsertAsync(TestData.Contact(1, "10.1.1.1", port: 1199, signedMinutes: 4));
            Assert.True(addressChange.Stored);
            Assert.True(addressChange.ShouldGossip);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FindManyClosestTo_ReturnsRequestedCountInMetricOrder()
    {
        var root = NewTempDirectory();
        try
        {
            var db = new XNode.Core.NodeDb.NodeDb(Options(root), new FixedClock(TestData.Now));
            await db.InitializeAsync();
            await db.UpsertAsync(TestData.Contact(1, "10.1.1.1"));
            await db.UpsertAsync(TestData.Contact(2, "10.1.2.1"));
            await db.UpsertAsync(TestData.Contact(3, "10.1.3.1"));
            db.LoadRegisteredRelaysFallback();

            var closest = db.FindManyClosestTo(TestData.Id(0), 2);

            Assert.Equal(new[] { TestData.Id(1), TestData.Id(2) }, closest);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static NodeDbOptions Options(string root)
    {
        return new NodeDbOptions
        {
            DataDirectory = root,
            LocalRouterId = TestData.Id(255).Value
        };
    }

    private static string NewTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "xnode-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
