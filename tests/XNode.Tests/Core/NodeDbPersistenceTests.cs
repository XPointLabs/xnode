using XNode.Core;
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
            db.SetRegisteredRelays([TestData.Id(1), TestData.Id(2), TestData.Id(3)]);

            var closest = db.FindManyClosestTo(TestData.Id(0), 2);

            Assert.Equal(new[] { TestData.Id(1), TestData.Id(2) }, closest);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UpsertAndRegisterAsync_StoresContactAndMembershipUnderOneGate()
    {
        var root = NewTempDirectory();
        try
        {
            var db = new XNode.Core.NodeDb.NodeDb(Options(root), new FixedClock(TestData.Now));
            await db.InitializeAsync();
            var contact = TestData.Contact(1, "10.1.1.1");

            var result = await db.UpsertAndRegisterAsync(contact);

            Assert.True(result.Stored);
            Assert.Equal(contact, db.GetContact(contact.RouterId));
            Assert.True(db.IsRegistered(contact.RouterId));
            Assert.Equal(1, db.Snapshot().RegisteredRelays);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task NodeDb_ConcurrentUpdatesPersistTheNewestContactWithoutTempCollisions()
    {
        var root = NewTempDirectory();
        try
        {
            var options = Options(root);
            var db = new XNode.Core.NodeDb.NodeDb(options, new FixedClock(TestData.Now));
            await db.InitializeAsync();

            var updates = Enumerable.Range(0, 12)
                .Select(index => TestData.Contact(1, $"10.2.0.{index + 1}", 1200 + index, signedMinutes: index * 2))
                .ToArray();
            await Task.WhenAll(updates.Select(contact => db.UpsertAsync(contact)));

            var expected = db.GetContact(TestData.Id(1));
            Assert.NotNull(expected);

            var recovered = new XNode.Core.NodeDb.NodeDb(options, new FixedClock(TestData.Now));
            await recovered.InitializeAsync();
            var persisted = recovered.GetContact(TestData.Id(1));

            Assert.NotNull(persisted);
            Assert.Equal(expected.SignedAt, persisted.SignedAt);
            Assert.Equal(expected.PublicHost, persisted.PublicHost);
            Assert.Empty(Directory.EnumerateFiles(Path.Combine(root, "nodedb"), "*.tmp"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task RegisteredRelayCatalogSnapshot_RemainsAtomicAndImmutableAcrossConcurrentUpdates()
    {
        var root = NewTempDirectory();
        try
        {
            var db = new XNode.Core.NodeDb.NodeDb(Options(root), new FixedClock(TestData.Now));
            await db.InitializeAsync();
            await db.UpsertAndRegisterAsync(ContactWithOnionKey(1, "aa", signedMinutes: 0));
            await db.UpsertAndRegisterAsync(ContactWithOnionKey(2, "aa", signedMinutes: 0));
            await db.UpsertAndRegisterAsync(ContactWithOnionKey(3, "bb", signedMinutes: 0));

            var snapshotCaptured = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var updatesCompleted = new TaskCompletionSource(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var reader = Task.Run(async () =>
            {
                var oldSnapshot = db.GetRegisteredRelayCatalogSnapshot();
                snapshotCaptured.SetResult();
                await updatesCompleted.Task;
                return OnionKeys(oldSnapshot);
            });
            var writer = Task.Run(async () =>
            {
                await snapshotCaptured.Task;
                await db.UpsertAndRegisterAsync(ContactWithOnionKey(3, "aa", signedMinutes: 2));
                var middleSnapshot = db.GetRegisteredRelayCatalogSnapshot();
                await db.UpsertAndRegisterAsync(ContactWithOnionKey(1, "cc", signedMinutes: 2));
                await db.UpsertAndRegisterAsync(ContactWithOnionKey(2, "cc", signedMinutes: 2));
                updatesCompleted.SetResult();
                return OnionKeys(middleSnapshot);
            });

            var oldKeys = await reader;
            var middleKeys = await writer;
            var finalSnapshot = db.GetRegisteredRelayCatalogSnapshot();
            var finalKeys = OnionKeys(finalSnapshot);

            Assert.Equal(["aa", "aa", "bb"], oldKeys);
            Assert.Equal(["aa", "aa", "aa"], middleKeys);
            Assert.Equal(["cc", "cc", "aa"], finalKeys);
            Assert.All(
                new[] { oldKeys, middleKeys, finalKeys },
                static keys => Assert.True(keys.Distinct(StringComparer.OrdinalIgnoreCase).Count() < keys.Length));
            Assert.Equal(3, finalSnapshot.RegisteredRelayCount);

            var leakedContact = finalSnapshot.GetContact(TestData.Id(1))!;
            leakedContact.Capabilities[0] = "mutated";
            Assert.Equal(
                "session-rpc",
                finalSnapshot.GetContact(TestData.Id(1))!.Capabilities[0]);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static RelayContact ContactWithOnionKey(byte id, string keyByte, int signedMinutes)
    {
        var contact = TestData.Contact(id, $"10.3.0.{id}", signedMinutes: signedMinutes);
        return contact with
        {
            X25519PublicKey = string.Concat(Enumerable.Repeat(keyByte, 32)),
            Capabilities = ["session-rpc", "onion-v1"]
        };
    }

    private static string[] OnionKeys(RegisteredRelayCatalogSnapshot snapshot) =>
        snapshot.GetContacts()
            .Select(static contact => contact.X25519PublicKey[..2])
            .ToArray();

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
