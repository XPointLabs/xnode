using System.Security.Cryptography;
using System.Text;
using XNode.Core.ContactResolver;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

public sealed class ContactResolverOpaqueStoreTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 7, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DcrPublicationSurvivesRestartAndReturnsDefensiveOpaqueCopies()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        var locator = Hash("locator/restart");
        var ciphertext = Ciphertext("dcr/restart", 96);
        var request = DcrRequest(locator, "restart/0", 0, Zero32(), ciphertext, clock);

        using (var store = fixture.Open(clock))
        {
            Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(request).Disposition);
        }

        using (var store = fixture.Open(clock))
        {
            var first = store.ResolveCurrentDcr(locator);
            Assert.Equal(ContactResolverReadDisposition.Current, first.Disposition);
            Assert.Equal(ciphertext, first.Publication!.Ciphertext);
            first.Publication.Ciphertext[0] ^= 0xff;
            first.Publication.ObjectCiphertextHash[0] ^= 0xff;
            var second = store.ResolveCurrentDcr(locator);
            Assert.Equal(ciphertext, second.Publication!.Ciphertext);
            Assert.Equal(SHA256.HashData(ciphertext), second.Publication.ObjectCiphertextHash);
        }
    }

    [Fact]
    public async Task ConcurrentExactDcrReplayCommitsExactlyOnce()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        using var store = fixture.Open(clock);
        var request = DcrRequest(Hash("locator/replay"), "replay/0", 0, Zero32(), Ciphertext("dcr/replay", 64), clock, 1);
        var results = await Task.WhenAll(Enumerable.Range(0, 24)
            .Select(_ => Task.Run(() => store.PublishDcr(request).Disposition)));
        Assert.Equal(1, results.Count(x => x == ContactResolverMutationDisposition.Committed));
        Assert.Equal(23, results.Count(x => x == ContactResolverMutationDisposition.ExactReplay));
    }

    [Fact]
    public void OneTimeResolveCommitsOnceAndReplaysExactlyAcrossRestart()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        var locator = Hash("locator/one-time");
        var publication = DcrRequest(
            locator,
            "one-time/publish",
            0,
            Zero32(),
            Ciphertext("one-time/dcr", 64),
            clock,
            usageLimit: 1);
        var operation = Hash("operation/one-time/redeem");
        var requestHash = Hash("request/one-time/redeem");
        var routeClosure = Enumerable.Repeat((byte)0x41,
            OpaqueDcrResolveRequest.MinimumRouteClosureBytes).ToArray();
        var responseTime = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());

        using (var store = fixture.Open(clock))
        {
            Assert.Equal(
                ContactResolverMutationDisposition.Committed,
                store.PublishDcr(publication).Disposition);
            var committed = store.ResolveDcr(
                new OpaqueDcrResolveRequest(
                    locator, operation, requestHash, routeClosure, responseTime));
            Assert.Equal(ContactResolverResolveDisposition.Committed, committed.Disposition);
            Assert.Equal<ulong>(1, committed.ClaimCommitGeneration);
            Assert.Equal(publication.Ciphertext.ToArray(), committed.Publication!.Ciphertext);
            Assert.Equal(routeClosure, committed.CanonicalRouteClosure);
            Assert.Equal(responseTime, committed.ResponseUnixSeconds);

            var replay = store.ResolveDcr(
                new OpaqueDcrResolveRequest(locator, operation, requestHash));
            Assert.Equal(ContactResolverResolveDisposition.ExactReplay, replay.Disposition);
            Assert.Equal(committed.ClaimCommitGeneration, replay.ClaimCommitGeneration);
            Assert.Equal(committed.Publication!.Ciphertext, replay.Publication!.Ciphertext);
            Assert.Equal(routeClosure, replay.CanonicalRouteClosure);

            var changedRequest = store.ResolveDcr(new OpaqueDcrResolveRequest(
                locator, operation, Hash("request/one-time/changed")));
            Assert.Equal(ContactResolverResolveDisposition.Conflict, changedRequest.Disposition);
            var anotherOperation = store.ResolveDcr(new OpaqueDcrResolveRequest(
                locator,
                Hash("operation/one-time/another"),
                Hash("request/one-time/another")));
            Assert.Equal(
                ContactResolverResolveDisposition.AlreadyClaimed,
                anotherOperation.Disposition);
            Assert.Null(anotherOperation.Publication);
        }

        using (var store = fixture.Open(clock))
        {
            Assert.Equal(
                ContactResolverResolveDisposition.ExactReplay,
                store.ResolveDcr(
                    new OpaqueDcrResolveRequest(locator, operation, requestHash)).Disposition);
            Assert.Equal(
                ContactResolverResolveDisposition.AlreadyClaimed,
                store.ResolveDcr(new OpaqueDcrResolveRequest(
                    locator,
                    Hash("operation/one-time/after-restart"),
                    Hash("request/one-time/after-restart"))).Disposition);
        }
    }

    [Fact]
    public async Task ConcurrentChangedDcrSuccessorsLatchConflict()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        using var store = fixture.Open(clock);
        var locator = Hash("locator/fork");
        var genesis = DcrRequest(locator, "fork/0", 0, Zero32(), Ciphertext("fork/0", 40), clock);
        Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(genesis).Disposition);
        var left = DcrRequest(locator, "fork/1/left", 1, genesis.ObjectCiphertextHash, Ciphertext("fork/left", 40), clock);
        var right = DcrRequest(locator, "fork/1/right", 1, genesis.ObjectCiphertextHash, Ciphertext("fork/right", 40), clock);
        var results = await Task.WhenAll(
            Task.Run(() => store.PublishDcr(left).Disposition),
            Task.Run(() => store.PublishDcr(right).Disposition));
        Assert.Contains(ContactResolverMutationDisposition.Committed, results);
        Assert.Contains(ContactResolverMutationDisposition.Conflict, results);
        Assert.Equal(ContactResolverReadDisposition.Conflict, store.ResolveCurrentDcr(locator).Disposition);
    }

    [Fact]
    public void ChangedRequestUnderSameOperationIdConflictsWithoutReplacingCurrent()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        using var store = fixture.Open(clock);
        var locator = Hash("locator/operation-conflict");
        var original = DcrRequest(locator, "same-operation", 0, Zero32(), Ciphertext("original", 40), clock);
        var changed = DcrRequest(locator, "same-operation", 0, Zero32(), Ciphertext("changed", 40), clock);
        Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(original).Disposition);
        Assert.Equal(ContactResolverMutationDisposition.Conflict, store.PublishDcr(changed).Disposition);
        var otherLocator = DcrRequest(Hash("locator/other"), "same-operation", 0, Zero32(), Ciphertext("original", 40), clock);
        Assert.Equal(ContactResolverMutationDisposition.Conflict, store.PublishDcr(otherLocator).Disposition);
        Assert.Equal(original.Ciphertext.ToArray(), store.ResolveCurrentDcr(locator).Publication!.Ciphertext);
        Assert.Equal(ContactResolverReadDisposition.NotFound, store.ResolveCurrentDcr(otherLocator.LocatorHash).Disposition);
    }

    [Fact]
    public void SignedExpiryBoundariesRejectMutationAndResolution()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        using var store = fixture.Open(clock);
        var locator = Hash("locator/expiry");
        var now = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        var expired = DcrRequest(locator, "expiry/already", 0, Zero32(), Ciphertext("expired", 40), clock, expiresAt: now);
        Assert.Equal(ContactResolverMutationDisposition.Expired, store.PublishDcr(expired).Disposition);
        var live = DcrRequest(locator, "expiry/live", 0, Zero32(), Ciphertext("live", 40), clock, expiresAt: now + 1);
        Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(live).Disposition);
        clock.UtcNow = clock.UtcNow.AddSeconds(1);
        Assert.Equal(ContactResolverReadDisposition.Expired, store.ResolveCurrentDcr(locator).Disposition);
        var tooFar = DcrRequest(Hash("locator/too-far"), "expiry/too-far", 0, Zero32(), Ciphertext("too-far", 40), clock,
            expiresAt: checked((ulong)clock.UtcNow.ToUnixTimeSeconds()) + checked((ulong)ContactResolverOpaqueStoreOptions.DcrMaximumRetention.TotalSeconds) + 1);
        Assert.Throws<ArgumentOutOfRangeException>(() => store.PublishDcr(tooFar));
        var expiredXur = XurRequest(Hash("capability/expired"), "xur/expired", 1, Zero32(), clock,
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
        Assert.Equal(ContactResolverMutationDisposition.Expired, store.WriteXurSuccessor(expiredXur).Disposition);
    }

    [Fact]
    public void CorruptStateIsQuarantinedAndNeverServed()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        using (var store = fixture.Open(clock))
        {
            store.PublishDcr(DcrRequest(Hash("locator/corrupt"), "corrupt/0", 0, Zero32(), Ciphertext("corrupt", 40), clock));
        }
        var bytes = File.ReadAllBytes(fixture.StatePath);
        bytes[^1] ^= 0x80;
        File.WriteAllBytes(fixture.StatePath, bytes);
        Assert.Throws<ContactResolverStoreCorruptException>(() => fixture.Open(clock));
        Assert.False(File.Exists(fixture.StatePath));
        Assert.Single(Directory.GetFiles(fixture.DirectoryPath, Path.GetFileName(fixture.StatePath) + ".quarantine.*"));
    }

    [Fact]
    public void LocatorQuotaRejectsWithoutMutatingExistingPublication()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        using var store = fixture.Open(clock, new ContactResolverOpaqueStoreOptions { MaximumPublicationLocators = 1 });
        var firstLocator = Hash("locator/quota/first");
        var first = DcrRequest(firstLocator, "quota/first", 0, Zero32(), Ciphertext("first", 40), clock);
        var second = DcrRequest(Hash("locator/quota/second"), "quota/second", 0, Zero32(), Ciphertext("second", 40), clock);
        Assert.Equal(ContactResolverMutationDisposition.Committed, store.PublishDcr(first).Disposition);
        Assert.Equal(ContactResolverMutationDisposition.QuotaExceeded, store.PublishDcr(second).Disposition);
        Assert.Equal(ContactResolverReadDisposition.Current, store.ResolveCurrentDcr(firstLocator).Disposition);
        Assert.Equal(ContactResolverReadDisposition.NotFound, store.ResolveCurrentDcr(second.LocatorHash).Disposition);
    }

    [Fact]
    public void XurSuccessorsReplayRestartAndCompactOnlyBehindVerifiedCheckpoint()
    {
        using var fixture = new StoreFixture();
        var clock = new FixedClock(Start);
        var capability = Hash("capability/retention");
        var exactXur1Hash = XurExactHash(capability);
        var hashes = new List<byte[]>(1_026);
        OpaqueXurWriteRequest? latest = null;
        using (var store = fixture.Open(clock))
        {
            var predecessor = Zero32();
            for (ulong generation = 1; generation <= 1_026; generation++)
            {
                latest = XurRequest(capability, $"xur/{generation}", generation, predecessor, clock);
                Assert.Equal(ContactResolverMutationDisposition.Committed, store.WriteXurSuccessor(latest).Disposition);
                predecessor = latest.EventHash.ToArray();
                hashes.Add(predecessor);
            }
            Assert.Equal(ContactResolverMutationDisposition.ExactReplay, store.WriteXurSuccessor(latest!).Disposition);
            var checkpoint = VerifiedXurCompactionCheckpoint.FromVerifiedClosure(capability, 2, hashes[1]);
            clock.UtcNow = Start.AddDays(400).AddSeconds(-1);
            Assert.Equal(0, store.CollectGarbage(checkpoint));
            clock.UtcNow = Start.AddDays(400);
            Assert.Equal(0, store.CollectGarbage(VerifiedXurCompactionCheckpoint.FromVerifiedClosure(capability, 2, Hash("wrong"))));
            Assert.Equal(2, store.CollectGarbage(checkpoint));
        }
        using (var store = fixture.Open(clock))
        {
            var stale = store.ResolveXurSuccessors(capability, exactXur1Hash, 0, 64);
            Assert.Equal(ContactResolverReadDisposition.StaleGeneration, stale.Disposition);
            Assert.Equal<ulong>(1_026, stale.CurrentGeneration);
            Assert.Equal(hashes[^1], stale.CurrentEventHash);
            var page = store.ResolveXurSuccessors(capability, exactXur1Hash, 2, 64);
            Assert.Equal(ContactResolverReadDisposition.Current, page.Disposition);
            Assert.Equal(64, page.Events.Count);
            Assert.Equal<ulong>(3, page.Events[0].Generation);
            Assert.Equal(hashes[1], page.Events[0].PredecessorEventHash);
        }
    }

    private static OpaqueDcrPublishRequest DcrRequest(byte[] locator, string operation, ulong generation,
        ReadOnlySpan<byte> predecessor, byte[] ciphertext, FixedClock clock, uint usageLimit = 0, ulong? expiresAt = null) =>
        new(locator, Hash("operation/" + operation), Hash("request/" + operation + Convert.ToHexString(SHA256.HashData(ciphertext))),
            generation, predecessor, SHA256.HashData(ciphertext), ciphertext, usageLimit,
            expiresAt ?? checked((ulong)clock.UtcNow.AddDays(1).ToUnixTimeSeconds()));

    private static OpaqueXurWriteRequest XurRequest(byte[] capability, string operation, ulong generation,
        ReadOnlySpan<byte> predecessor, FixedClock clock, ulong? expiresAt = null)
    {
        var ciphertext = Ciphertext("ciphertext/" + operation, 32);
        return new(capability, Hash("operation/" + operation), Hash("request/" + operation), XurExactHash(capability),
            generation, predecessor, Hash("event/" + operation), SHA256.HashData(ciphertext), ciphertext,
            expiresAt ?? checked((ulong)clock.UtcNow.AddDays(400).ToUnixTimeSeconds()));
    }

    private static byte[] XurExactHash(byte[] capability) =>
        SHA256.HashData(Encoding.UTF8.GetBytes("exact-xur1/" + Convert.ToHexString(capability)));

    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static byte[] Ciphertext(string value, int length)
    {
        var seed = Hash(value);
        var result = new byte[length];
        for (var i = 0; i < length; i++) result[i] = seed[i % seed.Length];
        return result;
    }
    private static byte[] Zero32() => new byte[32];

    private sealed class StoreFixture : IDisposable
    {
        internal StoreFixture()
        {
            DirectoryPath = Path.Combine(Path.GetTempPath(), "xnode-contact-resolver-tests-" + Guid.NewGuid().ToString("N"));
            StatePath = Path.Combine(DirectoryPath, "resolver.state");
        }
        internal string DirectoryPath { get; }
        internal string StatePath { get; }
        internal ContactResolverOpaqueStore Open(FixedClock clock, ContactResolverOpaqueStoreOptions? options = null) =>
            new(StatePath, options, clock, new TestStorageSecurity(), new MailboxDurabilityBarrier());
        public void Dispose()
        {
            if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, recursive: true);
        }
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }
}
