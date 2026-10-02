using System.Security.Cryptography;
using XNode.Core.Blob;
using XNode.Core.Mailbox;

namespace XNode.Tests.Core;

// Real local filesystem/barriers only. Not a remote BLOB authorization/receipt.
public sealed class DurableBlobChunkStoreTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(262160)]
    public void ExactCiphertextSurvivesColdReopenWithoutReplacement(int length)
    {
        using var f = new Fixture(); var bytes = RandomNumberGenerator.GetBytes(length); var hash = SHA256.HashData(bytes);
        using (var store = f.Open())
        {
            Assert.Equal(BlobChunkWriteResult.Committed, store.Put(hash, bytes));
            var copy = store.Read(hash)!; Assert.Equal(bytes, copy); copy[0] ^= 1;
            Assert.Equal(bytes, store.Read(hash));
        }
        var stamp = File.GetLastWriteTimeUtc(f.Chunk(hash));
        using (var reopened = f.Open())
        {
            Assert.Equal(bytes, reopened.Read(hash));
            Assert.Equal(BlobChunkWriteResult.ExactReplay, reopened.Put(hash, bytes));
        }
        Assert.Equal(stamp, File.GetLastWriteTimeUtc(f.Chunk(hash)));
    }

    [Fact]
    public void HundredFullChunksResumeAtTwentyFivePercentAndRespectQuota()
    {
        using var f = new Fixture(); var chunks = Enumerable.Range(0, 100).Select(_ => RandomNumberGenerator.GetBytes(262160)).ToArray();
        var hashes = chunks.Select(bytes => SHA256.HashData(bytes)).ToArray();
        using (var first = f.Open(100, 26216000))
            for (var i = 0; i < 25; i++) Assert.Equal(BlobChunkWriteResult.Committed, first.Put(hashes[i], chunks[i]));
        using (var resumed = f.Open(100, 26216000))
        {
            for (var i = 0; i < 25; i++) Assert.Equal(BlobChunkWriteResult.ExactReplay, resumed.Put(hashes[i], chunks[i]));
            Assert.Null(resumed.Read(hashes[25]));
            for (var i = 25; i < 100; i++) Assert.Equal(BlobChunkWriteResult.Committed, resumed.Put(hashes[i], chunks[i]));
            for (var i = 0; i < 100; i++) Assert.Equal(chunks[i], resumed.Read(hashes[i]));
            Assert.Equal(BlobChunkWriteResult.QuotaExceeded, resumed.Put(SHA256.HashData(new byte[] { 1 }), [1]));
        }
    }

    [Fact]
    public void InvalidCommitmentGeometryAndCancellationMutateNothing()
    {
        using var f = new Fixture(); using var store = f.Open(); var bytes = new byte[] { 1, 2 }; var hash = SHA256.HashData(bytes);
        Assert.Throws<ArgumentException>(() => store.Put(new byte[31], bytes));
        Assert.Throws<CryptographicException>(() => store.Put(new byte[32], bytes));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Put(hash, []));
        Assert.Throws<ArgumentOutOfRangeException>(() => store.Put(hash, new byte[262161]));
        using var c = new CancellationTokenSource(); c.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => store.Put(hash, bytes, c.Token));
        Assert.Null(store.Read(hash)); Assert.Single(Directory.GetFiles(f.Path));
        store.Dispose(); Assert.Throws<ObjectDisposedException>(() => store.Read(hash));
    }

    [Fact]
    public void ByteQuotaIsDurableAndExactRetryDoesNotConsumeItAgain()
    {
        using var f = new Fixture(); var a = new byte[] { 1, 2 }; var b = new byte[] { 2, 3 }; var hash = SHA256.HashData(a);
        using (var first = f.Open(2, 3)) Assert.Equal(BlobChunkWriteResult.Committed, first.Put(hash, a));
        using var second = f.Open(2, 3);
        Assert.Equal(BlobChunkWriteResult.ExactReplay, second.Put(hash, a));
        Assert.Equal(BlobChunkWriteResult.QuotaExceeded, second.Put(SHA256.HashData(b), b));
        Assert.Null(second.Read(SHA256.HashData(b)));
    }

    [Theory]
    [InlineData("changed")]
    [InlineData("empty")]
    [InlineData("oversized")]
    public void CorruptCommittedFileCannotBeReadOrReopened(string mutation)
    {
        using var f = new Fixture(); var bytes = new byte[] { 1, 2 }; var hash = SHA256.HashData(bytes);
        using (var first = f.Open()) Assert.Equal(BlobChunkWriteResult.Committed, first.Put(hash, bytes));
        File.WriteAllBytes(f.Chunk(hash), mutation switch { "empty" => [], "oversized" => new byte[262161], _ => [3, 4] });
        if (mutation == "changed") Assert.Throws<CryptographicException>(() => f.Open());
        else Assert.Throws<InvalidDataException>(() => f.Open());
        Assert.Equal(mutation == "oversized" ? 262161 : mutation == "empty" ? 0 : 2, new FileInfo(f.Chunk(hash)).Length);
    }

    [Fact]
    public void ExclusiveOwnerAndQuotaChangeRejectWithoutDeletingCommittedData()
    {
        using var f = new Fixture(); var bytes = new byte[] { 1, 2 }; var hash = SHA256.HashData(bytes);
        using (var first = f.Open())
        {
            first.Put(hash, bytes);
            Assert.Throws<IOException>(() => f.Open());
        }
        Assert.Throws<InvalidDataException>(() => f.Open(1, 1));
        using var restored = f.Open(); Assert.Equal(bytes, restored.Read(hash));
    }

    [Fact]
    public void UnknownEntryRejectsWhileOnlyClosedUnpublishedStagingCanBeDiscarded()
    {
        using var f = new Fixture(); using (var first = f.Open()) { }
        var unknown = System.IO.Path.Combine(f.Path, "unknown.pending"); File.WriteAllBytes(unknown, [8]);
        Assert.Throws<InvalidDataException>(() => f.Open()); Assert.True(File.Exists(unknown)); File.Delete(unknown);
        var pending = System.IO.Path.Combine(f.Path, new string('a', 64) + "." + Guid.NewGuid().ToString("N") + ".pending");
        File.WriteAllBytes(pending, [8]);
        using var reopened = f.Open(); Assert.False(File.Exists(pending));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PersistenceFailureHasUnknownOutcomeAndRequiresReopen(bool afterReplace)
    {
        using var f = new Fixture(); var bytes = new byte[] { 1 }; var hash = SHA256.HashData(bytes);
        using (var first = f.Open(durability: new FaultingBarrier(afterReplace)))
        {
            Assert.Throws<IOException>(() => first.Put(hash, bytes));
            Assert.Throws<IOException>(() => first.Read(hash));
        }
        using var reopened = f.Open();
        Assert.Equal(afterReplace ? bytes : null, reopened.Read(hash));
        Assert.Equal(afterReplace ? BlobChunkWriteResult.ExactReplay : BlobChunkWriteResult.Committed, reopened.Put(hash, bytes));
        Assert.Empty(Directory.GetFiles(f.Path, "*.pending"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CancellationBeforeOrAfterPromotionPreservesExactRecovery(bool afterReplace)
    {
        using var f = new Fixture(); using var cancellation = new CancellationTokenSource();
        var bytes = new byte[] { 1 }; var hash = SHA256.HashData(bytes);
        using var store = f.Open(durability: new CancellingBarrier(cancellation, afterReplace));
        Assert.ThrowsAny<OperationCanceledException>(() => store.Put(hash, bytes, cancellation.Token));
        Assert.Equal(afterReplace ? bytes : null, store.Read(hash));
        Assert.Equal(afterReplace ? BlobChunkWriteResult.ExactReplay : BlobChunkWriteResult.Committed, store.Put(hash, bytes));
        Assert.Empty(Directory.GetFiles(f.Path, "*.pending"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ChangedLiveFileFailsClosedWithoutRepair(bool retry)
    {
        using var f = new Fixture(); using var store = f.Open();
        var bytes = new byte[] { 1 }; var hash = SHA256.HashData(bytes); store.Put(hash, bytes);
        File.WriteAllBytes(f.Chunk(hash), [2]);
        if (retry) Assert.Throws<CryptographicException>(() => store.Put(hash, bytes));
        else Assert.Throws<CryptographicException>(() => store.Read(hash));
        Assert.Throws<IOException>(() => store.Read(hash));
        Assert.Equal(new byte[] { 2 }, File.ReadAllBytes(f.Chunk(hash)));
    }

    private sealed class CancellingBarrier(CancellationTokenSource cancellation, bool afterReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier actual = new();
        public void FlushFileAndParentDirectory(string path)
        {
            actual.FlushFileAndParentDirectory(path);
            if (!afterReplace && path.EndsWith(".pending", StringComparison.Ordinal)) cancellation.Cancel();
        }
        public void FlushParentDirectory(string path) => actual.FlushParentDirectory(path);
        public void ReplaceFile(string pending, string final)
        {
            actual.ReplaceFile(pending, final);
            if (afterReplace) cancellation.Cancel();
        }
    }

    private sealed class FaultingBarrier(bool afterReplace) : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier actual = new();
        public void FlushFileAndParentDirectory(string path) => actual.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => actual.FlushParentDirectory(path);
        public void ReplaceFile(string pending, string final)
        {
            if (afterReplace) actual.ReplaceFile(pending, final);
            throw new IOException("Injected blob promotion failure.");
        }
    }

    private sealed class Fixture : IDisposable
    {
        internal string Path { get; } = System.IO.Path.GetFullPath(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "deep-blob-chunks-" + Guid.NewGuid().ToString("N")));
        internal DurableBlobChunkStore Open(int count = 100, long bytes = 26216000, IMailboxDurabilityBarrier? durability = null)
            => new(Path, count, bytes, durability: durability);
        internal string Chunk(byte[] hash) => System.IO.Path.Combine(Path, Convert.ToHexStringLower(hash) + ".chunk");
        public void Dispose()
        {
            Assert.StartsWith(System.IO.Path.GetFullPath(System.IO.Path.GetTempPath()), Path, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith("deep-blob-chunks-", System.IO.Path.GetFileName(Path), StringComparison.Ordinal);
            if (!Directory.Exists(Path)) return;
            Assert.Equal(0, (int)(File.GetAttributes(Path) & FileAttributes.ReparsePoint));
            Directory.Delete(Path, recursive: true);
        }
    }
}
