using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.BlobV1;
using XNode.Core.Blob;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class BlobObjectStoreTests
{
    [Fact]
    public void RealDurableCiphertextAndDescriptorColdResumeExactReplay()
    {
        var root = TemporaryRoot(); var cipher = Bytes(528, 0x55); using var manifest = Manifest(cipher);
        using var put = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Put, 0, cipher));
        using var get = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Get, 0));
        try
        {
            using (var store = Open(root))
            {
                Assert.Equal(BlobChunkStatus.Stored, store.Execute(put, 100, 101, default).Status);
                Assert.Equal(BlobChunkStatus.ExactReplay, store.Execute(put, 102, 103, default).Status);
            }
            using var reopened = Open(root);
            Assert.Equal(cipher, reopened.Execute(get, 104, 105, default).Ciphertext);
            Assert.Equal(BlobChunkStatus.ExactReplay, reopened.Execute(put, 106, 107, default).Status);
            var descriptor = File.ReadAllBytes(Assert.Single(Directory.GetFiles(root, "*.object", SearchOption.AllDirectories)));
            Assert.True(descriptor.AsSpan().IndexOf(manifest.BlobCapability.Span) < 0);
            Assert.True(descriptor.AsSpan().IndexOf(manifest.ObjectKey.Span) < 0);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void ChangedDescriptorExpiryQuotaAndMissingNeverClaimStored()
    {
        var root = TemporaryRoot(); var cipher = Bytes(528, 0x55);
        using var first = Manifest(cipher); using var changed = Manifest(cipher, expiry: 1001); using var other = Manifest(cipher, objectMarker: 8);
        using var put = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(first, BlobChunkOperation.Put, 0, cipher));
        using var changedPut = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(changed, BlobChunkOperation.Put, 0, cipher));
        using var otherPut = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(other, BlobChunkOperation.Put, 0, cipher));
        using var get = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(first, BlobChunkOperation.Get, 0));
        try
        {
            using var store = Open(root);
            var before = Directory.GetFiles(root, "*", SearchOption.AllDirectories).Length;
            Assert.Equal(BlobChunkStatus.Missing, store.Execute(get, 100, 101, default).Status);
            Assert.Equal(before, Directory.GetFiles(root, "*", SearchOption.AllDirectories).Length);
            Assert.Equal(BlobChunkStatus.Expired, store.Execute(put, 999, 1000, default).Status);
            Assert.Equal(before, Directory.GetFiles(root, "*", SearchOption.AllDirectories).Length);
            Assert.Equal(BlobChunkStatus.Stored, store.Execute(put, 100, 101, default).Status);
            Assert.Equal(BlobChunkStatus.Conflict, store.Execute(changedPut, 100, 101, default).Status);
            Assert.Equal(BlobChunkStatus.Quota, store.Execute(otherPut, 100, 101, default).Status);
            Assert.Equal(cipher, store.Execute(get, 100, 101, default).Ciphertext);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void CorruptDescriptorAndCiphertextCannotBeSilentlyRepaired()
    {
        var root = TemporaryRoot(); var cipher = Bytes(528, 0x55); using var manifest = Manifest(cipher);
        using var put = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Put, 0, cipher));
        try
        {
            using (var store = Open(root)) Assert.Equal(BlobChunkStatus.Stored, store.Execute(put, 100, 101, default).Status);
            var path = Assert.Single(Directory.GetFiles(root, "*.object", SearchOption.AllDirectories));
            var original = File.ReadAllBytes(path); File.WriteAllBytes(path, [1, 2]);
            Assert.Throws<InvalidDataException>(() => Open(root));
            File.WriteAllBytes(path, original);
            var chunk = Assert.Single(Directory.GetFiles(root, "*.chunk", SearchOption.AllDirectories));
            var damaged = File.ReadAllBytes(chunk); damaged[^1] ^= 1; File.WriteAllBytes(chunk, damaged);
            Assert.Throws<CryptographicException>(() => Open(root));
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void ColdResumeDiscardsOnlyUnpublishedClosedStagingAndPreservesCommittedObjects()
    {
        var root = TemporaryRoot(); var cipher = Bytes(528, 0x55); using var manifest = Manifest(cipher);
        using var put = BlobChunkCodec.DecodeRequest(BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Put, 0, cipher));
        try
        {
            using (var first = Open(root)) Assert.Equal(BlobChunkStatus.Stored, first.Execute(put, 100, 101, default).Status);
            var objects = Path.Combine(root, "objects");
            var stage = Path.Combine(objects, new string('A', 64) + "." + new string('b', 32) + ".pending");
            File.WriteAllBytes(stage, [1, 2]); new MailboxStorageSecurity().SecureFile(stage);
            using (var resumed = Open(root))
            {
                Assert.False(File.Exists(stage));
                Assert.Equal(BlobChunkStatus.ExactReplay, resumed.Execute(put, 100, 101, default).Status);
            }
            var unknown = Path.Combine(objects, "unknown.pending");
            File.WriteAllBytes(unknown, [1, 2]); new MailboxStorageSecurity().SecureFile(unknown);
            Assert.Throws<InvalidDataException>(() => Open(root));
            Assert.True(File.Exists(unknown));
        }
        finally { Directory.Delete(root, true); }
    }

    private static DurableBlobObjectStore Open(string root) => new(root, 1, 1, 528, new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
    private static ParsedDam1 Manifest(byte[] cipher, byte objectMarker = 2, ulong expiry = 1000) =>
        ApplicationCoreCodec.AuthorDam1(Bytes(16, 1), Bytes(32, objectMarker), Bytes(32, 3), Bytes(32, 4), 512,
            [new(0, 528, SHA256.HashData(cipher))], expiry, "fixture.dat", "application/octet-stream");
    private static byte[] Bytes(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static string TemporaryRoot() => Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "deep-blob-test-" + Guid.NewGuid().ToString("N"))).FullName;
}
