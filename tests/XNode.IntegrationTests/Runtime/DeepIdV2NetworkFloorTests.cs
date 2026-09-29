using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

/// <summary>Real signed DID2/NETCODEC plus protected filesystem custody; not TLS/device evidence.</summary>
public sealed class DeepIdV2NetworkFloorTests
{
    [Fact]
    public async Task RestartReverifiesHistoryAndEqualTipIsIdempotent()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        DeepIdV2NetworkFloor prior;
        using (var store = files.Open())
        {
            Assert.Null(await store.ReadAsync(default));
            prior = await store.CommitVerifiedAsync(null, signed.NetworkContext, default);
            Assert.Equal(1UL, prior.Revision);
            await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await store.CommitVerifiedAsync(prior, signed.NetworkContext, default));
        }
        using var restarted = files.Open();
        var retained = await restarted.ReadAsync(default);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(prior, retained));
        var current = await signed.VerifyHistoryAsync(retained!.History);
        Assert.Equal(prior.History, OnionNetworkProtectedHistoryCodec.Encode(current));
        Assert.NotNull(current.PriorProtectedLkg);
        var committed = await restarted.CommitVerifiedAsync(retained, current, default);
        Assert.Equal(1UL, committed.Revision);
        Assert.True(FileDeepIdV2NetworkFloorStore.Same(prior, committed));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await restarted.CommitVerifiedAsync(retained with { Revision = 2 }, current, default));
    }

    [Theory]
    [InlineData("missing-floor")]
    [InlineData("missing-anchor")]
    [InlineData("corrupt-floor")]
    [InlineData("corrupt-anchor")]
    [InlineData("unknown-record")]
    public async Task RestartRejectsMissingCorruptOrPartialCustody(string fault)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        using (var store = files.Open())
            await store.CommitVerifiedAsync(null, signed.NetworkContext, default);
        switch (fault)
        {
            case "missing-floor": File.Delete(files.Floor); break;
            case "missing-anchor": File.Delete(files.Anchor); break;
            case "unknown-record": File.WriteAllBytes(files.Floor + ".partial", [1]); break;
            default:
                var path = fault == "corrupt-floor" ? files.Floor : files.Anchor;
                var bytes = File.ReadAllBytes(path); bytes[^1] ^= 1; File.WriteAllBytes(path, bytes); break;
        }
        using var restarted = files.Open();
        await Assert.ThrowsAnyAsync<Exception>(async () => await restarted.ReadAsync(default));
        Assert.False(File.Exists(files.Floor) && new FileInfo(files.Floor).Length == 0);
    }

    [Fact]
    public async Task IndependentAnchorRejectsAuthenticatedStaleState()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        using (var store = files.Open())
            await store.CommitVerifiedAsync(null, signed.NetworkContext, default);
        // Model a newer independently protected anchor remaining after an older
        // authentic state is restored. This is not an attacker forging a MAC.
        var plain = files.Protector.Unprotect(File.ReadAllBytes(files.Anchor));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(plain.AsSpan(8), 2);
        File.WriteAllBytes(files.Anchor, files.Protector.Protect(plain));
        CryptographicOperations.ZeroMemory(plain);
        using var restarted = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await restarted.ReadAsync(default));
    }

    [Fact]
    public async Task AuthenticatedAnchorWithDifferentHistoryLengthRejectsInRuntimeAndOfflineAudit()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        using (var store = files.Open())
            await store.CommitVerifiedAsync(null, signed.NetworkContext, default);
        var plain = files.Protector.Unprotect(File.ReadAllBytes(files.Anchor));
        var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(64));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(64), length + 1);
        File.WriteAllBytes(files.Anchor, files.Protector.Protect(plain));
        CryptographicOperations.ZeroMemory(plain);
        Assert.Throws<InvalidDataException>(() => FileDeepIdV2NetworkFloorStore.AuthenticateSnapshot(
            File.ReadAllBytes(files.Floor), File.ReadAllBytes(files.Anchor), files.Protector));
        using var restarted = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await restarted.ReadAsync(default));
    }

    [Fact]
    public async Task WrongPurposeAndConcurrentWriterCannotRestoreOrMutate()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        using (var store = files.Open())
        {
            await store.CommitVerifiedAsync(null, signed.NetworkContext, default);
            Assert.Throws<IOException>(() => files.Open());
        }
        using var wrongScope = files.Open(protector: new EphemeralDataProtectionProvider().CreateProtector("other-node"));
        await Assert.ThrowsAsync<CryptographicException>(async () => await wrongScope.ReadAsync(default));
    }

    [Fact]
    public async Task CrashAfterAnchorLatchesWriterAndRestartFailsClosed()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        using (var store = files.Open(new CrashAfterAnchor()))
        {
            await Assert.ThrowsAsync<IOException>(async () =>
                await store.CommitVerifiedAsync(null, signed.NetworkContext, default));
            await Assert.ThrowsAsync<InvalidOperationException>(async () => await store.ReadAsync(default));
        }
        Assert.True(File.Exists(files.Anchor));
        Assert.False(File.Exists(files.Floor));
        using var restarted = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(async () => await restarted.ReadAsync(default));
    }

    [Fact]
    public async Task CancellationBeforeCommitDoesNotInitializeCustody()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody();
        using var store = files.Open();
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await store.CommitVerifiedAsync(null, signed.NetworkContext, canceled.Token));
        Assert.Null(await store.ReadAsync(default));
        Assert.False(File.Exists(files.Anchor));
        Assert.False(File.Exists(files.Floor));
    }

    private sealed class Custody : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "did2-network-floor-" + Guid.NewGuid().ToString("N"));
        internal IDataProtector Protector { get; } = new EphemeralDataProtectionProvider().CreateProtector("test-network", "test-node");
        internal string Floor => Path.Combine(root, "did2-network-state", "floor.bin");
        internal string Anchor => Path.Combine(root, "did2-network-anchor", "anchor.bin");
        internal FileDeepIdV2NetworkFloorStore Open(IMailboxDurabilityBarrier? barrier = null, IDataProtector? protector = null) =>
            new(root, protector ?? Protector, new MailboxStorageSecurity(), barrier ?? new MailboxDurabilityBarrier());
        public void Dispose() { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private sealed class CrashAfterAnchor : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier inner = new();
        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            inner.ReplaceFile(temporaryPath, finalPath);
            if (Path.GetFileName(finalPath) == "anchor.bin") throw new IOException("Injected anchor commit crash.");
        }
        public void FlushFileAndParentDirectory(string path) => inner.FlushFileAndParentDirectory(path);
        public void FlushParentDirectory(string path) => inner.FlushParentDirectory(path);
    }
}
