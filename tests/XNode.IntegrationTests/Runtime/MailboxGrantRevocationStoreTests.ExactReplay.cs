using System.Security.Cryptography;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class MailboxGrantRevocationStoreTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task NoWriteReplayFailureRejectsAuthorityWithoutLatchingIntactCustody(bool historical, bool cancel)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed);
        using var cancellation = new CancellationTokenSource();
        var security = new ReplayReadSecurity();
        var host = await Host(signed);
        var first = Snapshot(signed);
        await using var store = files.Open(storageSecurity: security);
        await store.EnrollAsync(host, first);
        var before = new[] { files.Enrollment, files.Anchor, files.Floor }.Select(File.ReadAllBytes).ToArray();
        // Three reads restore the existing enrollment/anchor/floor before plan
        // verification. Inject at the first subsequent read-back: exact replay
        // has not written anything, unlike a changed-floor uncertain commit.
        security.Arm(() => { if (cancel) cancellation.Cancel(); else signed.Sample = 99; });
        Task Replay() => historical
            ? store.CatchUpAsync(host, first, cancellation.Token).AsTask()
            : store.AdvanceAsync(host, first, cancellation.Token).AsTask();
        if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(Replay);
        else await Assert.ThrowsAnyAsync<CryptographicException>(Replay);
        Assert.True(security.Triggered);
        Assert.Equal(first, (await store.ReadProtectedAsync()).ToArray());
        foreach (var (path, index) in new[] { files.Enrollment, files.Anchor, files.Floor }.Select((path, index) => (path, index)))
            Assert.Equal(before[index], File.ReadAllBytes(path));
        Assert.False(File.Exists(files.Fault));
        if (!cancel)
            await Assert.ThrowsAnyAsync<CryptographicException>(() => store.WithCurrentAsync(host,
                (_, _) => ValueTask.FromResult(1)).AsTask());
        signed.Sample = 100;
        await store.WithCurrentAsync(host, async (lease, token) =>
        { await lease.EnsureCurrentAsync(token); return 1; });
    }

    private sealed class ReplayReadSecurity : IMailboxStorageSecurity
    {
        private readonly IMailboxStorageSecurity inner = new MailboxStorageSecurity();
        private Action? fault;
        private int remaining;
        internal bool Triggered { get; private set; }
        internal void Arm(Action action) { fault = action; remaining = 4; }
        public void SecureDirectory(string path) => inner.SecureDirectory(path);
        public void SecureFile(string path) => inner.SecureFile(path);
        public void ValidateSecureFile(string path)
        {
            inner.ValidateSecureFile(path);
            if (fault is not null && path.EndsWith(".bin", StringComparison.Ordinal) && --remaining == 0)
            { var action = fault; fault = null; Triggered = true; action(); }
        }
    }
}
