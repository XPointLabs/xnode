using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class MailboxGrantRevocationStoreTests
{
    [Theory]
    [InlineData(MailboxCapabilityDomain.Deposit)]
    [InlineData(MailboxCapabilityDomain.Retrieve)]
    public async Task HistoricalCatchUpSurvivesColdRestartAndMoreThan64StepsWithoutExpiredAdmission(MailboxCapabilityDomain role)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed, role); var host = await Host(signed);
        var exact = Snapshot(signed, role, serials: [Bytes(16, 0x51)], expires: 1_110);
        byte[] enrollment;
        await using (var store = files.Open())
        {
            await store.EnrollAsync(host, exact); enrollment = File.ReadAllBytes(files.Enrollment);
        }
        signed.Sample = 105; // Full protected upper == old expiry. The complete host remains current.
        for (ulong generation = 2; generation <= 70; generation++)
        {
            // Reopen each step: no transient batch, skip or new enrollment carries authority.
            await using var store = files.Open();
            Assert.Equal(exact, (await store.ReadProtectedAsync()).ToArray());
            var next = Snapshot(signed, role, generation, exact, [Bytes(16, 0x51)], expires: 1_110);
            await store.CatchUpAsync(host, next);
            await store.CatchUpAsync(host, next); // exact replay is idempotent
            Assert.Equal(next, (await store.ReadProtectedAsync()).ToArray());
            Assert.Equal(enrollment, File.ReadAllBytes(files.Enrollment));
            var callbacks = 0;
            await Assert.ThrowsAsync<CryptographicException>(() => store.WithCurrentAsync(host, (_, _) =>
            { callbacks++; return ValueTask.FromResult(1); }).AsTask());
            Assert.Equal(0, callbacks); exact = next;
        }
        await using (var store = files.Open())
        {
            var fresh = Snapshot(signed, role, 71, exact, [Bytes(16, 0x51), Bytes(16, 0x52)]);
            await store.CatchUpAsync(host, fresh);
            await store.WithCurrentAsync(host, async (lease, token) =>
            {
                await Assert.ThrowsAsync<CryptographicException>(() => lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x51, expires: 1_115), token).AsTask());
                await lease.EnsureGrantNotRevokedAsync(Grant(signed, host, role, 0x53, expires: 1_115), token);
                return 1;
            });
            Assert.Equal(enrollment, File.ReadAllBytes(files.Enrollment)); exact = fresh;
        }
        await using var reopened = files.Open();
        Assert.Equal(exact, (await reopened.ReadProtectedAsync()).ToArray());
        await reopened.WithCurrentAsync(host, async (lease, token) => { await lease.EnsureCurrentAsync(token); return 1; });
    }

    [Fact]
    public async Task HistoricalCatchUpCannotProvisionMissingFloorOrResetInitializedCustody()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed); var host = await Host(signed); var first = Snapshot(signed);
        await using (var store = files.Open())
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => store.CatchUpAsync(host, first).AsTask());
            Assert.False(File.Exists(files.Enrollment));
            await store.EnrollAsync(host, first);
        }
        File.Delete(files.Floor);
        await using var reopened = files.Open();
        await Assert.ThrowsAsync<InvalidDataException>(() => reopened.CatchUpAsync(host, first).AsTask());
        Assert.False(File.Exists(files.Floor));
    }

    [Theory]
    [InlineData("fork", true)]
    [InlineData("removed", true)]
    [InlineData("gap", false)]
    [InlineData("rollback", false)]
    [InlineData("invalid-signature", false)]
    public async Task HistoricalCatchUpPreservesFloorAndOnlyAuthenticatedConflictsLatch(string kind, bool latch)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed); var host = await Host(signed);
        var first = Snapshot(signed, serials: [Bytes(16, 0x51)], expires: 1_110);
        var second = Snapshot(signed, generation: 2, prior: first, serials: [Bytes(16, 0x51)], expires: 1_110);
        await using (var store = files.Open())
        {
            await store.EnrollAsync(host, first); signed.Sample = 105;
            await store.CatchUpAsync(host, second);
            var saved = File.ReadAllBytes(files.Floor);
            var bad = kind switch
            {
                "fork" => Snapshot(signed, generation: 2, prior: first, serials: [Bytes(16, 0x52)], expires: 1_110),
                "removed" => Snapshot(signed, generation: 3, prior: second, expires: 1_110),
                "gap" => Snapshot(signed, generation: 4, prior: second, serials: [Bytes(16, 0x51)], expires: 1_110),
                "rollback" => first,
                _ => Snapshot(signed, generation: 3, prior: second, serials: [Bytes(16, 0x51)], expires: 1_110),
            };
            if (kind == "invalid-signature") bad[^1] ^= 1;
            await Assert.ThrowsAnyAsync<CryptographicException>(() => store.CatchUpAsync(host, bad).AsTask());
            Assert.Equal(latch, File.Exists(files.Fault)); Assert.Equal(saved, File.ReadAllBytes(files.Floor));
            if (!latch) Assert.Equal(second, (await store.ReadProtectedAsync()).ToArray());
        }
        await using var reopened = files.Open();
        if (latch) await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadProtectedAsync().AsTask());
        else Assert.Equal(second, (await reopened.ReadProtectedAsync()).ToArray());
    }

    [Theory]
    [InlineData("anchor.bin")]
    [InlineData("floor.bin")]
    public async Task HistoricalReplacementInterruptionNeverReleasesAdmissionAndReopenRequiresCompleteExactWrite(string target)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed); var host = await Host(signed);
        var first = Snapshot(signed, expires: 1_110);
        await using (var store = files.Open()) await store.EnrollAsync(host, first);
        signed.Sample = 105;
        var next = Snapshot(signed, generation: 2, prior: first, expires: 1_110);
        var crash = new Barrier(target);
        await using (var store = files.Open(crash))
        {
            await Assert.ThrowsAsync<IOException>(() => store.CatchUpAsync(host, next).AsTask());
            Assert.True(crash.ReachedTarget);
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.ReadProtectedAsync().AsTask());
        }
        await using var reopened = files.Open();
        if (target == "floor.bin")
        {
            Assert.Equal(next, (await reopened.ReadProtectedAsync()).ToArray());
            var callbacks = 0;
            await Assert.ThrowsAsync<CryptographicException>(() => reopened.WithCurrentAsync(host, (_, _) =>
            { callbacks++; return ValueTask.FromResult(1); }).AsTask());
            Assert.Equal(0, callbacks);
        }
        else await Assert.ThrowsAsync<InvalidDataException>(() => reopened.ReadProtectedAsync().AsTask());
    }

    [Fact]
    public async Task CancelledHistoricalCatchUpDoesNotReplaceProtectedFloor()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        using var files = new Custody(signed); var host = await Host(signed); var first = Snapshot(signed);
        await using var store = files.Open(); await store.EnrollAsync(host, first);
        var floor = File.ReadAllBytes(files.Floor); var anchor = File.ReadAllBytes(files.Anchor);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.CatchUpAsync(host,
            Snapshot(signed, generation: 2, prior: first), canceled.Token).AsTask());
        Assert.Equal(floor, File.ReadAllBytes(files.Floor)); Assert.Equal(anchor, File.ReadAllBytes(files.Anchor));
        await store.WithCurrentAsync(host, async (lease, token) => { await lease.EnsureCurrentAsync(token); return 1; });
    }
}
