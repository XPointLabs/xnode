using System.Security.Cryptography;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxOriginTimeTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OriginRequiresActualTimeConvergenceNotGrace(bool converges)
    {
        var reads = 0;
        var lease = new MailboxCurrentOperationLease(_ =>
            ValueTask.FromResult(++reads > 1 && converges ? 102UL : 100UL), () => { });
        if (converges) Assert.Equal(102UL, await lease.RequireOriginTimeAsync(101, default));
        else await Assert.ThrowsAsync<CryptographicException>(() => lease.RequireOriginTimeAsync(101, default).AsTask());
        Assert.Equal(2, reads);
    }

    [Fact]
    public async Task OutsideBoundAndCancellationNeverObtainOriginAuthority()
    {
        var reads = 0;
        var lease = new MailboxCurrentOperationLease(_ => { reads++; return ValueTask.FromResult(100UL); }, () => { });
        await Assert.ThrowsAsync<CryptographicException>(() => lease.RequireOriginTimeAsync(105, default).AsTask());
        Assert.Equal(1, reads);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lease.RequireOriginTimeAsync(101, cancel.Token).AsTask());
        Assert.Equal(2, reads);
    }

    [Fact]
    public async Task OriginTimingIsNotCalledWithoutAnActualWait()
    {
        var reports = 0;
        var lease = new MailboxCurrentOperationLease(_ => ValueTask.FromResult(100UL), () => { },
            _ => reports++);
        Assert.Equal(100UL, await lease.RequireOriginTimeAsync(100, default));
        await Assert.ThrowsAsync<CryptographicException>(() => lease.RequireOriginTimeAsync(105, default).AsTask());
        Assert.Equal(0, reports);
    }

    [Fact]
    public async Task InterruptedOriginWaitReportsOnlyElapsedResourceTimeAndPreservesCancellation()
    {
        var reads = 0; var reports = 0; double observed = -1;
        var lease = new MailboxCurrentOperationLease(_ =>
            { reads++; return ValueTask.FromResult(100UL); }, () => { }, milliseconds =>
            {
                observed = milliseconds;
                reports++;
                throw new IOException("Test-owned timing sink interruption.");
            });
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lease.RequireOriginTimeAsync(101, cancel.Token).AsTask());
        Assert.Equal(1, reads);
        Assert.Equal(1, reports);
        Assert.True(observed >= 0);
    }
}
