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
}
