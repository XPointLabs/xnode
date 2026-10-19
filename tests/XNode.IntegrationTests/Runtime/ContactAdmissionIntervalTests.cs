namespace XNode.IntegrationTests.Runtime;

public sealed class ContactAdmissionIntervalTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OneWaitRequiresFreshActualConvergence(bool converges)
    {
        var reads = 0;
        ValueTask<(ulong, ulong, uint)> Read(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); reads++;
            return ValueTask.FromResult((reads > 1 && converges ? 101UL : 100UL, 110UL, 5U));
        }
        if (converges) Assert.True(await ContactAdmissionInterval.RequireAsync(101, 220, true, Read, true, default));
        else await Assert.ThrowsAsync<ContactAdmissionIntervalException>(() =>
            ContactAdmissionInterval.RequireAsync(101, 220, true, Read, true, default).AsTask());
        Assert.Equal(2, reads);
    }

    [Fact]
    public async Task CancellationAndPostEffectChecksNeverWaitOrReleaseFutureTime()
    {
        var reads = 0;
        ValueTask<(ulong, ulong, uint)> Read(CancellationToken ct)
        { reads++; return ValueTask.FromResult((100UL, 110UL, 5U)); }
        await Assert.ThrowsAsync<ContactAdmissionIntervalException>(() =>
            ContactAdmissionInterval.RequireAsync(101, 220, true, Read, false, default).AsTask());
        Assert.Equal(1, reads);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            ContactAdmissionInterval.RequireAsync(101, 220, true, Read, true, cancel.Token).AsTask());
        Assert.Equal(2, reads);
    }

    [Theory]
    [InlineData(100UL, 100UL, 110UL, 0)]
    [InlineData(101UL, 100UL, 110UL, 2)]
    [InlineData(110UL, 100UL, 115UL, 11)]
    public void ConvergenceSchedulesOnlyBeforeEffectsWithoutAcceptingFutureTime(ulong issued, ulong lower, ulong upper, int wait)
    {
        Assert.Equal(wait, ContactAdmissionInterval.RequireOrDelay(issued, 220, true, lower, upper, 5));
        Assert.Equal(0, ContactAdmissionInterval.RequireOrDelay(issued, 220, true, issued, upper, 5));
    }

    [Theory]
    [InlineData(111UL, 220UL, 100UL, 115UL, 5U, "IssuedFuture")]
    [InlineData(103UL, 220UL, 100UL, 115UL, 1U, "IssuedFuture")]
    [InlineData(101UL, 110UL, 100UL, 110UL, 5U, "Expired")]
    [InlineData(100UL, 221UL, 100UL, 110UL, 5U, "InvalidWindow")]
    [InlineData(100UL, 100UL, 100UL, 110UL, 5U, "InvalidWindow")]
    [InlineData(100UL, 220UL, 111UL, 110UL, 5U, "InvalidWindow")]
    public void UnknownOrExpiredWindowCannotReceiveGrace(ulong issued, ulong expires, ulong lower, ulong upper,
        uint uncertainty, string rejection)
    {
        var error = Assert.Throws<ContactAdmissionIntervalException>(() =>
            ContactAdmissionInterval.RequireOrDelay(issued, expires, true, lower, upper, uncertainty));
        Assert.Equal(rejection, error.Rejection.ToString()); Assert.Empty(error.Data);
    }
}
