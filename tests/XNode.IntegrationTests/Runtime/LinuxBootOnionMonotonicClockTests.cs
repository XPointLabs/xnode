using System.Security.Cryptography;

namespace XNode.IntegrationTests.Runtime;

public sealed class LinuxBootOnionMonotonicClockTests
{
    private const string Boot = "550e8400-e29b-41d4-a716-446655440000\n";

    [Fact]
    public async Task SameKernelBootAndIncreasingUptimeAreAcceptedAcrossReads()
    {
        var uptimes = new Queue<string>(["120.99 1.0\n", "121.01 1.0\n"]);
        var clock = Clock(() => Boot, () => uptimes.Dequeue());

        var first = await clock.ReadAsync(default);
        var second = await clock.ReadAsync(default);

        Assert.Equal((ulong)120, first.SampleSeconds);
        Assert.Equal((ulong)121, second.SampleSeconds);
        Assert.True(CryptographicOperations.FixedTimeEquals(
            first.BootId.Span,
            second.BootId.Span));
    }

    [Fact]
    public async Task ProcessRestartDerivesTheSameBootIdentity()
    {
        var first = await Clock(() => Boot, () => "90.5 1.0").ReadAsync(default);
        var reopened = await Clock(() => Boot, () => "93.5 1.0").ReadAsync(default);

        Assert.Equal(first.BootId.ToArray(), reopened.BootId.ToArray());
    }

    [Fact]
    public async Task BootChangeAndUptimeRollbackFailClosed()
    {
        var boots = new Queue<string>(
        [
            Boot,
            "123e4567-e89b-12d3-a456-426614174000"
        ]);
        var changedBoot = Clock(() => boots.Dequeue(), () => "100.0 1.0");
        _ = await changedBoot.ReadAsync(default);
        await Assert.ThrowsAsync<IOException>(async () =>
            await changedBoot.ReadAsync(default));

        var uptimes = new Queue<string>(["100.0 1.0", "99.9 1.0"]);
        var rollback = Clock(() => Boot, () => uptimes.Dequeue());
        _ = await rollback.ReadAsync(default);
        await Assert.ThrowsAsync<IOException>(async () =>
            await rollback.ReadAsync(default));
    }

    [Theory]
    [InlineData("not-a-uuid", "1.0 1.0")]
    [InlineData(Boot, "nan 1.0")]
    [InlineData(Boot, "-1.0 1.0")]
    public async Task MalformedProcfsValuesFailClosed(string boot, string uptime)
    {
        var clock = Clock(() => boot, () => uptime);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await clock.ReadAsync(default));
    }

    private static LinuxBootOnionMonotonicClock Clock(
        Func<string> boot,
        Func<string> uptime) => new(
        _ => ValueTask.FromResult(boot()),
        _ => ValueTask.FromResult(uptime()));
}
