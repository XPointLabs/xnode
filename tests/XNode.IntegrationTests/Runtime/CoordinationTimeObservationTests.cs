using Xunit;

namespace XNode.IntegrationTests.Runtime;

public sealed class CoordinationTimeObservationTests
{
    [Theory]
    [InlineData(100UL, 110UL, 103UL, 2UL, 3, 10, 2)]
    [InlineData(100UL, 110UL, 99UL, 0UL, 0, 10, 0)]
    [InlineData(100UL, 99UL, 100UL, 0UL, 0, 0, 0)]
    [InlineData(0UL, ulong.MaxValue, ulong.MaxValue, ulong.MaxValue, 3600, 3600, 3600)]
    public void OnlyBoundedDurationsAreReleased(ulong lower, ulong upper, ulong issued, ulong age, int lead, int width, int elapsed) =>
        Assert.Equal(new CoordinationTimeObservation(lead, width, elapsed),
            CoordinationTimeObservation.Measure(lower, upper, issued, age));
}
