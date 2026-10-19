namespace XNode.IntegrationTests.Runtime;

public sealed class GroupControlAuthorityWindowTests
{
    [Theory]
    [InlineData(100UL, 120UL, 110UL, 200UL)]
    [InlineData(100UL, 220UL, 100UL, 220UL)]
    public void OriginalCarriageWindowRemainsLiveWithinExactBounds(ulong issued, ulong expires, ulong upper, ulong ceiling) =>
        DeepIdV2GroupControlAuthoritySource.RequireCarriageWindow(issued, expires, upper, ceiling);

    [Theory]
    [InlineData(111UL, 120UL, 110UL, 200UL, "IssuedFuture")]
    [InlineData(100UL, 120UL, 120UL, 200UL, "Expired")]
    [InlineData(100UL, 100UL, 90UL, 200UL, "InvalidWindow")]
    [InlineData(100UL, 221UL, 110UL, 500UL, "InvalidWindow")]
    [InlineData(100UL, 120UL, 110UL, 119UL, "NetworkCeiling")]
    public void RejectionHasOnlyClosedReasonNotAuthorityTimestamps(ulong issued, ulong expires, ulong upper, ulong ceiling,
        string expected)
    {
        var error = Assert.Throws<GroupControlAuthorityUnavailableException>(() =>
            DeepIdV2GroupControlAuthoritySource.RequireCarriageWindow(issued, expires, upper, ceiling));
        Assert.Equal(expected, error.Rejection.ToString()); Assert.Empty(error.Data);
    }
}
