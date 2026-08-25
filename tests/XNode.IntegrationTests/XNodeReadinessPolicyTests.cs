namespace XNode.IntegrationTests;

public sealed class XNodeReadinessPolicyTests
{
    [Theory]
    [InlineData(true, false, true)]
    [InlineData(true, true, true)]
    [InlineData(false, true, true)]
    [InlineData(false, false, false)]
    public void Privacy_readiness_is_optional_only_in_development(
        bool privacyEnabled,
        bool isDevelopment,
        bool expected)
    {
        Assert.Equal(
            expected,
            XNodeReadinessPolicy.IsPrivacyReady(privacyEnabled, isDevelopment));
    }
}
