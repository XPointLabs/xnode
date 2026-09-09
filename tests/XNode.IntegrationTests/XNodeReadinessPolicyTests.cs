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

    [Theory]
    [InlineData(true, true, true, true, true, "ready", "ready")]
    [InlineData(true, true, false, true, false, "required-unavailable", "ready")]
    [InlineData(true, true, true, false, false, "ready", "required-unavailable")]
    [InlineData(false, false, false, false, true, "disabled", "disabled")]
    public void Required_terminal_readiness_fails_closed_until_each_required_runtime_is_active(
        bool requireContact,
        bool requireGroupControl,
        bool contactActive,
        bool groupControlActive,
        bool expectedReady,
        string expectedContact,
        string expectedGroupControl)
    {
        var status = XNodeReadinessPolicy.RequiredTerminals(
            new RequiredTerminalServicesOptions
            {
                Contact = requireContact,
                GroupControl = requireGroupControl
            },
            contactActive,
            groupControlActive);

        Assert.Equal(expectedReady, status.Ready);
        Assert.Equal(expectedContact, status.Contact);
        Assert.Equal(expectedGroupControl, status.GroupControl);
    }
}
