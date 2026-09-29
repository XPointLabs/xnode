namespace XNode.IntegrationTests;

public sealed class XNodeReadinessPolicyTests
{
    [Theory]
    [InlineData(true, true, false, true)]
    [InlineData(true, true, true, true)]
    [InlineData(true, false, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(false, false, true, true)]
    [InlineData(false, false, false, false)]
    [InlineData(false, true, false, false)]
    public void Enabled_privacy_fails_closed_even_in_development(
        bool privacyEnabled,
        bool capabilityAvailable,
        bool isDevelopment,
        bool expected)
    {
        Assert.Equal(
            expected,
            XNodeReadinessPolicy.IsPrivacyReady(privacyEnabled, capabilityAvailable, isDevelopment));
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
