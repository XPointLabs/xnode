using XNode.Transport.Vless;

namespace XNode.Tests.Transport;

public sealed class VlessProfileGuardTests
{
    [Fact]
    public void Validate_RejectsMockInNonDevelopment()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            VlessProfileGuard.Validate(
                new VlessTransportOptions
                {
                    MockProcess = true,
                    XrayExecutablePath = "mock"
                },
                isDevelopment: false));

        Assert.Contains("not allowed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_AllowsMockInDevelopment()
    {
        VlessProfileGuard.Validate(
            new VlessTransportOptions
            {
                MockProcess = true,
                XrayExecutablePath = "mock"
            },
            isDevelopment: true);
    }
}
