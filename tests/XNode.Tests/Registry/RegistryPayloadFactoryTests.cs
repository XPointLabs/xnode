using XNode.Core;
using XNode.Registry;
using XNode.Transport.Vless;

namespace XNode.Tests.Registry;

public sealed class RegistryPayloadFactoryTests
{
    [Fact]
    public void Create_IncludesLiveTransportMetadataFromSupervisor()
    {
        var options = new VlessTransportOptions
        {
            Enabled = true,
            PublicHost = "node.example.org",
            PublicPort = 443,
            TransportMode = VlessTransportMode.Reality
        };

        var supervisor = new StubSupervisor(new XraySupervisorStatus(
            Enabled: true,
            Running: false,
            Mocked: false,
            Degraded: true,
            Mode: "degraded",
            RestartCount: 7,
            ConsecutiveFailures: 3,
            ProcessId: null,
            ConfigPath: "/tmp/xray.generated.json",
            LastExitReason: "xray-exited:1",
            LastStartedAt: DateTimeOffset.UtcNow.AddMinutes(-2),
            DegradedUntil: DateTimeOffset.UtcNow.AddSeconds(30)));

        var payload = new RegistryPayloadFactory(
            new RouterNodeOptions { RouterId = TestData.Id(1).Value },
            options,
            supervisor).Create();

        Assert.Equal("degraded", payload.Transport.Mode);
        Assert.True(payload.Transport.Degraded);
        Assert.Equal(7, payload.Transport.RestartCount);
        Assert.Equal("xray-exited:1", payload.Transport.LastExitReason);
    }

    private sealed class StubSupervisor : IXraySupervisor
    {
        public StubSupervisor(XraySupervisorStatus status)
        {
            Status = status;
        }

        public XraySupervisorStatus Status { get; }
    }
}
