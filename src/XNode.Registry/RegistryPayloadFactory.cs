using XNode.Core;
using XNode.Transport.Vless;

namespace XNode.Registry;

public sealed class RegistryPayloadFactory
{
    private readonly RouterNodeOptions _nodeOptions;
    private readonly VlessTransportOptions _transportOptions;
    private readonly IXraySupervisor? _xraySupervisor;

    public RegistryPayloadFactory(
        RouterNodeOptions nodeOptions,
        VlessTransportOptions transportOptions,
        IXraySupervisor? xraySupervisor = null)
    {
        _nodeOptions = nodeOptions;
        _transportOptions = transportOptions;
        _xraySupervisor = xraySupervisor;
    }

    public RegistryPayload Create()
    {
        var status = _xraySupervisor?.Status;
        var transport = new TransportMetadata(
            Enabled: status?.Enabled ?? _transportOptions.Enabled,
            Running: status?.Running ?? false,
            Degraded: status?.Degraded ?? false,
            Mode: status?.Mode ?? (_transportOptions.Enabled ? "unknown" : "disabled"),
            Mocked: status?.Mocked ?? _transportOptions.MockProcess,
            RestartCount: status?.RestartCount ?? 0,
            ConsecutiveFailures: status?.ConsecutiveFailures ?? 0,
            LastExitReason: status?.LastExitReason,
            LastStartedAt: status?.LastStartedAt,
            DegradedUntil: status?.DegradedUntil);

        return new RegistryPayload(
            _nodeOptions.RouterId,
            _transportOptions.MaskDomain,
            _transportOptions.TransportMode,
            _transportOptions.PublicHost,
            _transportOptions.PublicPort,
            _transportOptions.TransportMode == VlessTransportMode.Reality ? _transportOptions.Reality : null,
            _transportOptions.TransportMode == VlessTransportMode.Tls ? _transportOptions.Tls : null,
            _transportOptions.Capabilities,
            _transportOptions.ConfigVersion,
            DateTimeOffset.UtcNow,
            transport);
    }
}
