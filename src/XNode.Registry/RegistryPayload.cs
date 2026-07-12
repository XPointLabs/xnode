using XNode.Transport.Vless;

namespace XNode.Registry;

public sealed record RegistryPayload(
    string RouterId,
    string MaskDomain,
    VlessTransportMode TransportMode,
    string PublicHost,
    int PublicPort,
    RealityPublicMetadata? Reality,
    TlsMetadata? Tls,
    string[] Capabilities,
    int ConfigVersion,
    DateTimeOffset PublishedAt,
    TransportMetadata Transport);
