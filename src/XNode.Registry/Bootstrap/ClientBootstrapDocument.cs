using System.Text.Json.Nodes;

namespace XNode.Registry.Bootstrap;

public sealed record ClientBootstrapDocument(
    string RouterId,
    string PublicHost,
    int PublicPort,
    string MaskDomain,
    string TransportMode,
    int ConfigVersion,
    string VlessUri,
    JsonObject XrayOutbound);
