using System.Text.Json;

namespace XNode.Core.Session;

public sealed record SessionRpcRequest(
    string Id,
    string Method,
    JsonElement Payload,
    string? Nonce = null);
