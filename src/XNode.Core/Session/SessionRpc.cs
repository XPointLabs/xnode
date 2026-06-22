using System.Text.Json;

namespace XNode.Core.Session;

public static class SessionRpc
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };
}
