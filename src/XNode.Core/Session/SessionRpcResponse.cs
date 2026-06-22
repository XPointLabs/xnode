namespace XNode.Core.Session;

public sealed record SessionRpcResponse(
    string Id,
    bool Success,
    object? Result,
    string? Error)
{
    public static SessionRpcResponse Ok(string id, object? result) => new(id, true, result, null);

    public static SessionRpcResponse Fail(string id, string error) => new(id, false, null, error);
}
