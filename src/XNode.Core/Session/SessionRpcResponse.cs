namespace XNode.Core.Session;

public sealed record SessionRpcResponse(
    string Id,
    bool Success,
    object? Result,
    string? Error)
{
    public string? Version { get; init; }

    public string? ResponderRouterId { get; init; }

    public string? Method { get; init; }

    public string? Nonce { get; init; }

    public string? RequestPayloadSha256 { get; init; }

    public long? IssuedAtUnixMs { get; init; }

    public string? OutcomeSha256 { get; init; }

    public string? SignatureAlgorithm { get; init; }

    public string? Signature { get; init; }

    public static SessionRpcResponse Ok(string id, object? result) => new(id, true, result, null);

    public static SessionRpcResponse Fail(string id, string error) => new(id, false, null, error);
}
