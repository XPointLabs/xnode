using System.Text.Json;

namespace XNode.Core.Runtime;

public interface ISessionStorageRpcBackend
{
    Task<SessionStorageRpcResult> PostAsync(
        string path,
        JsonElement payload,
        CancellationToken cancellationToken);
}

public sealed record SessionStorageRpcResult(
    int StatusCode,
    JsonElement? Body,
    string? Error)
{
    public bool IsSuccessStatusCode => StatusCode is >= 200 and <= 299;
}

public sealed class DisabledSessionStorageRpcBackend : ISessionStorageRpcBackend
{
    public Task<SessionStorageRpcResult> PostAsync(
        string path,
        JsonElement payload,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new SessionStorageRpcResult(
            StatusCodes.ServiceUnavailable,
            null,
            "session-storage-rpc-disabled"));
    }

    private static class StatusCodes
    {
        public const int ServiceUnavailable = 503;
    }
}
