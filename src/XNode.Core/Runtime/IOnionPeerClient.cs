using XNode.Core.Onion;
using XNode.Core.Session;

namespace XNode.Core.Runtime;

public interface IOnionPeerClient
{
    Task<SessionRpcResponse> ForwardAsync(
        string rpcEndpoint,
        OnionRequest request,
        CancellationToken cancellationToken);
}

public sealed class DisabledOnionPeerClient : IOnionPeerClient
{
    public Task<SessionRpcResponse> ForwardAsync(
        string rpcEndpoint,
        OnionRequest request,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(SessionRpcResponse.Fail("onion-forward", "onion-peer-client-disabled"));
    }
}
