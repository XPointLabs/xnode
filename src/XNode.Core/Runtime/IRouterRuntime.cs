using XNode.Core.Session;

namespace XNode.Core.Runtime;

public interface IRouterRuntime
{
    RouterStatusSnapshot Status { get; }

    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);

    Task<SessionRpcResponse> HandleRpcAsync(SessionRpcRequest request, CancellationToken cancellationToken);
}
