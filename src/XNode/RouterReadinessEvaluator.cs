using XNode.Core.Runtime;

public readonly record struct RouterReadinessDecision(bool Ready, int StatusCode);

public static class RouterReadinessEvaluator
{
    public static RouterReadinessDecision Evaluate(
        RouterStatusSnapshot status,
        bool transportReady,
        bool publicPeerRoutingReady)
    {
        var ready = status.State == "running"
            && transportReady
            && publicPeerRoutingReady
            && status.PrivateMembership.Ready;
        return new RouterReadinessDecision(ready, ready ? 200 : 503);
    }
}
