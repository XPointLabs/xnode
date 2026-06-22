namespace XNode.Core.Paths;

public sealed record SelectedPath(
    IReadOnlyList<RelayContact> Hops,
    bool WasExtendedForEdgeOverlap)
{
    public RouterId Pivot => Hops[^1].RouterId;

    public RouterId Edge => Hops[0].RouterId;

    public IReadOnlyList<RouterId> RouterIds => Hops.Select(hop => hop.RouterId).ToArray();
}
