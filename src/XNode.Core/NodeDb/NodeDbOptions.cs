namespace XNode.Core.NodeDb;

public sealed class NodeDbOptions
{
    public string DataDirectory { get; set; } = "/var/lib/xnode";

    public string DirectoryName { get; set; } = "nodedb";

    public string LocalRouterId { get; set; } = "0000000000000000000000000000000000000000000000000000000000000000";

    public bool IsRelay { get; set; } = true;

    public RouterId GetLocalRouterId() => XNode.Core.RouterId.FromHex(LocalRouterId);
}
