namespace XNode.Core.Paths;

public sealed class PathSelectionOptions
{
    public const int MaxBuildLength = 8;

    public int EdgeConnections { get; set; } = 4;

    public int OutboundPaths { get; set; } = 2;

    public int ClientHops { get; set; } = 3;

    public int? RelayHops { get; set; }

    public int InboundPaths { get; set; } = 4;

    public int? InboundHops { get; set; }

    public int InboundPivotReuse { get; set; } = 1;

    public int UniqueHopNetmask { get; set; } = 0;

    public string[] StrictEdges { get; set; } = Array.Empty<string>();

    public string[] SnodeBlacklist { get; set; } = Array.Empty<string>();

    public TimeSpan MinExpiry { get; set; } = TimeSpan.FromMinutes(1);

    public TimeSpan AcceptableExpiry { get; set; } = TimeSpan.FromMinutes(5);

    public TimeSpan BuildTimeout { get; set; } = TimeSpan.FromSeconds(10);

    public TimeSpan PingInterval { get; set; } = TimeSpan.FromSeconds(5);

    public int MaxMissedPings { get; set; } = 5;

    public int GetRelayHops() => RelayHops ?? Math.Min(ClientHops + 1, MaxBuildLength);

    public int GetInboundHops() => InboundHops ?? ClientHops;

    public IReadOnlySet<RouterId> GetStrictEdges() => ParseRouterIdSet(StrictEdges);

    public IReadOnlySet<RouterId> GetSnodeBlacklist() => ParseRouterIdSet(SnodeBlacklist);

    public void Validate()
    {
        if (ClientHops is < 1 or > MaxBuildLength)
        {
            throw new InvalidOperationException($"ClientHops must be between 1 and {MaxBuildLength}.");
        }

        if (RelayHops is < 1 or > MaxBuildLength)
        {
            throw new InvalidOperationException($"RelayHops must be between 1 and {MaxBuildLength}.");
        }

        if (UniqueHopNetmask is not 0 and (< 4 or > 32))
        {
            throw new InvalidOperationException("UniqueHopNetmask must be 0 or between 4 and 32.");
        }

        if (MinExpiry > AcceptableExpiry)
        {
            throw new InvalidOperationException("MinExpiry cannot be longer than AcceptableExpiry.");
        }
    }

    private static IReadOnlySet<RouterId> ParseRouterIdSet(IEnumerable<string> values)
    {
        var set = new HashSet<RouterId>();
        foreach (var value in values)
        {
            set.Add(RouterId.FromHex(value));
        }

        return set;
    }
}
