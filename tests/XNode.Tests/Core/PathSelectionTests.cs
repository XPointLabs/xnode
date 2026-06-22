using XNode.Core;
using XNode.Core.Paths;

namespace XNode.Tests.Core;

public sealed class PathSelectionTests
{
    [Fact]
    public void SelectHopsToRemote_UsesDistinctRouterIdsAndIpv4Ranges()
    {
        var contacts = new[]
        {
            TestData.Contact(1, "10.10.1.1"),
            TestData.Contact(2, "10.10.2.1"),
            TestData.Contact(3, "10.10.3.1"),
            TestData.Contact(4, "10.10.1.99"),
            TestData.Contact(9, "10.10.9.1")
        };

        var selector = new PathSelector();
        var selected = selector.SelectHopsToRemote(
            TestData.Id(9),
            new PathSelectionOptions { ClientHops = 3, UniqueHopNetmask = 24 },
            contacts,
            new HashSet<RouterId> { TestData.Id(1) },
            random: new Random(1));

        Assert.NotNull(selected);
        Assert.Equal(3, selected.Hops.Count);
        Assert.Equal(TestData.Id(1), selected.Edge);
        Assert.Equal(TestData.Id(9), selected.Pivot);
        Assert.Equal(selected.RouterIds.Count, selected.RouterIds.Distinct().Count());
        Assert.DoesNotContain(selected.Hops, hop => hop.RouterId == TestData.Id(4));
    }

    [Fact]
    public void SelectHopsToRemote_ExtendsWhenTheOnlyEdgeIsThePivot()
    {
        var contacts = new[]
        {
            TestData.Contact(1, "10.20.1.1"),
            TestData.Contact(2, "10.20.2.1")
        };

        var selected = new PathSelector().SelectHopsToRemote(
            TestData.Id(1),
            new PathSelectionOptions { ClientHops = 2, UniqueHopNetmask = 24 },
            contacts,
            new HashSet<RouterId> { TestData.Id(1) },
            random: new Random(1));

        Assert.NotNull(selected);
        Assert.True(selected.WasExtendedForEdgeOverlap);
        Assert.Equal(3, selected.Hops.Count);
        Assert.Equal(TestData.Id(1), selected.Edge);
        Assert.Equal(TestData.Id(2), selected.Hops[1].RouterId);
        Assert.Equal(TestData.Id(1), selected.Pivot);
    }
}
