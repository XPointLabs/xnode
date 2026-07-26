using XNode.Core.Runtime;

namespace XNode.Tests.Core;

public sealed class MembershipRouteArtifactPublisherTests
{
    [Fact]
    public async Task UnconfiguredAndMissingArtifactsFailClosed()
    {
        var unconfigured = new MembershipRouteArtifactPublisher(new MembershipRouteArtifactOptions());
        Assert.False(unconfigured.IsConfigured);
        Assert.Null(await unconfigured.ReadAsync());

        var missing = new MembershipRouteArtifactPublisher(new MembershipRouteArtifactOptions
        {
            ArtifactPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "catalog.bin")
        });
        Assert.True(missing.IsConfigured);
        Assert.Null(await missing.ReadAsync());
    }

    [Fact]
    public async Task ConfiguredArtifactIsReturnedOpaqueAndBounded()
    {
        var directory = Path.Combine(Path.GetTempPath(), "xnode-membership-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "catalog.bin");
        var expected = Enumerable.Range(0, 256).Select(static value => (byte)value).ToArray();
        try
        {
            await File.WriteAllBytesAsync(path, expected);
            var publisher = new MembershipRouteArtifactPublisher(new MembershipRouteArtifactOptions
            {
                ArtifactPath = path,
                MaximumBytes = expected.Length
            });

            Assert.Equal(expected, await publisher.ReadAsync());
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
