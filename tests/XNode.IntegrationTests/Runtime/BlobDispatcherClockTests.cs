using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.BlobV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class BlobDispatcherClockTests
{
    [Fact]
    public void DispatcherConstructionDoesNotAcquireProductionTimeOrCreateCustody()
    {
        var root = Path.Combine(Path.GetTempPath(), "deep-blob-clock-" + Guid.NewGuid().ToString("N"));
        var resolutions = 0;
        using var services = Services(new RouterNodeOptions { DataDirectory = root }, () =>
        {
            resolutions++;
            throw new PlatformNotSupportedException("The test host has no production clock.");
        });
        _ = services.GetRequiredService<BlobChunkOnionDispatcher>();
        Assert.Equal(0, resolutions);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public async Task ActualBlobDispatchStillRequiresTheConfiguredClockBeforeMutation()
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync();
        var root = Path.Combine(Path.GetTempPath(), "deep-blob-clock-" + Guid.NewGuid().ToString("N"));
        var cipher = Enumerable.Repeat((byte)0x55, 528).ToArray();
        using var manifest = ApplicationCoreCodec.AuthorDam1(DeepIdV2PublicationAuthorityFixture.Network,
            Enumerable.Repeat((byte)2, 32).ToArray(), Enumerable.Repeat((byte)3, 32).ToArray(),
            Enumerable.Repeat((byte)4, 32).ToArray(), 512, [new(0, 528, SHA256.HashData(cipher))],
            1_300, "fixture.dat", "application/octet-stream");
        var local = OnionPathContextFactory.BlobNodeIds(signed.NetworkContext, manifest.ObjectId)[0];
        var resolutions = 0;
        using var services = Services(new RouterNodeOptions
        { DataDirectory = root, RouterId = Convert.ToHexString(local.Span) }, () =>
        {
            resolutions++;
            throw new PlatformNotSupportedException("The test host has no production clock.");
        }, signed);
        var dispatcher = services.GetRequiredService<BlobChunkOnionDispatcher>();
        Assert.Equal(0, resolutions);
        var request = OnionTerminalPayloadVerifierV1.VerifyRequest(signed.NetworkContext, OnionOperation.Blob,
            BlobChunkCodec.EncodeRequest(manifest, BlobChunkOperation.Put, 0, cipher));
        await Assert.ThrowsAsync<PlatformNotSupportedException>(() => dispatcher.DispatchAsync(request, default));
        Assert.Equal(1, resolutions);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void ProductionClockStillRejectsUnsupportedHosts()
    {
        if (!OperatingSystem.IsLinux())
            Assert.Throws<PlatformNotSupportedException>(() => new LinuxBootOnionMonotonicClock());
    }

    private static ServiceProvider Services(RouterNodeOptions node, Func<IOnionMonotonicClock> clock,
        IDeepIdV2ContactStoreAuthoritySource? authority = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(node);
        services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddSingleton<IOnionMonotonicClock>(_ => clock());
        if (authority is not null) services.AddSingleton(authority);
        services.AddSingleton<BlobChunkOnionDispatcher>();
        return services.BuildServiceProvider();
    }
}
