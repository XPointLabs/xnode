using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxAdmissionLimiterTests
{
    [Fact]
    public void TypedMailboxPeerClient_UsesTheExplicitPolicyAwareConstructor()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new ReplicatedMailboxOptions());
        services.AddSingleton(DevelopmentUatPrivatePeerAddressPolicy.Disabled);
        services.AddLogging();
        services.AddHttpClient<IMailboxReplicaPeerClient, HttpMailboxReplicaPeerClient>();
        using var provider = services.BuildServiceProvider();

        Assert.IsType<HttpMailboxReplicaPeerClient>(
            provider.GetRequiredService<IMailboxReplicaPeerClient>());
    }

    [Fact]
    public void ClientIngressLimiter_HasOnlyBoundedPerOperationState()
    {
        var limiter = new MailboxClientIngressLimiter();
        ulong now = 1;
        for (var index = 0; index < 4097; index++)
        {
            Assert.True(limiter.TryEnter(
                MailboxWireHttpContract.Store,
                now,
                out var lease));
            lease.Dispose();
            now += 61;
        }

        Assert.True(limiter.TryEnter(
            MailboxWireHttpContract.Retrieve,
            now,
            out var recovered));
        recovered.Dispose();
    }

    [Fact]
    public void ClientIngressLimiter_ConcurrencyRejectionDoesNotConsumeRateQuota()
    {
        var limiter = new MailboxClientIngressLimiter();
        var contract = MailboxWireHttpContract.Store with
        {
            MaximumConcurrentRequests = 1,
            RequestsPerMinute = 2
        };
        Assert.True(limiter.TryEnter(contract, 100, out var first));
        Assert.False(limiter.TryEnter(contract, 100, out var rejected));
        rejected.Dispose();
        first.Dispose();
        Assert.True(limiter.TryEnter(contract, 100, out var second));
        second.Dispose();
        Assert.False(limiter.TryEnter(contract, 100, out var exhausted));
        exhausted.Dispose();
    }

    [Fact]
    public void VerifiedHolderLimiter_IsOpaqueBoundedAndIndependentPerOperation()
    {
        var limiter = new MailboxClientVerifiedHolderLimiter();
        var holder = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        for (var index = 0; index < 120; index++)
        {
            Assert.True(limiter.TryAccept(
                holder,
                MailboxAuthenticatedOperation.Store,
                100));
        }

        Assert.False(limiter.TryAccept(
            holder,
            MailboxAuthenticatedOperation.Store,
            100));
        Assert.True(limiter.TryAccept(
            holder,
            MailboxAuthenticatedOperation.Retrieve,
            100));
        Assert.True(limiter.TryAccept(
            holder,
            MailboxAuthenticatedOperation.Store,
            161));

        var windows = typeof(MailboxClientVerifiedHolderLimiter)
            .GetField(
                "_windows",
                System.Reflection.BindingFlags.Instance
                | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(limiter)!;
        var keys = ((System.Collections.IEnumerable)windows)
            .Cast<object>()
            .Select(item => item.GetType().GetProperty("Key")!.GetValue(item)!.ToString())
            .ToArray();
        Assert.All(keys, key => Assert.Matches("^[0-9A-F]{64}$", key!));
        Assert.DoesNotContain(Convert.ToHexString(holder), keys);
    }

    [Fact]
    public void PeerTransportDoesNotMintClientReceiptsOrExposeStorageObservers()
    {
        Assert.False(typeof(IMailboxClientReplicaFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.False(typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.DoesNotContain(
            typeof(HttpMailboxReplicaPeerClient).GetMethods(),
            method => method.ReturnType == typeof(MailboxReplicaReceiptV2));
        Assert.DoesNotContain(
            typeof(MailboxClientStoreAdapter).GetConstructors()
                .SelectMany(static constructor => constructor.GetParameters()),
            parameter => parameter.ParameterType.Name.Contains(
                "Observer",
                StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(MailboxClientStoreAdapter).GetProperties(),
            property => property.Name.Contains("Observer", StringComparison.Ordinal));
    }
}
