using System.Security.Cryptography;
using XNode.Core.ContactResolver;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class RetainedMailboxRouteStoreTests
{
    [Fact]
    public async Task ProtectedReadCompletionUsesActualCustodyAcrossCallbackAndReopen()
    {
        using var f = ProtectedFiles();
        var publication = await Publication();
        _ = f.Enroll().PublishDcr(publication);
        var store = f.Open();
        var document = File.ReadAllBytes(f.Document);
        var checkpoint = File.ReadAllBytes(f.Checkpoint);
        var calls = 0;
        var result = await store.WithProtectedRetainedMailboxRouteAsync(await Request(), (facts, ct) =>
        {
            ct.ThrowIfCancellationRequested(); calls++;
            Assert.Equal(RetainedMailboxRouteDisposition.Found, facts.Disposition);
            Assert.Equal(publication.CanonicalRouteClosure.ToArray(), facts.ExactRouteClosure.ToArray());
            f.Custody!.RequireSnapshot(f.Document);
            return ValueTask.FromResult(facts.ReadUntilUnixSeconds);
        });
        Assert.Equal(1, calls);
        Assert.True(result > 0);
        Assert.Equal(document, File.ReadAllBytes(f.Document));
        Assert.Equal(checkpoint, File.ReadAllBytes(f.Checkpoint));
    }

    [Theory]
    [InlineData("document")]
    [InlineData("checkpoint")]
    [InlineData("enrollment")]
    public async Task ProtectedReadNeverReturnsCallbackResultAfterNativeCustodySubstitution(string defect)
    {
        using var f = ProtectedFiles(); var store = f.Enroll();
        _ = store.PublishDcr(await Publication());
        var request = await Request(); var calls = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => store.WithProtectedRetainedMailboxRouteAsync(
            request, (_, _) =>
            {
                calls++;
                var path = defect == "document" ? f.Document : defect == "checkpoint" ? f.Checkpoint : f.Enrollment;
                var bytes = File.ReadAllBytes(path); bytes[^1] ^= 1; File.WriteAllBytes(path, bytes);
                return ValueTask.FromResult("must not escape");
            }).AsTask());
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ProtectedReadRejectsLegitimateUnrelatedMutationAcrossSigningCallback()
    {
        using var f = ProtectedFiles(); var store = f.Enroll();
        _ = store.PublishDcr(await Publication()); var request = await Request();
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WithProtectedRetainedMailboxRouteAsync(
            request, (_, _) =>
            {
                Assert.Equal(ContactResolverMutationDisposition.Committed, store.WriteXurSuccessor(Update()).Disposition);
                return ValueTask.FromResult(1);
            }).AsTask());
        Assert.Equal(RetainedMailboxRouteDisposition.Found,
            (await store.ResolveProtectedRetainedMailboxRouteAsync(request)).Disposition);
    }

    [Theory]
    [InlineData("boot")]
    [InlineData("rollback")]
    [InlineData("expiry")]
    [InlineData("cancel")]
    public async Task ProtectedReadRechecksActualCurrentRequestAfterSigningCallback(string defect)
    {
        using var f = ProtectedFiles(); var store = f.Enroll();
        _ = store.PublishDcr(await Publication());
        var clock = new CallbackClock(); var request = await Request(clock: clock);
        using var cancel = new CancellationTokenSource(); var calls = 0;
        var document = File.ReadAllBytes(f.Document); var root = File.ReadAllBytes(f.Checkpoint);
        Task<int> Run() => store.WithProtectedRetainedMailboxRouteAsync(request, (_, _) =>
        {
            calls++;
            if (defect == "boot") clock.Boot = Bytes(16, 0xfb);
            if (defect == "rollback") clock.Sample = 99;
            if (defect == "expiry") clock.Sample = 300;
            if (defect == "cancel") cancel.Cancel();
            return ValueTask.FromResult(1);
        }, cancel.Token).AsTask();
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(Run);
        else await Assert.ThrowsAnyAsync<CryptographicException>(Run);
        Assert.Equal(1, calls);
        Assert.Equal(document, File.ReadAllBytes(f.Document)); Assert.Equal(root, File.ReadAllBytes(f.Checkpoint));
    }

    [Fact]
    public async Task UnprotectedReadCannotRunProtectedSigningCallback()
    {
        using var f = new Files(); using var store = f.Open();
        _ = store.PublishDcr(await Publication()); var request = await Request(); var calls = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.WithProtectedRetainedMailboxRouteAsync(
            request, (_, _) => { calls++; return ValueTask.FromResult(1); }).AsTask());
        Assert.Equal(0, calls);
    }
}
