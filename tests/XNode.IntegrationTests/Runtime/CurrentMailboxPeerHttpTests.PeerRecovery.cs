using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core.Mailbox;
using Peer = XNode.IntegrationTests.Runtime.CurrentMailboxReplicaReceiverTests.Fixture;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public void CurrentReleaseUsesOptimizedProtocolDependencies()
    {
#if !DEBUG
        foreach (var assembly in new[]
        {
            typeof(MailboxPeerWireV2Codec).Assembly,
            typeof(Deep.Protocol.DeepExtension.MembershipRoutes.MembershipRouteDescriptorCodec).Assembly
        })
        {
            var debugging = assembly.GetCustomAttributes(typeof(System.Diagnostics.DebuggableAttribute), false)
                .Cast<System.Diagnostics.DebuggableAttribute>().SingleOrDefault();
            Assert.False(debugging?.IsJITOptimizerDisabled ?? false);
        }
#endif
    }

    [Fact]
    public async Task CurrentHostRecoveryUsesOneAuthenticatedSnapshotForClientAndPeerJoin()
    {
        await using var f = await Fixture.CreateAsync(); f.OpenLedger();
        Assert.Equal(MailboxPeerQuorumStatus.Durable,
            (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        using (var document = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(f.LedgerFile)))
        {
            Assert.NotEmpty(document.RootElement.GetProperty("clientReplayFloors").EnumerateObject());
            Assert.NotEmpty(document.RootElement.GetProperty("peerReplayFloors").EnumerateObject());
        }
        var reads = 0;
        f.OpenLedger(afterVerifiedRead: () => reads++);
        await f.Sender.Receiver.InitializeHostAsync();
        Assert.Equal(1, reads);
        await f.Sender.Receiver.InitializeHostAsync();
        Assert.Equal(2, reads); // Fresh snapshot at each boundary, not a cache.

        File.Delete(Assert.Single(f.Sender.ReplayFiles));
        var damaged = AdmissionOwnerDigest(f.Sender.Node.DataRoot);
        var protection = PeerProtectionDigest(f.Sender);
        var requests = f.AllHttpRequests;
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Sender.Receiver.InitializeHostAsync().AsTask());
        Assert.Equal(3, reads);
        Assert.Equal(damaged, AdmissionOwnerDigest(f.Sender.Node.DataRoot));
        Assert.Equal(protection, PeerProtectionDigest(f.Sender));
        Assert.Equal(requests, f.AllHttpRequests);
        Assert.Empty(f.Sender.ReplayFiles);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CurrentStartupReturnsPostJoinTimeOrRejectsChangedAuthority(bool reject)
    {
        await using var f = await Fixture.CreateAsync();
        var before = File.ReadAllBytes(Path.Combine(f.Sender.Node.DataRoot, "mailbox-client-intent", "operations.json"));
        var sample = f.Signed.Sample;
        var expectedUpper = checked(f.Signed.Freshness.TrustedUpperUnixSeconds + sample -
            f.Signed.Freshness.MonotonicSample + 1);
        var checks = 0;
        async Task<ulong> Initialize() => await f.Sender.Node.Admission.WithHostAsync(async (scope, token) =>
            await f.Sender.Operations.InitializeCurrentAsync(f.Sender.Node.Node, scope.Host, scope.Lease, token,
                validatePeer: (floors, _) =>
                {
                    Assert.Empty(floors); checks++;
                    if (reject) f.Signed.RejectProof = true;
                    else f.Signed.Sample = checked(sample + 1);
                    return Task.CompletedTask;
                }));
        if (reject) await Assert.ThrowsAsync<CryptographicException>(Initialize);
        else Assert.Equal(expectedUpper, await Initialize());
        Assert.Equal(1, checks);
        Assert.Equal(before, File.ReadAllBytes(Path.Combine(f.Sender.Node.DataRoot, "mailbox-client-intent", "operations.json")));
        Assert.Equal(0, f.AllHttpRequests);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task CurrentPeerColdRecoveryRejectsCoordinatedNativeLossOrAuthenticPreAckRollback(
        bool recipient, bool restorePreAck)
    {
        await using var f = await Fixture.CreateAsync();
        f.OpenLedger(); AssertDescriptorKeys(f);
        Assert.Equal(MailboxPeerQuorumStatus.Durable,
            (await f.Coordinator.StoreClientAsync(f.ClientStoreFrame())).Status);
        var exactPeerStore = Assert.Single(f.ExactIntents);
        var peer = recipient ? f.Recipient : f.Sender;
        var oldNative = PeerRecoveryFiles(peer).ToDictionary(path => path, File.ReadAllBytes, StringComparer.Ordinal);
        Assert.Equal(3, oldNative.Count); // Store replay, mutation and encrypted blob.
        if (restorePreAck)
        {
            var page = DecodePage((await f.Sender.Receiver.RetrieveClientAsync(RetrieveFrame(f))).Span, f);
            AssertAck((await f.Coordinator.AcknowledgeClientAsync(AckFrame(f, page), f.AckLedger)).Span, page, 0x74);
            AssertTombstones(f, 1);
        }

        // Deliberately alter only this fixture's replaceable native peer data.
        // The operation document, independent checkpoint/enrollment, key ring,
        // current signed authority and client replay/outcomes remain intact.
        var ledgerFile = Path.Combine(peer.Node.DataRoot, "mailbox-client-intent", "operations.json");
        var ledgerDigest = SHA256.HashData(File.ReadAllBytes(ledgerFile));
        var independentDigest = PeerProtectionDigest(peer);
        foreach (var path in PeerRecoveryFiles(peer)) File.Delete(path);
        if (restorePreAck)
        foreach (var (path, bytes) in oldNative)
        {
            File.WriteAllBytes(path, bytes);
            new MailboxStorageSecurity().SecureFile(path);
        }
        f.Reopen();
        peer = recipient ? f.Recipient : f.Sender;
        var damagedDigest = AdmissionOwnerDigest(peer.Node.DataRoot);
        var requests = f.AllHttpRequests;
        using var host = RecoveryHost(f, recipient);
        await host.StartAsync();
        var status = await host.Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync();
        Assert.False(status.Recovered);
        Assert.Equal("unavailable", status.State);
        if (recipient)
            await Assert.ThrowsAsync<InvalidDataException>(() => peer.Receiver.ReceiveAsync(
                exactPeerStore, MailboxPeerReplicationOperation.Store).AsTask());
        else
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.ReplicateAsync(
                exactPeerStore, MailboxPeerReplicationOperation.Store).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => peer.Receiver.RetrieveClientAsync(
            RetrieveFrame(f)).AsTask());
        if (!recipient)
            await Assert.ThrowsAsync<InvalidDataException>(() => f.Coordinator.StoreClientAsync(
                f.ClientStoreFrame()).AsTask());
        Assert.Equal(damagedDigest, AdmissionOwnerDigest(peer.Node.DataRoot));
        Assert.Equal(ledgerDigest, SHA256.HashData(File.ReadAllBytes(ledgerFile)));
        Assert.Equal(independentDigest, PeerProtectionDigest(peer));
        Assert.Equal(requests, f.AllHttpRequests);
        await host.StopAsync();
    }

    private static string[] PeerRecoveryFiles(Peer peer) => peer.ReplayFiles.Concat(peer.MutationFiles)
        .Concat(Directory.GetFiles(Path.Combine(peer.Node.DataRoot, "mailbox-v1"), "*.json", SearchOption.AllDirectories))
        .Order(StringComparer.Ordinal).ToArray();

    private static byte[] PeerProtectionDigest(Peer peer)
    {
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        // Include only aggregate digests in assertion evidence, never protected
        // bytes, key material, opaque selectors or fixture-private paths.
        foreach (var name in new[] { "enrollment.bin", "checkpoint.bin" })
            digest.AppendData(SHA256.HashData(File.ReadAllBytes(Assert.Single(Directory.GetFiles(
                peer.Node.OperationCustodyRoot, name, SearchOption.AllDirectories)))));
        foreach (var path in Directory.GetFiles(peer.Node.ProtectionRoot, "*.xml").Order(StringComparer.Ordinal))
            digest.AppendData(SHA256.HashData(File.ReadAllBytes(path)));
        return digest.GetHashAndReset();
    }
}
