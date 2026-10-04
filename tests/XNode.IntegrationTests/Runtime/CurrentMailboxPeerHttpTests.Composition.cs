using System.Net;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    public async Task ActualRegisteredOwnersCompleteNativeStoreRetrieveAckAndColdExactRetryOverPinnedHttp()
    {
        var hosts = new List<Host>();
        var owners = new List<RegisteredPeer>();
        DeepIdV2PublicationAuthorityFixture? signed = null;
        try
        {
            for (var i = 0; i < 3; i++) hosts.Add(await Host.CreateAsync());
            signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true,
                transportOrigins: hosts.Select(h => new DeepIdV2PublicationAuthorityFixture.TransportOrigin(
                    IPAddress.Loopback, checked((ushort)h.Port), h.Pin, SHA256.HashData(h.Pin))).ToArray());
            var host = await MailboxGrantRevocationStoreTests.Host(signed);
            var deposit = MailboxGrantRevocationStoreTests.Grant(signed, host, MailboxCapabilityDomain.Deposit, 0x51);
            var retrieve = MailboxGrantRevocationStoreTests.Grant(signed, host, MailboxCapabilityDomain.Retrieve, 0x52);
            var replicas = await host.ResolveGrantReplicasAsync(deposit);
            foreach (var replica in replicas)
            {
                var http = hosts.Single(h => h.Port == replica.Transport.Port);
                var peer = new RegisteredPeer(signed, replica.NodeId.ToArray(), http.Port);
                owners.Add(peer);
                await peer.Services.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit)
                    .EnrollAsync(host, MailboxGrantRevocationStoreTests.Snapshot(signed));
                await peer.Services.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Retrieve)
                    .EnrollAsync(host, MailboxGrantRevocationStoreTests.Snapshot(signed, MailboxCapabilityDomain.Retrieve));
                await peer.Services.GetRequiredService<CurrentMailboxAdmission>()
                    .EnrollNewOperationsAsync(peer.Services.GetRequiredService<MailboxClientOperationLedger>());
                await peer.Services.GetRequiredService<CurrentMailboxReplicaReceiver>().InitializeHostAsync();
                http.Endpoint = peer.Services.GetRequiredService<CurrentMailboxPeerHttpEndpoint>();
            }
            var body = new MailboxEncryptedEnvelope
            {
                Epoch = host.SelectionEpoch, MailboxId = new(Repeated(32, 0x54)), PlacementId = new(Repeated(32, 0x55)),
                OperationId = Repeated(16, 0x58), DeduplicationDigest = Repeated(32, 0x59),
                CreatedAtUnixSeconds = 1_090, ExpiresAtUnixSeconds = 1_150, Ciphertext = Repeated(64, 0x60)
            };
            byte[] Present(MailboxAuthenticatedRequestBinding binding, byte[] grant, ulong counter = 1) =>
                MailboxAuthenticatedClientRequestCodec.Encode(new()
                {
                    Binding = binding,
                    Presentation = new SodiumMailboxCapabilityCrypto().SignPresentation(
                        MailboxAuthenticatedCapabilityCodec.DecodeGrant(grant), binding, counter, Repeated(32, 0x57))
                });
            async Task<byte[]> Dispatch(RegisteredPeer peer, OnionOperation operation, byte[] request)
            {
                var result = await ((ILocalNativeMailboxExitDispatcher)peer.Services.GetRequiredService<NativeMailboxExitDispatcher>())
                    .DispatchAsync(operation, request, default);
                Assert.Equal(NativeMailboxDispatchCertainty.Completed, result.Certainty);
                Assert.Equal(200, result.StatusCode);
                return result.CanonicalBody.ToArray();
            }
            MailboxRetrievePage Page(byte[] bytes) => MailboxClientCodec.DecodeRetrievePage(bytes, new()
            {
                NowUnixSeconds = 1_100,
                EpochWindow = new() { CurrentEpoch = host.SelectionEpoch, CurrentNotBeforeUnixSeconds = 1_090,
                    CurrentExpiresAtUnixSeconds = 1_110, NextEpoch = 0, NextNotBeforeUnixSeconds = 0,
                    NextExpiresAtUnixSeconds = 0 }, CapabilityPolicy = new() { CurrentBucket = 0, MinimumGeneration = 1 }
            });
            var store = Present(MailboxAuthenticatedRequestTranscript.ForStore(body), deposit);
            var stored = await Dispatch(owners[0], OnionOperation.Store, store);
            var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(stored);
            Assert.False(quorum.FirstReplica.ReplicaId.Span.SequenceEqual(quorum.SecondReplica.ReplicaId.Span));
            var read = Present(MailboxAuthenticatedRequestTranscript.ForRetrieve(body.Epoch,
                Repeated(16, 0x71), body.MailboxId, body.PlacementId, 0, 10, []), retrieve);
            foreach (var owner in owners)
            {
                var item = Assert.Single(Page(await Dispatch(owner, OnionOperation.Retrieve, read)).Items);
                Assert.Equal(body.Ciphertext.ToArray(), item.Envelope.Ciphertext.ToArray());
            }
            var page = Page(await Dispatch(owners[0], OnionOperation.Retrieve, read));
            var ack = Present(MailboxAuthenticatedRequestTranscript.ForAck(body.Epoch, Repeated(16, 0x74),
                body.MailboxId, body.PlacementId, !page.HasMore, page.ContinuationToken.Span,
                page.Items.Select(item => item.ToAcknowledgement()).ToArray()), retrieve);
            var acknowledged = await Dispatch(owners[0], OnionOperation.Acknowledge, ack);
            AssertAck(acknowledged, page, 0x74);
            var requests = hosts.Sum(h => h.Requests);
            Assert.Equal(2, requests);
            foreach (var owner in owners)
            {
                await owner.ReopenAsync();
                hosts.Single(h => h.Port == owner.Port).Endpoint = owner.Services.GetRequiredService<CurrentMailboxPeerHttpEndpoint>();
                await owner.Services.GetRequiredService<CurrentMailboxReplicaReceiver>().InitializeHostAsync();
            }
            signed.Sample = 101;
            Assert.Equal(stored, await Dispatch(owners[0], OnionOperation.Store, store));
            Assert.Equal(acknowledged, await Dispatch(owners[0], OnionOperation.Acknowledge, ack));
            var freshRead = Present(MailboxAuthenticatedRequestTranscript.ForRetrieve(body.Epoch,
                Repeated(16, 0x72), body.MailboxId, body.PlacementId, 0, 10, []), retrieve, 2);
            foreach (var owner in owners) Assert.Empty(Page(await Dispatch(owner, OnionOperation.Retrieve, freshRead)).Items);
            Assert.Equal(requests, hosts.Sum(h => h.Requests));
        }
        finally
        {
            foreach (var http in hosts) await http.DisposeAsync();
            foreach (var owner in owners) await owner.DisposeAsync();
            signed?.Dispose();
        }
    }

    // Explicit test-owned signed enrollment; production registration and readers
    // remain unchanged. Actual HTTP uses the existing descriptor-pinned client.
    private sealed class RegisteredPeer : IAsyncDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "deep-registered-peer-" + Guid.NewGuid().ToString("N"));
        private readonly DeepIdV2PublicationAuthorityFixture signed;
        private readonly RouterNodeOptions node;
        private readonly ReplicatedMailboxOptions mailbox = new() { Enabled = true };
        private readonly CurrentMailboxCustodyConfiguration configuration;
        internal ServiceProvider Services { get; private set; }
        internal int Port { get; }
        internal RegisteredPeer(DeepIdV2PublicationAuthorityFixture signed, byte[] id, int port)
        {
            this.signed = signed; Port = port;
            node = new() { DataDirectory = Path.Combine(root, "data"), RouterId = Convert.ToHexString(id),
                Ed25519PrivateKey = Convert.ToHexString(signed.Node(id).Seed), PrivacyPeerH2ListenUrl = "https://127.0.0.1:" + port };
            var keys = Path.Combine(root, "keys");
            var security = new MailboxStorageSecurity(); security.SecureDirectory(keys);
            var provisioning = new ServiceCollection();
            provisioning.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keys))
                .SetApplicationName(CurrentMailboxHostComposition.ProtectionApplication).DisableAutomaticKeyGeneration();
            using (var provider = provisioning.BuildServiceProvider())
                provider.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(90));
            foreach (var key in Directory.GetFiles(keys)) security.SecureFile(key);
            configuration = new CurrentMailboxCustodyOptions
            {
                NetworkIdHex = Convert.ToHexString(signed.NetworkContext.NetworkId.Span).ToLowerInvariant(),
                MailboxAuthorityCoreHashHex = Convert.ToHexString(ContactCodec.Decode(ProtocolMagic.PMA2, signed.MailboxAuthority.Span).CoreHash.Span).ToLowerInvariant(),
                IndependentCustodyDirectory = Path.Combine(root, "custody"), DataProtectionKeysDirectory = keys
            }.Validate(node, mailbox)!;
            Services = Open();
        }
        private ServiceProvider Open()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(signed);
            services.AddSingleton<IOnionMonotonicClock>(signed);
            services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
            services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
            services.AddSingleton(mailbox); services.AddSingleton<NativeMailboxExitDispatcher>();
            services.AddCurrentMailboxHost(configuration, node, mailbox);
            return services.BuildServiceProvider();
        }
        internal async Task ReopenAsync() { await Services.DisposeAsync(); Services = Open(); }
        public async ValueTask DisposeAsync()
        {
            await Services.DisposeAsync();
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
    private static byte[] Repeated(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
}
