using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualRegisteredOwnersCompleteNativeStoreRetrieveAckAndColdExactRetryOverPinnedHttp(bool actualProgram)
        => await CompleteRegisteredCycleAsync(actualProgram);

    [Fact]
    public async Task ConfiguredProgramSourcesEnrollRecoverAndCompleteStoreRetrieveAckOverPinnedHttp()
        => await CompleteRegisteredCycleAsync(actualProgram: true, configuredProgram: true);

    private async Task CompleteRegisteredCycleAsync(bool actualProgram, bool configuredProgram = false)
    {
        var hosts = new List<Host>();
        var owners = new List<RegisteredPeer>();
        DeepIdV2PublicationAuthorityFixture? signed = null;
        ConfiguredAuthority? configured = null;
        try
        {
            for (var i = 0; i < 3; i++) hosts.Add(configuredProgram ? Host.ReserveConfiguredProgram()
                : actualProgram ? await Host.CreateProgramAsync() : await Host.CreateAsync());
            signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true,
                transportOrigins: hosts.Select(h => new DeepIdV2PublicationAuthorityFixture.TransportOrigin(
                    IPAddress.Loopback, checked((ushort)h.Port), h.Pin, SHA256.HashData(h.Pin))).ToArray());
            if (configuredProgram) configured = await ConfiguredAuthority.CreateAsync(signed);
            var host = await MailboxGrantRevocationStoreTests.Host(signed);
            var deposit = MailboxGrantRevocationStoreTests.Grant(signed, host, MailboxCapabilityDomain.Deposit, 0x51);
            var retrieve = MailboxGrantRevocationStoreTests.Grant(signed, host, MailboxCapabilityDomain.Retrieve, 0x52);
            var replicas = await host.ResolveGrantReplicasAsync(deposit);
            var ownedReplicas = replicas.ToList();
            if (configuredProgram)
                foreach (var id in signed.NodeIds)
                    if (!ownedReplicas.Any(replica => replica.NodeId.Span.SequenceEqual(id.Span)))
                        ownedReplicas.Add(await host.ResolveReplicaAsync(id));
            foreach (var replica in ownedReplicas)
            {
                var http = hosts.Single(h => h.Port == replica.Transport.Port);
                var peer = new RegisteredPeer(signed, replica.NodeId.ToArray(), http.Port, configured, http, hosts);
                owners.Add(peer);
                if (configuredProgram)
                {
                    await CurrentMailboxEnrollmentCommand.EnrollConfiguredAsync(peer.Services,
                        MailboxGrantRevocationStoreTests.Snapshot(signed),
                        MailboxGrantRevocationStoreTests.Snapshot(signed, MailboxCapabilityDomain.Retrieve), default);
                    await peer.StartConfiguredProgramAsync();
                    continue;
                }
                await peer.Services.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Deposit)
                    .EnrollAsync(host, MailboxGrantRevocationStoreTests.Snapshot(signed));
                await peer.Services.GetRequiredKeyedService<FileMailboxGrantRevocationStore>(MailboxCapabilityDomain.Retrieve)
                    .EnrollAsync(host, MailboxGrantRevocationStoreTests.Snapshot(signed, MailboxCapabilityDomain.Retrieve));
                await peer.Services.GetRequiredService<CurrentMailboxAdmission>()
                    .EnrollNewOperationsAsync(peer.Services.GetRequiredService<MailboxClientOperationLedger>());
                await peer.Services.GetRequiredService<CurrentMailboxReplicaReceiver>().InitializeHostAsync();
                http.Endpoint = peer.Services.GetRequiredService<CurrentMailboxPeerHttpEndpoint>();
            }
            if (actualProgram)
            {
                var http = hosts.Single(h => h.Port == replicas[0].Transport.Port);
                var proofReads = signed.ProofReads;
                using var pinned = new HttpClient(HttpPrivacyPeerClient.CreatePinnedHandler(replicas[0].Transport))
                { DefaultRequestVersion = HttpVersion.Version20, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact };
                var origin = "https://127.0.0.1:" + http.Port;
                foreach (var retired in new[] { "/api/peer/mailbox-authority/v1/store", "/api/peer/mailbox-authority/v1/retrieve",
                    "/api/peer/mailbox-authority/v1/acknowledge", "/api/client/mailbox/v2/store" })
                {
                    using var result = await pinned.PostAsync(origin + retired, new ByteArrayContent([]));
                    Assert.Equal(HttpStatusCode.NotFound, result.StatusCode);
                }
                using (var result = await pinned.GetAsync(origin + MailboxWireHttpContract.PeerStoreRoute))
                    Assert.Equal(HttpStatusCode.NotFound, result.StatusCode);
                using (var invalid = new ByteArrayContent([1]))
                using (var result = await pinned.PostAsync(origin + MailboxWireHttpContract.PeerStoreRoute, invalid))
                    Assert.Equal(HttpStatusCode.UnsupportedMediaType, result.StatusCode);
                using (var oversized = new ByteArrayContent(new byte[MailboxWireHttpContract.PeerStore.MaximumRequestBytes + 1]))
                {
                    oversized.Headers.ContentType = new MediaTypeHeaderValue(MailboxWireHttpContract.PeerStore.RequestContentType);
                    using var result = await pinned.PostAsync(origin + MailboxWireHttpContract.PeerStoreRoute, oversized);
                    Assert.Equal(HttpStatusCode.RequestEntityTooLarge, result.StatusCode);
                }
                using var api = new HttpClient();
                using (var result = await api.PostAsync("http://127.0.0.1:" + http.ApiPort + MailboxWireHttpContract.PeerStoreRoute,
                    new ByteArrayContent([])))
                    Assert.Equal(HttpStatusCode.NotFound, result.StatusCode);
                Assert.Equal(proofReads, signed.ProofReads);
                // A configured host retains its independent refresh workers;
                // their legitimate HTTP proof reads are not caused by these rejected requests.
                Assert.Equal(3, hosts.Sum(h => h.Requests));
            }
            var rejectedRequests = hosts.Sum(h => h.Requests);
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
                if (configuredProgram)
                    return await configured!.DispatchOnionAsync(peer, owners, operation, request,
                        replicas[0].NodeId, replicas[1].NodeId);
                var result = await ((ILocalNativeMailboxExitDispatcher)peer.Services.GetRequiredService<NativeMailboxExitDispatcher>())
                    .DispatchAsync(operation, request, default);
                Assert.True(result.Certainty == NativeMailboxDispatchCertainty.Completed,
                    $"{operation}: {result.Certainty}; peer requests={hosts.Sum(h => h.Requests)}; statuses={string.Join(',', hosts.Select(h => h.LastStatus))}; byte counts={string.Join(',', hosts.Select(h => h.LastBytes))}");
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
            if (configuredProgram)
            {
                // The second member is a genuine selected replica with a valid
                // descriptor and TLS pin, but is not the grant's Store writer.
                // Send through the public entry, not a direct dispatcher call.
                var before = owners.Select(owner => owner.NativeMailboxDigest()).ToArray();
                await configured!.DispatchOnionAsync(owners[1], owners, OnionOperation.Store, store,
                    replicas[0].NodeId, replicas[1].NodeId, expectFailure: true);
                for (var index = 0; index < owners.Count; index++)
                    Assert.Equal(before[index], owners[index].NativeMailboxDigest());
                Assert.Equal(rejectedRequests, hosts.Sum(h => h.Requests));
            }
            var stored = await Dispatch(owners[0], OnionOperation.Store, store);
            var quorum = MailboxReceiptV3Codec.DecodeDurableQuorum(stored);
            Assert.False(quorum.FirstReplica.ReplicaId.Span.SequenceEqual(quorum.SecondReplica.ReplicaId.Span));
            var read = Present(MailboxAuthenticatedRequestTranscript.ForRetrieve(body.Epoch,
                Repeated(16, 0x71), body.MailboxId, body.PlacementId, 0, 10, []), retrieve);
            foreach (var owner in owners.Take(2))
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
            Assert.Equal(2 + rejectedRequests, requests);
            foreach (var owner in owners)
            {
                await owner.ReopenAsync();
                if (!configuredProgram)
                    hosts.Single(h => h.Port == owner.Port).Endpoint = owner.Services.GetRequiredService<CurrentMailboxPeerHttpEndpoint>();
                await owner.Services.GetRequiredService<CurrentMailboxReplicaReceiver>().InitializeHostAsync();
                if (configuredProgram) await owner.AssertConfiguredReadyAsync();
            }
            signed.Sample = 101;
            Assert.Equal(stored, await Dispatch(owners[0], OnionOperation.Store, store));
            Assert.Equal(acknowledged, await Dispatch(owners[0], OnionOperation.Acknowledge, ack));
            var freshRead = Present(MailboxAuthenticatedRequestTranscript.ForRetrieve(body.Epoch,
                Repeated(16, 0x72), body.MailboxId, body.PlacementId, 0, 10, []), retrieve, 2);
            foreach (var owner in owners.Take(2)) Assert.Empty(Page(await Dispatch(owner, OnionOperation.Retrieve, freshRead)).Items);
            Assert.Equal(requests, hosts.Sum(h => h.Requests));
            if (configuredProgram)
            {
                Assert.True(configured!.ProofRequests >= owners.Count * 2); // independently acquired after each cold host start
                Assert.Equal(0, signed.ProofReads); // no verified fixture-source shortcut
                foreach (var owner in owners) await owner.AssertConfiguredAuthorityLossAsync();
            }
        }
        finally
        {
            foreach (var http in hosts) await http.DisposeAsync();
            foreach (var owner in owners) await owner.DisposeAsync();
            if (configured is not null) await configured.DisposeAsync();
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
        private ServiceProvider? ownedServices;
        private readonly ConfiguredAuthority? configured;
        private readonly Host? configuredHost;
        private readonly Dictionary<string, string?>? programConfiguration;
        internal IServiceProvider Services { get; private set; }
        internal int Port { get; }
        internal byte[] NativeMailboxDigest()
        {
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            foreach (var directory in Directory.GetDirectories(node.DataDirectory)
                .Where(path => Path.GetFileName(path).StartsWith("mailbox-", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
            {
                digest.AppendData(System.Text.Encoding.UTF8.GetBytes(Path.GetFileName(directory) + "\0"));
                foreach (var file in Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                {
                    digest.AppendData(System.Text.Encoding.UTF8.GetBytes(Path.GetRelativePath(node.DataDirectory, file) + "\0"));
                    if (Path.GetFileName(file) is ".replay.lock" or ".outcomes.lock" or ".adapter.lock" or ".lease")
                    {
                        // Actual owners deliberately deny a second open. Their
                        // empty lock inventory is checked, never bypassed.
                        Assert.Equal(0, new FileInfo(file).Length);
                        digest.AppendData(SHA256.HashData(Array.Empty<byte>()));
                    }
                    else digest.AppendData(SHA256.HashData(File.ReadAllBytes(file)));
                }
            }
            return digest.GetHashAndReset();
        }
        internal RegisteredPeer(DeepIdV2PublicationAuthorityFixture signed, byte[] id, int port,
            ConfiguredAuthority? configured = null, Host? http = null, IReadOnlyList<Host>? hosts = null)
        {
            this.signed = signed; Port = port;
            this.configured = configured; configuredHost = http;
            node = new() { DataDirectory = Path.Combine(root, "data"), RouterId = Convert.ToHexString(id),
                Ed25519PrivateKey = Convert.ToHexString(signed.Node(id).Seed), PrivacyPeerH2ListenUrl = "https://127.0.0.1:" +
                    (configured is null ? port : http!.configuredPorts![3]) };
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
            if (configured is not null)
                programConfiguration = configured.CreateConfiguration(root, node, configuration, http!, hosts!);
            Services = ownedServices = Open();
        }
        private ServiceProvider Open()
        {
            var services = new ServiceCollection();
            services.AddSingleton(node);
            if (configured is null) services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(signed);
            else
            {
                var input = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                    .AddInMemoryCollection(programConfiguration!).Build();
                services.AddDeepIdV2DirectoryProof(input.GetSection("DeepIdV2DirectoryProof")
                    .Get<DeepIdV2DirectoryProofOptions>()!.ValidateAndLoad(node, true)!);
                services.AddDeepIdV2NetworkPlacement(input.GetSection("DeepIdV2NetworkPlacement")
                    .Get<DeepIdV2NetworkPlacementOptions>()!.ValidateAndLoad(true, true)!);
                configured.ConfigureTestDependencies(services);
            }
            services.AddSingleton<IOnionMonotonicClock>(signed);
            services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
            services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
            services.AddSingleton(mailbox); services.AddSingleton<NativeMailboxExitDispatcher>();
            services.AddCurrentMailboxHost(configuration, node, mailbox);
            return services.BuildServiceProvider();
        }
        internal async Task ReopenAsync()
        {
            if (configured is null) { await ownedServices!.DisposeAsync(); Services = ownedServices = Open(); }
            else { await configuredHost!.CloseConfiguredProgramAsync(); await StartConfiguredProgramAsync(); }
        }
        internal async Task StartConfiguredProgramAsync()
        {
            if (ownedServices is not null) { await ownedServices.DisposeAsync(); ownedServices = null; }
            Services = configuredHost!.StartConfiguredProgram(programConfiguration!, configured!);
            await configuredHost.StartConfiguredIngressAsync();
            await AssertConfiguredReadyAsync();
        }
        internal async Task AssertConfiguredReadyAsync()
        {
            Assert.IsType<DeepIdV2NetworkPlacementRuntime>(Services.GetRequiredService<IDeepIdV2ContactStoreAuthoritySource>());
            await Services.GetRequiredService<CurrentMailboxReplicaReceiver>().InitializeHostAsync();
            var recovery = await Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync();
            Assert.True(recovery.Recovered, recovery.State);
            using var client = new HttpClient();
            using var result = await client.GetAsync("http://127.0.0.1:" + configuredHost!.ApiPort + "/health/ready");
            Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        }
        internal async Task AssertConfiguredAuthorityLossAsync()
        {
            // Admission must not reacquire proof or repair a damaged signed source.
            var path = programConfiguration!["DeepIdV2NetworkPlacement:ExactMailboxAuthorityPaths:0"]!;
            var original = File.ReadAllBytes(path); File.WriteAllBytes(path, [1]);
            try
            {
                Assert.False((await Services.GetRequiredService<CurrentMailboxHostRecovery>().CheckAsync()).Recovered);
                using var client = new HttpClient();
                using var result = await client.GetAsync("http://127.0.0.1:" + configuredHost!.ApiPort + "/health/ready");
                Assert.Equal(HttpStatusCode.ServiceUnavailable, result.StatusCode);
                Assert.Equal(new byte[] { 1 }, File.ReadAllBytes(path));
            }
            finally { File.WriteAllBytes(path, original); }
        }
        public async ValueTask DisposeAsync()
        {
            if (ownedServices is not null) await ownedServices.DisposeAsync();
            if (Directory.Exists(root)) Directory.Delete(root, true);
        }
    }
    private static byte[] Repeated(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
}
