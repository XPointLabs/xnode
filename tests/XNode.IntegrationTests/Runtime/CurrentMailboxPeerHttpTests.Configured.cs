using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.PrivacyRouting;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    // Actual configured Program/native owners and HTTP artifact verification.
    // Only the clock and trust of a test-owned loopback TLS certificate are
    // supplied here. Xray is explicitly disabled: this is not carrier/device evidence.
    private sealed class ConfiguredAuthority : IAsyncDisposable
    {
        private readonly DeepIdV2PublicationAuthorityFixture signed;
        private readonly Host tls = Host.CreateCertificate();
        private WebApplication app = null!;
        private int proofRequests;
        private readonly string clientRoot = Path.Combine(Path.GetTempPath(), "deep-configured-onion-client-" + Guid.NewGuid().ToString("N"));
        private DurableOnionEntropyUniquenessLedger? entropy;
        private FileOnionKeyAgreementVault? vault;
        private PrivacyRoutingCodec? client;
        private bool checkedIngressRefusals;
        internal int ProofRequests => Volatile.Read(ref proofRequests);
        internal string Origin { get; private set; } = "";

        private ConfiguredAuthority(DeepIdV2PublicationAuthorityFixture signed) => this.signed = signed;

        internal static async Task<ConfiguredAuthority> CreateAsync(DeepIdV2PublicationAuthorityFixture signed)
        {
            var source = new ConfiguredAuthority(signed);
            try
            {
                var builder = WebApplication.CreateSlimBuilder(); builder.Logging.ClearProviders();
                builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0,
                    listen => listen.UseHttps(source.tls.certificate)));
                source.app = builder.Build();
                source.app.MapPost("/api/v2/account-directory/proofs", async (HttpContext context) =>
                {
                    if (signed.RejectProof) return Results.StatusCode(503);
                    Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestMediaType, context.Request.ContentType);
                    Assert.Equal(DeepIdV2DirectoryProofWireCodec.RequestLength, context.Request.ContentLength);
                    var exact = new byte[DeepIdV2DirectoryProofWireCodec.RequestLength];
                    await context.Request.Body.ReadExactlyAsync(exact, context.RequestAborted);
                    var query = DeepIdV2DirectoryProofWireCodec.DecodeRequest(exact);
                    Interlocked.Increment(ref source.proofRequests);
                    var response = await signed.AuthorHttpProofAsync(query);
                    context.Response.Headers.CacheControl = "no-store";
                    return Results.Bytes(response, DeepIdV2DirectoryProofWireCodec.ResponseMediaType);
                });
                // Use the canonical PMA core binding, not a configured replica list.
                var hash = Convert.ToHexString(Deep.Protocol.ContactV1.ContactCodec.Decode("PMA2",
                    signed.MailboxAuthority.Span).CoreHash.Span).ToLowerInvariant();
                foreach (var role in new[] { MailboxCapabilityDomain.Deposit, MailboxCapabilityDomain.Retrieve })
                {
                    var snapshot = MailboxGrantRevocationStoreTests.Snapshot(signed, role);
                    foreach (var generation in new[] { "latest", "1" })
                        source.app.MapGet(HttpsMailboxGrantRevocationArtifactSource.Prefix + "/" +
                            Convert.ToHexString(DeepIdV2PublicationAuthorityFixture.Network).ToLowerInvariant() + "/" +
                            hash + "/" + (byte)role + "/" + generation, (HttpContext context) =>
                        {
                            context.Response.Headers.CacheControl = "no-store";
                            context.Response.Headers.XContentTypeOptions = "nosniff";
                            return Results.Bytes(snapshot, HttpsMailboxGrantRevocationArtifactSource.MediaType);
                        });
                }
                await source.app.StartAsync();
                source.Origin = source.app.Services.GetRequiredService<IServer>().Features
                    .Get<IServerAddressesFeature>()!.Addresses.Single();
                return source;
            }
            catch { await source.DisposeAsync(); throw; }
        }

        internal void ConfigureTestDependencies(IServiceCollection services)
        {
            services.RemoveAll<IOnionMonotonicClock>(); services.AddSingleton<IOnionMonotonicClock>(signed);
            services.AddHttpClient("did2-directory-proof").ConfigurePrimaryHttpMessageHandler(() =>
                new HttpClientHandler
                {
                    AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
                    ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
                    {
                        if (certificate is null || (errors & (SslPolicyErrors.RemoteCertificateNameMismatch |
                            SslPolicyErrors.RemoteCertificateNotAvailable)) != 0) return false;
                        using var chain = new X509Chain();
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.Add(tls.certificate);
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
                        return chain.Build(certificate);
                    }
                });
        }

        internal async Task<byte[]> DispatchOnionAsync(RegisteredPeer exit, IReadOnlyList<RegisteredPeer> owners,
            OnionOperation operation, byte[] exact, ReadOnlyMemory<byte> firstReplica, ReadOnlyMemory<byte> secondReplica,
            bool expectFailure = false)
        {
            if (client is null)
            {
                var security = new MailboxStorageSecurity(); security.SecureDirectory(clientRoot);
                var key = Path.Combine(clientRoot, "client.key");
                File.WriteAllBytes(key, RandomNumberGenerator.GetBytes(32)); security.SecureFile(key);
                entropy = new(Path.Combine(clientRoot, "entropy"), key);
                vault = new(Path.Combine(clientRoot, "vault"), key);
                client = new(new(entropy), new(vault));
            }
            var network = (await exit.Services.GetRequiredService<IDeepIdV2ContactStoreAuthoritySource>()
                .ReadPublicationAuthorityAsync(default)).Network;
            var exitId = exit.Services.GetRequiredService<CurrentMailboxAdmission>().LocalNodeId;
            var forward = OnionPathCandidateSnapshotFactory.Create(network).Candidates
                .Where(candidate => !candidate.NodeId.Span.SequenceEqual(exitId.Span)).ToArray();
            Assert.Equal(2, forward.Length);
            var path = OnionPathContextFactory.CreateMailbox(network, operation, firstReplica, secondReplica,
                forward[0].NodeId, forward[1].NodeId, exitId);
            var request = OnionTerminalPayloadVerifierV1.VerifyRequest(network, operation, exact);
            using var built = await client.BuildAsync(path, request, default);
            var entry = owners.Single(owner => owner.Services.GetRequiredService<CurrentMailboxAdmission>()
                .LocalNodeId.Span.SequenceEqual(forward[0].NodeId.Span));
            var selectedEntry = OnionEntryTransportFactory.Create(path);
            selectedEntry.EnsureCurrent();
            Assert.Equal(entry.Port, selectedEntry.Peer.Port);
            using var transport = new HttpClient(HttpPrivacyPeerClient.CreatePinnedHandler(selectedEntry.Peer));
            if (!checkedIngressRefusals)
            {
                var otherPath = OnionPathContextFactory.CreateMailbox(network, operation, firstReplica, secondReplica,
                    forward[1].NodeId, forward[0].NodeId, exitId);
                await AssertConfiguredIngressRefusalsAsync(transport, selectedEntry.Peer.Port, built.Frame,
                    OnionEntryTransportFactory.Create(otherPath).Peer, owners);
                checkedIngressRefusals = true;
            }
            using var message = new HttpRequestMessage(HttpMethod.Post,
                "https://127.0.0.1:" + selectedEntry.Peer.Port + ManagedIngressH2Contract.FramePath)
            {
                Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(built.Frame.ToArray())
            };
            message.Content.Headers.ContentType = new(ManagedIngressH2Contract.OpaqueMediaType);
            message.Headers.Accept.Add(new(ManagedIngressH2Contract.OpaqueMediaType));
            using var result = await transport.SendAsync(message);
            var opaque = await result.Content.ReadAsByteArrayAsync();
            var metadata = new ManagedIngressResponseMetadata((int)result.StatusCode, result.Version,
                result.Content.Headers.ContentType?.ToString(), result.Content.Headers.ContentEncoding.SingleOrDefault(),
                result.Content.Headers.ContentLength ?? -1,
                result.Headers.SelectMany(header => header.Value.Select(value => new ManagedIngressHeader(header.Key.ToLowerInvariant(), value)))
                    .ToArray());
            if (expectFailure)
            {
                // Forwarding already happened at the entry/core. The client
                // must retain the exact intent, not infer absence of effects
                // from an exit's admission refusal or attempt a replacement.
                Assert.Equal(HttpStatusCode.GatewayTimeout, result.StatusCode);
                Assert.Equal(ManagedIngressTransportResult.OutcomeUnknown,
                    ManagedIngressH2Contract.ClassifyFrameResponse(metadata, opaque));
                var error = ManagedIngressH2Contract.ClassifyErrorResponse(metadata, opaque);
                Assert.Equal(ManagedIngressTransportResult.OutcomeUnknown, error.Result);
                Assert.NotNull(error.Error);
                Assert.Equal(ManagedIngressErrorClass.UpstreamOutcomeUnknown, error.Error.ErrorClass);
                return [];
            }
            Assert.True(ManagedIngressH2Contract.ClassifyFrameResponse(metadata, opaque) ==
                ManagedIngressTransportResult.TransitCompleted,
                $"MHT response: status={metadata.StatusCode}; HTTP={metadata.HttpVersion}; " +
                $"declared={metadata.BodyLength}; received={opaque.Length}; " +
                $"opaqueType={result.Content.Headers.ContentType?.MediaType == ManagedIngressH2Contract.OpaqueMediaType}; " +
                $"encoded={!string.IsNullOrEmpty(metadata.ContentEncoding)}; " +
                $"supplementalNames={string.Join(',', metadata.Headers.Select(header => header.Name))}");
            var opened = await client.OpenResponseAsync(opaque, built.ReplyContext, default);
            Assert.Equal(OnionTerminalResultKind.Success, opened.Result.Kind);
            Assert.Null(opened.Result.FailureCode);
            return opened.Result.Body.ToArray();
        }

        internal Dictionary<string, string?> CreateConfiguration(string root, RouterNodeOptions node,
            CurrentMailboxCustodyConfiguration custody, Host host, IReadOnlyList<Host> hosts)
        {
            var security = new MailboxStorageSecurity(); security.SecureDirectory(root);
            string Write(string name, ReadOnlySpan<byte> exact)
            {
                var path = Path.Combine(root, name); File.WriteAllBytes(path, exact.ToArray()); security.SecureFile(path); return path;
            }
            var scalar = signed.TestOnionScalar(Convert.FromHexString(node.RouterId));
            string onionKey;
            try { onionKey = Write("onion.key", System.Text.Encoding.ASCII.GetBytes(Convert.ToHexString(scalar).ToLowerInvariant())); }
            finally { CryptographicOperations.ZeroMemory(scalar); }
            var input = new Dictionary<string, string?>
            {
                ["Node:DataDirectory"] = node.DataDirectory, ["Node:RouterId"] = node.RouterId,
                ["Node:Ed25519PrivateKey"] = node.Ed25519PrivateKey.ToLowerInvariant(),
                ["Node:IsRelay"] = "true", ["Node:Network"] = "local",
                ["Node:ApiListenUrl"] = "http://127.0.0.1:" + host.ApiPort,
                ["Node:PeerRpcListenUrl"] = "http://127.0.0.1:" + host.configuredPorts![1],
                ["Node:PrivacyPeerH2ListenUrl"] = node.PrivacyPeerH2ListenUrl,
                ["Node:ManagedIngressH2ListenUrl"] = "https://127.0.0.1:" + host.configuredPorts![4],
                ["Node:ManagedIngressTrustedProxyAddresses:0"] = "127.0.0.1",
                ["Kestrel:Certificates:Default:Path"] = host.certificatePath,
                ["Vless:Enabled"] = "false", ["RegistryHeartbeat:Enabled"] = "false",
                ["Mailbox:Enabled"] = "true",
                ["CurrentMailboxCustody:NetworkIdHex"] = Convert.ToHexString(custody.NetworkId).ToLowerInvariant(),
                ["CurrentMailboxCustody:MailboxAuthorityCoreHashHex"] = Convert.ToHexString(custody.PolicyReference.AsSpan(6)).ToLowerInvariant(),
                ["CurrentMailboxCustody:IndependentCustodyDirectory"] = custody.IndependentCustodyDirectory,
                ["CurrentMailboxCustody:DataProtectionKeysDirectory"] = custody.DataProtectionKeysDirectory,
                ["DeepIdV2DirectoryProof:Enabled"] = "true", ["DeepIdV2DirectoryProof:RegistryOrigin"] = Origin,
                ["DeepIdV2DirectoryProof:NetworkIdHex"] = Convert.ToHexString(DeepIdV2PublicationAuthorityFixture.Network),
                ["DeepIdV2DirectoryProof:GenesisAuthorityCoreHashHex"] = Convert.ToHexString(signed.GenesisPin.AuthorityCoreHash.Span),
                ["DeepIdV2DirectoryProof:ExactAuthorityPaths:0"] = Write("authority.bin", signed.ExactAuthority.Span),
                ["DeepIdV2DirectoryProof:ExactTimePolicyPaths:0"] = Write("time.bin", signed.ExactTimePolicy.Span),
                ["DeepIdV2DirectoryProof:GenesisHeadPath"] = Write("genesis.bin", signed.ExactDirectoryGenesis.Span),
                ["DeepIdV2DirectoryProof:GenesisHeadCoreHashHex"] = Convert.ToHexString(signed.DirectoryGenesisCoreHash.Span),
                ["DeepIdV2DirectoryProof:StateRelativeDirectory"] = "directory-state",
                ["DeepIdV2DirectoryProof:DataProtectionKeysRelativeDirectory"] = "directory-keys",
                ["DeepIdV2DirectoryProof:DeploymentProfileId"] = "1", ["DeepIdV2DirectoryProof:RequestTimeoutSeconds"] = "5",
                ["DeepIdV2NetworkPlacement:Enabled"] = "true",
                ["DeepIdV2NetworkPlacement:ExactPolicyPaths:0"] = Write("policy.bin", signed.Policy.Span),
                ["DeepIdV2NetworkPlacement:ExactViewPaths:0"] = Write("view.bin", signed.View.Span),
                ["DeepIdV2NetworkPlacement:ExactHeadPaths:0"] = Write("head.bin", signed.Head.Span),
                ["DeepIdV2NetworkPlacement:ExactMailboxProjectionPaths:0"] = Write("projection.bin", signed.Projection.Span),
                ["DeepIdV2NetworkPlacement:ExactMailboxAuthorityPaths:0"] = Write("mailbox-authority.bin", signed.MailboxAuthority.Span),
                ["DeepIdV2NetworkPlacement:PublicObservationDid2Path"] = Write("observer.bin", signed.Publisher.CanonicalBytes.Span),
                ["PrivacyRouting:Enabled"] = "true", ["PrivacyRouting:X25519PrivateKeyPath"] = onionKey,
                ["PrivacyRouting:StateProtectionKeyPath"] = Write("onion-state.key", RandomNumberGenerator.GetBytes(32)),
                ["PrivacyRouting:ReplayStateRelativePath"] = "onion-replay", ["PrivacyRouting:EntropyStateRelativePath"] = "onion-entropy",
                ["PrivacyRouting:KeyVaultDirectoryRelativePath"] = "onion-vault",
                ["PrivacyRouting:PublicPeerBaseUrl"] = "https://127.0.0.1:" + host.Port
            };
            for (var i = 0; i < signed.Descriptors.Count; i++)
                input["DeepIdV2NetworkPlacement:ExactActiveNodePaths:" + i] = Write("node-" + i + ".bin", signed.Descriptors[i].Span);
            var peerIndex = 0;
            for (var i = 0; i < hosts.Count; i++)
            {
                if (ReferenceEquals(hosts[i], host)) continue;
                var prefix = "PrivacyRouting:Peers:" + peerIndex++ + ":";
                input[prefix + "RouterId"] = Convert.ToHexString(signed.NodeIds[i].Span);
                input[prefix + "BaseUrl"] = "https://127.0.0.1:" + hosts[i].Port;
                input[prefix + "CurrentSpkiSha256"] = Convert.ToHexString(hosts[i].Pin).ToLowerInvariant();
                input[prefix + "NextSpkiSha256"] = Convert.ToHexString(SHA256.HashData(hosts[i].Pin)).ToLowerInvariant();
            }
            return input;
        }

        public async ValueTask DisposeAsync()
        {
            if (app is not null) { await app.StopAsync(); await app.DisposeAsync(); }
            await tls.DisposeAsync();
            vault?.Dispose(); entropy?.Dispose();
            if (Directory.Exists(clientRoot))
            {
                var resolved = Path.GetFullPath(clientRoot);
                var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!resolved.StartsWith(temp, StringComparison.OrdinalIgnoreCase) ||
                    !Path.GetFileName(resolved).StartsWith("deep-configured-onion-client-", StringComparison.Ordinal))
                    throw new InvalidOperationException("Unexpected test-owned client cleanup target.");
                Directory.Delete(resolved, recursive: true);
            }
        }
    }

    private sealed partial class Host
    {
        internal int[]? configuredPorts;
        private TcpListener[]? configuredReservations;
        internal static Host ReserveConfiguredProgram()
        {
            var host = CreateCertificate(forProgram: true);
            var reservations = Enumerable.Range(0, 5).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToArray();
            host.configuredReservations = reservations;
            try
            {
                foreach (var listener in reservations) listener.Start();
                host.configuredPorts = reservations.Select(listener => ((IPEndPoint)listener.LocalEndpoint).Port).ToArray();
                host.ApiPort = host.configuredPorts[0]; host.Port = host.configuredPorts[2]; return host;
            }
            catch { host.ReleaseConfiguredReservations(); host.certificate.Dispose(); host.RemoveTestCertificate(); throw; }
        }

        private void ReleaseConfiguredReservations(bool privateOnly = false)
        {
            if (configuredReservations is null) return;
            for (var i = 0; i < configuredReservations.Length; i++)
                if (!privateOnly || i != 2) configuredReservations[i].Stop();
            if (privateOnly) return;
            configuredReservations = null;
        }

        internal IServiceProvider StartConfiguredProgram(Dictionary<string, string?> input, ConfiguredAuthority authority)
        {
            program = new ConfiguredProgramFactory(this, input, authority);
            // Keep every host's ports reserved throughout the signed ceremony;
            // releasing each during allocation permits Windows to reuse another host's port.
            ReleaseConfiguredReservations(privateOnly: true);
            program.UseKestrel(); program.StartServer(); return program.Services;
        }
        internal async Task CloseConfiguredProgramAsync()
        {
            await CloseConfiguredIngressAsync();
            if (program is not null) { await program.DisposeAsync(); program = null; }
        }
    }

    private sealed class ConfiguredProgramFactory(Host host, Dictionary<string, string?> input,
        ConfiguredAuthority authority) : WebApplicationFactory<Program>
    {
        protected override IHost CreateHost(IHostBuilder builder)
        {
            builder.ConfigureHostConfiguration(configuration => configuration.AddInMemoryCollection(input));
            return base.CreateHost(builder);
        }
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development"); builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services =>
            {
                authority.ConfigureTestDependencies(services);
                services.AddTransient<IStartupFilter>(_ => new CountPeerRequests(host));
                // No endpoint/authority/owner replacement and no hosted-service removal.
            });
        }
    }
}
