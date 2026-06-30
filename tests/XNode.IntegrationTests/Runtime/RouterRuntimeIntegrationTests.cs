using System.Text.Json;
using XNode.Core;
using XNode.Core.NodeDb;
using XNode.Core.Onion;
using XNode.Core.Paths;
using XNode.Core.Runtime;
using XNode.Core.Session;
using Microsoft.Extensions.Logging.Abstractions;
using Sodium;

namespace XNode.IntegrationTests.Runtime;

public sealed class RouterRuntimeIntegrationTests
{
    [Fact]
    public async Task Runtime_RestartsAndRecoversNodeDbFromDisk()
    {
        var root = NewTempDirectory();
        try
        {
            var node = NodeOptions(root);
            var contact = Contact(1, "10.30.1.1");
            var first = CreateRuntime(root, node, new FakeStorageBackend(contact));

            await first.StartAsync(CancellationToken.None);
            Assert.Equal(1, first.Status.NodeDb.KnownRelayContacts);
            await first.StopAsync(CancellationToken.None);

            var recovered = CreateRuntime(root, node, new FakeStorageBackend());
            await recovered.StartAsync(CancellationToken.None);

            Assert.Equal(1, recovered.Status.NodeDb.KnownRelayContacts);
            Assert.Equal(1, recovered.Status.NodeDb.RegisteredRelays);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Runtime_UsesFakeStorageBackendForSessionRpcIngress()
    {
        var root = NewTempDirectory();
        try
        {
            var runtime = CreateRuntime(
                root,
                NodeOptions(root),
                new FakeStorageBackend(Contact(1, "10.31.1.1"), Contact(2, "10.31.2.1")));

            await runtime.StartAsync(CancellationToken.None);

            var response = await runtime.HandleRpcAsync(
                new SessionRpcRequest("1", "fetch_rids", JsonSerializer.SerializeToElement(new { })),
                CancellationToken.None);

            Assert.True(response.Success);
            var ids = JsonSerializer.Deserialize<string[]>(JsonSerializer.Serialize(response.Result))!;
            Assert.Equal(2, ids.Length);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Runtime_WritesHeartbeatSnapshotToStorageBackend()
    {
        var root = NewTempDirectory();
        try
        {
            var node = NodeOptions(root);
            var nodeDb = new XNode.Core.NodeDb.NodeDb(
                new NodeDbOptions
                {
                    DataDirectory = root,
                    LocalRouterId = node.RouterId,
                    IsRelay = true
                },
                new FixedClock(TestData.Now));

            await nodeDb.InitializeAsync();

            var runtime = new RouterRuntime(
                node,
                new RouterRuntimeOptions { BootstrapFromStorage = false, RequireSignedRelayContacts = false },
                new PathSelectionOptions { ClientHops = 2 },
                nodeDb,
                new NodeDbStorageBackend(nodeDb, node),
                new PathSelector(),
                new FixedClock(TestData.Now),
                NullLogger<RouterRuntime>.Instance);

            await runtime.StartAsync(CancellationToken.None);

            var heartbeatPath = Path.Combine(root, "artifacts", "router-heartbeat.json");
            Assert.True(File.Exists(heartbeatPath));

            var json = await File.ReadAllTextAsync(heartbeatPath);
            using var document = JsonDocument.Parse(json);
            Assert.Equal("running", document.RootElement.GetProperty("state").GetString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Runtime_ContinuesRunningWhenSyncBackendFails_AndTracksMetrics()
    {
        var root = NewTempDirectory();
        try
        {
            var runtime = CreateRuntime(
                root,
                NodeOptions(root),
                new FlakyStorageBackend(Contact(1, "10.32.1.1"), Contact(2, "10.32.2.1")),
                new RouterRuntimeOptions
                {
                    BootstrapFromStorage = true,
                    HeartbeatInterval = TimeSpan.FromMilliseconds(50),
                    RequireSignedRelayContacts = false
                });

            await runtime.StartAsync(CancellationToken.None);
            await Task.Delay(220);

            var status = runtime.Status;
            Assert.Equal("running", status.State);
            Assert.True(status.Metrics.RelaySyncCycles > 0);
            Assert.True(status.Metrics.RelaySyncFailures > 0);

            await runtime.StopAsync(CancellationToken.None);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Runtime_SelectPathAvoidsChurnBlockedRouters()
    {
        var root = NewTempDirectory();
        try
        {
            var runtime = CreateRuntime(
                root,
                NodeOptions(root),
                new FakeStorageBackend(
                    Contact(1, "10.33.1.1"),
                    Contact(2, "10.33.2.1"),
                    Contact(3, "10.33.3.1"),
                    Contact(4, "10.33.4.1")),
                new RouterRuntimeOptions
                {
                    BootstrapFromStorage = true,
                    PathFailureThreshold = 2,
                    RequireSignedRelayContacts = false
                },
                new PathSelectionOptions
                {
                    ClientHops = 3,
                    UniqueHopNetmask = 24
                });

            await runtime.StartAsync(CancellationToken.None);

            var reportPayload = JsonSerializer.SerializeToElement(new
            {
                success = false,
                hops = new[] { TestData.Id(2).Value }
            });

            await runtime.HandleRpcAsync(new SessionRpcRequest("report-1", "report_path_result", reportPayload), CancellationToken.None);
            await runtime.HandleRpcAsync(new SessionRpcRequest("report-2", "report_path_result", reportPayload), CancellationToken.None);

            var selectPayload = JsonSerializer.SerializeToElement(new
            {
                pivot = TestData.Id(4).Value,
                edges = new[] { TestData.Id(2).Value, TestData.Id(3).Value }
            });

            var response = await runtime.HandleRpcAsync(
                new SessionRpcRequest("select", "select_path", selectPayload),
                CancellationToken.None);

            Assert.True(response.Success);
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(response.Result));
            var hops = json.RootElement.GetProperty("hops").EnumerateArray().Select(static item => item.GetString()).ToArray();
            Assert.DoesNotContain(TestData.Id(2).Value, hops);
            Assert.True(runtime.Status.Metrics.ChurnBlockedRouters >= 1);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Runtime_StorageRpcBuildsRouteFromEntryNodeAndForwardsPayload()
    {
        var root = NewTempDirectory();
        try
        {
            var local = NodeOptions(root);
            var storageRpc = new FakeSessionStorageRpcBackend();
            var runtime = CreateRuntime(
                root,
                local,
                new FakeStorageBackend(
                    Contact(254, "10.35.254.1"),
                    Contact(1, "10.35.1.1"),
                    Contact(2, "10.35.2.1")),
                new RouterRuntimeOptions
                {
                    BootstrapFromStorage = true,
                    RequireSignedRelayContacts = false
                },
                new PathSelectionOptions { ClientHops = 3 },
                storageRpc);

            await runtime.StartAsync(CancellationToken.None);

            var requestPayload = JsonSerializer.SerializeToElement(new
            {
                body = new
                {
                    pubkey = "05recipient",
                    @namespace = 0,
                    data = "cGF5bG9hZA=="
                }
            });

            var response = await runtime.HandleRpcAsync(
                new SessionRpcRequest("storage-1", "storage_store", requestPayload),
                CancellationToken.None);

            Assert.True(response.Success);
            Assert.Single(storageRpc.Requests);
            Assert.Equal("/storage/store", storageRpc.Requests[0].Path);
            Assert.Equal("05recipient", storageRpc.Requests[0].Payload.GetProperty("pubkey").GetString());

            using var json = JsonDocument.Parse(JsonSerializer.Serialize(response.Result));
            var route = json.RootElement.GetProperty("route").EnumerateArray().ToArray();
            Assert.Equal(3, route.Length);
            Assert.Equal(local.RouterId, route[0].GetProperty("routerId").GetString());
            Assert.Equal("stored", json.RootElement.GetProperty("storage").GetProperty("status").GetString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Runtime_OnionRequestTraversesThreeNodesAndOnlyExitCallsStorage()
    {
        var roots = new[] { NewTempDirectory(), NewTempDirectory(), NewTempDirectory() };
        var peerClient = new InMemoryOnionPeerClient();
        try
        {
            var nodes = new[]
            {
                NodeOptionsFromSeed(roots[0], Seed(1), "http://xnode-1:8080"),
                NodeOptionsFromSeed(roots[1], Seed(33), "http://xnode-2:8080"),
                NodeOptionsFromSeed(roots[2], Seed(65), "http://xnode-3:8080")
            };
            var contacts = nodes.Select(SignedContact).ToArray();
            var storageBackends = new[]
            {
                new FakeSessionStorageRpcBackend(),
                new FakeSessionStorageRpcBackend(),
                new FakeSessionStorageRpcBackend()
            };
            var runtimes = new[]
            {
                CreateRuntime(roots[0], nodes[0], new FakeStorageBackend(contacts), new RouterRuntimeOptions { BootstrapFromStorage = true, RequireSignedRelayContacts = true }, new PathSelectionOptions { ClientHops = 3 }, storageBackends[0], peerClient),
                CreateRuntime(roots[1], nodes[1], new FakeStorageBackend(contacts), new RouterRuntimeOptions { BootstrapFromStorage = true, RequireSignedRelayContacts = true }, new PathSelectionOptions { ClientHops = 3 }, storageBackends[1], peerClient),
                CreateRuntime(roots[2], nodes[2], new FakeStorageBackend(contacts), new RouterRuntimeOptions { BootstrapFromStorage = true, RequireSignedRelayContacts = true }, new PathSelectionOptions { ClientHops = 3 }, storageBackends[2], peerClient)
            };

            peerClient.Register(nodes[0].PublicPeerRpcEndpoint, runtimes[0]);
            peerClient.Register(nodes[1].PublicPeerRpcEndpoint, runtimes[1]);
            peerClient.Register(nodes[2].PublicPeerRpcEndpoint, runtimes[2]);

            foreach (var runtime in runtimes)
            {
                await runtime.StartAsync(CancellationToken.None);
            }

            var routeResponse = await runtimes[0].HandleRpcAsync(
                new SessionRpcRequest(
                    "route",
                    "storage_route",
                    JsonSerializer.SerializeToElement(new { targetKey = "05recipient" }, SessionRpc.JsonOptions)),
                CancellationToken.None);
            Assert.True(routeResponse.Success);

            var route = ParseRoute(routeResponse.Result);
            Assert.Equal(3, route.Count);

            var body = JsonSerializer.SerializeToElement(new
            {
                pubkey = "05recipient",
                @namespace = 0,
                data = "cGF5bG9hZA=="
            }, SessionRpc.JsonOptions);
            var responseKeyPair = PublicKeyBox.GenerateKeyPair();
            var onionRequest = BuildOnionStorageRequest(route, body, responseKeyPair.PublicKey);

            var onionResponse = await runtimes[0].HandleRpcAsync(
                new SessionRpcRequest(
                    "onion",
                    "onion_request",
                    JsonSerializer.SerializeToElement(onionRequest, SessionRpc.JsonOptions)),
                CancellationToken.None);

            Assert.True(onionResponse.Success);
            Assert.Empty(storageBackends[0].Requests);
            Assert.Empty(storageBackends[1].Requests);
            Assert.Single(storageBackends[2].Requests);
            Assert.Equal("/storage/store", storageBackends[2].Requests[0].Path);

            using var responseDocument = JsonDocument.Parse(JsonSerializer.Serialize(onionResponse.Result, SessionRpc.JsonOptions));
            var encryptedResponse = responseDocument.RootElement
                .GetProperty("onionResponse")
                .Deserialize<OnionResponseEnvelope>(SessionRpc.JsonOptions)!;
            var decrypted = OnionCrypto.DecryptResponse(encryptedResponse, responseKeyPair.PrivateKey);
            Assert.Equal(200, decrypted.GetProperty("storageStatusCode").GetInt32());
            Assert.Equal("stored", decrypted.GetProperty("storage").GetProperty("status").GetString());
        }
        finally
        {
            foreach (var endpoint in peerClient.Runtimes.Values)
            {
                await endpoint.StopAsync(CancellationToken.None);
            }

            foreach (var root in roots)
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [Fact]
    public async Task Runtime_RejectsUnsignedRelayContact_WhenRequired()
    {
        var root = NewTempDirectory();
        try
        {
            var runtime = CreateRuntime(
                root,
                NodeOptions(root),
                new FakeStorageBackend(),
                new RouterRuntimeOptions
                {
                    BootstrapFromStorage = false,
                    RequireSignedRelayContacts = true
                });

            await runtime.StartAsync(CancellationToken.None);

            var response = await runtime.HandleRpcAsync(
                new SessionRpcRequest(
                    "store",
                    "store_rc",
                    JsonSerializer.SerializeToElement(Contact(1, "10.34.1.1"), SessionRpc.JsonOptions)),
                CancellationToken.None);

            Assert.False(response.Success);
            Assert.Equal("invalid-relay-contact-signature", response.Error);
            Assert.Equal(0, runtime.Status.NodeDb.KnownRelayContacts);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static RouterRuntime CreateRuntime(
        string root,
        RouterNodeOptions node,
        IStorageBackend storage,
        RouterRuntimeOptions? runtimeOptions = null,
        PathSelectionOptions? pathOptions = null,
        ISessionStorageRpcBackend? sessionStorageRpc = null,
        IOnionPeerClient? onionPeerClient = null)
    {
        var nodeDb = new XNode.Core.NodeDb.NodeDb(
            new NodeDbOptions
            {
                DataDirectory = root,
                LocalRouterId = node.RouterId,
                IsRelay = true
            },
            new FixedClock(TestData.Now));

        return new RouterRuntime(
            node,
            runtimeOptions ?? new RouterRuntimeOptions { BootstrapFromStorage = true, RequireSignedRelayContacts = false },
            pathOptions ?? new PathSelectionOptions { ClientHops = 2 },
            nodeDb,
            storage,
            sessionStorageRpc,
            onionPeerClient,
            new PathSelector(),
            new FixedClock(TestData.Now),
            NullLogger<RouterRuntime>.Instance);
    }

    private static RouterNodeOptions NodeOptions(string root)
    {
        return new RouterNodeOptions
        {
            DataDirectory = root,
            RouterId = TestData.Id(254).Value,
            IsRelay = true,
            Network = "testnet"
        };
    }

    private static RouterNodeOptions NodeOptionsFromSeed(string root, string seed, string rpcEndpoint)
    {
        return new RouterNodeOptions
        {
            DataDirectory = root,
            RouterId = RelayContactSigner.DeriveRouterId(seed).Value,
            Ed25519PrivateKey = seed,
            IsRelay = true,
            Network = "testnet",
            PublicHost = new Uri(rpcEndpoint).Host,
            PublicPort = 443,
            PublicPeerRpcEndpoint = rpcEndpoint
        };
    }

    private static string NewTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "xnode-integration", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static RelayContact Contact(byte id, string ip)
    {
        var onionKeyBytes = new byte[32];
        onionKeyBytes[^1] = id;
        return new RelayContact
        {
            RouterId = TestData.Id(id),
            PublicHost = ip,
            PublicIp = ip,
            PublicPort = 1190,
            X25519PublicKey = Convert.ToHexString(onionKeyBytes).ToLowerInvariant(),
            RpcEndpoint = $"http://router-{id}:8080",
            SignedAt = TestData.Now,
            ExpiresAt = TestData.Now.AddDays(1),
            Capabilities = ["session-rpc", "onion-v1"]
        };
    }

    private static RelayContact SignedContact(RouterNodeOptions node)
    {
        var seed = node.GetEd25519PrivateKey();
        var onion = OnionCrypto.DeriveNodeKeysFromEd25519Seed(seed);
        var contact = new RelayContact
        {
            RouterId = node.GetRouterId(),
            PublicHost = node.PublicHost,
            PublicIp = null,
            PublicPort = node.PublicPort,
            X25519PublicKey = OnionCrypto.Hex(onion.PublicKey),
            RpcEndpoint = node.PublicPeerRpcEndpoint,
            SignedAt = TestData.Now,
            ExpiresAt = TestData.Now.AddDays(1),
            IsReachable = true,
            Capabilities = ["session-rpc", "onion-v1"]
        };

        return RelayContactSigner.Sign(contact, seed);
    }

    private static string Seed(byte first)
    {
        var bytes = Enumerable.Range(0, 32)
            .Select(offset => unchecked((byte)(first + offset)))
            .ToArray();
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static IReadOnlyList<RouteNodeDocument> ParseRoute(object? result)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(result, SessionRpc.JsonOptions));
        return document.RootElement.GetProperty("route")
            .EnumerateArray()
            .Select(static node => new RouteNodeDocument(
                node.GetProperty("routerId").GetString()!,
                node.GetProperty("x25519PublicKey").GetString()!,
                node.GetProperty("rpcEndpoint").GetString()!))
            .ToArray();
    }

    private static OnionRequest BuildOnionStorageRequest(
        IReadOnlyList<RouteNodeDocument> route,
        JsonElement body,
        byte[] responsePublicKey)
    {
        OnionEnvelope? envelope = null;
        for (var index = route.Count - 1; index >= 0; index--)
        {
            object layer = index == route.Count - 1
                ? new OnionLayer(
                    OnionCrypto.StorageLayerType,
                    null,
                    null,
                    null,
                    "/storage/store",
                    body.Clone(),
                    Convert.ToBase64String(responsePublicKey))
                : new OnionLayer(
                    OnionCrypto.RelayLayerType,
                    route[index + 1].RouterId,
                    route[index + 1].RpcEndpoint,
                    envelope,
                    null,
                    null,
                    null);

            envelope = OnionCrypto.EncryptForNode(
                OnionCrypto.DecodeHex32(route[index].X25519PublicKey, nameof(RouteNodeDocument.X25519PublicKey)),
                layer);
        }

        return new OnionRequest(envelope!);
    }

    private sealed record RouteNodeDocument(
        string RouterId,
        string X25519PublicKey,
        string RpcEndpoint);

    private sealed class FakeStorageBackend : IStorageBackend
    {
        private readonly IReadOnlyList<RelayContact> _contacts;

        public FakeStorageBackend(params RelayContact[] contacts)
        {
            _contacts = contacts;
        }

        public Task<IReadOnlyList<RelayContact>> GetBootstrapRelayContactsAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(_contacts);
        }

        public Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FlakyStorageBackend : IStorageBackend
    {
        private readonly IReadOnlyList<RelayContact> _contacts;
        private int _bootstrapAttempts;

        public FlakyStorageBackend(params RelayContact[] contacts)
        {
            _contacts = contacts;
        }

        public Task<IReadOnlyList<RelayContact>> GetBootstrapRelayContactsAsync(CancellationToken cancellationToken)
        {
            _bootstrapAttempts++;
            if (_bootstrapAttempts % 2 == 1)
            {
                throw new InvalidOperationException("simulated sync failure");
            }

            return Task.FromResult(_contacts);
        }

        public Task SubmitHeartbeatAsync(RouterStatusSnapshot snapshot, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class FakeSessionStorageRpcBackend : ISessionStorageRpcBackend
    {
        public List<(string Path, JsonElement Payload)> Requests { get; } = [];

        public Task<SessionStorageRpcResult> PostAsync(
            string path,
            JsonElement payload,
            CancellationToken cancellationToken)
        {
            Requests.Add((path, payload.Clone()));
            var body = JsonSerializer.SerializeToElement(new { status = "stored" });
            return Task.FromResult(new SessionStorageRpcResult(200, body, null));
        }
    }

    private sealed class InMemoryOnionPeerClient : IOnionPeerClient
    {
        public Dictionary<string, RouterRuntime> Runtimes { get; } = new(StringComparer.OrdinalIgnoreCase);

        public void Register(string endpoint, RouterRuntime runtime)
        {
            Runtimes[endpoint.TrimEnd('/')] = runtime;
        }

        public Task<SessionRpcResponse> ForwardAsync(
            string rpcEndpoint,
            OnionRequest request,
            CancellationToken cancellationToken)
        {
            if (!Runtimes.TryGetValue(rpcEndpoint.TrimEnd('/'), out var runtime))
            {
                return Task.FromResult(SessionRpcResponse.Fail("onion-forward", "unknown-peer"));
            }

            return runtime.HandleRpcAsync(
                new SessionRpcRequest(
                    "forward",
                    "onion_request",
                    JsonSerializer.SerializeToElement(request, SessionRpc.JsonOptions)),
                cancellationToken);
        }
    }

    private static class TestData
    {
        public static readonly DateTimeOffset Now = new(2026, 5, 28, 12, 0, 0, TimeSpan.Zero);

        public static RouterId Id(byte value)
        {
            var bytes = new byte[RouterId.ByteLength];
            bytes[^1] = value;
            return RouterId.FromBytes(bytes);
        }
    }

    private sealed class FixedClock : IClock
    {
        public FixedClock(DateTimeOffset utcNow)
        {
            UtcNow = utcNow;
        }

        public DateTimeOffset UtcNow { get; }
    }
}
