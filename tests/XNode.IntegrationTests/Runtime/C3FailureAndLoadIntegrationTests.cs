using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using XNode.Core;
using XNode.Core.NodeDb;
using XNode.Core.Paths;
using XNode.Core.Runtime;
using XNode.Core.Session;
using XNode.Transport.Vless;
using Microsoft.Extensions.Logging.Abstractions;

namespace XNode.IntegrationTests.Runtime;

public sealed class C3FailureAndLoadIntegrationTests
{
    [Fact]
    public async Task C3_SoakChaosLoad_BaselineAndArtifacts()
    {
        var runtimeRoot = NewTempDirectory("xnode-c3-runtime");
        var transportRoot = NewTempDirectory("xnode-c3-transport");

        try
        {
            var runtime = CreateRuntime(runtimeRoot);
            await runtime.StartAsync(CancellationToken.None);

            var soak = await RunSoakScenarioAsync(runtime, TimeSpan.FromSeconds(2), CancellationToken.None);
            var chaos = await RunChaosScenarioAsync(runtime, iterations: 120, packetLossRate: 0.35, CancellationToken.None);
            var load = await RunLoadScenarioAsync(runtime, totalRequests: 2400, concurrency: 12, CancellationToken.None);

            var restartStorm = await RunRestartStormScenarioAsync(transportRoot, CancellationToken.None);

            var slo = EvaluateSloBaseline(soak, chaos, load, restartStorm);

            var report = new C3BaselineReport(
                GeneratedAt: DateTimeOffset.UtcNow,
                Soak: soak,
                Chaos: chaos,
                Load: load,
                RestartStorm: restartStorm,
                SloBaseline: slo,
                Bottlenecks: BuildBottlenecks(soak, chaos, load, restartStorm),
                RemediationPlan: BuildRemediationPlan());

            var output = ArtifactOutput.Write(report);

            Assert.True(slo.Passed, $"C3 baseline SLO failed. See artifact: {output.JsonPath}");
            Assert.True(File.Exists(output.JsonPath));
            Assert.True(File.Exists(output.MarkdownPath));

            await runtime.StopAsync(CancellationToken.None);
        }
        finally
        {
            TryDeleteDirectory(runtimeRoot);
            TryDeleteDirectory(transportRoot);
        }
    }

    private static async Task<SoakMetrics> RunSoakScenarioAsync(RouterRuntime runtime, TimeSpan duration, CancellationToken cancellationToken)
    {
        var end = DateTimeOffset.UtcNow + duration;
        var sent = 0;
        var failed = 0;
        var latency = new List<double>();
        var sequence = 0;

        while (DateTimeOffset.UtcNow < end)
        {
            sequence++;
            var stopwatch = Stopwatch.StartNew();

            var select = await SelectPathAsync(runtime, sequence, pivot: TestData.Id(9), edges: new[] { TestData.Id(1), TestData.Id(2), TestData.Id(3) }, cancellationToken);
            stopwatch.Stop();
            latency.Add(stopwatch.Elapsed.TotalMilliseconds);
            sent++;

            if (!select.Success)
            {
                failed++;
            }

            var ping = await runtime.HandleRpcAsync(
                new SessionRpcRequest($"ping-{sequence}", "path_ping", JsonSerializer.SerializeToElement(new { })),
                cancellationToken);
            sent++;
            if (!ping.Success)
            {
                failed++;
            }
        }

        return new SoakMetrics(
            DurationSeconds: duration.TotalSeconds,
            TotalRequests: sent,
            FailedRequests: failed,
            SuccessRate: sent == 0 ? 0 : 1d - ((double)failed / sent),
            PathSelectP95Ms: Percentile(latency, 95),
            PathSelectMaxMs: latency.Count == 0 ? 0 : latency.Max());
    }

    private static async Task<ChaosMetrics> RunChaosScenarioAsync(
        RouterRuntime runtime,
        int iterations,
        double packetLossRate,
        CancellationToken cancellationToken)
    {
        var random = new Random(42);
        var success = 0;
        var failed = 0;
        var churnUpdates = 0;

        for (var i = 0; i < iterations; i++)
        {
            var relayId = TestData.Id((byte)((i % 8) + 1));
            var store = await runtime.HandleRpcAsync(
                new SessionRpcRequest(
                    $"store-{i}",
                    "store_rc",
                    JsonSerializer.SerializeToElement(new
                    {
                        routerId = relayId.Value,
                        publicHost = $"10.80.{i % 16}.{(i % 200) + 1}",
                        publicIp = $"10.80.{i % 16}.{(i % 200) + 1}",
                        publicPort = 1190 + (i % 5),
                        signedAt = DateTimeOffset.UtcNow,
                        expiresAt = DateTimeOffset.UtcNow.AddDays(1)
                    })),
                cancellationToken);

            if (store.Success)
            {
                churnUpdates++;
            }

            var select = await SelectPathAsync(runtime, i, pivot: TestData.Id(10), edges: new[] { TestData.Id(1), TestData.Id(2), TestData.Id(4) }, cancellationToken);
            if (!select.Success)
            {
                failed++;
                continue;
            }

            var hops = ParseHops(select.Result);
            var packetDropped = random.NextDouble() < packetLossRate;
            var report = await runtime.HandleRpcAsync(
                new SessionRpcRequest(
                    $"report-{i}",
                    "report_path_result",
                    JsonSerializer.SerializeToElement(new { success = !packetDropped, hops })),
                cancellationToken);

            if (!report.Success)
            {
                failed++;
                continue;
            }

            if (packetDropped)
            {
                failed++;
            }
            else
            {
                success++;
            }
        }

        return new ChaosMetrics(
            Iterations: iterations,
            PacketLossRate: packetLossRate,
            SuccessfulIterations: success,
            FailedIterations: failed,
            ChurnUpdates: churnUpdates,
            ChurnBlockedRouters: runtime.Status.Metrics.ChurnBlockedRouters,
            SuccessRate: iterations == 0 ? 0 : (double)success / iterations);
    }

    private static async Task<LoadMetrics> RunLoadScenarioAsync(
        RouterRuntime runtime,
        int totalRequests,
        int concurrency,
        CancellationToken cancellationToken)
    {
        var perWorker = Math.Max(1, totalRequests / Math.Max(1, concurrency));
        var latencies = new ConcurrentBag<double>();
        var succeeded = 0;
        var failed = 0;
        var wall = Stopwatch.StartNew();

        var workers = Enumerable.Range(0, concurrency)
            .Select(workerId => Task.Run(async () =>
            {
                for (var i = 0; i < perWorker; i++)
                {
                    var sequence = (workerId * perWorker) + i;
                    var watch = Stopwatch.StartNew();
                    var response = await SelectPathAsync(runtime, sequence, pivot: TestData.Id(11), edges: new[] { TestData.Id(1), TestData.Id(3), TestData.Id(5) }, cancellationToken);
                    watch.Stop();
                    latencies.Add(watch.Elapsed.TotalMilliseconds);

                    if (response.Success)
                    {
                        Interlocked.Increment(ref succeeded);
                    }
                    else
                    {
                        Interlocked.Increment(ref failed);
                    }
                }
            }, cancellationToken))
            .ToArray();

        await Task.WhenAll(workers);
        wall.Stop();

        var completed = succeeded + failed;
        var throughput = wall.Elapsed.TotalSeconds <= 0 ? 0 : completed / wall.Elapsed.TotalSeconds;
        var successRate = completed == 0 ? 0 : (double)succeeded / completed;

        return new LoadMetrics(
            Requested: totalRequests,
            Completed: completed,
            Succeeded: succeeded,
            Failed: failed,
            ThroughputRps: throughput,
            SuccessRate: successRate,
            LatencyP50Ms: Percentile(latencies, 50),
            LatencyP95Ms: Percentile(latencies, 95),
            LatencyP99Ms: Percentile(latencies, 99));
    }

    private static async Task<RestartStormMetrics> RunRestartStormScenarioAsync(string root, CancellationToken cancellationToken)
    {
        var options = new VlessTransportOptions
        {
            Enabled = true,
            XrayExecutablePath = "missing-xray-binary",
            GeneratedConfigPath = Path.Combine(root, "xray.generated.json"),
            WorkingDirectory = root,
            MockProcess = false,
            RestartDelay = TimeSpan.FromMilliseconds(40),
            MaxRestartAttempts = 1,
            FailureWindow = TimeSpan.FromSeconds(5),
            DegradedCooldown = TimeSpan.FromMilliseconds(800)
        };

        var supervisor = new XraySupervisor(options, new XrayConfigGenerator());
        var watch = Stopwatch.StartNew();

        await supervisor.StartAsync(cancellationToken);
        await Task.Delay(300, cancellationToken);

        var status = supervisor.Status;
        await supervisor.StopAsync(cancellationToken);
        watch.Stop();

        return new RestartStormMetrics(
            RestartCount: status.RestartCount,
            Degraded: status.Degraded,
            Mode: status.Mode,
            DegradedUntil: status.DegradedUntil,
            DetectionSeconds: watch.Elapsed.TotalSeconds);
    }

    private static SloBaseline EvaluateSloBaseline(SoakMetrics soak, ChaosMetrics chaos, LoadMetrics load, RestartStormMetrics restartStorm)
    {
        var checks = new List<SloCheck>
        {
            new("soak-success-rate", soak.SuccessRate >= 0.99, soak.SuccessRate, 0.99, "fraction"),
            new("chaos-success-rate", chaos.SuccessRate >= 0.55, chaos.SuccessRate, 0.55, "fraction"),
            new("load-throughput-rps", load.ThroughputRps >= 400, load.ThroughputRps, 400, "rps"),
            new("path-select-p95-ms", load.LatencyP95Ms <= 15, load.LatencyP95Ms, 15, "ms"),
            new("restart-storm-degraded", restartStorm.Degraded, restartStorm.Degraded ? 1 : 0, 1, "bool")
        };

        return new SloBaseline(
            Passed: checks.All(static check => check.Passed),
            Checks: checks.ToArray());
    }

    private static Bottleneck[] BuildBottlenecks(
        SoakMetrics soak,
        ChaosMetrics chaos,
        LoadMetrics load,
        RestartStormMetrics restartStorm)
    {
        var bottlenecks = new List<Bottleneck>();

        if (load.LatencyP95Ms > 8)
        {
            bottlenecks.Add(new Bottleneck(
                "path-selection-latency-tail",
                $"Observed p95={load.LatencyP95Ms:F2}ms under concurrent select_path load.",
                "medium"));
        }

        if (chaos.ChurnBlockedRouters > 0)
        {
            bottlenecks.Add(new Bottleneck(
                "churn-blocked-router-pressure",
                $"Churn blocklist reached {chaos.ChurnBlockedRouters} routers during loss/churn simulation.",
                "medium"));
        }

        if (restartStorm.RestartCount > 2)
        {
            bottlenecks.Add(new Bottleneck(
                "restart-storm-intensity",
                $"Supervisor restart count reached {restartStorm.RestartCount} before cooldown stabilized.",
                "high"));
        }

        if (soak.PathSelectMaxMs > 20)
        {
            bottlenecks.Add(new Bottleneck(
                "soak-latency-spikes",
                $"Max path-select latency spike={soak.PathSelectMaxMs:F2}ms over soak window.",
                "low"));
        }

        return bottlenecks.Count == 0
            ? new[]
            {
                new Bottleneck("none-critical", "No bottleneck crossed alert threshold in current baseline run.", "info")
            }
            : bottlenecks.ToArray();
    }

    private static RemediationAction[] BuildRemediationPlan()
    {
        return new[]
        {
            new RemediationAction("Scale path candidate pool", "Increase relay contact freshness and candidate breadth during churn to reduce tail-latency retries."),
            new RemediationAction("Adaptive packet-loss feedback", "Tune failure-score decay and threshold by observed loss profile to avoid over-blocking relays."),
            new RemediationAction("Supervisor jitter", "Add randomized restart jitter per node to reduce synchronized restart storms."),
            new RemediationAction("RPC concurrency budget", "Apply bounded worker pools and backpressure on ingress when throughput approaches saturation.")
        };
    }

    private static async Task<SessionRpcResponse> SelectPathAsync(
        RouterRuntime runtime,
        int sequence,
        RouterId pivot,
        IReadOnlyList<RouterId> edges,
        CancellationToken cancellationToken)
    {
        return await runtime.HandleRpcAsync(
            new SessionRpcRequest(
                $"select-{sequence}",
                "select_path",
                JsonSerializer.SerializeToElement(new
                {
                    pivot = pivot.Value,
                    edges = edges.Select(static id => id.Value).ToArray()
                })),
            cancellationToken);
    }

    private static string[] ParseHops(object? result)
    {
        if (result is null)
        {
            return Array.Empty<string>();
        }

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(result));
        if (!json.RootElement.TryGetProperty("hops", out var hopsElement))
        {
            return Array.Empty<string>();
        }

        return hopsElement.EnumerateArray().Select(static item => item.GetString() ?? string.Empty).Where(static s => s.Length > 0).ToArray();
    }

    private static double Percentile(IEnumerable<double> values, int percentile)
    {
        var ordered = values.OrderBy(static value => value).ToArray();
        if (ordered.Length == 0)
        {
            return 0;
        }

        var index = (int)Math.Ceiling((percentile / 100d) * ordered.Length) - 1;
        index = Math.Clamp(index, 0, ordered.Length - 1);
        return ordered[index];
    }

    private static RouterRuntime CreateRuntime(string root)
    {
        const string identitySeed = "f0e0d0c0b0a090807060504030201000102030405060708090a0b0c0d0e0f001";
        var localRouterId = RelayContactSigner.DeriveRouterId(identitySeed);
        var node = new RouterNodeOptions
        {
            DataDirectory = root,
            RouterId = localRouterId.Value,
            Ed25519PrivateKey = identitySeed,
            IsRelay = true,
            Network = "testnet"
        };

        var contacts = Enumerable.Range(1, 32)
            .Select(index => new RelayContact
            {
                RouterId = TestData.Id((byte)index),
                PublicHost = $"10.50.{index / 255}.{index % 255}",
                PublicIp = $"10.50.{index / 255}.{index % 255}",
                PublicPort = 1190,
                SignedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
            })
            .ToArray();

        var nodeDb = new XNode.Core.NodeDb.NodeDb(
            new NodeDbOptions
            {
                DataDirectory = root,
                LocalRouterId = localRouterId.Value,
                IsRelay = true
            });

        return new RouterRuntime(
            node,
            new RouterRuntimeOptions
            {
                BootstrapFromStorage = true,
                HeartbeatInterval = TimeSpan.FromMilliseconds(60),
                PathFailureThreshold = 3,
                PathFailureDecayInterval = TimeSpan.FromMilliseconds(220),
                RequireSignedRelayContacts = false
            },
            new PathSelectionOptions
            {
                ClientHops = 3,
                EdgeConnections = 4,
                UniqueHopNetmask = 24
            },
            nodeDb,
            new FakeStorageBackend(contacts),
            new PathSelector(),
            logger: NullLogger<RouterRuntime>.Instance);
    }

    private static string NewTempDirectory(string prefix)
    {
        var path = Path.Combine(Path.GetTempPath(), prefix, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void TryDeleteDirectory(string path)
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, recursive: true);
                }

                return;
            }
            catch (IOException)
            {
                Thread.Sleep(50);
            }
            catch (UnauthorizedAccessException)
            {
                Thread.Sleep(50);
            }
        }
    }

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

    private static class ArtifactOutput
    {
        public static WriteResult Write(C3BaselineReport report)
        {
            var outputDirectory = ResolveOutputDirectory();
            Directory.CreateDirectory(outputDirectory);

            var jsonPath = Path.Combine(outputDirectory, "latest.json");
            var markdownPath = Path.Combine(outputDirectory, "latest.md");

            var json = JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true
            });

            File.WriteAllText(jsonPath, json);
            File.WriteAllText(markdownPath, ToMarkdown(report));

            return new WriteResult(jsonPath, markdownPath);
        }

        private static string ResolveOutputDirectory()
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "XNode.slnx")))
                {
                    return Path.Combine(directory.FullName, "artifacts", "test-results", "c3");
                }

                directory = directory.Parent;
            }

            return Path.Combine(AppContext.BaseDirectory, "artifacts", "test-results", "c3");
        }

        private static string ToMarkdown(C3BaselineReport report)
        {
            var builder = new StringBuilder();
            builder.AppendLine("# C3 Failure/Load Baseline");
            builder.AppendLine();
            builder.AppendLine($"GeneratedAt: {report.GeneratedAt:O}");
            builder.AppendLine();
            builder.AppendLine("## Soak");
            builder.AppendLine($"- DurationSeconds: {report.Soak.DurationSeconds:F1}");
            builder.AppendLine($"- SuccessRate: {report.Soak.SuccessRate:P2}");
            builder.AppendLine($"- PathSelectP95Ms: {report.Soak.PathSelectP95Ms:F2}");
            builder.AppendLine();
            builder.AppendLine("## Chaos");
            builder.AppendLine($"- Iterations: {report.Chaos.Iterations}");
            builder.AppendLine($"- PacketLossRate: {report.Chaos.PacketLossRate:P0}");
            builder.AppendLine($"- SuccessRate: {report.Chaos.SuccessRate:P2}");
            builder.AppendLine($"- ChurnBlockedRouters: {report.Chaos.ChurnBlockedRouters}");
            builder.AppendLine();
            builder.AppendLine("## Load");
            builder.AppendLine($"- ThroughputRps: {report.Load.ThroughputRps:F2}");
            builder.AppendLine($"- SuccessRate: {report.Load.SuccessRate:P2}");
            builder.AppendLine($"- LatencyP95Ms: {report.Load.LatencyP95Ms:F2}");
            builder.AppendLine();
            builder.AppendLine("## Restart Storm");
            builder.AppendLine($"- RestartCount: {report.RestartStorm.RestartCount}");
            builder.AppendLine($"- Degraded: {report.RestartStorm.Degraded}");
            builder.AppendLine($"- Mode: {report.RestartStorm.Mode}");
            builder.AppendLine();
            builder.AppendLine("## SLO Baseline");
            builder.AppendLine($"- Passed: {report.SloBaseline.Passed}");
            foreach (var check in report.SloBaseline.Checks)
            {
                builder.AppendLine($"- {check.Name}: {(check.Passed ? "PASS" : "FAIL")} observed={check.Observed:F4} target={check.Target:F4} ({check.Unit})");
            }

            builder.AppendLine();
            builder.AppendLine("## Bottlenecks");
            foreach (var bottleneck in report.Bottlenecks)
            {
                builder.AppendLine($"- [{bottleneck.Severity}] {bottleneck.Name}: {bottleneck.Details}");
            }

            builder.AppendLine();
            builder.AppendLine("## Remediation Plan");
            foreach (var remediationAction in report.RemediationPlan)
            {
                builder.AppendLine($"- {remediationAction.Action}: {remediationAction.Why}");
            }

            return builder.ToString();
        }
    }

    private static class TestData
    {
        public static RouterId Id(byte value)
        {
            var bytes = new byte[RouterId.ByteLength];
            bytes[^1] = value;
            return RouterId.FromBytes(bytes);
        }
    }

    private sealed record WriteResult(string JsonPath, string MarkdownPath);

    private sealed record SoakMetrics(
        double DurationSeconds,
        int TotalRequests,
        int FailedRequests,
        double SuccessRate,
        double PathSelectP95Ms,
        double PathSelectMaxMs);

    private sealed record ChaosMetrics(
        int Iterations,
        double PacketLossRate,
        int SuccessfulIterations,
        int FailedIterations,
        int ChurnUpdates,
        int ChurnBlockedRouters,
        double SuccessRate);

    private sealed record LoadMetrics(
        int Requested,
        int Completed,
        int Succeeded,
        int Failed,
        double ThroughputRps,
        double SuccessRate,
        double LatencyP50Ms,
        double LatencyP95Ms,
        double LatencyP99Ms);

    private sealed record RestartStormMetrics(
        int RestartCount,
        bool Degraded,
        string Mode,
        DateTimeOffset? DegradedUntil,
        double DetectionSeconds);

    private sealed record SloCheck(string Name, bool Passed, double Observed, double Target, string Unit);

    private sealed record SloBaseline(bool Passed, IReadOnlyList<SloCheck> Checks);

    private sealed record Bottleneck(string Name, string Details, string Severity);

    private sealed record RemediationAction(string Action, string Why);

    private sealed record C3BaselineReport(
        DateTimeOffset GeneratedAt,
        SoakMetrics Soak,
        ChaosMetrics Chaos,
        LoadMetrics Load,
        RestartStormMetrics RestartStorm,
        SloBaseline SloBaseline,
        IReadOnlyList<Bottleneck> Bottlenecks,
        IReadOnlyList<RemediationAction> RemediationPlan);
}
