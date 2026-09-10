using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Transport.Vless;

namespace XNode.IntegrationTests.Runtime;

public sealed class NativePrivacyC3EvidenceTests
{
    [Fact]
    public async Task C3_NativePrivacyFailClosedAndRestartStorm_BaselineAndArtifacts()
    {
        var effects = new Effects();
        var runtime = new PrivacyRoutingRuntime(
            PrivacyRoutingConfiguration.Disabled,
            effects,
            effects);

        var soak = await RunSoakAsync(runtime, TimeSpan.FromSeconds(1));
        var chaos = await RunMalformedFrameChaosAsync(runtime, iterations: 256);
        var load = await RunConcurrentLoadAsync(runtime, requested: 4096, concurrency: 16);
        var restartStorm = await RunRestartStormAsync();
        var sloBaseline = EvaluateSlo(soak, chaos, load, restartStorm, effects);

        var report = new C3Report(
            Schema: "xnode-native-privacy-c3.v1",
            Architecture: "native-privacy-v1",
            GeneratedAt: DateTimeOffset.UtcNow,
            Semantics: "Success means the native privacy boundary produced the expected fail-closed outcome without forwarding attacker-controlled input.",
            Soak: soak,
            Chaos: chaos,
            Load: load,
            RestartStorm: restartStorm,
            SloBaseline: sloBaseline,
            SideEffects: effects.Snapshot(),
            Limitations:
            [
                "This CI baseline exercises fail-closed handling and supervisor degradation without production authority material.",
                "Authority-bound multi-hop delivery remains a separate staging/production release gate."
            ]);

        var output = WriteArtifacts(report);

        Assert.True(sloBaseline.Passed, $"Native privacy C3 baseline failed. See {output.JsonPath}");
        Assert.Equal(0, effects.TotalCalls);
        Assert.True(File.Exists(output.JsonPath));
        Assert.True(File.Exists(output.MarkdownPath));
    }

    private static async Task<SoakMetrics> RunSoakAsync(
        PrivacyRoutingRuntime runtime,
        TimeSpan duration)
    {
        var deadline = Stopwatch.StartNew();
        var total = 0;
        var expected = 0;
        var latencies = new List<double>();

        while (deadline.Elapsed < duration)
        {
            var watch = Stopwatch.StartNew();
            var result = await runtime.ProcessAsync("c3-soak-frame"u8.ToArray(), default);
            watch.Stop();
            total++;
            latencies.Add(watch.Elapsed.TotalMilliseconds);
            if (result.Outcome == PrivacyRuntimeOutcome.UnavailableBeforeForward
                && result.OpaqueReply.IsEmpty)
            {
                expected++;
            }
        }

        return new SoakMetrics(
            DurationSeconds: deadline.Elapsed.TotalSeconds,
            TotalRequests: total,
            FailedRequests: total - expected,
            SuccessRate: Rate(expected, total),
            LatencyP95Ms: Percentile(latencies, 95),
            LatencyMaxMs: latencies.Count == 0 ? 0 : latencies.Max());
    }

    private static async Task<ChaosMetrics> RunMalformedFrameChaosAsync(
        PrivacyRoutingRuntime runtime,
        int iterations)
    {
        var random = new Random(42);
        var expected = 0;
        var malformedSizes = new HashSet<int>();

        for (var index = 0; index < iterations; index++)
        {
            var frame = new byte[random.Next(0, 8193)];
            random.NextBytes(frame);
            malformedSizes.Add(frame.Length);
            var result = await runtime.ProcessAsync(frame, default);
            if (result.Outcome == PrivacyRuntimeOutcome.UnavailableBeforeForward
                && result.OpaqueReply.IsEmpty)
            {
                expected++;
            }
        }

        return new ChaosMetrics(
            Iterations: iterations,
            SuccessfulIterations: expected,
            FailedIterations: iterations - expected,
            DistinctMalformedFrameSizes: malformedSizes.Count,
            SuccessRate: Rate(expected, iterations));
    }

    private static async Task<LoadMetrics> RunConcurrentLoadAsync(
        PrivacyRoutingRuntime runtime,
        int requested,
        int concurrency)
    {
        var latencies = new ConcurrentBag<double>();
        var succeeded = 0;
        var failed = 0;
        var next = -1;
        var wall = Stopwatch.StartNew();

        var workers = Enumerable.Range(0, concurrency).Select(_ => Task.Run(async () =>
        {
            while (true)
            {
                var index = Interlocked.Increment(ref next);
                if (index >= requested)
                {
                    return;
                }

                var watch = Stopwatch.StartNew();
                var result = await runtime.ProcessAsync(
                    BitConverter.GetBytes(index),
                    default);
                watch.Stop();
                latencies.Add(watch.Elapsed.TotalMilliseconds);
                if (result.Outcome == PrivacyRuntimeOutcome.UnavailableBeforeForward
                    && result.OpaqueReply.IsEmpty)
                {
                    Interlocked.Increment(ref succeeded);
                }
                else
                {
                    Interlocked.Increment(ref failed);
                }
            }
        })).ToArray();

        await Task.WhenAll(workers);
        wall.Stop();
        var completed = succeeded + failed;

        return new LoadMetrics(
            Requested: requested,
            Completed: completed,
            Succeeded: succeeded,
            Failed: failed,
            ThroughputRps: completed / Math.Max(wall.Elapsed.TotalSeconds, 0.000001),
            SuccessRate: Rate(succeeded, completed),
            LatencyP50Ms: Percentile(latencies, 50),
            LatencyP95Ms: Percentile(latencies, 95),
            LatencyP99Ms: Percentile(latencies, 99));
    }

    private static async Task<RestartStormMetrics> RunRestartStormAsync()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            "xnode-native-privacy-c3",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        try
        {
            var supervisor = new XraySupervisor(
                new VlessTransportOptions
                {
                    Enabled = true,
                    XrayExecutablePath = "dotnet",
                    GeneratedConfigPath = Path.Combine(root, "xray.generated.json"),
                    WorkingDirectory = root,
                    MockProcess = false,
                    RestartDelay = TimeSpan.FromMilliseconds(40),
                    MaxRestartAttempts = 1,
                    FailureWindow = TimeSpan.FromSeconds(5),
                    DegradedCooldown = TimeSpan.FromSeconds(2)
                },
                new XrayConfigGenerator());
            var watch = Stopwatch.StartNew();
            await supervisor.StartAsync(default);
            await WaitUntilAsync(
                () => supervisor.Status.RestartCount >= 1 && supervisor.Status.Degraded,
                TimeSpan.FromSeconds(5));
            var status = supervisor.Status;
            await supervisor.StopAsync(default);
            watch.Stop();

            return new RestartStormMetrics(
                RestartCount: status.RestartCount,
                Degraded: status.Degraded,
                Mode: status.Mode,
                DegradedUntil: status.DegradedUntil,
                DetectionSeconds: watch.Elapsed.TotalSeconds);
        }
        finally
        {
            TryDeleteDirectory(root);
        }
    }

    private static SloBaseline EvaluateSlo(
        SoakMetrics soak,
        ChaosMetrics chaos,
        LoadMetrics load,
        RestartStormMetrics restartStorm,
        Effects effects)
    {
        var checks = new[]
        {
            new SloCheck("soak-success-rate", soak.SuccessRate >= 0.99, soak.SuccessRate, 0.99, "fraction"),
            new SloCheck("chaos-success-rate", chaos.SuccessRate >= 0.99, chaos.SuccessRate, 0.99, "fraction"),
            new SloCheck("load-success-rate", load.SuccessRate >= 0.99, load.SuccessRate, 0.99, "fraction"),
            new SloCheck("load-throughput-rps", load.ThroughputRps >= 400, load.ThroughputRps, 400, "rps"),
            new SloCheck("path-select-p95-ms", load.LatencyP95Ms <= 15, load.LatencyP95Ms, 15, "ms"),
            new SloCheck("restart-storm-degraded", restartStorm.Degraded, restartStorm.Degraded ? 1 : 0, 1, "bool"),
            new SloCheck("untrusted-side-effects", effects.TotalCalls == 0, effects.TotalCalls, 0, "calls")
        };
        return new SloBaseline(checks.All(static check => check.Passed), checks);
    }

    private static (string JsonPath, string MarkdownPath) WriteArtifacts(C3Report report)
    {
        var root = FindRepositoryRoot();
        var output = Path.Combine(root, "artifacts", "test-results", "c3");
        Directory.CreateDirectory(output);
        var jsonPath = Path.Combine(output, "latest.json");
        var markdownPath = Path.Combine(output, "latest.md");
        File.WriteAllText(
            jsonPath,
            JsonSerializer.Serialize(report, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            }) + Environment.NewLine,
            new UTF8Encoding(false));

        var markdown = $"""
            # Native Privacy C3 Baseline

            GeneratedAt: {report.GeneratedAt:O}
            Architecture: {report.Architecture}

            - Soak safe-outcome rate: {report.Soak.SuccessRate:P2}
            - Malformed-frame chaos safe-outcome rate: {report.Chaos.SuccessRate:P2}
            - Concurrent load safe-outcome rate: {report.Load.SuccessRate:P2}
            - Concurrent load throughput: {report.Load.ThroughputRps:F2} requests/second
            - Concurrent load p95: {report.Load.LatencyP95Ms:F3} ms
            - Supervisor degraded after restart failure: {report.RestartStorm.Degraded}
            - Untrusted forwarding/dispatch calls: {report.SideEffects.TotalCalls}
            - SLO baseline: {(report.SloBaseline.Passed ? "PASS" : "FAIL")}

            This CI evidence does not replace authority-bound multi-hop staging or production acceptance.
            """;
        File.WriteAllText(markdownPath, markdown + Environment.NewLine, new UTF8Encoding(false));
        return (jsonPath, markdownPath);
    }

    private static double Rate(int succeeded, int total) =>
        total == 0 ? 0 : (double)succeeded / total;

    private static double Percentile(IEnumerable<double> values, double percentile)
    {
        var sorted = values.Order().ToArray();
        if (sorted.Length == 0)
        {
            return 0;
        }

        var rank = (percentile / 100d) * (sorted.Length - 1);
        var lower = (int)Math.Floor(rank);
        var upper = (int)Math.Ceiling(rank);
        if (lower == upper)
        {
            return sorted[lower];
        }

        return sorted[lower] + ((sorted[upper] - sorted[lower]) * (rank - lower));
    }

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }

            await Task.Delay(50);
        }

        Assert.True(condition(), "condition was not met before timeout");
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("XNode repository root was not found.");
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

    private sealed class Effects : IPrivacyPeerClient, INativeMailboxExitDispatcher
    {
        private int peerCalls;
        private int terminalCalls;

        public int TotalCalls => Volatile.Read(ref peerCalls) + Volatile.Read(ref terminalCalls);

        public Task<PrivacyForwardResult> ForwardAsync(
            VerifiedOnionNextHopTransport nextHop,
            ReadOnlyMemory<byte> innerFrame,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref peerCalls);
            return Task.FromResult(PrivacyForwardResult.Rejected);
        }

        public Task<NativeMailboxDispatchResult> DispatchAsync(
            VerifiedCanonicalOnionRequest request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref terminalCalls);
            return Task.FromResult(NativeMailboxDispatchResult.RejectedBeforeForward());
        }

        public SideEffectMetrics Snapshot() => new(
            Volatile.Read(ref peerCalls),
            Volatile.Read(ref terminalCalls),
            TotalCalls);
    }

    private sealed record C3Report(
        string Schema,
        string Architecture,
        DateTimeOffset GeneratedAt,
        string Semantics,
        SoakMetrics Soak,
        ChaosMetrics Chaos,
        LoadMetrics Load,
        RestartStormMetrics RestartStorm,
        SloBaseline SloBaseline,
        SideEffectMetrics SideEffects,
        string[] Limitations);

    private sealed record SoakMetrics(
        double DurationSeconds,
        int TotalRequests,
        int FailedRequests,
        double SuccessRate,
        double LatencyP95Ms,
        double LatencyMaxMs);

    private sealed record ChaosMetrics(
        int Iterations,
        int SuccessfulIterations,
        int FailedIterations,
        int DistinctMalformedFrameSizes,
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

    private sealed record SloBaseline(bool Passed, SloCheck[] Checks);

    private sealed record SloCheck(
        string Name,
        bool Passed,
        double Observed,
        double Target,
        string Unit);

    private sealed record SideEffectMetrics(int PeerCalls, int TerminalCalls, int TotalCalls);
}
