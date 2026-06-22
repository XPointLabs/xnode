using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace XNode.Transport.Vless;

public sealed class XraySupervisor : BackgroundService, IXraySupervisor
{
    private readonly VlessTransportOptions _options;
    private readonly XrayConfigGenerator _configGenerator;
    private readonly ILogger<XraySupervisor> _logger;
    private readonly object _statusGate = new();
    private Process? _process;
    private readonly Queue<DateTimeOffset> _failureTimestamps = new();
    private XraySupervisorStatus _status;

    public XraySupervisor(
        VlessTransportOptions options,
        XrayConfigGenerator configGenerator,
        ILogger<XraySupervisor>? logger = null)
    {
        _options = options;
        _configGenerator = configGenerator;
        _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<XraySupervisor>.Instance;
        _status = new XraySupervisorStatus(
            options.Enabled,
            Running: false,
            Mocked: options.MockProcess,
            Degraded: false,
            Mode: options.Enabled ? "starting" : "disabled",
            RestartCount: 0,
            ConsecutiveFailures: 0,
            ProcessId: null,
            options.GeneratedConfigPath,
            LastExitReason: null,
            LastStartedAt: null,
            DegradedUntil: null);
    }

    public XraySupervisorStatus Status
    {
        get
        {
            lock (_statusGate)
            {
                return _status;
            }
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            SetStatus(running: false, processId: null, lastExitReason: "disabled", mode: "disabled");
            return;
        }

        if (_options.MockProcess || string.Equals(_options.XrayExecutablePath, "mock", StringComparison.OrdinalIgnoreCase))
        {
            SetStatus(running: true, processId: null, lastExitReason: "mocked", mode: "mocked");
            await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
            return;
        }

        Directory.CreateDirectory(_options.WorkingDirectory);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (Status.Degraded && Status.DegradedUntil is { } degradedUntil)
                {
                    var remaining = degradedUntil - DateTimeOffset.UtcNow;
                    if (remaining > TimeSpan.Zero)
                    {
                        await Task.Delay(remaining, stoppingToken).ConfigureAwait(false);
                    }
                }

                await _configGenerator.WriteAsync(_options, stoppingToken).ConfigureAwait(false);

                var startInfo = new ProcessStartInfo
                {
                    FileName = _options.XrayExecutablePath,
                    WorkingDirectory = _options.WorkingDirectory,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                };
                startInfo.ArgumentList.Add("run");
                startInfo.ArgumentList.Add("-config");
                startInfo.ArgumentList.Add(_options.GeneratedConfigPath);

                _process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start Xray.");
                SetStatus(running: true, processId: _process.Id, lastExitReason: null, mode: "running");
                _logger.LogInformation("Started Xray sidecar with pid {Pid}.", _process.Id);

                await _process.WaitForExitAsync(stoppingToken).ConfigureAwait(false);
                var exitReason = $"xray-exited:{_process.ExitCode}";
                RegisterFailure(exitReason);
                _logger.LogWarning("Xray sidecar exited with code {ExitCode}; restarting.", _process.ExitCode);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception e)
            {
                RegisterFailure(e.Message);
                _logger.LogError(e, "Xray supervision loop failed.");
            }

            await Task.Delay(_options.RestartDelay, stoppingToken).ConfigureAwait(false);
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }

        SetStatus(running: false, processId: null, lastExitReason: "stopped", mode: "stopped");
        return base.StopAsync(cancellationToken);
    }

    private void SetStatus(bool running, int? processId, string? lastExitReason, string mode)
    {
        lock (_statusGate)
        {
            _status = _status with
            {
                Running = running,
                Degraded = mode == "degraded",
                Mode = mode,
                ProcessId = processId,
                LastExitReason = lastExitReason,
                LastStartedAt = running ? DateTimeOffset.UtcNow : _status.LastStartedAt,
                DegradedUntil = mode == "degraded" ? _status.DegradedUntil : null
            };
        }
    }

    private void RegisterFailure(string reason)
    {
        lock (_statusGate)
        {
            var now = DateTimeOffset.UtcNow;
            _failureTimestamps.Enqueue(now);

            while (_failureTimestamps.Count > 0 && now - _failureTimestamps.Peek() > _options.FailureWindow)
            {
                _failureTimestamps.Dequeue();
            }

            var failures = _failureTimestamps.Count;
            var degraded = failures >= Math.Max(1, _options.MaxRestartAttempts);
            var degradedUntil = degraded ? now + _options.DegradedCooldown : (DateTimeOffset?)null;

            _status = _status with
            {
                Running = false,
                Degraded = degraded,
                Mode = degraded ? "degraded" : "restarting",
                ProcessId = null,
                RestartCount = _status.RestartCount + 1,
                ConsecutiveFailures = failures,
                LastExitReason = reason,
                DegradedUntil = degradedUntil
            };
        }
    }
}
