using XNode.Transport.Vless;

namespace XNode.IntegrationTests.Runtime;

public sealed class TransportSupervisorIntegrationTests
{
    [Fact]
    public async Task Supervisor_RestartsFailingProcess_AndEntersDegradedMode()
    {
        var root = NewTempDirectory();
        try
        {
            var options = new VlessTransportOptions
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
            };

            var supervisor = new XraySupervisor(options, new XrayConfigGenerator());
            await supervisor.StartAsync(CancellationToken.None);
            await WaitUntilAsync(
                () => supervisor.Status.RestartCount >= 1 && supervisor.Status.Degraded,
                TimeSpan.FromSeconds(5));

            var status = supervisor.Status;
            Assert.True(status.RestartCount >= 1);
            Assert.True(status.Degraded);
            Assert.Equal("degraded", status.Mode);
            Assert.NotNull(status.DegradedUntil);

            await supervisor.StopAsync(CancellationToken.None);
        }
        finally
        {
            TryDeleteDirectory(root);
        }
    }

    private static string NewTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "xnode-transport-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
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
}
