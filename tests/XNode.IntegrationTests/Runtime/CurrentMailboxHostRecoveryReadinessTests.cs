using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxHostRecoveryReadinessTests
{
    [Theory]
    [InlineData(true, true, false, "unconfigured")]
    [InlineData(true, false, false, "not-running")]
    [InlineData(false, true, true, "disabled")]
    public async Task ActualProgramHealthCannotSubstituteDisabledOrMissingCompositionForRecovery(
        bool enabled, bool startRecovery, bool recovered, string state)
    {
        using var factory = new RecoveryOnlyFactory(enabled, startRecovery);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var response = await client.GetAsync("/health/ready");
        using var body = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        var status = body.RootElement.GetProperty("currentMailboxHost");
        Assert.Equal(recovered, status.GetProperty("recovered").GetBoolean());
        Assert.Equal(state, status.GetProperty("state").GetString());
        Assert.Equal(new[] { "recovered", "state" }, status.EnumerateObject().Select(p => p.Name).ToArray());
        if (enabled)
        {
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            Assert.False(body.RootElement.GetProperty("ready").GetBoolean());
        }
    }

    // Negative actual-Program HTTP evidence only: no authority, storage, Xray
    // or retired background service is provisioned or claimed as qualified.
    private sealed class RecoveryOnlyFactory(bool enabled, bool startRecovery) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHostedService>();
                services.Replace(ServiceDescriptor.Singleton(new ReplicatedMailboxOptions { Enabled = enabled }));
                if (startRecovery)
                    services.AddHostedService(provider => provider.GetRequiredService<CurrentMailboxHostRecovery>());
            });
        }
    }
}
