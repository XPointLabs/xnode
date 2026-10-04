using System.Net;
using System.Net.Sockets;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    private sealed partial class Host
    {
        private WebApplicationFactory<Program>? program;
        internal int ApiPort;
        private string? certificateRoot;
        internal string? certificatePath;

        private void RemoveTestCertificate()
        {
            if (certificatePath is not null && File.Exists(certificatePath)) File.Delete(certificatePath);
            if (certificateRoot is not null && Directory.Exists(certificateRoot)) Directory.Delete(certificateRoot);
        }

        internal static Task<Host> CreateProgramAsync()
        {
            var host = CreateCertificate(forProgram: true);
            // Reserve distinct test-owned listeners together; no fixed/operator ports.
            var reservations = Enumerable.Range(0, 3).Select(_ => new TcpListener(IPAddress.Loopback, 0)).ToArray();
            try
            {
                foreach (var listener in reservations) listener.Start();
                var ports = reservations.Select(listener => ((IPEndPoint)listener.LocalEndpoint).Port).ToArray();
                host.ApiPort = ports[0]; host.Port = ports[2];
                foreach (var listener in reservations) listener.Stop();
                host.program = new PeerProgramFactory(host, ports);
                host.program.UseKestrel();
                host.program.StartServer();
                return Task.FromResult(host);
            }
            catch
            {
                host.program?.Dispose();
                host.certificate.Dispose();
                host.RemoveTestCertificate();
                throw;
            }
            finally { foreach (var listener in reservations) listener.Stop(); }
        }
    }

    // Exercise the real Program pipeline/listener/route wrapper over Kestrel TLS/H2.
    // Only the already qualified, independently registered native endpoint is
    // supplied by the signed test fixture; this does not provision a network
    // observer, enable ONION or prove production configuration/shipping readiness.
    private sealed class PeerProgramFactory(Host host, int[] ports) : WebApplicationFactory<Program>
    {
        protected override IHost CreateHost(IHostBuilder builder)
        {
            // Program binds its listener plan before Build. Deferred host
            // configuration becomes entry-point arguments; late app callbacks
            // cannot change the already captured listener/security policy.
            builder.ConfigureHostConfiguration(configuration => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Node:ApiListenUrl"] = "http://127.0.0.1:" + ports[0],
                ["Node:PeerRpcListenUrl"] = "http://127.0.0.1:" + ports[1],
                ["Node:PrivacyPeerH2ListenUrl"] = "https://127.0.0.1:" + ports[2],
                // Listener UseHttps resolves its default while Kestrel options
                // are configured, before the factory's later callbacks.
                ["Kestrel:Certificates:Default:Path"] = host.certificatePath
            }));
            return base.CreateHost(builder);
        }

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IHostedService>();
                services.Replace(ServiceDescriptor.Singleton(new ReplicatedMailboxOptions { Enabled = true }));
                services.AddTransient(_ => host.Endpoint ?? throw new InvalidOperationException("Test-owned endpoint is not yet attached."));
                services.AddTransient<IStartupFilter>(_ => new CountPeerRequests(host));
            });
        }
    }

    private sealed class CountPeerRequests(Host host) : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, continuation) =>
            {
                if (context.Connection.LocalPort == host.Port &&
                    (context.Request.Path.Equals(MailboxWireHttpContract.PeerStoreRoute) ||
                     context.Request.Path.Equals(MailboxWireHttpContract.PeerTombstoneRoute)))
                    Interlocked.Increment(ref host.Requests);
                await continuation(context);
                host.LastStatus = context.Response.StatusCode;
                host.LastBytes = checked((int)(context.Response.ContentLength ?? 0));
            });
            next(app);
        };
    }
}
