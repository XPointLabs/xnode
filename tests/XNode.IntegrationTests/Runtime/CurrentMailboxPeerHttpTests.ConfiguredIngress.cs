using System.Net;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace XNode.IntegrationTests.Runtime;

public sealed partial class CurrentMailboxPeerHttpTests
{
    [Fact]
    [Trait("FixturePreflight", "true")]
    public async Task FixturePreflight_ConfiguredIngressHasSupportedNodeAndValidHelper()
    {
        var start = new ProcessStartInfo(Host.FindConfiguredIngressNode())
        { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        start.Environment.Clear();
        if (systemRoot is not null) start.Environment["SystemRoot"] = systemRoot;
        start.ArgumentList.Add("--version");
        using (var process = Process.Start(start)!)
        {
            var version = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5));
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, process.ExitCode);
            Assert.True(version is not null && int.TryParse(version.TrimStart('v').Split('.')[0], out var major) && major >= 22);
        }
        start.ArgumentList.Clear();
        start.ArgumentList.Add("--check");
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Fixtures", "configured-ingress.cjs"));
        using var syntax = Process.Start(start)!;
        await syntax.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, syntax.ExitCode);
    }

    private static async Task AssertConfiguredIngressRefusalsAsync(HttpClient client, int port,
        ReadOnlyMemory<byte> validFrame, VerifiedOnionNextHopTransport differentEntry, IReadOnlyList<RegisteredPeer> owners)
    {
        var original = owners.Select(owner => owner.NativeMailboxDigest()).ToArray();
        foreach (var defect in new[] { "query", "media", "accept", "encoding", "early-data", "authorization", "short", "oversize" })
        {
            using var request = new HttpRequestMessage(HttpMethod.Post,
                "https://127.0.0.1:" + port + ManagedIngressH2Contract.FramePath + (defect == "query" ? "?extra=1" : ""))
            {
                Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(defect switch
                {
                    "short" => new byte[ManagedIngressLimits.MinimumOpaqueFrameBytes - 1],
                    "oversize" => new byte[ManagedIngressLimits.MaximumOpaqueFrameBytes + 1],
                    _ => validFrame.ToArray()
                })
            };
            request.Content.Headers.ContentType = new(defect == "media" ? "application/octet-stream" : ManagedIngressH2Contract.OpaqueMediaType);
            request.Headers.Accept.Add(new(defect == "accept" ? "application/json" : ManagedIngressH2Contract.OpaqueMediaType));
            if (defect == "encoding") request.Content.Headers.ContentEncoding.Add("gzip");
            if (defect == "early-data") request.Headers.TryAddWithoutValidation("Early-Data", "1");
            if (defect == "authorization") request.Headers.TryAddWithoutValidation("Authorization", "Bearer invalid-fixture-input");
            using var response = await client.SendAsync(request);
            Assert.InRange((int)response.StatusCode, 400, 499);
            for (var index = 0; index < owners.Count; index++) Assert.Equal(original[index], owners[index].NativeMailboxDigest());
        }
        // A valid sealed frame still belongs to its exact selected entry, not
        // any other genuine signed member with a valid TLS pin and Entry role.
        using var differentClient = new HttpClient(HttpPrivacyPeerClient.CreatePinnedHandler(differentEntry));
        using var misplaced = new HttpRequestMessage(HttpMethod.Post,
            "https://127.0.0.1:" + differentEntry.Port + ManagedIngressH2Contract.FramePath)
        {
            Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = new ByteArrayContent(validFrame.ToArray())
        };
        misplaced.Content.Headers.ContentType = new(ManagedIngressH2Contract.OpaqueMediaType);
        misplaced.Headers.Accept.Add(new(ManagedIngressH2Contract.OpaqueMediaType));
        using var refused = await differentClient.SendAsync(misplaced);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        for (var index = 0; index < owners.Count; index++) Assert.Equal(original[index], owners[index].NativeMailboxDigest());
    }

    private sealed partial class Host
    {
        private Process? configuredIngress;

        // Transparent test-owned shared TLS origin. It makes no authorization,
        // codec, health or outcome decision: those all belong to actual Program.
        // Both public and private hops use pinned HTTPS/H2. This is not a claim
        // about the deployed HAProxy/carrier or an installed client composition.
        internal async Task StartConfiguredIngressAsync()
        {
            var start = new ProcessStartInfo(FindConfiguredIngressNode())
            {
                UseShellExecute = false, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                CreateNoWindow = true
            };
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Fixtures", "configured-ingress.cjs"));
            // The helper needs only Node's built-in HTTP/2/TLS modules, no npm
            // packages and no inherited credentials or Git configuration.
            var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            start.Environment.Clear();
            if (systemRoot is not null) start.Environment["SystemRoot"] = systemRoot;
            // Preserve the signed public-origin reservation until the private
            // Program is running and this listener is ready to take ownership.
            ReleaseConfiguredReservations();
            configuredIngress = Process.Start(start) ?? throw new InvalidOperationException("Test ingress did not start.");
            // Re-import only this already exportable, test-generated PFX. The
            // Schannel listener keeps its non-exportable native handle.
            using var transportCertificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath!, null,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
            using var privateKey = transportCertificate.GetRSAPrivateKey()!;
            await configuredIngress.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new
            {
                port = Port, managedPort = configuredPorts![4], peerPort = configuredPorts[3],
                cert = certificate.ExportCertificatePem(), key = privateKey.ExportPkcs8PrivateKeyPem(),
                pin = Convert.ToHexString(Pin).ToLowerInvariant()
            }));
            Assert.Equal("ready", await configuredIngress.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)));
        }

        internal static string FindConfiguredIngressNode()
        {
            var name = OperatingSystem.IsWindows() ? "node.exe" : "node";
            foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(directory)) continue;
                var candidate = Path.GetFullPath(Path.Combine(directory, name));
                if (File.Exists(candidate)) return candidate;
            }
            throw new InvalidOperationException("Configured HTTPS/H2 ingress fixture requires Node.js 22 or newer on PATH.");
        }

        private async Task CloseConfiguredIngressAsync()
        {
            if (configuredIngress is not null)
            {
                configuredIngress.StandardInput.Close();
                try { await configuredIngress.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); }
                catch (TimeoutException)
                {
                    configuredIngress.Kill(entireProcessTree: true);
                    await configuredIngress.WaitForExitAsync();
                }
                configuredIngress.Dispose(); configuredIngress = null;
            }
        }
    }
}
