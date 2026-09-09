using System.Text.Json.Nodes;
using XNode.Transport.Vless;

namespace XNode.Tests.Transport;

public sealed class XrayConfigGenerationTests
{
    [Fact]
    public void XrayConfigGenerator_RendersVlessRealitySidecarConfig()
    {
        var options = Options();
        var json = new XrayConfigGenerator().Generate(options);
        var root = JsonNode.Parse(json)!.AsObject();

        var inbound = root["inbounds"]![0]!.AsObject();
        Assert.Equal("vless", inbound["protocol"]!.GetValue<string>());
        Assert.Equal(options.InboundListenPort, inbound["port"]!.GetValue<int>());
        Assert.Equal("reality", inbound["streamSettings"]!["security"]!.GetValue<string>());
        Assert.Equal(options.ClientId, inbound["settings"]!["clients"]![0]!["id"]!.GetValue<string>());
        Assert.Equal("cloudflare-dns.com:443", inbound["streamSettings"]!["realitySettings"]!["target"]!.GetValue<string>());
        Assert.Null(inbound["streamSettings"]!["realitySettings"]!["dest"]);
        Assert.Single(inbound["streamSettings"]!["realitySettings"]!["serverNames"]!.AsArray());

        var outbound = root["outbounds"]![0]!.AsObject();
        Assert.Equal("freedom", outbound["protocol"]!.GetValue<string>());
        Assert.Equal("127.0.0.1:8080", outbound["settings"]!["redirect"]!.GetValue<string>());
    }

    [Fact]
    public void SecretFileLoader_ReplacesConfiguredPlaceholdersWithBoundedCanonicalFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), $"xnode-vless-secrets-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var clientIdPath = Path.Combine(root, "client-id");
            var privateKeyPath = Path.Combine(root, "reality-private");
            File.WriteAllText(clientIdPath, "22222222-2222-4222-8222-222222222222\n");
            File.WriteAllText(privateKeyPath, new string('A', 43) + "\n");
            var options = Options();
            options.ClientId = "not-the-file-value";
            options.ClientIdFile = clientIdPath;
            options.Reality.PrivateKey = "not-the-file-value";
            options.Reality.PrivateKeyFile = privateKeyPath;

            VlessSecretFileLoader.Load(options);

            Assert.Equal("22222222-2222-4222-8222-222222222222", options.ClientId);
            Assert.Equal(new string('A', 43), options.Reality.PrivateKey);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void SecretFileLoader_RejectsNonCanonicalAndMultilineSecrets()
    {
        var root = Path.Combine(Path.GetTempPath(), $"xnode-vless-secrets-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var clientIdPath = Path.Combine(root, "client-id");
            var privateKeyPath = Path.Combine(root, "reality-private");
            File.WriteAllText(clientIdPath, "22222222-2222-4222-8222-222222222222\nextra\n");
            File.WriteAllText(privateKeyPath, new string('A', 43) + "\n");
            var options = Options();
            options.ClientIdFile = clientIdPath;
            options.Reality.PrivateKeyFile = privateKeyPath;

            Assert.Throws<InvalidDataException>(() => VlessSecretFileLoader.Load(options));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void SecretFileLoader_ProductionRejectsDirectCredentialConfiguration()
    {
        var options = Options();

        var exception = Assert.Throws<InvalidOperationException>(() =>
            VlessSecretFileLoader.Load(options, requireProtectedFiles: true));

        Assert.Contains("protected client-id file", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task XrayConfigGenerator_WritesAtomicallyWithOwnerOnlyUnixPermissions()
    {
        var root = Path.Combine(Path.GetTempPath(), $"xnode-xray-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var options = Options();
            options.GeneratedConfigPath = Path.Combine(root, "config.json");

            await new XrayConfigGenerator().WriteAsync(options);

            var json = await File.ReadAllTextAsync(options.GeneratedConfigPath);
            Assert.Contains(options.ClientId, json, StringComparison.Ordinal);
            Assert.Contains(options.Reality.PrivateKey, json, StringComparison.Ordinal);
            Assert.Empty(Directory.EnumerateFiles(root, "*.tmp"));
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(
                    UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(options.GeneratedConfigPath));
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    public static VlessTransportOptions Options()
    {
        return new VlessTransportOptions
        {
            PublicHost = "node.example.org",
            PublicPort = 443,
            InboundListenPort = 443,
            ApiIngressHost = "127.0.0.1",
            ApiIngressPort = 8080,
            ClientId = "11111111-1111-1111-1111-111111111111",
            MaskDomain = "cloudflare-dns.com",
            TransportMode = VlessTransportMode.Reality,
            Reality = new RealityMetadata
            {
                ServerName = "cloudflare-dns.com",
                PublicKey = "pub",
                PrivateKey = "priv",
                ShortId = "abcd",
                Fingerprint = "chrome",
                SpiderX = "/"
            }
        };
    }
}
