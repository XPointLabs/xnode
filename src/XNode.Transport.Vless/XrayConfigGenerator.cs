using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;

namespace XNode.Transport.Vless;

public sealed class XrayConfigGenerator
{
    public string Generate(VlessTransportOptions options)
    {
        var inbound = new JsonObject
        {
            ["tag"] = "vless-ingress",
            ["listen"] = options.InboundListenHost,
            ["port"] = options.InboundListenPort,
            ["protocol"] = "vless",
            ["settings"] = new JsonObject
            {
                ["clients"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["id"] = options.ClientId,
                        ["flow"] = options.TransportMode == VlessTransportMode.Reality ? "xtls-rprx-vision" : ""
                    }
                },
                ["decryption"] = "none"
            },
            ["streamSettings"] = BuildStreamSettings(options)
        };

        var root = new JsonObject
        {
            ["log"] = new JsonObject
            {
                ["loglevel"] = "warning"
            },
            ["inbounds"] = new JsonArray { inbound },
            ["outbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["tag"] = "local-session-router",
                    ["protocol"] = "freedom",
                    ["settings"] = new JsonObject
                    {
                        ["redirect"] = $"{options.ApiIngressHost}:{options.ApiIngressPort}"
                    }
                },
                new JsonObject
                {
                    ["tag"] = "blocked",
                    ["protocol"] = "blackhole"
                }
            },
            ["routing"] = new JsonObject
            {
                ["domainStrategy"] = "AsIs",
                ["rules"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["type"] = "field",
                        ["inboundTag"] = new JsonArray { "vless-ingress" },
                        ["outboundTag"] = "local-session-router"
                    }
                }
            }
        };

        return root.ToJsonString(new JsonSerializerOptions
        {
            WriteIndented = true,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver()
        });
    }

    public async Task WriteAsync(
        VlessTransportOptions options,
        CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(options.GeneratedConfigPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(options.GeneratedConfigPath, Generate(options), cancellationToken)
            .ConfigureAwait(false);
    }

    private static JsonObject BuildStreamSettings(VlessTransportOptions options)
    {
        var stream = new JsonObject
        {
            ["network"] = "tcp"
        };

        switch (options.TransportMode)
        {
            case VlessTransportMode.Reality:
                var serverNames = new[] { options.MaskDomain, options.Reality.ServerName }
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(value => JsonValue.Create(value))
                    .ToArray();
                stream["security"] = "reality";
                stream["realitySettings"] = new JsonObject
                {
                    ["show"] = false,
                    ["target"] = $"{options.MaskDomain}:443",
                    ["serverNames"] = new JsonArray(serverNames),
                    ["privateKey"] = options.Reality.PrivateKey,
                    ["shortIds"] = new JsonArray { options.Reality.ShortId },
                    ["fingerprint"] = options.Reality.Fingerprint,
                    ["spiderX"] = options.Reality.SpiderX
                };
                break;

            case VlessTransportMode.Tls:
                stream["security"] = "tls";
                stream["tlsSettings"] = new JsonObject
                {
                    ["serverName"] = string.IsNullOrWhiteSpace(options.Tls.ServerName) ? options.PublicHost : options.Tls.ServerName,
                    ["alpn"] = new JsonArray(options.Tls.Alpn.Select(value => JsonValue.Create(value)).ToArray()),
                    ["certificates"] = new JsonArray
                    {
                        new JsonObject
                        {
                            ["certificateFile"] = options.Tls.CertificateFile,
                            ["keyFile"] = options.Tls.KeyFile
                        }
                    }
                };
                break;

            case VlessTransportMode.Tcp:
                stream["security"] = "none";
                break;
        }

        return stream;
    }
}
