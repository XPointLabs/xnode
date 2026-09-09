using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using System.Text;

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
                    ["tag"] = "local-privacy-ingress",
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
                        ["outboundTag"] = "local-privacy-ingress"
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
        var configPath = Path.GetFullPath(options.GeneratedConfigPath);
        var directory = Path.GetDirectoryName(configPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = $"{configPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            var streamOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.Asynchronous | FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows())
            {
                streamOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            await using (var stream = new FileStream(temporaryPath, streamOptions))
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                await writer.WriteAsync(Generate(options).AsMemory(), cancellationToken)
                    .ConfigureAwait(false);
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, configPath, overwrite: true);
        }
        finally
        {
            File.Delete(temporaryPath);
        }
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
