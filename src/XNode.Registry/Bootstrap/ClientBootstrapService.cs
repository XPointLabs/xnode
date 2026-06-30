using System.Text;
using System.Text.Json.Nodes;
using XNode.Transport.Vless;

namespace XNode.Registry.Bootstrap;

public sealed class ClientBootstrapService
{
    private readonly RegistryPayloadFactory _payloadFactory;
    private readonly VlessTransportOptions _transportOptions;

    public ClientBootstrapService(RegistryPayloadFactory payloadFactory, VlessTransportOptions transportOptions)
    {
        _payloadFactory = payloadFactory;
        _transportOptions = transportOptions;
    }

    public ClientBootstrapDocument Create()
    {
        var payload = _payloadFactory.Create();
        var uri = BuildVlessUri(payload);
        return new ClientBootstrapDocument(
            payload.RouterId,
            payload.PublicHost,
            payload.PublicPort,
            payload.MaskDomain,
            payload.TransportMode.ToString().ToLowerInvariant(),
            payload.ConfigVersion,
            uri,
            BuildXrayOutbound(payload));
    }

    private string BuildVlessUri(RegistryPayload payload)
    {
        var query = new Dictionary<string, string?>
        {
            ["encryption"] = "none",
            ["type"] = "tcp"
        };

        switch (payload.TransportMode)
        {
            case VlessTransportMode.Reality:
                query["security"] = "reality";
                query["sni"] = payload.MaskDomain;
                query["fp"] = payload.Reality?.Fingerprint ?? "chrome";
                query["pbk"] = payload.Reality?.PublicKey ?? "";
                query["sid"] = payload.Reality?.ShortId ?? "";
                query["flow"] = "xtls-rprx-vision";
                query["spx"] = payload.Reality?.SpiderX ?? "/";
                break;

            case VlessTransportMode.Tls:
                query["security"] = "tls";
                query["sni"] = payload.Tls?.ServerName ?? payload.PublicHost;
                break;

            case VlessTransportMode.Tcp:
                query["security"] = "none";
                break;
        }

        var queryString = string.Join(
            "&",
            query
                .Where(pair => pair.Value is not null)
                .Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value!)}"));

        var fragment = Uri.EscapeDataString($"Deep-{payload.RouterId[..8]}");
        return $"vless://{_transportOptions.ClientId}@{payload.PublicHost}:{payload.PublicPort}?{queryString}#{fragment}";
    }

    private JsonObject BuildXrayOutbound(RegistryPayload payload)
    {
        var streamSettings = new JsonObject
        {
            ["network"] = "tcp"
        };

        if (payload.TransportMode == VlessTransportMode.Reality)
        {
            streamSettings["security"] = "reality";
            streamSettings["realitySettings"] = new JsonObject
            {
                ["serverName"] = payload.MaskDomain,
                ["fingerprint"] = payload.Reality?.Fingerprint ?? "chrome",
                ["password"] = payload.Reality?.PublicKey ?? "",
                ["shortId"] = payload.Reality?.ShortId ?? "",
                ["spiderX"] = payload.Reality?.SpiderX ?? "/"
            };
        }
        else if (payload.TransportMode == VlessTransportMode.Tls)
        {
            streamSettings["security"] = "tls";
            streamSettings["tlsSettings"] = new JsonObject
            {
                ["serverName"] = payload.Tls?.ServerName ?? payload.PublicHost
            };
        }
        else
        {
            streamSettings["security"] = "none";
        }

        return new JsonObject
        {
            ["tag"] = "deep-node",
            ["protocol"] = "vless",
            ["settings"] = new JsonObject
            {
                ["vnext"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["address"] = payload.PublicHost,
                        ["port"] = payload.PublicPort,
                        ["users"] = new JsonArray
                        {
                            new JsonObject
                            {
                                ["id"] = _transportOptions.ClientId,
                                ["encryption"] = "none",
                                ["flow"] = payload.TransportMode == VlessTransportMode.Reality ? "xtls-rprx-vision" : ""
                            }
                        }
                    }
                }
            },
            ["streamSettings"] = streamSettings
        };
    }
}
