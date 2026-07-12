using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using XNode.Core;
using XNode.Core.Onion;
using XNode.Core.Runtime;
using XNode.Core.Session;

namespace XNode;

public sealed class HttpOnionPeerClient : IOnionPeerClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly RouterNodeOptions _nodeOptions;
    private readonly RouterRuntimeOptions _runtimeOptions;
    private readonly IClock _clock;

    public HttpOnionPeerClient(
        HttpClient httpClient,
        RouterNodeOptions nodeOptions,
        RouterRuntimeOptions runtimeOptions,
        IClock clock)
    {
        _httpClient = httpClient;
        _nodeOptions = nodeOptions;
        _runtimeOptions = runtimeOptions;
        _clock = clock;
    }

    public async Task<SessionRpcResponse> ForwardAsync(
        RouterId recipientRouterId,
        string rpcEndpoint,
        OnionRequest request,
        CancellationToken cancellationToken)
    {
        var endpointError = "invalid-onion-peer-endpoint";
        if (!Uri.TryCreate(rpcEndpoint.Trim(), UriKind.Absolute, out var uri)
            || !PeerEndpointPolicy.TryValidateUri(uri, _runtimeOptions.AllowLoopbackPeerEndpoints, out endpointError)
            || !string.Equals(uri.AbsolutePath, "/api/peer/onion", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Query))
        {
            return SessionRpcResponse.Fail("onion-forward", endpointError);
        }

        var signed = SignedOnionPeerRequestAuthenticator.Sign(
            _nodeOptions.GetRouterId(),
            recipientRouterId,
            _nodeOptions.GetEd25519PrivateKey(),
            request,
            _clock.UtcNow);

        try
        {
            using var content = JsonContent.Create(signed, options: JsonOptions);
            using var message = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
            using var response = await _httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);

            if ((int)response.StatusCode is >= 300 and < 400)
            {
                return SessionRpcResponse.Fail("onion-forward", $"onion-peer-redirect-blocked:{(int)response.StatusCode}");
            }

            if (response.Content.Headers.ContentLength is > 0 and var contentLength
                && contentLength > _runtimeOptions.MaxPeerRequestBodyBytes)
            {
                return SessionRpcResponse.Fail("onion-forward", "onion-peer-response-too-large");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            var bytes = await ReadBoundedAsync(stream, _runtimeOptions.MaxPeerRequestBodyBytes, cancellationToken)
                .ConfigureAwait(false);
            var body = JsonSerializer.Deserialize<SessionRpcResponse>(bytes, JsonOptions);

            return body ?? SessionRpcResponse.Fail(
                "onion-forward",
                $"onion-peer-empty-response:{(int)response.StatusCode}");
        }
        catch (HttpRequestException)
        {
            return SessionRpcResponse.Fail("onion-forward", "onion-peer-transport-failed");
        }
        catch (SocketException)
        {
            return SessionRpcResponse.Fail("onion-forward", "onion-peer-transport-failed");
        }
        catch (InvalidDataException)
        {
            return SessionRpcResponse.Fail("onion-forward", "onion-peer-response-too-large");
        }
        catch (JsonException)
        {
            return SessionRpcResponse.Fail("onion-forward", "onion-peer-invalid-response");
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        await using var output = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (output.Length + read > maxBytes)
            {
                throw new InvalidDataException("Peer response exceeded the configured limit.");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return output.ToArray();
    }
}

public static class OnionPeerHttpHandler
{
    public static SocketsHttpHandler Create(RouterRuntimeOptions runtimeOptions)
    {
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) => ConnectAsync(
                context.DnsEndPoint,
                runtimeOptions.AllowLoopbackPeerEndpoints,
                cancellationToken)
        };
    }

    private static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endpoint,
        bool allowLoopback,
        CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken).ConfigureAwait(false);
        var permitted = addresses
            .Where(address => PeerEndpointPolicy.IsPubliclyRoutable(address, allowLoopback))
            .ToArray();
        if (permitted.Length == 0)
        {
            throw new HttpRequestException("Onion peer resolved only to blocked addresses.");
        }

        Exception? lastError = null;
        foreach (var address in permitted)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, endpoint.Port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception error) when (error is SocketException or OperationCanceledException)
            {
                socket.Dispose();
                lastError = error;
            }
        }

        throw new HttpRequestException("Unable to connect to a permitted onion peer endpoint.", lastError);
    }
}
