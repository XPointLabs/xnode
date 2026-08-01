using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using XNode.Core;
using XNode.Core.Onion;
using XNode.Core.Runtime;
using XNode.Core.Session;

namespace XNode;

public sealed class HttpOnionPeerClient : IOnionPeerClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    internal static readonly HttpRequestOptionsKey<string> RecipientRouterIdOption =
        new("XNode.OnionPeer.RecipientRouterId");
    internal static readonly HttpRequestOptionsKey<string> ExpectedPeerPathOption =
        new("XNode.Peer.ExpectedPath");

    private readonly HttpClient _httpClient;
    private readonly RouterNodeOptions _nodeOptions;
    private readonly RouterRuntimeOptions _runtimeOptions;
    private readonly PeerEndpointPolicy _peerEndpointPolicy;
    private readonly IClock _clock;

    public HttpOnionPeerClient(
        HttpClient httpClient,
        RouterNodeOptions nodeOptions,
        RouterRuntimeOptions runtimeOptions,
        PeerEndpointPolicy peerEndpointPolicy,
        IClock clock)
    {
        _httpClient = httpClient;
        _nodeOptions = nodeOptions;
        _runtimeOptions = runtimeOptions;
        _peerEndpointPolicy = peerEndpointPolicy;
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
            || !_peerEndpointPolicy.TryValidatePeerEndpoint(recipientRouterId, uri, out endpointError))
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
            message.Options.Set(RecipientRouterIdOption, recipientRouterId.Value);
            message.Options.Set(ExpectedPeerPathOption, PeerEndpointPolicy.OnionPeerPath);
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
    public static SocketsHttpHandler Create(
        PeerEndpointPolicy peerEndpointPolicy,
        ReadOnlyMemory<byte> currentSpkiSha256 = default,
        ReadOnlyMemory<byte> nextSpkiSha256 = default)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) => ConnectAsync(
                context.DnsEndPoint,
                context.InitialRequestMessage,
                peerEndpointPolicy,
                cancellationToken)
        };
        if (!currentSpkiSha256.IsEmpty || !nextSpkiSha256.IsEmpty)
        {
            var current = currentSpkiSha256.ToArray();
            var next = nextSpkiSha256.ToArray();
            if (current.Length != 32
                || next.Length != 32
                || CryptographicOperations.FixedTimeEquals(current, next))
            {
                handler.Dispose();
                throw new ArgumentException("Mailbox replica SPKI pins are invalid.");
            }

            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, _, errors) =>
                {
                    if (errors != SslPolicyErrors.None
                        || certificate is not X509Certificate2 certificate2)
                    {
                        return false;
                    }

                    return MatchesPinnedSpki(certificate2, current, next);
                };
        }

        return handler;
    }

    internal static bool MatchesPinnedSpki(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> currentSpkiSha256,
        ReadOnlySpan<byte> nextSpkiSha256)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if (currentSpkiSha256.Length != 32 || nextSpkiSha256.Length != 32)
        {
            return false;
        }

        var observed = SHA256.HashData(
            certificate.PublicKey.ExportSubjectPublicKeyInfo());
        return CryptographicOperations.FixedTimeEquals(observed, currentSpkiSha256)
            || CryptographicOperations.FixedTimeEquals(observed, nextSpkiSha256);
    }

    private static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endpoint,
        HttpRequestMessage request,
        PeerEndpointPolicy peerEndpointPolicy,
        CancellationToken cancellationToken)
    {
        if (request.RequestUri is null
            || !request.Options.TryGetValue(HttpOnionPeerClient.RecipientRouterIdOption, out var recipientValue)
            || !RouterId.TryParse(recipientValue, out var recipientRouterId)
            || !request.Options.TryGetValue(HttpOnionPeerClient.ExpectedPeerPathOption, out var expectedPath)
            || !peerEndpointPolicy.TryValidatePeerRouteEndpoint(
                recipientRouterId,
                request.RequestUri,
                expectedPath,
                out _))
        {
            throw new HttpRequestException("Onion peer request is missing a permitted endpoint binding.");
        }

        var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken).ConfigureAwait(false);
        var permitted = addresses
            .Where(address => peerEndpointPolicy.IsResolvedAddressAllowed(
                recipientRouterId,
                request.RequestUri,
                expectedPath,
                address))
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
