using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.DeepExtension.ManagedIngress;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core;

namespace XNode;

public enum PrivacyForwardFailure
{
    None = 0,
    RejectedBeforeForward,
    OutcomeUnknown
}

public sealed record PrivacyForwardResult(
    ReadOnlyMemory<byte> OpaqueReply,
    PrivacyForwardFailure Failure)
{
    public static PrivacyForwardResult Rejected { get; } =
        new(ReadOnlyMemory<byte>.Empty, PrivacyForwardFailure.RejectedBeforeForward);

    public static PrivacyForwardResult Unknown { get; } =
        new(ReadOnlyMemory<byte>.Empty, PrivacyForwardFailure.OutcomeUnknown);
}

public interface IPrivacyPeerClient
{
    Task<PrivacyForwardResult> ForwardAsync(
        VerifiedOnionNextHopTransport nextHop,
        VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> innerFrame,
        CancellationToken cancellationToken);
}

public sealed class HttpPrivacyPeerClient : IPrivacyPeerClient, IDisposable
{
    private readonly RouterNodeOptions _node;
    private readonly IClock _clock;
    private readonly ILogger<HttpPrivacyPeerClient>? _logger;
    private readonly PrivacyPeerHttpPool connections = new();

    public void Dispose() => connections.Dispose();

    public HttpPrivacyPeerClient(
        RouterNodeOptions node,
        IClock clock,
        ILogger<HttpPrivacyPeerClient>? logger = null)
    {
        _node = node;
        _clock = clock;
        _logger = logger;
    }

    public async Task<PrivacyForwardResult> ForwardAsync(
        VerifiedOnionNextHopTransport nextHop,
        VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> innerFrame,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nextHop);
        if (nextHop.Transport != OnionNextHopTransport.TcpTls)
        {
            _logger?.LogWarning(
                "Privacy peer transport rejected before forward: transport={Transport}.",
                nextHop.Transport);
            return PrivacyForwardResult.Rejected;
        }

        try
        {
            _ = ManagedIngressH2Contract.ValidateOpaqueFrame(innerFrame.Span);
            var recipient = RouterId.FromBytes(nextHop.NodeId.Span);
            var authentication = PrivacyPeerAuthenticator.Sign(
                network,
                _node.GetRouterId(),
                recipient,
                _node.GetEd25519PrivateKey(),
                innerFrame.Span,
                _clock.UtcNow);
            using var content = new ByteArrayContent(innerFrame.ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(
                ManagedIngressH2Contract.OpaqueMediaType);
            using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint(nextHop))
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = content
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                ManagedIngressH2Contract.OpaqueMediaType));
            request.Headers.TryAddWithoutValidation(
                PrivacyPeerAuthenticator.SenderHeader,
                authentication.SenderRouterId);
            request.Headers.TryAddWithoutValidation(
                PrivacyPeerAuthenticator.RecipientHeader,
                authentication.RecipientRouterId);
            request.Headers.TryAddWithoutValidation(
                PrivacyPeerAuthenticator.TimestampHeader,
                authentication.TimestampUnixMilliseconds.ToString(
                    System.Globalization.CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation(
                PrivacyPeerAuthenticator.NonceHeader,
                authentication.Nonce);
            request.Headers.TryAddWithoutValidation(
                PrivacyPeerAuthenticator.SignatureHeader,
                authentication.Signature);

            // Reuse a socket only inside the same verified network object and
            // exact selected hop. This never reuses a frame, nonce, signature,
            // replay decision or operation authority, nor retries a dispatch.
            network.EnsureCurrent();
            var binding = string.Join(':', Convert.ToHexString(nextHop.NetworkId.Span),
                Convert.ToHexString(nextHop.NodeId.Span), Convert.ToHexString(nextHop.OriginId.Span),
                (int)nextHop.Transport, (int)nextHop.AddressFamily,
                Convert.ToHexString(nextHop.Address.Span), nextHop.Port,
                Convert.ToHexString(nextHop.SpkiSha256.Span));
            using var connection = connections.Borrow(network, binding, certificateUntil =>
                new HttpClient(CreatePinnedHandler(nextHop, certificateUntil), disposeHandler: true));
            using var response = await connection.Client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            if (!connection.CertificateCurrent) return PrivacyForwardResult.Unknown;
            if (response.Version != HttpVersion.Version20)
            {
                _logger?.LogWarning(
                    "Privacy peer response rejected: version={HttpVersion}, status={StatusCode}.",
                    response.Version,
                    (int)response.StatusCode);
                return PrivacyForwardResult.Unknown;
            }

            var length = response.Content.Headers.ContentLength;
            if (length is null or < 0 or > ManagedIngressLimits.MaximumOpaqueFrameBytes)
            {
                _logger?.LogWarning(
                    "Privacy peer response rejected: status={StatusCode}, length={ContentLength}, contentType={ContentType}.",
                    (int)response.StatusCode,
                    length,
                    response.Content.Headers.ContentType?.MediaType ?? "missing");
                return PrivacyForwardResult.Unknown;
            }

            var body = await ReadExactlyBoundedAsync(
                    response.Content,
                    checked((int)length.Value),
                    cancellationToken)
                .ConfigureAwait(false);
            if (!connection.CertificateCurrent) return PrivacyForwardResult.Unknown;
            if ((int)response.StatusCode == StatusCodes.Status200OK
                && string.Equals(
                    response.Content.Headers.ContentType?.ToString(),
                    ManagedIngressH2Contract.OpaqueMediaType,
                    StringComparison.Ordinal)
                && body.Length >= ManagedIngressLimits.MinimumOpaqueFrameBytes)
            {
                return new PrivacyForwardResult(body, PrivacyForwardFailure.None);
            }

            var metadata = new ManagedIngressResponseMetadata(
                (int)response.StatusCode,
                response.Version,
                response.Content.Headers.ContentType?.ToString(),
                response.Content.Headers.ContentEncoding.SingleOrDefault(),
                body.Length,
                ResponseHeaders(response));
            var error = ManagedIngressH2Contract.ClassifyErrorResponse(metadata, body);
            _logger?.LogWarning(
                "Privacy peer returned a bounded non-success response: status={StatusCode}, length={ContentLength}, classification={Classification}.",
                (int)response.StatusCode,
                body.Length,
                error.Result);
            return error.Result == ManagedIngressTransportResult.RejectedBeforeForward
                ? PrivacyForwardResult.Rejected
                : PrivacyForwardResult.Unknown;
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or SocketException
                or OperationCanceledException or ManagedIngressContractException
                or InvalidDataException)
        {
            _logger?.LogWarning(
                "Privacy peer transport failed before an exact response: failure={FailureType}, httpError={HttpRequestError}, inner={InnerFailureType}.",
                exception.GetType().Name,
                SafeHttpRequestError(exception),
                exception.InnerException?.GetType().Name ?? "none");
            return PrivacyForwardResult.Unknown;
        }
    }

    internal static string SafeHttpRequestError(Exception exception) =>
        exception is HttpRequestException http
            ? http.HttpRequestError.ToString()
            : "none";

    internal static SocketsHttpHandler CreatePinnedHandler(
        VerifiedOnionNextHopTransport nextHop, Action<DateTime, DateTime>? certificateValidity = null)
    {
        ArgumentNullException.ThrowIfNull(nextHop);
        var expectedAddress = Address(nextHop);
        var expectedPort = nextHop.Port;
        var expectedSpki = nextHop.SpkiSha256.ToArray();
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = PrivacyPeerHttpPool.Lifetime,
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
            ConnectCallback = (context, cancellationToken) => ConnectAsync(
                context.DnsEndPoint,
                expectedAddress,
                expectedPort,
                cancellationToken)
        };
        handler.SslOptions.AllowTlsResume = false;
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
        {
            var valid = ValidatePinnedCertificate(certificate, errors, expectedSpki);
            if (valid) certificateValidity?.Invoke(((X509Certificate2)certificate!).NotBefore.ToUniversalTime(),
                ((X509Certificate2)certificate).NotAfter.ToUniversalTime());
            return valid;
        };
        return handler;
    }

    internal static SocketsHttpHandler CreatePinnedHandler(PrivacyPeer peer)
    {
        ArgumentNullException.ThrowIfNull(peer);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) =>
                ConnectConfiguredPeerAsync(
                    context.DnsEndPoint,
                    peer,
                    cancellationToken)
        };
        if (peer.Endpoint.Scheme == Uri.UriSchemeHttps)
        {
            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, _, errors) =>
                    ValidatePinnedCertificate(
                        certificate,
                        errors,
                        peer.CurrentSpkiSha256,
                        peer.NextSpkiSha256);
        }

        return handler;
    }

    internal static bool ValidatePinnedCertificate(
        X509Certificate? certificate,
        SslPolicyErrors errors,
        ReadOnlySpan<byte> currentSpkiSha256,
        ReadOnlySpan<byte> nextSpkiSha256 = default)
    {
        if (certificate is not X509Certificate2 certificate2 ||
            (errors & (SslPolicyErrors.RemoteCertificateNameMismatch |
                SslPolicyErrors.RemoteCertificateNotAvailable)) != 0 ||
            (errors != SslPolicyErrors.None &&
                errors != SslPolicyErrors.RemoteCertificateChainErrors))
        {
            return false;
        }

        var now = DateTime.UtcNow;
        if (certificate2.NotBefore.ToUniversalTime() > now ||
            certificate2.NotAfter.ToUniversalTime() <= now)
        {
            return false;
        }

        var observed = SHA256.HashData(
            certificate2.PublicKey.ExportSubjectPublicKeyInfo());
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                       observed,
                       currentSpkiSha256) ||
                   (!nextSpkiSha256.IsEmpty &&
                    CryptographicOperations.FixedTimeEquals(
                        observed,
                        nextSpkiSha256));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(observed);
        }
    }

    private static Uri Endpoint(VerifiedOnionNextHopTransport nextHop)
    {
        var address = Address(nextHop);
        return new UriBuilder(
            Uri.UriSchemeHttps,
            address.ToString(),
            nextHop.Port,
            PrivacyRoutingOptions.PeerFramePath).Uri;
    }

    private static IPAddress Address(VerifiedOnionNextHopTransport nextHop)
    {
        var bytes = nextHop.Address.ToArray();
        try
        {
            return nextHop.AddressFamily switch
            {
                OnionNextHopAddressFamily.IPv4 => new IPAddress(bytes.AsSpan(0, 4)),
                OnionNextHopAddressFamily.IPv6 => new IPAddress(bytes),
                _ => throw new InvalidDataException(
                    "The verified ONION next-hop address family is unsupported.")
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endpoint,
        IPAddress expectedAddress,
        ushort expectedPort,
        CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(endpoint.Host, out var requestedAddress)
            || !requestedAddress.Equals(expectedAddress)
            || endpoint.Port != expectedPort)
        {
            throw new HttpRequestException("Verified privacy peer endpoint binding changed.");
        }

        var socket = new Socket(
            expectedAddress.AddressFamily,
            SocketType.Stream,
            ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(
                    new IPEndPoint(expectedAddress, expectedPort),
                    cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch (Exception exception) when (
            exception is SocketException or OperationCanceledException)
        {
            socket.Dispose();
            throw new HttpRequestException(
                "Unable to connect to verified privacy peer.", exception);
        }
    }

    private static async ValueTask<Stream> ConnectConfiguredPeerAsync(
        DnsEndPoint endpoint,
        PrivacyPeer peer,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(
                endpoint.Host,
                peer.Endpoint.Host,
                StringComparison.OrdinalIgnoreCase)
            || endpoint.Port != peer.Endpoint.Port)
        {
            throw new HttpRequestException("Privacy peer endpoint binding changed.");
        }

        var addresses = await Dns.GetHostAddressesAsync(
                endpoint.Host,
                cancellationToken)
            .ConfigureAwait(false);
        var permitted = addresses.Where(peer.AllowsResolvedAddress).ToArray();
        if (permitted.Length == 0)
        {
            throw new HttpRequestException(
                "Privacy peer resolved only to blocked addresses.");
        }

        Exception? last = null;
        foreach (var address in permitted)
        {
            var socket = new Socket(
                address.AddressFamily,
                SocketType.Stream,
                ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(
                        new IPEndPoint(address, endpoint.Port),
                        cancellationToken)
                    .ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception exception) when (
                exception is SocketException or OperationCanceledException)
            {
                socket.Dispose();
                last = exception;
            }
        }

        throw new HttpRequestException(
            "Unable to connect to pinned privacy peer.",
            last);
    }

    private static IReadOnlyList<ManagedIngressHeader> ResponseHeaders(
        HttpResponseMessage response)
    {
        var headers = new List<ManagedIngressHeader>();
        if (response.Headers.CacheControl is not null)
        {
            headers.Add(new ManagedIngressHeader(
                "cache-control",
                response.Headers.CacheControl.ToString()));
        }

        if (response.Headers.RetryAfter is not null)
        {
            headers.Add(new ManagedIngressHeader(
                "retry-after",
                response.Headers.RetryAfter.Delta?.TotalSeconds.ToString(
                    System.Globalization.CultureInfo.InvariantCulture) ?? ""));
        }

        return headers;
    }

    internal static async Task<byte[]> ReadExactlyBoundedAsync(
        HttpContent content,
        int length,
        CancellationToken cancellationToken)
    {
        var body = new byte[length];
        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        await stream.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
        var extra = new byte[1];
        if (await stream.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0)
        {
            throw new InvalidDataException("Privacy peer response exceeded Content-Length.");
        }

        return body;
    }
}
