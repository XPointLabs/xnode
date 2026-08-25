using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Deep.Protocol.DeepExtension.ManagedIngress;
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
        PrivacyPeer peer,
        ReadOnlyMemory<byte> innerFrame,
        CancellationToken cancellationToken);
}

public sealed class HttpPrivacyPeerClient : IPrivacyPeerClient
{
    private readonly RouterNodeOptions _node;
    private readonly IClock _clock;

    public HttpPrivacyPeerClient(RouterNodeOptions node, IClock clock)
    {
        _node = node;
        _clock = clock;
    }

    public async Task<PrivacyForwardResult> ForwardAsync(
        PrivacyPeer peer,
        ReadOnlyMemory<byte> innerFrame,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(peer);
        try
        {
            _ = ManagedIngressH2Contract.ValidateOpaqueFrame(innerFrame.Span);
            var authentication = PrivacyPeerAuthenticator.Sign(
                _node.GetRouterId(),
                peer.RouterId,
                _node.GetEd25519PrivateKey(),
                innerFrame.Span,
                _clock.UtcNow);
            using var content = new ByteArrayContent(innerFrame.ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(
                ManagedIngressH2Contract.OpaqueMediaType);
            using var request = new HttpRequestMessage(HttpMethod.Post, peer.Endpoint)
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

            using var handler = CreatePinnedHandler(peer);
            using var client = new HttpClient(handler, disposeHandler: false);
            using var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            if (response.Version != HttpVersion.Version20)
            {
                return PrivacyForwardResult.Unknown;
            }

            var length = response.Content.Headers.ContentLength;
            if (length is null or < 0 or > ManagedIngressLimits.MaximumOpaqueFrameBytes)
            {
                return PrivacyForwardResult.Unknown;
            }

            var body = await ReadExactlyBoundedAsync(
                    response.Content,
                    checked((int)length.Value),
                    cancellationToken)
                .ConfigureAwait(false);
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
            return error.Result == ManagedIngressTransportResult.RejectedBeforeForward
                ? PrivacyForwardResult.Rejected
                : PrivacyForwardResult.Unknown;
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException or SocketException
                or OperationCanceledException or ManagedIngressContractException
                or InvalidDataException)
        {
            return PrivacyForwardResult.Unknown;
        }
    }

    private static SocketsHttpHandler CreatePinnedHandler(PrivacyPeer peer)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ConnectCallback = (context, cancellationToken) => ConnectAsync(
                context.DnsEndPoint,
                peer,
                cancellationToken)
        };
        if (peer.Endpoint.Scheme == Uri.UriSchemeHttps)
        {
            handler.SslOptions.RemoteCertificateValidationCallback =
                (_, certificate, _, errors) =>
                {
                    if (errors != SslPolicyErrors.None
                        || certificate is not X509Certificate2 certificate2)
                    {
                        return false;
                    }

                    var observed = SHA256.HashData(
                        certificate2.PublicKey.ExportSubjectPublicKeyInfo());
                    return CryptographicOperations.FixedTimeEquals(
                               observed,
                               peer.CurrentSpkiSha256)
                           || CryptographicOperations.FixedTimeEquals(
                               observed,
                               peer.NextSpkiSha256);
                };
        }
        return handler;
    }

    private static async ValueTask<Stream> ConnectAsync(
        DnsEndPoint endpoint,
        PrivacyPeer peer,
        CancellationToken cancellationToken)
    {
        if (!string.Equals(endpoint.Host, peer.Endpoint.Host, StringComparison.OrdinalIgnoreCase)
            || endpoint.Port != peer.Endpoint.Port)
        {
            throw new HttpRequestException("Privacy peer endpoint binding changed.");
        }

        var addresses = await Dns.GetHostAddressesAsync(
                endpoint.Host,
                cancellationToken)
            .ConfigureAwait(false);
        var permitted = addresses
            .Where(address => PeerNetworkAddressGuard.IsPubliclyRoutable(address)
                || peer.AllowPrivateResolvedAddresses
                    && PeerNetworkAddressGuard.IsPrivate(address))
            .ToArray();
        if (permitted.Length == 0)
        {
            throw new HttpRequestException(
                "Privacy peer resolved only to blocked addresses.");
        }

        Exception? last = null;
        foreach (var address in permitted)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
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

        throw new HttpRequestException("Unable to connect to pinned privacy peer.", last);
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

    private static async Task<byte[]> ReadExactlyBoundedAsync(
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
