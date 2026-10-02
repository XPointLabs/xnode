using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Rebex.Security.Cryptography;
using XNode.Core;

namespace XNode;

// Private DR48 backend only. Not a client resolver, route selector or public fallback.
internal sealed class HttpContactCoordinationBackendClient
{
    private readonly Uri origin;
    private readonly byte[] network;
    private readonly RouterNodeOptions node;
    private readonly IClock clock;
    private readonly Func<HttpMessageHandler> handlerFactory;

    internal HttpContactCoordinationBackendClient(Uri origin, ReadOnlySpan<byte> network,
        RouterNodeOptions node, IClock clock)
        : this(origin, network, node, clock, CreateHandler) { }

    internal HttpContactCoordinationBackendClient(Uri origin, ReadOnlySpan<byte> network,
        RouterNodeOptions node, IClock clock, Func<HttpMessageHandler> handlerFactory)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (!origin.IsAbsoluteUri || origin.Scheme != Uri.UriSchemeHttps || origin.AbsolutePath != "/" ||
            origin.Query.Length != 0 || origin.Fragment.Length != 0 || origin.UserInfo.Length != 0 ||
            network.Length != 16 || network.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Private coordination requires one HTTPS origin and an exact network.");
        this.origin = new Uri(origin.AbsoluteUri);
        this.network = network.ToArray();
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.handlerFactory = handlerFactory ?? throw new ArgumentNullException(nameof(handlerFactory));
    }

    internal static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        AutomaticDecompression = DecompressionMethods.None,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(30),
        MaxResponseHeadersLength = 16,
        // Platform certificate validation; no certificate callback or trust exemption.
    };

    internal async ValueTask<byte[]> SendAsync(ContactCoordinationTarget target, ReadOnlyMemory<byte> exactRequest,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var limits = target switch
        {
            ContactCoordinationTarget.Route => (ContactRouteAuthorityWireCodec.RequestBytes, ContactRouteAuthorityWireCodec.RequestBytes,
                ContactRouteAuthorityWireCodec.MinimumResponseBytes, ContactRouteAuthorityWireCodec.MaximumResponseBytes,
                "/api/v2/contact-route-authority", ContactRouteAuthorityWireCodec.RequestMediaType, ContactRouteAuthorityWireCodec.ResponseMediaType),
            ContactCoordinationTarget.Publication => (ContactPublicationAuthorityWireCodec.MinimumRequestBytes, ContactPublicationAuthorityWireCodec.MaximumRequestBytes,
                ContactPublicationAuthorityWireCodec.MinimumResponseBytes, ContactPublicationAuthorityWireCodec.MaximumResponseBytes,
                "/api/v2/contact-publication-authority", ContactPublicationAuthorityWireCodec.RequestMediaType, ContactPublicationAuthorityWireCodec.ResponseMediaType),
            _ => throw new ArgumentException("Unknown private coordination target.", nameof(target)),
        };
        if (exactRequest.Length < limits.Item1 || exactRequest.Length > limits.Item2)
            throw new ArgumentException("Private coordination request exceeds its target bound.", nameof(exactRequest));
        var body = exactRequest.ToArray(); // Caller mutation cannot alter either signed or submitted bytes.
        ContactRouteAuthorityWireRequest? route = null;
        ContactPublicationAuthorityWireRequest? publication = null;
        ContactCoordinationPeerHeaders authentication;
        try
        {
            var requestNetwork = target == ContactCoordinationTarget.Route ?
                (route = ContactRouteAuthorityWireCodec.DecodeRequest(body)).NetworkId :
                (publication = ContactPublicationAuthorityWireCodec.DecodeRequest(body)).NetworkId;
            if (!CryptographicOperations.FixedTimeEquals(requestNetwork.Span, network))
                throw new ArgumentException("Private coordination request belongs to another network.");
            var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
            byte[]? input = null;
            try
            {
                var signer = new Ed25519(); signer.FromSeed(seed);
                var publicKey = signer.GetPublicKey();
                if (RouterId.FromBytes(publicKey) != node.GetRouterId())
                    throw new InvalidOperationException("Private coordination signer is not the registered local node.");
                var now = clock.UtcNow.ToUnixTimeMilliseconds();
                var nonce = RandomNumberGenerator.GetBytes(16);
                input = ContactCoordinationPeerAuthentication.GetSigningInput(network, target, publicKey, now, nonce, body);
                authentication = new(Convert.ToHexStringLower(publicKey), now.ToString(CultureInfo.InvariantCulture),
                    Convert.ToHexStringLower(nonce), Convert.ToHexStringLower(signer.SignMessage(input)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                if (input is not null) CryptographicOperations.ZeroMemory(input);
            }
        }
        catch { CryptographicOperations.ZeroMemory(body); throw; }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var attemptToken = timeout.Token;
        var attempt = ExchangeAsync();
        try { return await attempt.WaitAsync(attemptToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { ObserveLateAttempt(attempt); throw new IOException("Private coordination deadline elapsed; outcome is unknown."); }
        catch (OperationCanceledException) { ObserveLateAttempt(attempt); throw; }
        catch (Exception error) when (error is HttpRequestException or InvalidDataException or FormatException or CryptographicException)
        { throw new IOException("Private coordination ended without an exact response; outcome is unknown."); }

        async Task<byte[]> ExchangeAsync()
        {
            try
            {
                using var handler = handlerFactory();
                using var client = new HttpClient(handler, disposeHandler: false) { Timeout = Timeout.InfiniteTimeSpan };
                using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, limits.Item5))
                { Content = new ByteArrayContent(body) };
                message.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(limits.Item6);
                message.Headers.Accept.Add(new(limits.Item7));
                message.Headers.Add(ContactCoordinationPeerAuthentication.NodeHeader, authentication.NodePublicKeyHex);
                message.Headers.Add(ContactCoordinationPeerAuthentication.TimestampHeader, authentication.TimestampUnixMilliseconds);
                message.Headers.Add(ContactCoordinationPeerAuthentication.NonceHeader, authentication.NonceHex);
                message.Headers.Add(ContactCoordinationPeerAuthentication.SignatureHeader, authentication.SignatureHex);
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, attemptToken).ConfigureAwait(false);
                attemptToken.ThrowIfCancellationRequested();
                if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength is not long length ||
                    length < limits.Item3 || length > limits.Item4 || response.Content.Headers.ContentEncoding.Count != 0 ||
                    !string.Equals(response.Content.Headers.ContentType?.ToString(), limits.Item7, StringComparison.Ordinal))
                    throw new IOException("Private coordination returned an unavailable or noncanonical envelope; outcome is unknown.");
                var result = await HttpPrivacyPeerClient.ReadExactlyBoundedAsync(response.Content, checked((int)length), attemptToken).ConfigureAwait(false);
                attemptToken.ThrowIfCancellationRequested();
                if (route is not null) _ = ContactRouteAuthorityWireCodec.DecodeResponse(route, result);
                else _ = ContactPublicationAuthorityWireCodec.DecodeResponse(publication!, result);
                return result;
            }
            finally { CryptographicOperations.ZeroMemory(body); }
        }
    }

    private static void ObserveLateAttempt(Task<byte[]> attempt) =>
        _ = attempt.ContinueWith(completed => { _ = completed.Exception; }, CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously | TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
}
