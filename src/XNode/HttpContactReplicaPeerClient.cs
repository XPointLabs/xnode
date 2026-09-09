using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using XNode.Core;

namespace XNode;

internal static class ContactReplicaHttpContract
{
    internal const string Route = "/api/peer/contact-replica/v1/execute";
    internal const string MediaType = "application/vnd.deep.contact-replica-v1";
}

internal sealed class HttpContactReplicaPeerClient : IContactReplicaPeerClient
{
    private readonly RouterNodeOptions node;
    private readonly PrivacyRoutingConfiguration privacy;
    private readonly ContactServicePersistenceOptions options;
    private readonly IClock clock;
    private readonly Func<PrivacyPeer, HttpMessageHandler> handlerFactory;
    private readonly ILogger<HttpContactReplicaPeerClient>? logger;

    public HttpContactReplicaPeerClient(
        RouterNodeOptions node,
        PrivacyRoutingConfiguration privacy,
        ContactServicePersistenceOptions options,
        IClock clock,
        ILogger<HttpContactReplicaPeerClient>? logger = null)
        : this(
            node,
            privacy,
            options,
            clock,
            static peer => HttpPrivacyPeerClient.CreatePinnedHandler(peer),
            logger)
    {
    }

    internal HttpContactReplicaPeerClient(
        RouterNodeOptions node,
        PrivacyRoutingConfiguration privacy,
        ContactServicePersistenceOptions options,
        IClock clock,
        Func<PrivacyPeer, HttpMessageHandler> handlerFactory,
        ILogger<HttpContactReplicaPeerClient>? logger = null)
    {
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        this.privacy = privacy ?? throw new ArgumentNullException(nameof(privacy));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        this.handlerFactory = handlerFactory ?? throw new ArgumentNullException(nameof(handlerFactory));
        this.logger = logger;
    }

    public async ValueTask<ContactReplicaRpcResponse> SendAsync(
        ContactReplicaRpcCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var local = node.GetRouterId();
        command.Placement.EnsureUsable(
            checked((ulong)clock.UtcNow.ToUnixTimeSeconds()));
        var remoteBytes = command.Placement.OtherReplica(local.ToBytes());
        var remote = RouterId.FromBytes(remoteBytes);
        if (!privacy.Enabled
            || !privacy.Peers.TryGetValue(remote, out var peer)
            || peer.RouterId != remote
            || peer.Endpoint.Scheme != Uri.UriSchemeHttps)
        {
            throw new IOException(
                "The exact NETCODEC-selected contact replica has no authenticated HTTPS peer binding.");
        }

        var body = ContactReplicaWireCodec.Encode(command);
        var authentication = ContactReplicaPeerAuthenticator.SignRequest(
            local,
            remote,
            node.GetEd25519PrivateKey(),
            command.CorrelationId.Span,
            body,
            clock.UtcNow);
        using var content = new ByteArrayContent(body);
        content.Headers.ContentType = new MediaTypeHeaderValue(ContactReplicaHttpContract.MediaType);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(peer.Endpoint, ContactReplicaHttpContract.Route))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
            Content = content
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(ContactReplicaHttpContract.MediaType));
        AddHeaders(request, authentication);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(options.ReplicaTimeout);
        try
        {
            using var handler = handlerFactory(peer);
            using var client = new HttpClient(handler, disposeHandler: false);
            using var response = await client.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            if (response.Version != HttpVersion.Version20
                || (int)response.StatusCode != StatusCodes.Status200OK
                || response.Content.Headers.ContentLength is not long length
                || length is < 76 or > ContactReplicaWireCodec.MaximumResponseBytes
                || !string.Equals(
                    response.Content.Headers.ContentType?.ToString(),
                    ContactReplicaHttpContract.MediaType,
                    StringComparison.Ordinal)
                || response.Content.Headers.ContentEncoding.Count != 0)
            {
                throw new IOException("The contact replica response envelope is not exact.");
            }

            var exact = await HttpPrivacyPeerClient.ReadExactlyBoundedAsync(
                response.Content,
                checked((int)length),
                timeout.Token).ConfigureAwait(false);
            var decoded = ContactReplicaWireCodec.DecodeResponse(exact);
            var headers = ReadHeaders(response);
            if (!ContactReplicaPeerAuthenticator.VerifyResponse(
                    headers,
                    local,
                    remote,
                    command.CorrelationId.Span,
                    exact,
                    clock.UtcNow)
                || decoded.Operation != command.Operation
                || !CryptographicOperations.FixedTimeEquals(
                    decoded.CorrelationId.Span,
                    command.CorrelationId.Span)
                || !CryptographicOperations.FixedTimeEquals(decoded.ReplicaId.Span, remoteBytes))
            {
                throw new IOException("The contact replica response peer or correlation binding is invalid.");
            }
            return decoded;
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new IOException("The contact replica transport deadline elapsed; outcome is unknown.", exception);
        }
        catch (Exception exception) when (exception is HttpRequestException
            or InvalidDataException
            or CryptographicException)
        {
            logger?.LogWarning(
                "Contact replica transport ended without an authenticated exact response: failure={FailureType}.",
                exception.GetType().Name);
            throw new IOException("The contact replica outcome is unknown.", exception);
        }
    }

    internal static void AddHeaders(
        HttpRequestMessage request,
        ContactReplicaAuthenticationHeaders headers)
    {
        request.Headers.TryAddWithoutValidation(ContactReplicaPeerAuthenticator.SenderHeader, headers.SenderReplicaId);
        request.Headers.TryAddWithoutValidation(ContactReplicaPeerAuthenticator.RecipientHeader, headers.RecipientReplicaId);
        request.Headers.TryAddWithoutValidation(
            ContactReplicaPeerAuthenticator.TimestampHeader,
            headers.TimestampUnixMilliseconds.ToString(CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(ContactReplicaPeerAuthenticator.NonceHeader, headers.Nonce);
        request.Headers.TryAddWithoutValidation(ContactReplicaPeerAuthenticator.CorrelationHeader, headers.Correlation);
        request.Headers.TryAddWithoutValidation(ContactReplicaPeerAuthenticator.SignatureHeader, headers.Signature);
    }

    internal static ContactReplicaAuthenticationHeaders ReadHeaders(HttpResponseMessage response) => new(
        Single(response, ContactReplicaPeerAuthenticator.SenderHeader),
        Single(response, ContactReplicaPeerAuthenticator.RecipientHeader),
        long.TryParse(
            Single(response, ContactReplicaPeerAuthenticator.TimestampHeader),
            NumberStyles.None,
            CultureInfo.InvariantCulture,
            out var timestamp) ? timestamp : long.MinValue,
        Single(response, ContactReplicaPeerAuthenticator.NonceHeader),
        Single(response, ContactReplicaPeerAuthenticator.CorrelationHeader),
        Single(response, ContactReplicaPeerAuthenticator.SignatureHeader));

    private static string Single(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values)
            ? values.SingleOrDefault() ?? ""
            : "";
}
