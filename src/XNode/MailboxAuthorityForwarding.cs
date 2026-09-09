using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core;

namespace XNode;

public sealed class MailboxAuthorityForwardingOptions
{
    public bool Enabled { get; set; }
    public string AuthorityRouterId { get; set; } = "";
    public string[] AllowedExitRouterIds { get; set; } = [];

    public MailboxAuthorityForwardingConfiguration Validate(
        MailboxClientActivationPlan client,
        PrivacyRoutingConfiguration privacy,
        RouterNodeOptions node,
        bool useProductionAuthority = false)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(privacy);
        ArgumentNullException.ThrowIfNull(node);

        var localRouterId = node.GetRouterId();
        PrivacyPeer? authority = null;
        RouterId? configuredAuthorityRouterId = null;
        if (Enabled)
        {
            if (client.RoutesMapped
                || !privacy.Enabled
                || !RouterId.TryParse(AuthorityRouterId, out var authorityRouterId)
                || !string.Equals(
                    AuthorityRouterId,
                    authorityRouterId.Value,
                    StringComparison.Ordinal)
                || authorityRouterId == localRouterId
                || !useProductionAuthority
                    && !privacy.Peers.TryGetValue(authorityRouterId, out authority))
            {
                throw new InvalidOperationException(
                    "MailboxAuthorityForwarding requires a distinct pinned authority and no local client adapter.");
            }
            configuredAuthorityRouterId = authorityRouterId;
        }
        else if (!string.IsNullOrWhiteSpace(AuthorityRouterId))
        {
            throw new InvalidOperationException(
                "MailboxAuthorityForwarding authority must be empty when forwarding is disabled.");
        }

        var allowed = new HashSet<RouterId>();
        foreach (var value in AllowedExitRouterIds)
        {
            if (!RouterId.TryParse(value, out var routerId)
                || !string.Equals(value, routerId.Value, StringComparison.Ordinal)
                || routerId == localRouterId
                || !privacy.Peers.ContainsKey(routerId)
                || !allowed.Add(routerId))
            {
                throw new InvalidOperationException(
                    "MailboxAuthorityForwarding allowed exits must be unique pinned privacy peers.");
            }
        }

        if (allowed.Count != 0 && (!client.RoutesMapped || Enabled))
        {
            throw new InvalidOperationException(
                "MailboxAuthorityForwarding allowed exits require the local authoritative client adapter.");
        }

        return new MailboxAuthorityForwardingConfiguration(
            configuredAuthorityRouterId,
            authority,
            useProductionAuthority && Enabled,
            allowed);
    }
}

public sealed class MailboxAuthorityForwardingConfiguration
{
    public MailboxAuthorityForwardingConfiguration(
        PrivacyPeer? authority,
        IReadOnlySet<RouterId> allowedExitRouterIds)
        : this(
            authority?.RouterId,
            authority,
            false,
            allowedExitRouterIds)
    {
    }

    public MailboxAuthorityForwardingConfiguration(
        RouterId? authorityRouterId,
        PrivacyPeer? developmentAuthority,
        bool useProductionAuthority,
        IReadOnlySet<RouterId> allowedExitRouterIds)
    {
        AuthorityRouterId = authorityRouterId;
        DevelopmentAuthority = developmentAuthority;
        UseProductionAuthority = useProductionAuthority;
        AllowedExitRouterIds = new HashSet<RouterId>(allowedExitRouterIds);
    }

    public RouterId? AuthorityRouterId { get; }
    public PrivacyPeer? DevelopmentAuthority { get; }
    public bool UseProductionAuthority { get; }
    public IReadOnlySet<RouterId> AllowedExitRouterIds { get; }
    public bool ForwardingEnabled => AuthorityRouterId is not null;
    public bool AuthorityIngressEnabled => AllowedExitRouterIds.Count != 0;
    public string Role => ForwardingEnabled
        ? "forwarding-exit"
        : AuthorityIngressEnabled
            ? "authority"
            : "disabled";
}

public static class MailboxAuthorityForwardingHttpContract
{
    public const string StoreRoute = "/api/peer/mailbox-authority/v1/store";
    public const string RetrieveRoute = "/api/peer/mailbox-authority/v1/retrieve";
    public const string AcknowledgeRoute = "/api/peer/mailbox-authority/v1/acknowledge";

    public static string Route(OnionOperation operation) => operation switch
    {
        OnionOperation.Store => StoreRoute,
        OnionOperation.Retrieve => RetrieveRoute,
        OnionOperation.Acknowledge => AcknowledgeRoute,
        _ => throw new ArgumentOutOfRangeException(nameof(operation))
    };

    public static bool TryOperation(PathString path, out OnionOperation operation)
    {
        if (path.Equals(StoreRoute))
        {
            operation = OnionOperation.Store;
            return true;
        }
        if (path.Equals(RetrieveRoute))
        {
            operation = OnionOperation.Retrieve;
            return true;
        }
        if (path.Equals(AcknowledgeRoute))
        {
            operation = OnionOperation.Acknowledge;
            return true;
        }

        operation = default;
        return false;
    }

    public static MailboxHttpEndpointContract Contract(
        OnionOperation operation) => operation switch
        {
            OnionOperation.Store => MailboxWireHttpContract.Store,
            OnionOperation.Retrieve => MailboxWireHttpContract.Retrieve,
            OnionOperation.Acknowledge => MailboxWireHttpContract.Acknowledge,
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
}

public interface IMailboxAuthorityForwardingClient
{
    Task<NativeMailboxDispatchResult> ForwardAsync(
        OnionOperation operation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken);
}

public sealed class MailboxAuthorityForwardingClient : IMailboxAuthorityForwardingClient
{
    private readonly MailboxAuthorityForwardingConfiguration _configuration;
    private readonly RouterNodeOptions _node;
    private readonly IClock _clock;
    private readonly ProductionMailboxAuthorityProvider _productionAuthority;
    private readonly ILogger<MailboxAuthorityForwardingClient>? _logger;

    public MailboxAuthorityForwardingClient(
        MailboxAuthorityForwardingConfiguration configuration,
        RouterNodeOptions node,
        IClock clock,
        ProductionMailboxAuthorityProvider productionAuthority,
        ILogger<MailboxAuthorityForwardingClient>? logger = null)
    {
        _configuration = configuration;
        _node = node;
        _clock = clock;
        _productionAuthority = productionAuthority;
        _logger = logger;
    }

    public async Task<NativeMailboxDispatchResult> ForwardAsync(
        OnionOperation operation,
        ReadOnlyMemory<byte> canonicalMau2,
        CancellationToken cancellationToken)
    {
        var authority = ResolveAuthority();
        if (authority is null)
        {
            return NativeMailboxDispatchResult.RejectedBeforeForward();
        }

        var contract = MailboxAuthorityForwardingHttpContract.Contract(operation);
        try
        {
            var authentication = MailboxAuthorityForwardingAuthenticator.Sign(
                _node.GetRouterId(),
                authority.RouterId,
                _node.GetEd25519PrivateKey(),
                operation,
                canonicalMau2.Span,
                _clock.UtcNow);
            using var content = new ByteArrayContent(canonicalMau2.ToArray());
            content.Headers.ContentType = new MediaTypeHeaderValue(contract.RequestContentType);
            using var request = new HttpRequestMessage(
                HttpMethod.Post,
                new Uri(authority.Endpoint, MailboxAuthorityForwardingHttpContract.Route(operation)))
            {
                Version = HttpVersion.Version20,
                VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                Content = content
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                contract.ResponseContentType));
            AddAuthentication(request, authentication);

            using var handler = HttpPrivacyPeerClient.CreatePinnedHandler(authority);
            using var client = new HttpClient(handler, disposeHandler: false);
            using var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
            if (response.Version != HttpVersion.Version20
                || response.Content.Headers.ContentEncoding.Count != 0)
            {
                return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
            }

            var status = (int)response.StatusCode;
            var length = response.Content.Headers.ContentLength;
            if (status == StatusCodes.Status200OK)
            {
                if (length is null
                    || length < contract.MinimumResponseBytes
                    || length > contract.MaximumResponseBytes
                    || !string.Equals(
                        response.Content.Headers.ContentType?.ToString(),
                        contract.ResponseContentType,
                        StringComparison.Ordinal))
                {
                    return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
                }

                var body = await HttpPrivacyPeerClient.ReadExactlyBoundedAsync(
                        response.Content,
                        checked((int)length.Value),
                        cancellationToken)
                    .ConfigureAwait(false);
                return new NativeMailboxDispatchResult(status, body);
            }

            if (length != 0
                || status is StatusCodes.Status503ServiceUnavailable
                    or StatusCodes.Status504GatewayTimeout
                || !IsCanonicalFailure(status))
            {
                return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
            }

            return new NativeMailboxDispatchResult(status, ReadOnlyMemory<byte>.Empty);
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException
                or OperationCanceledException or InvalidDataException
                or ArgumentException or InvalidOperationException)
        {
            _logger?.LogWarning(
                "Authoritative mailbox forwarding ended without an exact response: failure={FailureType}, httpError={HttpRequestError}, inner={InnerFailureType}.",
                exception.GetType().Name,
                HttpPrivacyPeerClient.SafeHttpRequestError(exception),
                exception.InnerException?.GetType().Name ?? "none");
            return NativeMailboxDispatchResult.OutcomeUnknownAfterForward();
        }
    }

    private PrivacyPeer? ResolveAuthority()
    {
        if (_configuration.DevelopmentAuthority is not null)
        {
            return _configuration.DevelopmentAuthority;
        }

        if (!_configuration.UseProductionAuthority
            || _configuration.AuthorityRouterId is not { } routerId
            || _productionAuthority.NodeIngress is not { } ingress
            || ingress.Endpoint.Scheme != Uri.UriSchemeHttps
            || ingress.CurrentSpkiSha256.Length != 32
            || ingress.NextSpkiSha256.Length != 32)
        {
            return null;
        }

        return new PrivacyPeer(
            routerId,
            ingress.Endpoint,
            ingress.CurrentSpkiSha256.Span,
            ingress.NextSpkiSha256.Span,
            allowPrivateResolvedAddresses: false);
    }

    private static void AddAuthentication(
        HttpRequestMessage request,
        MailboxAuthorityForwardingAuthenticationHeaders authentication)
    {
        request.Headers.TryAddWithoutValidation(
            MailboxAuthorityForwardingAuthenticator.SenderHeader,
            authentication.SenderRouterId);
        request.Headers.TryAddWithoutValidation(
            MailboxAuthorityForwardingAuthenticator.RecipientHeader,
            authentication.RecipientRouterId);
        request.Headers.TryAddWithoutValidation(
            MailboxAuthorityForwardingAuthenticator.TimestampHeader,
            authentication.TimestampUnixMilliseconds.ToString(
                CultureInfo.InvariantCulture));
        request.Headers.TryAddWithoutValidation(
            MailboxAuthorityForwardingAuthenticator.NonceHeader,
            authentication.Nonce);
        request.Headers.TryAddWithoutValidation(
            MailboxAuthorityForwardingAuthenticator.SignatureHeader,
            authentication.Signature);
    }

    private static bool IsCanonicalFailure(int statusCode) => statusCode is
        StatusCodes.Status400BadRequest or
        StatusCodes.Status401Unauthorized or
        StatusCodes.Status403Forbidden or
        StatusCodes.Status409Conflict or
        StatusCodes.Status413PayloadTooLarge or
        StatusCodes.Status429TooManyRequests or
        StatusCodes.Status503ServiceUnavailable or
        StatusCodes.Status504GatewayTimeout;

}

public sealed class RoutedNativeMailboxExitDispatcher : INativeMailboxExitDispatcher
{
    private readonly MailboxAuthorityForwardingConfiguration _configuration;
    private readonly ILocalNativeMailboxExitDispatcher _local;
    private readonly IMailboxAuthorityForwardingClient _forwarding;

    public RoutedNativeMailboxExitDispatcher(
        MailboxAuthorityForwardingConfiguration configuration,
        ILocalNativeMailboxExitDispatcher local,
        IMailboxAuthorityForwardingClient forwarding)
    {
        _configuration = configuration;
        _local = local;
        _forwarding = forwarding;
    }

    public Task<NativeMailboxDispatchResult> DispatchAsync(
        VerifiedCanonicalOnionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var privacyOperation = request.Operation;
        var canonicalMau2 = request.CanonicalBytes;
        return
        _configuration.ForwardingEnabled
            ? _forwarding.ForwardAsync(
                privacyOperation,
                canonicalMau2,
                cancellationToken)
            : _local.DispatchAsync(
                privacyOperation,
                canonicalMau2,
                cancellationToken);
    }
}
