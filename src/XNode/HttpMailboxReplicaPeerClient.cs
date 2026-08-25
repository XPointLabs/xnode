using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MembershipRoutes;
using XNode.Core.Mailbox;
using XNode.Core.Runtime;

namespace XNode;

public sealed class HttpMailboxReplicaPeerClient : IMailboxReplicaPeerClient
{
    private readonly HttpClient _httpClient;
    private readonly ReplicatedMailboxOptions _mailboxOptions;
    private readonly ILogger<HttpMailboxReplicaPeerClient>? _logger;

    public HttpMailboxReplicaPeerClient(
        HttpClient httpClient,
        ReplicatedMailboxOptions mailboxOptions,
        ILogger<HttpMailboxReplicaPeerClient>? logger = null)
    {
        _httpClient = httpClient;
        _mailboxOptions = mailboxOptions;
        _logger = logger;
    }

    public async Task<ReadOnlyMemory<byte>?> SendAsync(
        MailboxReplicaPeer peer,
        MailboxPeerReplicationOperation operation,
        ReadOnlyMemory<byte> canonicalPrq2,
        CancellationToken cancellationToken)
    {
        var contract = operation == MailboxPeerReplicationOperation.Store
            ? MailboxWireHttpContract.PeerStore
            : operation == MailboxPeerReplicationOperation.Tombstone
                ? MailboxWireHttpContract.PeerTombstone
                : throw new ArgumentOutOfRangeException(nameof(operation));
        MailboxPeerWireRequestV2 decoded;
        MembershipRouteDescriptor recipientDescriptor;
        try
        {
            decoded = MailboxPeerWireV2Codec.Decode(canonicalPrq2.Span);
            recipientDescriptor = MailboxReplicaRouteProofCodec.Decode(
                decoded.RecipientMembershipProof.CanonicalInclusionProof.Span).Descriptor;
        }
        catch (Exception exception) when (
            exception is MailboxPeerReplicationException or MembershipRouteDescriptorException)
        {
            throw new HttpRequestException("Invalid canonical PRQ2 peer request.", exception);
        }

        if (canonicalPrq2.Length < contract.MinimumRequestBytes
            || canonicalPrq2.Length > contract.MaximumRequestBytes
            || decoded.Operation != operation
            || !Fixed(decoded.RecipientRouterId.Span, peer.RouterId.ToBytes())
            || !Fixed(recipientDescriptor.RouterId.Span, decoded.RecipientRouterId.Span)
            || !Fixed(
                recipientDescriptor.Ed25519PublicKey.Span,
                decoded.RecipientMembershipProof.SigningPublicKey.Span)
            || !MailboxPeerEndpointBinding.IsExact(
                recipientDescriptor.RpcEndpoint,
                peer.Endpoint,
                contract.Route)
            || !Uri.TryCreate(peer.Endpoint.Trim(), UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps
                && !_mailboxOptions.AllowInsecureHttpPeerTransport
            || !string.Equals(uri.AbsolutePath, contract.Route, StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Query))
        {
            throw new HttpRequestException("Invalid canonical PRQ2 peer request.");
        }

        using var content = new ByteArrayContent(canonicalPrq2.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue(contract.RequestContentType);
        using var message = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = content
        };
        message.Options.Set(MailboxPeerHttpHandler.ExpectedPeerPathOption, contract.Route);
        using var pinnedClient = peer.CurrentSpkiSha256.IsEmpty
            && peer.NextSpkiSha256.IsEmpty
                ? null
                : new HttpClient(MailboxPeerHttpHandler.Create(
                    _mailboxOptions,
                    peer.CurrentSpkiSha256,
                    peer.NextSpkiSha256), disposeHandler: true);
        var client = pinnedClient ?? _httpClient;
        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(
                    message,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is HttpRequestException or IOException)
        {
            _logger?.LogWarning(
                "Mailbox peer transport failed before an exact response: {FailureType}.",
                exception.GetType().Name);
            throw;
        }
        using var responseScope = response;
        if ((int)response.StatusCode != contract.SuccessStatusCode
            || response.Content.Headers.ContentLength != contract.MaximumResponseBytes
            || !string.Equals(
                response.Content.Headers.ContentType?.ToString(),
                contract.ResponseContentType,
                StringComparison.Ordinal)
            || response.Content.Headers.ContentEncoding.Count != 0)
        {
            _logger?.LogWarning(
                "Mailbox peer response rejected: status={StatusCode}, length={ContentLength}, contentTypePresent={ContentTypePresent}, encodingCount={EncodingCount}.",
                (int)response.StatusCode,
                response.Content.Headers.ContentLength,
                response.Content.Headers.ContentType is not null,
                response.Content.Headers.ContentEncoding.Count);
            return null;
        }

        var result = new byte[contract.MaximumResponseBytes];
        await using var stream =
            await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var offset = 0;
        while (offset < result.Length)
        {
            var read = await stream.ReadAsync(
                result.AsMemory(offset),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            offset += read;
        }

        var extra = new byte[1];
        if (await stream.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0)
        {
            return null;
        }

        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length
        && CryptographicOperations.FixedTimeEquals(left, right);
}
