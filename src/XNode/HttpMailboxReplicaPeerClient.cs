using System.Net.Http.Headers;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Runtime;

namespace XNode;

public sealed class HttpMailboxReplicaPeerClient : IMailboxReplicaPeerClient
{
    private readonly HttpClient _httpClient;
    private readonly RouterRuntimeOptions _runtimeOptions;
    private readonly ReplicatedMailboxOptions _mailboxOptions;

    public HttpMailboxReplicaPeerClient(
        HttpClient httpClient,
        RouterRuntimeOptions runtimeOptions,
        ReplicatedMailboxOptions mailboxOptions)
    {
        _httpClient = httpClient;
        _runtimeOptions = runtimeOptions;
        _mailboxOptions = mailboxOptions;
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
        if (canonicalPrq2.Length < contract.MinimumRequestBytes
            || canonicalPrq2.Length > contract.MaximumRequestBytes
            || !Uri.TryCreate(peer.Endpoint.Trim(), UriKind.Absolute, out var uri)
            || !PeerEndpointPolicy.TryValidateUri(
                uri,
                _runtimeOptions.AllowLoopbackPeerEndpoints,
                _runtimeOptions.AllowPrivatePeerEndpoints,
                out _)
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
        using var response = await _httpClient.SendAsync(
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if ((int)response.StatusCode != contract.SuccessStatusCode
            || response.Content.Headers.ContentLength != contract.MaximumResponseBytes
            || !string.Equals(
                response.Content.Headers.ContentType?.ToString(),
                contract.ResponseContentType,
                StringComparison.Ordinal)
            || response.Content.Headers.ContentEncoding.Count != 0)
        {
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
}
