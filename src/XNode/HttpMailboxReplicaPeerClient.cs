using System.Net.Http.Json;
using System.Text.Json;
using XNode.Core.Mailbox;
using XNode.Core.Runtime;

namespace XNode;

public sealed class HttpMailboxReplicaPeerClient : IMailboxReplicaPeerClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
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

    public async Task<MailboxWriteReceipt?> PutAsync(
        MailboxReplicaPeer peer,
        SignedMailboxReplicaRequest request,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(peer.Endpoint.Trim(), UriKind.Absolute, out var uri)
            || !PeerEndpointPolicy.TryValidateUri(
                uri,
                _runtimeOptions.AllowLoopbackPeerEndpoints,
                _runtimeOptions.AllowPrivatePeerEndpoints,
                out _)
            || (uri.Scheme != Uri.UriSchemeHttps
                && !_mailboxOptions.AllowInsecureHttpPeerTransport)
            || !string.Equals(uri.AbsolutePath, "/api/peer/mailbox/replica", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(uri.Query))
        {
            throw new HttpRequestException("Invalid mailbox peer endpoint.");
        }

        using var message = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = JsonContent.Create(request, options: JsonOptions)
        };
        using var response = await _httpClient.SendAsync(
            message,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        if (response.Content.Headers.ContentLength is > 0 and var contentLength
            && contentLength > _runtimeOptions.MaxPeerRequestBodyBytes)
        {
            return null;
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using var bounded = new MemoryStream();
        var buffer = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (bounded.Length + read > _runtimeOptions.MaxPeerRequestBodyBytes)
            {
                return null;
            }

            await bounded.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        bounded.Position = 0;
        return await JsonSerializer.DeserializeAsync<MailboxWriteReceipt>(
            bounded,
            JsonOptions,
            cancellationToken).ConfigureAwait(false);
    }
}
