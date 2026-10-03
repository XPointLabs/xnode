using System.Net;
using System.Net.Http.Headers;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace XNode;

/// <summary>Only descriptor-minted exact origin/SPKI. No configured endpoint,
/// DNS rerank, P04 decode, redirect, proxy or insecure transport fallback.</summary>
internal sealed class CurrentMailboxReplicaPeerClient : ICurrentMailboxReplicaPeerClient
{
    public async ValueTask<ReadOnlyMemory<byte>?> SendAsync(VerifiedOnionNextHopTransport recipient,
        MailboxPeerReplicationOperation operation, ReadOnlyMemory<byte> exactRequest, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        if (recipient.Transport != OnionNextHopTransport.TcpTls) throw new HttpRequestException("Current mailbox transport is unavailable.");
        var contract = operation switch
        {
            MailboxPeerReplicationOperation.Store => MailboxWireHttpContract.PeerStore,
            MailboxPeerReplicationOperation.Tombstone => MailboxWireHttpContract.PeerTombstone,
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };
        var request = MailboxPeerWireV2Codec.Decode(exactRequest.Span);
        if (request.Operation != operation || !request.RecipientRouterId.Span.SequenceEqual(recipient.NodeId.Span))
            throw new HttpRequestException("Current mailbox recipient differs from its admitted transport.");
        var address = recipient.AddressFamily == OnionNextHopAddressFamily.IPv4
            ? new IPAddress(recipient.Address.Span[..4]) : new IPAddress(recipient.Address.Span);
        var origin = new UriBuilder(Uri.UriSchemeHttps, address.ToString(), recipient.Port, contract.Route).Uri;
        using var client = new HttpClient(HttpPrivacyPeerClient.CreatePinnedHandler(recipient), disposeHandler: true)
        { Timeout = Timeout.InfiniteTimeSpan };
        using var content = new ByteArrayContent(exactRequest.ToArray());
        content.Headers.ContentType = new MediaTypeHeaderValue(contract.RequestContentType);
        using var message = new HttpRequestMessage(HttpMethod.Post, origin)
        { Content = content, Version = HttpVersion.Version20, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        if (response.Version != HttpVersion.Version20 || (int)response.StatusCode != contract.SuccessStatusCode ||
            !string.Equals(response.Content.Headers.ContentType?.ToString(), contract.ResponseContentType, StringComparison.Ordinal) ||
            response.Content.Headers.ContentEncoding.Count != 0 || response.Content.Headers.ContentLength != contract.MaximumResponseBytes)
            return null;
        var result = new byte[contract.MaximumResponseBytes];
        await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        try { await stream.ReadExactlyAsync(result, token).ConfigureAwait(false); }
        catch (EndOfStreamException) { return null; }
        if (await stream.ReadAsync(new byte[1], token).ConfigureAwait(false) != 0) return null;
        return result;
    }
}
