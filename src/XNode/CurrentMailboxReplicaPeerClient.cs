using System.Net;
using System.Net.Http.Headers;
using System.Diagnostics;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace XNode;

/// <summary>Only descriptor-minted exact origin/SPKI. No configured endpoint,
/// DNS rerank, P04 decode, redirect, proxy or insecure transport fallback.</summary>
internal sealed class CurrentMailboxReplicaPeerClient(ILogger<CurrentMailboxReplicaPeerClient>? logger = null) : ICurrentMailboxReplicaPeerClient
{
    private long lastDiagnostic;
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
        var request = MailboxPeerWireV2Codec.Decode(operation == MailboxPeerReplicationOperation.Tombstone
            ? MailboxPeerWireV2Codec.DecodeForwardedTombstoneRequest(exactRequest.Span)
            : MailboxPeerWireV2Codec.DecodeForwardedStoreRequest(exactRequest.Span));
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
        var phase = "send"; var status = 0;
        try
        {
            using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
            phase = "headers"; status = (int)response.StatusCode;
            var rejection = response.Version != HttpVersion.Version20 ? "version" :
                status != contract.SuccessStatusCode ? "status" :
                !string.Equals(response.Content.Headers.ContentType?.ToString(), contract.ResponseContentType, StringComparison.Ordinal) ? "content-type" :
                response.Content.Headers.ContentEncoding.Count != 0 ? "encoding" :
                response.Content.Headers.ContentLength != contract.MaximumResponseBytes ? "length" : null;
            if (rejection is not null) { Report(phase, status, rejection); return null; }
            phase = "body";
            var result = new byte[contract.MaximumResponseBytes];
            await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            try { await stream.ReadExactlyAsync(result, token).ConfigureAwait(false); }
            catch (EndOfStreamException) { Report(phase, status, "truncated"); return null; }
            if (await stream.ReadAsync(new byte[1], token).ConfigureAwait(false) != 0)
            { Report(phase, status, "trailing"); return null; }
            return result;
        }
        catch (HttpRequestException) { Report(phase, status, "http"); throw; }
        catch (OperationCanceledException) { Report(phase, status, "cancelled"); throw; }
        catch (IOException) { Report(phase, status, "io"); throw; }
    }

    private void Report(string phase, int status, string reason)
    {
        if (logger is null) return;
        var now = Stopwatch.GetTimestamp(); var previous = Volatile.Read(ref lastDiagnostic);
        if (previous != 0 && Stopwatch.GetElapsedTime(previous, now) < TimeSpan.FromSeconds(10) ||
            Interlocked.CompareExchange(ref lastDiagnostic, now, previous) != previous) return;
        try { logger.LogWarning("Current mailbox peer hop incomplete: phase={Phase}; status={Status}; reason={Reason}; original custody retained.", phase, status, reason); }
        catch { /* A diagnostic sink cannot change the original transport result. */ }
    }
}
