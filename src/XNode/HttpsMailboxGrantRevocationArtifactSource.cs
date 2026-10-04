using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace XNode;

// Returns raw request-bound signed bytes, never a floor/currentness capability.
internal interface IMailboxGrantRevocationArtifactSource
{
    ValueTask<ReadOnlyMemory<byte>> FetchAsync(ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> policyReference,
        MailboxCapabilityDomain role, ulong? generation, CancellationToken ct);
}

internal sealed class HttpsMailboxGrantRevocationArtifactSource : IMailboxGrantRevocationArtifactSource
{
    internal const string Prefix = "/api/v1/node-control/mailbox-revocations";
    internal const string MediaType = "application/vnd.deep.mailbox-grant-revocation.v1+octet-stream";
    private readonly HttpClient client;
    private readonly Uri origin;
    internal HttpsMailboxGrantRevocationArtifactSource(HttpClient client, string exactOrigin)
    {
        this.client = client ?? throw new ArgumentNullException(nameof(client));
        if (string.IsNullOrEmpty(exactOrigin) || exactOrigin != exactOrigin.Trim() || exactOrigin.Any(char.IsControl) ||
            exactOrigin.Contains('\u005c') || exactOrigin.Contains('%') || exactOrigin.Contains('?') || exactOrigin.Contains('#') ||
            !Uri.TryCreate(exactOrigin, UriKind.Absolute, out var parsed) || parsed.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrEmpty(parsed.Host) || parsed.HostNameType == UriHostNameType.Unknown ||
            !string.IsNullOrEmpty(parsed.UserInfo) || parsed.AbsolutePath != "/" || parsed.Query != "" || parsed.Fragment != "")
            throw new ArgumentException("Mailbox control requires an exact HTTPS origin.", nameof(exactOrigin));
        origin = parsed;
    }

    public async ValueTask<ReadOnlyMemory<byte>> FetchAsync(ReadOnlyMemory<byte> network, ReadOnlyMemory<byte> policyReference,
        MailboxCapabilityDomain role, ulong? generation, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (network.Length != 16 || network.Span.IndexOfAnyExcept((byte)0) < 0 || policyReference.Length != 38 ||
            !policyReference.Span[..4].SequenceEqual("PMA2"u8) || policyReference.Span[4] != 0 || policyReference.Span[5] != 1 ||
            policyReference.Span[6..].IndexOfAnyExcept((byte)0) < 0 ||
            role is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve) || generation is 0 or > 1_048_576)
            throw new ArgumentException("Mailbox control query is outside its closed bounds.");
        // Capture before HTTP/content callbacks; caller arrays cannot change bindings.
        var ownedNetwork = network.ToArray(); var ownedPolicy = policyReference.ToArray();
        var path = Prefix + "/" + Convert.ToHexString(ownedNetwork).ToLowerInvariant() + "/" +
            Convert.ToHexString(ownedPolicy.AsSpan(6)).ToLowerInvariant() + "/" + ((byte)role).ToString(CultureInfo.InvariantCulture) +
            "/" + (generation?.ToString(CultureInfo.InvariantCulture) ?? "latest");
        var endpoint = new Uri(origin, path);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Accept.Add(new(MediaType)); request.Headers.CacheControl = new() { NoStore = true };
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        if (response.RequestMessage?.RequestUri is not { } actual ||
            Uri.Compare(actual, endpoint, UriComponents.AbsoluteUri, UriFormat.UriEscaped, StringComparison.Ordinal) != 0)
            throw new InvalidDataException("Mailbox control endpoint changed.");
        if (response.StatusCode is HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
            throw new IOException("Mailbox signed control is unavailable.");
        var media = response.Content.Headers.ContentType;
        var length = response.Content.Headers.ContentLength;
        if (response.StatusCode != HttpStatusCode.OK || media?.MediaType != MediaType || media.Parameters.Count != 0 ||
            response.Content.Headers.ContentEncoding.Count != 0 || response.Headers.CacheControl?.NoStore != true ||
            !response.Headers.TryGetValues("X-Content-Type-Options", out var sniff) || !sniff.SequenceEqual(["nosniff"]) ||
            length is null or < MailboxGrantRevocationV1Codec.MinimumBytes or > MailboxGrantRevocationV1Codec.MaximumBytes)
            throw new InvalidDataException("Mailbox signed control response framing is invalid.");
        var body = new byte[checked((int)length.Value)];
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            await stream.ReadExactlyAsync(body, deadline.Token).ConfigureAwait(false);
            if (await stream.ReadAsync(new byte[1], deadline.Token).ConfigureAwait(false) != 0)
                throw new InvalidDataException("Mailbox signed control response has trailing bytes.");
            var record = MailboxGrantRevocationV1Codec.Decode(body);
            if (record.Generation > 1_048_576 || !CryptographicOperations.FixedTimeEquals(ownedNetwork, record.Field(1).Span) ||
                !CryptographicOperations.FixedTimeEquals(ownedPolicy, record.Field(2).Span) || record.Domain != role ||
                generation is { } exactGeneration && record.Generation != exactGeneration)
                throw new CryptographicException("Mailbox signed control response differs from its request.");
            deadline.Token.ThrowIfCancellationRequested();
            // Structural/request binding only. Actual host signature/time,
            // sequential predecessor and native durable read-back remain mandatory.
            return record.CanonicalBytes.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(body); }
    }
}
