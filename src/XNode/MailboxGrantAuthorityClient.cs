using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Registry;
using Sodium;
using XNode.Core;

namespace XNode;

internal sealed record MailboxGrantAuthorityRequest(
    ReadOnlyMemory<byte> ExactXmg1,
    MailboxGrantAcquisitionResultCode ResultCode,
    ReadOnlyMemory<byte> ExactRouteClosure,
    ushort RouteDisposition,
    ulong RouteEffectiveExpiresAtUnixSeconds,
    ulong ResultExpiresAtUnixSeconds,
    IReadOnlyList<MailboxGrantReplicaEvidence> ReplicaEvidence);

internal sealed record MailboxGrantReplicaEvidence(
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> Signature);

/// <summary>
/// Authenticated internal authority boundary. Implementations journal the exact
/// XMG1 operation before authoring XMC2 and keep the mailbox issuer private key
/// outside XNode. This is not a public Registry endpoint.
/// </summary>
internal interface IMailboxGrantAuthorityClient
{
    ValueTask<ReadOnlyMemory<byte>> AuthorizeAsync(
        MailboxGrantAuthorityRequest request,
        CancellationToken cancellationToken);
}

internal sealed class UnavailableMailboxGrantAuthorityClient
    : IMailboxGrantAuthorityClient
{
    public ValueTask<ReadOnlyMemory<byte>> AuthorizeAsync(
        MailboxGrantAuthorityRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        throw new ContactServiceUnavailableException(
            "The internal mailbox grant authority is unavailable.");
    }
}

internal sealed class HttpsMailboxGrantAuthorityClient
    : IMailboxGrantAuthorityClient
{
    internal const string EndpointPath =
        "/api/production-mailbox/internal/contact-grants";
    internal const string RequestMediaType =
        "application/json";
    internal const string ResponseMediaType =
        "application/vnd.deep.mailbox-contact-grant-result.v1+octet-stream";
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly HttpClient httpClient;
    private readonly RouterNodeOptions node;
    private readonly IClock clock;
    private readonly Uri endpoint;

    public HttpsMailboxGrantAuthorityClient(
        HttpClient httpClient,
        RouterNodeOptions node,
        Uri authorityOrigin,
        IClock clock)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        this.node = node ?? throw new ArgumentNullException(nameof(node));
        ArgumentNullException.ThrowIfNull(authorityOrigin);
        this.clock = clock ?? throw new ArgumentNullException(nameof(clock));
        endpoint = new UriBuilder(
            authorityOrigin.Scheme,
            authorityOrigin.Host,
            authorityOrigin.IsDefaultPort ? -1 : authorityOrigin.Port,
            EndpointPath).Uri;
    }

    public async ValueTask<ReadOnlyMemory<byte>> AuthorizeAsync(
        MailboxGrantAuthorityRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (request.ReplicaEvidence.Count != 2)
            throw new ContactServiceUnavailableException(
                "Mailbox grant authority requires two resolver attestations.");

        var issuedAt = checked((ulong)clock.UtcNow.ToUnixTimeSeconds());
        var nonce = RandomNonZero32();
        var nodeId = node.GetRouterId().ToBytes();
        var seed = Convert.FromHexString(node.GetEd25519PrivateKey());
        byte[]? privateKey = null;
        try
        {
            var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
            privateKey = keyPair.PrivateKey;
            if (!CryptographicOperations.FixedTimeEquals(keyPair.PublicKey, nodeId))
                throw new ContactServiceUnavailableException(
                    "The XNode signing seed does not match its RouterId.");
            var signingBytes = MailboxGrantAuthorityAuthentication.GetSigningBytes(
                request.ExactXmg1.Span,
                request.ResultCode,
                request.ExactRouteClosure.Span,
                request.ResultExpiresAtUnixSeconds,
                nodeId,
                issuedAt,
                nonce);
            var signature = PublicKeyAuth.SignDetached(signingBytes, privateKey);
            var model = new ContactGrantAuthorityHttpRequest(
                Base64Url(request.ExactXmg1.Span),
                checked((ushort)request.ResultCode),
                Base64Url(request.ExactRouteClosure.Span),
                request.RouteDisposition,
                request.RouteEffectiveExpiresAtUnixSeconds,
                request.ResultExpiresAtUnixSeconds,
                Convert.ToHexString(nodeId).ToLowerInvariant(),
                issuedAt,
                Base64Url(nonce),
                Base64Url(signature),
                request.ReplicaEvidence.Select(static item =>
                    new ContactGrantReplicaEvidenceHttpRequest(
                        Convert.ToHexString(item.ReplicaId.Span).ToLowerInvariant(),
                        Base64Url(item.Signature.Span))).ToArray());
            var body = JsonSerializer.SerializeToUtf8Bytes(model, JsonOptions);
            using var message = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new ByteArrayContent(body),
            };
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(ResponseMediaType));
            message.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            message.Content.Headers.ContentType = new MediaTypeHeaderValue(RequestMediaType);
            message.Content.Headers.ContentLength = body.Length;

            using var response = await httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK
                || !string.Equals(response.Content.Headers.ContentType?.MediaType,
                    ResponseMediaType, StringComparison.Ordinal)
                || response.Content.Headers.ContentEncoding.Count != 0
                || response.Content.Headers.ContentLength is not long length
                || length is not (206 or 510))
                throw new ContactServiceUnavailableException(
                    "The mailbox grant authority returned no exact authenticated result.");
            var exact = await HttpPrivacyPeerClient.ReadExactlyBoundedAsync(
                response.Content,
                checked((int)length),
                cancellationToken).ConfigureAwait(false);
            var decoded = ContactCodec.Decode(
                DeepProtocolIdentifiers.Magic.XMC2,
                exact);
            ContactCodec.ValidateMailboxGrantResultBinding(
                ContactCodec.Decode(DeepProtocolIdentifiers.Magic.XMG1, request.ExactXmg1.Span), decoded);
            return decoded.CanonicalBytes.ToArray();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ContactServiceUnavailableException)
        {
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException
            or IOException
            or CryptographicException
            or ContactFormatException
            or JsonException
            or InvalidDataException)
        {
            throw new ContactServiceUnavailableException(
                "The internal mailbox grant authority hop failed closed.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (privateKey is not null) CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private static byte[] RandomNonZero32()
    {
        var value = new byte[32];
        do RandomNumberGenerator.Fill(value);
        while (value.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return value;
    }

    private static string Base64Url(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed record ContactGrantAuthorityHttpRequest(
        string ExactXmg1,
        ushort ResultCode,
        string ExactRouteClosure,
        ushort RouteDisposition,
        ulong RouteEffectiveExpiresAtUnixSeconds,
        ulong ResultExpiresAtUnixSeconds,
        string NodeId,
        ulong IssuedAtUnixSeconds,
        string Nonce,
        string Signature,
        IReadOnlyList<ContactGrantReplicaEvidenceHttpRequest> ReplicaEvidence);

    private sealed record ContactGrantReplicaEvidenceHttpRequest(
        string ReplicaId,
        string Signature);
}
