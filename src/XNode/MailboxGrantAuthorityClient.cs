using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Registry;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using XNode.Core;

namespace XNode;

internal enum MailboxGrantAuthorityEvidenceKind : ushort
{
    CurrentRoute = 1,
    RetainedRead = 2
}

internal sealed record MailboxGrantAuthorityRequest(
    VerifiedContactServicePlacement Placement,
    ReadOnlyMemory<byte> ExactXmg2,
    MailboxGrantAcquisitionResultCode ResultCode,
    ReadOnlyMemory<byte> ExactRouteClosure,
    ushort RouteDisposition,
    ulong RouteEffectiveExpiresAtUnixSeconds,
    ulong ResultExpiresAtUnixSeconds,
    IReadOnlyList<MailboxGrantReplicaEvidence> ReplicaEvidence,
    MailboxGrantAuthorityEvidenceKind EvidenceKind,
    ulong ReadUntilUnixSeconds);

internal sealed record MailboxGrantReplicaEvidence(
    ReadOnlyMemory<byte> ReplicaId,
    ReadOnlyMemory<byte> Signature);

/// <summary>
/// Authenticated internal authority boundary. Implementations journal the exact
/// XMG2 operation before authoring XMC2 and keep the mailbox issuer private key
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
        ArgumentNullException.ThrowIfNull(request.Placement);
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
        if (!authorityOrigin.IsAbsoluteUri || authorityOrigin.Scheme != Uri.UriSchemeHttps ||
            authorityOrigin.AbsolutePath != "/" || authorityOrigin.UserInfo.Length != 0 ||
            authorityOrigin.Query.Length != 0 || authorityOrigin.Fragment.Length != 0)
            throw new ArgumentException("Private grant authority requires one credential-free HTTPS origin.", nameof(authorityOrigin));
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
        ArgumentNullException.ThrowIfNull(request.Placement);
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
            var exactRequest = ContactCodec.Decode(DeepProtocolIdentifiers.Magic.XMG2, request.ExactXmg2.Span);
            ContactCodec.VerifyMailboxGrantHolderSignature(exactRequest);
            var placement = request.Placement;
            placement.Network.EnsureCurrent();
            if (!placement.Binds(ContactServiceRequestKind.ResolveInvite, exactRequest.Field(3)) ||
                !CryptographicOperations.FixedTimeEquals(placement.Network.NetworkId.Span, exactRequest.Field(1).Span) ||
                !placement.RankedReplicaNodeIds.Any(id => CryptographicOperations.FixedTimeEquals(id.Span, nodeId)))
                throw new ContactServiceUnavailableException("The forwarding node has no exact current resolver placement.");
            var keyPair = PublicKeyAuth.GenerateKeyPair(seed);
            privateKey = keyPair.PrivateKey;
            if (!CryptographicOperations.FixedTimeEquals(keyPair.PublicKey,
                placement.Network.ResolveNodeIdentityPublicKey(nodeId).Span))
                throw new ContactServiceUnavailableException(
                    "The XNode signing seed does not match its signed descriptor.");
            var signingBytes = request.EvidenceKind switch
            {
                MailboxGrantAuthorityEvidenceKind.CurrentRoute when request.ReadUntilUnixSeconds == 0 =>
                    MailboxGrantAuthorityAuthentication.GetSigningBytes(
                exactRequest.CanonicalBytes.Span,
                request.ResultCode,
                request.ExactRouteClosure.Span,
                request.ResultExpiresAtUnixSeconds,
                nodeId,
                issuedAt,
                nonce),
                MailboxGrantAuthorityEvidenceKind.RetainedRead when request.ResultCode == MailboxGrantAcquisitionResultCode.Success &&
                    request.RouteDisposition == 1 && request.RouteEffectiveExpiresAtUnixSeconds == 0 && request.ReadUntilUnixSeconds != 0 =>
                    MailboxRetainedReadAuthorityAuthentication.GetSigningBytes(exactRequest.CanonicalBytes.Span,
                        request.ExactRouteClosure.Span, request.ReadUntilUnixSeconds, request.ResultExpiresAtUnixSeconds,
                        nodeId, issuedAt, nonce),
                _ => throw new ContactServiceUnavailableException("Private grant evidence kind/role/horizon is invalid.")
            };
            var signature = PublicKeyAuth.SignDetached(signingBytes, privateKey);
            var model = new ContactGrantAuthorityHttpRequest(
                Base64Url(exactRequest.CanonicalBytes.Span),
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
                        Base64Url(item.Signature.Span))).ToArray(),
                checked((ushort)request.EvidenceKind), request.ReadUntilUnixSeconds);
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
            placement.Network.EnsureCurrent();
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
                exactRequest, decoded);
            if (request.EvidenceKind == MailboxGrantAuthorityEvidenceKind.RetainedRead &&
                (length != 510 || decoded.Field(8).Length != 304))
                throw new ContactServiceUnavailableException("Retained authority requires one exact successful current grant.");
            placement.Network.EnsureCurrent();
            cancellationToken.ThrowIfCancellationRequested();
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
            or InvalidDataException
            or ArgumentException
            or OnionBoundaryException)
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
        string ExactXmg2,
        ushort ResultCode,
        string ExactRouteClosure,
        ushort RouteDisposition,
        ulong RouteEffectiveExpiresAtUnixSeconds,
        ulong ResultExpiresAtUnixSeconds,
        string NodeId,
        ulong IssuedAtUnixSeconds,
        string Nonce,
        string Signature,
        IReadOnlyList<ContactGrantReplicaEvidenceHttpRequest> ReplicaEvidence,
        ushort EvidenceKind,
        ulong ReadUntilUnixSeconds);

    private sealed record ContactGrantReplicaEvidenceHttpRequest(
        string ReplicaId,
        string Signature);
}
