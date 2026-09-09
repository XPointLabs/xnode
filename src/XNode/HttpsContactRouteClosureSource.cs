using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode;

public sealed class ProductionContactRouteClosureOptions
{
    public bool Enabled { get; set; }
    public string RegistryOrigin { get; set; } = string.Empty;
    public string StateRelativePath { get; set; } = string.Empty;
    public int MaximumProtectedStateBytes { get; set; }
    public int RequestTimeoutSeconds { get; set; }

    internal ProductionContactRouteClosureConfiguration? ValidateAndLoad(
        RouterNodeOptions node,
        bool contactAuthorityEnabled)
    {
        ArgumentNullException.ThrowIfNull(node);
        var anyConfigured = Enabled
            || !string.IsNullOrEmpty(RegistryOrigin)
            || !string.IsNullOrEmpty(StateRelativePath)
            || MaximumProtectedStateBytes != 0
            || RequestTimeoutSeconds != 0;
        if (!Enabled)
        {
            if (anyConfigured)
            {
                throw new InvalidOperationException(
                    "ContactRouteClosure configuration is partial: Enabled=false requires every production field to be absent.");
            }
            return null;
        }
        if (!contactAuthorityEnabled)
        {
            throw new InvalidOperationException(
                "ContactRouteClosure activation requires the production ContactAuthority snapshot runtime.");
        }
        if (string.IsNullOrEmpty(RegistryOrigin)
            || string.IsNullOrEmpty(StateRelativePath)
            || MaximumProtectedStateBytes == 0
            || RequestTimeoutSeconds == 0)
        {
            throw new InvalidOperationException(
                "ContactRouteClosure activation requires every production field to be configured explicitly.");
        }
        if (MaximumProtectedStateBytes is < 4_096 or > 128 * 1024 * 1024)
        {
            throw new InvalidOperationException(
                "ContactRouteClosure protected-state bound must be in 4096..134217728 bytes.");
        }
        if (RequestTimeoutSeconds is < 1 or > 120)
        {
            throw new InvalidOperationException(
                "ContactRouteClosure request timeout must be in 1..120 seconds.");
        }

        return new ProductionContactRouteClosureConfiguration(
            new ContactRouteClosureHttpSourceOptions(
                RegistryOrigin,
                TimeSpan.FromSeconds(RequestTimeoutSeconds)),
            ResolveStatePath(node.DataDirectory, StateRelativePath),
            MaximumProtectedStateBytes);
    }

    private static string ResolveStatePath(string dataDirectory, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory)
            || relativePath != relativePath.Trim()
            || Path.IsPathFullyQualified(relativePath)
            || relativePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            throw new InvalidOperationException(
                "ContactRouteClosure state path must be a clean relative path inside Node:DataDirectory.");
        }
        var root = Path.GetFullPath(dataDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var path = Path.GetFullPath(Path.Combine(root, relativePath));
        var relative = Path.GetRelativePath(root, path);
        if (relative is "." or ".."
            || relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
            || Path.IsPathFullyQualified(relative)
            || string.IsNullOrEmpty(Path.GetFileName(path))
            || Directory.Exists(path))
        {
            throw new InvalidOperationException(
                "ContactRouteClosure state path must resolve to a file inside Node:DataDirectory.");
        }
        return path;
    }
}

internal sealed record ProductionContactRouteClosureConfiguration(
    ContactRouteClosureHttpSourceOptions Source,
    string StatePath,
    int MaximumProtectedStateBytes);

internal sealed class ContactRouteClosureHttpSourceOptions
{
    internal ContactRouteClosureHttpSourceOptions(string registryOrigin, TimeSpan requestTimeout)
    {
        Endpoint = ContactRouteClosureHttpEndpointPolicy.Create(registryOrigin);
        if (requestTimeout < TimeSpan.FromSeconds(1)
            || requestTimeout > TimeSpan.FromSeconds(120))
        {
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        }
        RequestTimeout = requestTimeout;
    }

    internal Uri Endpoint { get; }
    internal TimeSpan RequestTimeout { get; }
}

internal static class ContactRouteClosureHttpEndpointPolicy
{
    internal const string EndpointPath = "/api/v1/contact-route-closures";

    internal static Uri Create(string exactOrigin)
    {
        if (string.IsNullOrEmpty(exactOrigin)
            || exactOrigin != exactOrigin.Trim()
            || exactOrigin.Any(char.IsControl)
            || exactOrigin.Contains('\\')
            || exactOrigin.Contains('%')
            || exactOrigin.Contains('?')
            || exactOrigin.Contains('#')
            || !Uri.TryCreate(exactOrigin, UriKind.Absolute, out var origin)
            || !string.Equals(origin.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrEmpty(origin.Host)
            || origin.HostNameType == UriHostNameType.Unknown
            || !string.IsNullOrEmpty(origin.UserInfo)
            || !string.IsNullOrEmpty(origin.Query)
            || !string.IsNullOrEmpty(origin.Fragment)
            || origin.AbsolutePath != "/")
        {
            throw new ArgumentException(
                "RegistryOrigin must be an HTTPS origin without userinfo, path, query, fragment, escaping, or backslashes.",
                nameof(exactOrigin));
        }
        return new UriBuilder(
            Uri.UriSchemeHttps,
            origin.Host,
            origin.IsDefaultPort ? -1 : origin.Port,
            EndpointPath).Uri;
    }
}

internal sealed record ContactRouteClosureArtifactPackage(
    ContactRecord Reachability,
    ContactRecord Authorization,
    ContactRecord Route,
    ContactRecord Successor,
    ContactRecord Projection,
    ContactRecord Selection);

internal interface IContactRouteClosureArtifactSource
{
    ValueTask<ContactRouteClosureArtifactPackage?> FetchAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal interface IContactRouteClosureArtifactCodec
{
    ContactRecord Decode(string expectedMagic, ReadOnlySpan<byte> exact);
}

internal sealed class ContactRouteClosureArtifactCodec : IContactRouteClosureArtifactCodec
{
    public ContactRecord Decode(string expectedMagic, ReadOnlySpan<byte> exact) =>
        ContactCodec.Decode(expectedMagic, exact);
}

internal sealed class HttpsContactRouteClosureArtifactSource(
    HttpClient httpClient,
    ContactRouteClosureHttpSourceOptions options,
    IContactRouteClosureArtifactCodec codec)
    : IContactRouteClosureArtifactSource
{
    internal const string RequestMediaType =
        "application/vnd.deep.contact-route-closure-request.v1+octet-stream";
    internal const string ResponseMediaType =
        "application/vnd.deep.contact-route-closure.v1+octet-stream";
    internal const int RequestBytes = 50;
    private const ushort Version = 1;

    private readonly HttpClient httpClient =
        httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private readonly ContactRouteClosureHttpSourceOptions options =
        options ?? throw new ArgumentNullException(nameof(options));
    private readonly IContactRouteClosureArtifactCodec codec =
        codec ?? throw new ArgumentNullException(nameof(codec));

    public async ValueTask<ContactRouteClosureArtifactPackage?> FetchAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        ValidateSelector(networkId.Span, locatorHash.Span);
        cancellationToken.ThrowIfCancellationRequested();
        var requestBytes = new byte[RequestBytes];
        BinaryPrimitives.WriteUInt16BigEndian(requestBytes, Version);
        networkId.Span.CopyTo(requestBytes.AsSpan(2, 16));
        locatorHash.Span.CopyTo(requestBytes.AsSpan(18, 32));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, options.Endpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(ResponseMediaType));
            request.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            request.Content = new ByteArrayContent(requestBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(RequestMediaType);
            request.Content.Headers.ContentLength = RequestBytes;

            using var response = await httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            EnsureEndpoint(response);
            if (response.StatusCode is HttpStatusCode.NotFound
                or HttpStatusCode.ServiceUnavailable)
            {
                if (response.Headers.CacheControl?.NoStore != true)
                {
                    throw new ContactRouteClosureTransportException(
                        "no-store-required",
                        "A coarse route-closure response must declare Cache-Control: no-store.");
                }
                return null;
            }
            EnsureResponseHeaders(response);
            var exact = await ReadExactAsync(response.Content, cancellationToken)
                .ConfigureAwait(false);
            try
            {
                return Decode(exact, codec);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exact);
            }
        }
        catch (OperationCanceledException exception)
            when (!cancellationToken.IsCancellationRequested)
        {
            throw new ContactRouteClosureTransportException(
                "request-timeout", "The route-closure request timed out.", exception);
        }
        catch (HttpRequestException exception)
        {
            throw new ContactRouteClosureTransportException(
                "request-failed", "The route-closure request failed.", exception);
        }
        catch (IOException exception)
            when (exception is not ContactRouteClosureTransportException)
        {
            throw new ContactRouteClosureTransportException(
                "response-read-failed", "The route-closure response could not be read.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(requestBytes);
        }
    }

    private void EnsureResponseHeaders(HttpResponseMessage response)
    {
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new ContactRouteClosureTransportException(
                "unexpected-status", "The route-closure endpoint did not return HTTP 200.");
        }
        EnsureContentHeaders(response);
    }

    private void EnsureEndpoint(HttpResponseMessage response)
    {
        if (response.RequestMessage?.RequestUri is not { } finalUri
            || Uri.Compare(finalUri, options.Endpoint, UriComponents.AbsoluteUri,
                UriFormat.UriEscaped, StringComparison.Ordinal) != 0)
        {
            throw new ContactRouteClosureTransportException(
                "endpoint-changed", "The route-closure request was redirected or changed endpoint.");
        }
    }

    private static void EnsureContentHeaders(HttpResponseMessage response)
    {
        var contentType = response.Content.Headers.ContentType;
        if (contentType is null
            || !string.Equals(contentType.MediaType, ResponseMediaType,
                StringComparison.OrdinalIgnoreCase)
            || contentType.Parameters.Count != 0)
        {
            throw new ContactRouteClosureTransportException(
                "unexpected-media-type", "The route-closure response media type is invalid.");
        }
        if (response.Content.Headers.ContentEncoding.Count != 0)
        {
            throw new ContactRouteClosureTransportException(
                "content-encoding-forbidden", "The route-closure response must not use content encoding.");
        }
        if (response.Headers.TransferEncoding.Count != 0)
        {
            throw new ContactRouteClosureTransportException(
                "transfer-encoding-forbidden", "The route-closure response must use only Content-Length framing.");
        }
        if (response.Headers.CacheControl?.NoStore != true)
        {
            throw new ContactRouteClosureTransportException(
                "no-store-required", "The route-closure response must declare Cache-Control: no-store.");
        }
        var length = response.Content.Headers.ContentLength;
        if (length is null)
        {
            throw new ContactRouteClosureTransportException(
                "content-length-required", "The route-closure response requires Content-Length.");
        }
        if (length is < ContactRouteClosureCanonicalizer.MinimumEncodedBytes
            or > ContactRouteClosureCanonicalizer.MaximumEncodedBytes)
        {
            throw new ContactRouteClosureTransportException(
                "response-length-invalid", "The route-closure response length is outside its exact bound.");
        }
    }

    private static async Task<byte[]> ReadExactAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        var declared = checked((int)(content.Headers.ContentLength
            ?? throw new ContactRouteClosureTransportException(
                "content-length-required", "The route-closure response requires Content-Length.")));
        var bytes = new byte[declared];
        var extra = new byte[1];
        try
        {
            await using var stream = await content.ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
            if (await stream.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw new ContactRouteClosureTransportException(
                    "trailing-response-bytes", "The route-closure response exceeds Content-Length.");
            }
            return bytes;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(extra);
        }
    }

    internal static ContactRouteClosureArtifactPackage Decode(
        ReadOnlySpan<byte> exact,
        IContactRouteClosureArtifactCodec codec)
    {
        if (exact.Length is < ContactRouteClosureCanonicalizer.MinimumEncodedBytes
            or > ContactRouteClosureCanonicalizer.MaximumEncodedBytes
            || exact[0] != 6)
        {
            throw new ContactRouteClosureTransportException(
                "invalid-envelope", "The route-closure response framing is invalid.");
        }
        string[] magics = ["XRR1", "XRA1", "XRC1", "XSS1", "PMT2", "PMS2"];
        (int Minimum, int Maximum)[] bounds =
        [
            (643, 643),
            (550, 550),
            (940, 4_012),
            (643, 3_523),
            (842, 11_066),
            (500, 3_476)
        ];
        var records = new ContactRecord[6];
        var offset = 1;
        for (var index = 0; index < records.Length; index++)
        {
            if (offset > exact.Length - sizeof(uint))
            {
                throw new ContactRouteClosureTransportException(
                    "truncated-envelope", "The route-closure response is truncated.");
            }
            var length = BinaryPrimitives.ReadUInt32BigEndian(exact[offset..]);
            offset += sizeof(uint);
            if (length > int.MaxValue
                || length < bounds[index].Minimum
                || length > bounds[index].Maximum
                || offset > exact.Length - (int)length)
            {
                throw new ContactRouteClosureTransportException(
                    "invalid-record-length", "A route-closure record length is invalid.");
            }
            try
            {
                records[index] = codec.Decode(magics[index], exact.Slice(offset, (int)length));
            }
            catch (Exception exception) when (exception is ContactFormatException
                or CryptographicException
                or ArgumentException
                or OverflowException)
            {
                throw new ContactRouteClosureTransportException(
                    "invalid-record", "A route-closure record is not exact canonical bytes.", exception);
            }
            offset += (int)length;
        }
        if (offset != exact.Length)
        {
            throw new ContactRouteClosureTransportException(
                "trailing-envelope-bytes", "The route-closure response contains trailing bytes.");
        }
        return new(records[0], records[1], records[2], records[3], records[4], records[5]);
    }

    internal static void ValidateSelector(ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> locatorHash)
    {
        if (networkId.Length != 16 || networkId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The route-closure network id must be exactly 16 nonzero bytes.");
        }
        if (locatorHash.Length != 32 || locatorHash.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("The route-closure locator hash must be exactly 32 nonzero bytes.");
        }
    }
}

internal sealed class ContactRouteClosureTransportException : IOException
{
    internal ContactRouteClosureTransportException(
        string code,
        string message,
        Exception? innerException = null) : base(message, innerException) => Code = code;

    internal string Code { get; }
}

/// <summary>
/// Recipient-specific, Protocol-minted authority and independently obtained exact XIR1.
/// Implementations may not promote Registry bytes, manifest metadata, booleans or caller keys.
/// </summary>
internal sealed class ContactRouteVerifiedAuthoritySnapshot
{
    private readonly byte[] exactXir1;

    internal ContactRouteVerifiedAuthoritySnapshot(
        ReadOnlyMemory<byte> exactXir1,
        VerifiedContactNetworkAuthority authority)
    {
        if (exactXir1.Length != 611)
        {
            throw new ArgumentException("The route authority snapshot requires exact 611-byte XIR1.",
                nameof(exactXir1));
        }
        this.exactXir1 = exactXir1.ToArray();
        Authority = authority ?? throw new ArgumentNullException(nameof(authority));
    }

    internal ReadOnlyMemory<byte> ExactXir1 => exactXir1.ToArray();
    internal VerifiedContactNetworkAuthority Authority { get; }
}

/// <summary>
/// Exact network-side inputs retained from the same verified Contact/XPoint
/// authority transaction. Raw Registry responses cannot construct this value.
/// </summary>
internal sealed class ContactRouteCurrentNetworkAuthorityMaterial
{
    private readonly byte[] networkId;
    private readonly byte[] exactXnv1;
    private readonly byte[] exactXnh1;
    private readonly byte[] exactAdh1;
    private readonly byte[] exactPmt2;

    internal ContactRouteCurrentNetworkAuthorityMaterial(
        ContactVerifiedAuthoritySnapshot snapshot,
        ReadOnlySpan<byte> networkId,
        ulong authorityGeneration,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds,
        ReadOnlySpan<byte> exactXnv1,
        ReadOnlySpan<byte> exactXnh1,
        ReadOnlySpan<byte> exactAdh1,
        ReadOnlySpan<byte> exactPmt2)
    {
        Snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
        this.networkId = Required(networkId, 16, nameof(networkId));
        if (trustedUpperUnixSeconds < trustedLowerUnixSeconds)
        {
            throw new ArgumentException("The current Contact authority freshness interval is invalid.");
        }
        AuthorityGeneration = authorityGeneration;
        TrustedLowerUnixSeconds = trustedLowerUnixSeconds;
        TrustedUpperUnixSeconds = trustedUpperUnixSeconds;
        this.exactXnv1 = RequiredExact(exactXnv1, nameof(exactXnv1));
        this.exactXnh1 = RequiredExact(exactXnh1, nameof(exactXnh1));
        this.exactAdh1 = RequiredExact(exactAdh1, nameof(exactAdh1));
        this.exactPmt2 = RequiredExact(exactPmt2, nameof(exactPmt2));
    }

    internal ContactVerifiedAuthoritySnapshot Snapshot { get; }
    internal ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    internal ulong AuthorityGeneration { get; }
    internal ulong TrustedLowerUnixSeconds { get; }
    internal ulong TrustedUpperUnixSeconds { get; }
    internal ReadOnlyMemory<byte> ExactXnv1 => exactXnv1.ToArray();
    internal ReadOnlyMemory<byte> ExactXnh1 => exactXnh1.ToArray();
    internal ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    internal ReadOnlyMemory<byte> ExactPmt2 => exactPmt2.ToArray();

    internal static ContactRouteCurrentNetworkAuthorityMaterial FromVerified(
        ContactAuthorityVerificationResult verified)
    {
        ArgumentNullException.ThrowIfNull(verified);
        var snapshot = verified.Snapshot;
        var state = verified.State;
        snapshot.EnsureConsistent();
        if (state.Xnv1Chain.Length == 0
            || state.Xnh1Chain.Length == 0
            || state.Pmt2Chain.Length == 0
            || !Fixed(state.NetworkId, snapshot.Network.NetworkId.Span)
            || !Fixed(state.AuthorityCoreReference, snapshot.Authority.AuthorityCoreReference.Span)
            || !Fixed(state.ExactAdh1, snapshot.DirectoryFreshness.ExactAdh1.Span)
            || state.AdhGeneration != snapshot.DirectoryFreshness.AdhGeneration
            || state.AdhTreeSize != snapshot.DirectoryFreshness.TreeSize)
        {
            throw new InvalidDataException(
                "The protected Contact authority state does not match its verified current snapshot.");
        }
        return new(
            snapshot,
            snapshot.Network.NetworkId.Span,
            snapshot.Authority.AuthorityGeneration,
            snapshot.DirectoryFreshness.TrustedLowerUnixSeconds,
            snapshot.DirectoryFreshness.TrustedUpperUnixSeconds,
            state.Xnv1Chain[^1],
            state.Xnh1Chain[^1],
            state.ExactAdh1,
            state.Pmt2Chain[^1]);
    }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException($"{name} must be exactly {length} nonzero bytes.", name);
        }
        return value.ToArray();
    }

    private static byte[] RequiredExact(ReadOnlySpan<byte> value, string name)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException($"{name} must contain exact canonical bytes.", name);
        }
        return value.ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal interface IContactRouteCurrentNetworkAuthoritySource
{
    ValueTask<ContactRouteCurrentNetworkAuthorityMaterial> ReadCurrentRouteAuthorityAsync(
        CancellationToken cancellationToken);
}

/// <summary>
/// Narrow upstream boundary still required from the recipient Contact
/// composition. Implementations must supply Protocol-minted device and DCA1
/// capabilities plus independently retained exact XIR1/PMS2; raw caller keys,
/// trust booleans and Registry response bytes are forbidden.
/// </summary>
internal sealed class ContactRouteRecipientAuthorityMaterial
{
    private readonly byte[] exactXir1;
    private readonly byte[] exactPms2;

    internal ContactRouteRecipientAuthorityMaterial(
        ReadOnlySpan<byte> exactXir1,
        VerifiedDevice recipientDevice,
        CurrentlyAuthoritativeDca1 recipientAuthorization,
        ReadOnlySpan<byte> exactPms2)
    {
        if (exactXir1.Length != 611)
        {
            throw new ArgumentException("The recipient authority requires exact 611-byte XIR1.",
                nameof(exactXir1));
        }
        if (exactPms2.Length is < 500 or > 3_476)
        {
            throw new ArgumentException("The recipient authority PMS2 length is invalid.",
                nameof(exactPms2));
        }
        this.exactXir1 = exactXir1.ToArray();
        this.exactPms2 = exactPms2.ToArray();
        RecipientDevice = recipientDevice
            ?? throw new ArgumentNullException(nameof(recipientDevice));
        RecipientAuthorization = recipientAuthorization
            ?? throw new ArgumentNullException(nameof(recipientAuthorization));
    }

    internal ReadOnlyMemory<byte> ExactXir1 => exactXir1.ToArray();
    internal VerifiedDevice RecipientDevice { get; }
    internal CurrentlyAuthoritativeDca1 RecipientAuthorization { get; }
    internal ReadOnlyMemory<byte> ExactPms2 => exactPms2.ToArray();
}

internal interface IContactRouteRecipientAuthoritySource
{
    ValueTask<ContactRouteRecipientAuthorityMaterial?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal sealed class ClosedContactRouteRecipientAuthoritySource
    : IContactRouteRecipientAuthoritySource
{
    public ValueTask<ContactRouteRecipientAuthorityMaterial?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = networkId;
        _ = locatorHash;
        return ValueTask.FromResult<ContactRouteRecipientAuthorityMaterial?>(null);
    }
}

internal interface IContactRouteNetworkAuthorityVerifier
{
    ValueTask<VerifiedContactNetworkAuthority> VerifyAsync(
        ContactRouteCurrentNetworkAuthorityMaterial current,
        ContactRouteRecipientAuthorityMaterial recipient,
        CancellationToken cancellationToken);
}

internal sealed class ProtocolContactRouteNetworkAuthorityVerifier
    : IContactRouteNetworkAuthorityVerifier
{
    public ValueTask<VerifiedContactNetworkAuthority> VerifyAsync(
        ContactRouteCurrentNetworkAuthorityMaterial current,
        ContactRouteRecipientAuthorityMaterial recipient,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(recipient);
        return ContactNetworkAuthorityVerifier.VerifyAsync(
            current.Snapshot.Authority,
            current.Snapshot.Network,
            current.Snapshot.DirectoryFreshness,
            recipient.RecipientDevice,
            recipient.RecipientAuthorization,
            current.ExactXnv1,
            current.ExactXnh1,
            current.ExactAdh1,
            current.ExactPmt2,
            recipient.ExactPms2,
            current.Snapshot.TrustedTimeAuthority,
            cancellationToken);
    }
}

internal sealed class ProductionContactRouteVerifiedAuthoritySnapshotSource(
    IContactRouteCurrentNetworkAuthoritySource currentAuthorities,
    IContactRouteRecipientAuthoritySource recipients,
    IContactRouteClosureArtifactCodec codec,
    IContactRouteNetworkAuthorityVerifier verifier)
    : IContactRouteVerifiedAuthoritySnapshotSource
{
    private readonly IContactRouteCurrentNetworkAuthoritySource currentAuthorities =
        currentAuthorities ?? throw new ArgumentNullException(nameof(currentAuthorities));
    private readonly IContactRouteRecipientAuthoritySource recipients =
        recipients ?? throw new ArgumentNullException(nameof(recipients));
    private readonly IContactRouteClosureArtifactCodec codec =
        codec ?? throw new ArgumentNullException(nameof(codec));
    private readonly IContactRouteNetworkAuthorityVerifier verifier =
        verifier ?? throw new ArgumentNullException(nameof(verifier));

    public async ValueTask<ContactRouteVerifiedAuthoritySnapshot?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        HttpsContactRouteClosureArtifactSource.ValidateSelector(networkId.Span, locatorHash.Span);
        cancellationToken.ThrowIfCancellationRequested();
        var current = await currentAuthorities.ReadCurrentRouteAuthorityAsync(cancellationToken)
            .ConfigureAwait(false);
        if (!Fixed(current.NetworkId.Span, networkId.Span))
        {
            return null;
        }
        var recipient = await recipients.ReadCurrentAsync(
            networkId, locatorHash, cancellationToken).ConfigureAwait(false);
        if (recipient is null)
        {
            return null;
        }
        var invite = codec.Decode("XIR1", recipient.ExactXir1.Span);
        if (!Fixed(invite.Field(1).Span, networkId.Span)
            || !Fixed(invite.Field(2).Span, locatorHash.Span))
        {
            return null;
        }
        var authority = await verifier.VerifyAsync(current, recipient, cancellationToken)
            .ConfigureAwait(false);
        if (!Fixed(authority.NetworkId.Span, networkId.Span)
            || authority.AuthorityGeneration != current.AuthorityGeneration
            || authority.TrustedLowerUnixSeconds != current.TrustedLowerUnixSeconds
            || authority.TrustedUpperUnixSeconds != current.TrustedUpperUnixSeconds)
        {
            throw new InvalidDataException(
                "The Protocol-minted recipient authority is stale or does not bind the current snapshot.");
        }
        return new(recipient.ExactXir1, authority);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal interface IContactRouteVerifiedAuthoritySnapshotSource
{
    ValueTask<ContactRouteVerifiedAuthoritySnapshot?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken);
}

internal interface IContactRouteClosureProtocolVerifier
{
    VerifiedContactRouteClosure Verify(
        ReadOnlyMemory<byte> exactXir1,
        ContactRouteClosureArtifactPackage package,
        VerifiedContactNetworkAuthority authority);
}

internal sealed class ContactRouteClosureProtocolVerifier : IContactRouteClosureProtocolVerifier
{
    public VerifiedContactRouteClosure Verify(
        ReadOnlyMemory<byte> exactXir1,
        ContactRouteClosureArtifactPackage package,
        VerifiedContactNetworkAuthority authority) => ContactCodec.VerifyRouteUpdateClosure(
            ContactCodec.Decode("XIR1", exactXir1.Span),
            package.Reachability,
            package.Authorization,
            package.Route,
            package.Successor,
            package.Projection,
            package.Selection,
            authority);
}

internal sealed class HttpsVerifiedContactRouteClosureSource
    : IVerifiedContactRouteClosureSource
{
    private readonly IContactRouteClosureArtifactSource artifacts;
    private readonly IContactRouteVerifiedAuthoritySnapshotSource authorities;
    private readonly IContactRouteClosureProtocolVerifier verifier;
    private readonly IContactRouteClosureLineageStore lineage;

    internal HttpsVerifiedContactRouteClosureSource(
        IContactRouteClosureArtifactSource artifacts,
        IContactRouteVerifiedAuthoritySnapshotSource authorities,
        IContactRouteClosureProtocolVerifier verifier,
        IContactRouteClosureLineageStore lineage)
    {
        this.artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        this.authorities = authorities ?? throw new ArgumentNullException(nameof(authorities));
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        this.lineage = lineage ?? throw new ArgumentNullException(nameof(lineage));
    }

    public async ValueTask<VerifiedContactRouteClosure?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        HttpsContactRouteClosureArtifactSource.ValidateSelector(networkId.Span, locatorHash.Span);
        cancellationToken.ThrowIfCancellationRequested();
        ContactRouteVerifiedAuthoritySnapshot? authority;
        try
        {
            authority = await authorities.ReadCurrentAsync(
                networkId, locatorHash, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (Expected(exception))
        {
            return null;
        }
        if (authority is null)
        {
            return null;
        }
        if (!Fixed(authority.Authority.NetworkId.Span, networkId.Span))
        {
            return null;
        }

        ContactRouteClosureArtifactPackage? package;
        try
        {
            package = await artifacts.FetchAsync(
                networkId, locatorHash, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (Expected(exception))
        {
            return null;
        }
        if (package is null)
        {
            return null;
        }

        try
        {
            var verified = verifier.Verify(authority.ExactXir1, package, authority.Authority);
            EnsureSelector(verified, networkId.Span, locatorHash.Span);
            await lineage.ObserveAsync(
                ContactRouteClosureLineageObservation.FromVerified(
                    networkId.Span,
                    locatorHash.Span,
                    verified),
                cancellationToken).ConfigureAwait(false);
            return verified;
        }
        catch (Exception exception) when (Expected(exception))
        {
            return null;
        }
    }

    private static void EnsureSelector(
        VerifiedContactRouteClosure closure,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locatorHash)
    {
        if (!Fixed(closure.Invite.Field(1).Span, networkId)
            || !Fixed(closure.Invite.Field(2).Span, locatorHash))
        {
            throw new InvalidDataException(
                "The verified route closure does not bind the requested selector.");
        }
    }

    private static bool Expected(Exception exception) => exception is
        ContactRouteClosureTransportException
        or ContactFormatException
        or CryptographicException
        or InvalidDataException
        or IOException
        or HttpRequestException
        or InvalidOperationException
        or ArgumentException
        or FormatException
        or UnauthorizedAccessException
        or OverflowException;

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

internal sealed record ContactRouteClosureLineageObservation(
    byte[] NetworkId,
    byte[] LocatorHash,
    ContactRouteClosureLineagePart[] Parts)
{
    internal static ContactRouteClosureLineageObservation FromVerified(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> locatorHash,
        VerifiedContactRouteClosure closure)
    {
        ArgumentNullException.ThrowIfNull(closure);
        return new(
            networkId.ToArray(),
            locatorHash.ToArray(),
            [
                new ContactRouteClosureLineagePart(
                    closure.Authority.AuthorityGeneration,
                    SHA256.HashData(closure.Authority.AuthorityCoreReference.Span),
                    SHA256.HashData(closure.Authority.RecipientDeviceId.Span)),
                Part(closure.Invite, 3),
                Part(closure.Reachability, 3),
                Part(closure.Authorization, 3),
                Part(closure.Route, 3),
                Part(closure.Successor, 3),
                Part(closure.Projection, 2),
                Part(closure.Selection, 4)
            ]);
    }

    private static ContactRouteClosureLineagePart Part(
        ContactRecord record,
        int generationTag) => new(
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(generationTag).Span),
            SHA256.HashData(record.CanonicalBytes.Span),
            SHA256.HashData(record.Field(2).Span));
}

internal sealed record ContactRouteClosureLineagePart(
    ulong Generation,
    byte[] Hash,
    byte[] StableId);

internal interface IContactRouteClosureLineageStore
{
    ValueTask InitializeAsync(CancellationToken cancellationToken);
    ValueTask ObserveAsync(
        ContactRouteClosureLineageObservation observation,
        CancellationToken cancellationToken);
}

internal sealed class FileContactRouteClosureLineageStore
    : IContactRouteClosureLineageStore
{
    private const ushort Version = 1;
    private const int PartCount = 8;
    private const int MaximumEntries = 100_000;
    private const int EntryBytes = 48 + PartCount * 72 + 1;
    private const int HeaderBytes = 24;
    private static readonly byte[] DomainPrefix =
        SHA256.HashData("Deep/XNode/ContactRouteClosureLkg/V1"u8)[..16];
    private readonly string path;
    private readonly int maximumBytes;
    private readonly IDataProtector protector;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly Dictionary<string, State> states = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim gate = new(1, 1);
    private bool initialized;

    internal FileContactRouteClosureLineageStore(
        ProductionContactRouteClosureConfiguration configuration,
        IDataProtectionProvider protection,
        IMailboxStorageSecurity security,
        IMailboxDurabilityBarrier durability)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        path = configuration.StatePath;
        maximumBytes = configuration.MaximumProtectedStateBytes;
        protector = (protection ?? throw new ArgumentNullException(nameof(protection)))
            .CreateProtector("Deep.XNode.ContactRouteClosureLineage.V1");
        this.security = security ?? throw new ArgumentNullException(nameof(security));
        this.durability = durability ?? throw new ArgumentNullException(nameof(durability));
        security.SecureDirectory(Path.GetDirectoryName(path)!);
    }

    public async ValueTask InitializeAsync(CancellationToken cancellationToken)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore(cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    private void InitializeCore(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (initialized)
        {
            return;
        }
        if (File.Exists(path))
        {
            EnsureRegular(path);
            var protectedBytes = File.ReadAllBytes(path);
            if (protectedBytes.Length is <= 0 || protectedBytes.Length > maximumBytes)
            {
                throw new InvalidDataException("The Contact route-closure LKG length is invalid.");
            }
            byte[] plaintext;
            try
            {
                plaintext = protector.Unprotect(protectedBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
            }
            try
            {
                Decode(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        initialized = true;
    }

    public async ValueTask ObserveAsync(
        ContactRouteClosureLineageObservation observation,
        CancellationToken cancellationToken)
    {
        Validate(observation);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            InitializeCore(cancellationToken);
            var keyBytes = new byte[48];
            observation.NetworkId.CopyTo(keyBytes, 0);
            observation.LocatorHash.CopyTo(keyBytes, 16);
            var key = Convert.ToHexString(keyBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
            if (states.TryGetValue(key, out var prior))
            {
                if (prior.Forked)
                {
                    throw new InvalidDataException("The Contact route-closure lineage is permanently fork-latched.");
                }
                var fork = false;
                var advanced = false;
                for (var index = 0; index < PartCount; index++)
                {
                    var oldPart = prior.Parts[index];
                    var candidate = observation.Parts[index];
                    if (candidate.Generation < oldPart.Generation)
                    {
                        throw new InvalidDataException("The Contact route-closure lineage rolls back.");
                    }
                    if (candidate.Generation == oldPart.Generation)
                    {
                        fork |= !Fixed(oldPart.Hash, candidate.Hash);
                    }
                    else
                    {
                        advanced = true;
                        fork |= !Fixed(oldPart.StableId, candidate.StableId);
                    }
                }
                if (fork)
                {
                    states[key] = prior with { Forked = true };
                    await CommitAsync(cancellationToken).ConfigureAwait(false);
                    throw new InvalidDataException("The Contact route-closure lineage forked.");
                }
                if (!advanced)
                {
                    return;
                }
            }
            else if (states.Count >= MaximumEntries)
            {
                throw new InvalidDataException("The Contact route-closure LKG reached its entry bound.");
            }

            states[key] = new State(
                observation.NetworkId.ToArray(),
                observation.LocatorHash.ToArray(),
                observation.Parts.Select(static part => new ContactRouteClosureLineagePart(
                    part.Generation, part.Hash.ToArray(), part.StableId.ToArray())).ToArray(),
                false);
            await CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static void Validate(ContactRouteClosureLineageObservation observation)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (observation.NetworkId.Length != 16
            || observation.NetworkId.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || observation.LocatorHash.Length != 32
            || observation.LocatorHash.AsSpan().IndexOfAnyExcept((byte)0) < 0
            || observation.Parts.Length != PartCount
            || observation.Parts.Any(static part => part.Hash.Length != 32
                || part.Hash.AsSpan().IndexOfAnyExcept((byte)0) < 0
                || part.StableId.Length != 32
                || part.StableId.AsSpan().IndexOfAnyExcept((byte)0) < 0))
        {
            throw new InvalidDataException("The Contact route-closure lineage observation is invalid.");
        }
    }

    private async ValueTask CommitAsync(CancellationToken cancellationToken)
    {
        var plaintext = Encode();
        byte[] protectedBytes;
        try
        {
            protectedBytes = protector.Protect(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
        if (protectedBytes.Length > maximumBytes)
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            throw new InvalidDataException("The Contact route-closure LKG exceeds its configured bound.");
        }
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(protectedBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            security.SecureFile(temporary);
            EnsureRegular(temporary);
            if (File.Exists(path))
            {
                EnsureRegular(path);
            }
            durability.ReplaceFile(temporary, path);
            security.SecureFile(path);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedBytes);
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private byte[] Encode()
    {
        var ordered = states.Values
            .OrderBy(static value => value.NetworkId, ByteComparer.Instance)
            .ThenBy(static value => value.LocatorHash, ByteComparer.Instance)
            .ToArray();
        var bytes = new byte[HeaderBytes + ordered.Length * EntryBytes];
        DomainPrefix.CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(16), Version);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(18), 0);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(20), checked((uint)ordered.Length));
        var offset = HeaderBytes;
        foreach (var state in ordered)
        {
            state.NetworkId.CopyTo(bytes, offset); offset += 16;
            state.LocatorHash.CopyTo(bytes, offset); offset += 32;
            foreach (var part in state.Parts)
            {
                BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset), part.Generation); offset += 8;
                part.Hash.CopyTo(bytes, offset); offset += 32;
                part.StableId.CopyTo(bytes, offset); offset += 32;
            }
            bytes[offset++] = state.Forked ? (byte)1 : (byte)0;
        }
        return bytes;
    }

    private void Decode(ReadOnlySpan<byte> exact)
    {
        if (exact.Length < HeaderBytes
            || !exact[..16].SequenceEqual(DomainPrefix)
            || BinaryPrimitives.ReadUInt16BigEndian(exact[16..]) != Version
            || BinaryPrimitives.ReadUInt16BigEndian(exact[18..]) != 0)
        {
            throw new InvalidDataException("The Contact route-closure LKG header is invalid.");
        }
        var count = BinaryPrimitives.ReadUInt32BigEndian(exact[20..]);
        if (count > MaximumEntries
            || exact.Length != HeaderBytes + checked((int)count) * EntryBytes)
        {
            throw new InvalidDataException("The Contact route-closure LKG shape is invalid.");
        }
        var offset = HeaderBytes;
        byte[]? previousKey = null;
        for (var index = 0; index < count; index++)
        {
            var network = exact.Slice(offset, 16).ToArray(); offset += 16;
            var locator = exact.Slice(offset, 32).ToArray(); offset += 32;
            var parts = new ContactRouteClosureLineagePart[PartCount];
            for (var partIndex = 0; partIndex < PartCount; partIndex++)
            {
                var generation = BinaryPrimitives.ReadUInt64BigEndian(exact[offset..]); offset += 8;
                var hash = exact.Slice(offset, 32).ToArray(); offset += 32;
                var stableId = exact.Slice(offset, 32).ToArray(); offset += 32;
                parts[partIndex] = new(generation, hash, stableId);
            }
            var forked = exact[offset++] switch
            {
                0 => false,
                1 => true,
                _ => throw new InvalidDataException("The Contact route-closure fork marker is invalid.")
            };
            var keyBytes = new byte[48];
            network.CopyTo(keyBytes, 0);
            locator.CopyTo(keyBytes, 16);
            var key = Convert.ToHexString(keyBytes);
            if (previousKey is not null && previousKey.AsSpan().SequenceCompareTo(keyBytes) >= 0)
            {
                throw new InvalidDataException("The Contact route-closure LKG is not canonically ordered.");
            }
            Validate(new(network, locator, parts));
            if (!states.TryAdd(key, new(network, locator, parts, forked)))
            {
                throw new InvalidDataException("The Contact route-closure LKG contains a duplicate selector.");
            }
            previousKey = keyBytes;
        }
    }

    private static void EnsureRegular(string candidate)
    {
        if ((File.GetAttributes(candidate)
            & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new InvalidDataException("The Contact route-closure LKG path is not a regular file.");
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private sealed record State(
        byte[] NetworkId,
        byte[] LocatorHash,
        ContactRouteClosureLineagePart[] Parts,
        bool Forked);

    private sealed class ByteComparer : IComparer<byte[]>
    {
        internal static ByteComparer Instance { get; } = new();
        public int Compare(byte[]? x, byte[]? y) =>
            (x ?? []).AsSpan().SequenceCompareTo(y ?? []);
    }
}

internal sealed class ContactRouteClosureLineageHostedService(
    IContactRouteClosureLineageStore lineage) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken) =>
        await lineage.InitializeAsync(cancellationToken).ConfigureAwait(false);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal static class ProductionContactRouteClosureHostComposition
{
    internal static IServiceCollection AddProductionContactRouteClosure(
        this IServiceCollection services,
        ProductionContactRouteClosureConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.AddSingleton(configuration);
        services.AddSingleton(configuration.Source);
        services.AddHttpClient<IContactRouteClosureArtifactSource,
                HttpsContactRouteClosureArtifactSource>(client =>
            {
                client.Timeout = configuration.Source.RequestTimeout;
                client.DefaultRequestHeaders.ExpectContinue = false;
            })
            .ConfigurePrimaryHttpMessageHandler(static () => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.None
            });
        services.TryAddSingleton<IContactRouteClosureArtifactCodec,
            ContactRouteClosureArtifactCodec>();
        services.TryAddSingleton(
            ProductionContactRecipientEvidenceCacheConfiguration.FromRouteClosure(configuration));
        services.TryAddSingleton<IContactRecipientResolveEvidenceVerifier,
            ProtocolContactRecipientResolveEvidenceVerifier>();
        services.TryAddSingleton<FileContactRecipientResolveEvidenceCache>();
        services.TryAddSingleton<IContactRouteRecipientResolveClosureSource>(provider =>
            provider.GetRequiredService<FileContactRecipientResolveEvidenceCache>());
        services.TryAddSingleton<IContactPreKeyRecipientResolveEvidenceSource>(provider =>
            provider.GetRequiredService<FileContactRecipientResolveEvidenceCache>());
        services.TryAddSingleton<IContactRouteRecipientResolveEvidenceOwner>(provider =>
            provider.GetRequiredService<FileContactRecipientResolveEvidenceCache>());
        services.TryAddSingleton<IPrivacyRoutedContactRecipientResolveEvidenceIngestion,
            PrivacyRoutedContactRecipientResolveEvidenceIngestion>();
        services.AddHostedService<ContactRecipientResolveEvidenceCacheHostedService>();
        services.TryAddSingleton<IContactRouteRecipientEvidenceProjector,
            ProtocolContactRouteRecipientEvidenceProjector>();
        services.TryAddSingleton<IContactRouteRecipientAuthoritySource,
            ProtocolContactRouteRecipientAuthoritySource>();
        services.TryAddSingleton<IContactRouteNetworkAuthorityVerifier,
            ProtocolContactRouteNetworkAuthorityVerifier>();
        services.TryAddSingleton<IContactPreKeyRecipientAuthoritySource,
            ProtocolContactPreKeyRecipientAuthoritySource>();
        services.TryAddSingleton<IContactRouteVerifiedAuthoritySnapshotSource,
            ProductionContactRouteVerifiedAuthoritySnapshotSource>();
        services.TryAddSingleton<IContactRouteClosureProtocolVerifier,
            ContactRouteClosureProtocolVerifier>();
        services.TryAddSingleton<IContactRouteClosureLineageStore,
            FileContactRouteClosureLineageStore>();
        services.AddHostedService<ContactRouteClosureLineageHostedService>();
        services.AddSingleton<IVerifiedContactRouteClosureSource,
            HttpsVerifiedContactRouteClosureSource>();
        return services;
    }
}
