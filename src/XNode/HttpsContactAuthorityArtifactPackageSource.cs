using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using XNode.Core;

namespace XNode;

public sealed class ProductionContactAuthorityOptions
{
    public bool Enabled { get; set; }
    public string RegistryOrigin { get; set; } = string.Empty;
    public string NetworkIdHex { get; set; } = string.Empty;
    public string XPointNetworkGenesisPinHex { get; set; } = string.Empty;
    public string DirectoryLeafKeyHex { get; set; } = string.Empty;
    public string StateRelativePath { get; set; } = string.Empty;
    public ushort SupportedDirectoryReader { get; set; }
    public int MaximumResponseBytes { get; set; }
    public int MaximumProtectedStateBytes { get; set; }
    public int RequestTimeoutSeconds { get; set; }

    internal ProductionContactAuthorityConfiguration? ValidateAndLoad(
        RouterNodeOptions node,
        ContactServicePersistenceOptions contact)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(contact);
        contact.Validate();

        var anyConfigured = Enabled
            || !string.IsNullOrEmpty(RegistryOrigin)
            || !string.IsNullOrEmpty(NetworkIdHex)
            || !string.IsNullOrEmpty(XPointNetworkGenesisPinHex)
            || !string.IsNullOrEmpty(DirectoryLeafKeyHex)
            || !string.IsNullOrEmpty(StateRelativePath)
            || SupportedDirectoryReader != 0
            || MaximumResponseBytes != 0
            || MaximumProtectedStateBytes != 0
            || RequestTimeoutSeconds != 0;
        if (!Enabled)
        {
            if (anyConfigured)
            {
                throw new InvalidOperationException(
                    "ContactAuthority configuration is partial: Enabled=false requires every production field to be absent.");
            }
            if (contact.RuntimeActivation || contact.MapReplicaEndpoint)
            {
                throw new InvalidOperationException(
                    "ContactService cannot activate without a complete explicit ContactAuthority configuration.");
            }
            return null;
        }

        if (!contact.RuntimeActivation || !contact.MapReplicaEndpoint)
        {
            throw new InvalidOperationException(
                "ContactAuthority activation requires both ContactService runtime and replica endpoint activation.");
        }
        if (string.IsNullOrEmpty(RegistryOrigin)
            || string.IsNullOrEmpty(NetworkIdHex)
            || string.IsNullOrEmpty(XPointNetworkGenesisPinHex)
            || string.IsNullOrEmpty(DirectoryLeafKeyHex)
            || string.IsNullOrEmpty(StateRelativePath)
            || SupportedDirectoryReader == 0
            || MaximumResponseBytes == 0
            || MaximumProtectedStateBytes == 0
            || RequestTimeoutSeconds == 0)
        {
            throw new InvalidOperationException(
                "ContactAuthority activation requires every production field to be configured explicitly.");
        }
        if (RequestTimeoutSeconds is < 1 or > 120)
        {
            throw new InvalidOperationException(
                "ContactAuthority request timeout must be in 1..120 seconds.");
        }

        var networkId = Hex(NetworkIdHex, 16, nameof(NetworkIdHex));
        var genesisHash = Hex(
            XPointNetworkGenesisPinHex,
            32,
            nameof(XPointNetworkGenesisPinHex));
        var leafKey = Hex(DirectoryLeafKeyHex, 32, nameof(DirectoryLeafKeyHex));
        try
        {
            var pin = new XPointNetworkGenesisPin(networkId, genesisHash);
            var source = new ContactAuthorityHttpSourceOptions(
                RegistryOrigin,
                pin,
                leafKey,
                MaximumResponseBytes,
                TimeSpan.FromSeconds(RequestTimeoutSeconds));
            var statePath = ResolveStatePath(node.DataDirectory, StateRelativePath);
            var persistence = new ContactAuthoritySnapshotPersistenceOptions
            {
                StatePath = statePath,
                SupportedDirectoryReader = SupportedDirectoryReader,
                MaximumProtectedStateBytes = MaximumProtectedStateBytes
            };
            _ = persistence.ValidateAndGetStatePath(node);
            return new ProductionContactAuthorityConfiguration(source, persistence);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(networkId);
            CryptographicOperations.ZeroMemory(genesisHash);
            CryptographicOperations.ZeroMemory(leafKey);
        }
    }

    private static byte[] Hex(string exact, int length, string name)
    {
        if (exact.Length != length * 2 || exact.Any(char.IsWhiteSpace))
        {
            throw new InvalidOperationException(
                $"ContactAuthority:{name} must be exactly {length * 2} hexadecimal characters.");
        }
        byte[] value;
        try
        {
            value = Convert.FromHexString(exact);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"ContactAuthority:{name} is not canonical hexadecimal.", exception);
        }
        if (value.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            CryptographicOperations.ZeroMemory(value);
            throw new InvalidOperationException(
                $"ContactAuthority:{name} must be nonzero.");
        }
        return value;
    }

    private static string ResolveStatePath(string dataDirectory, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(dataDirectory)
            || relativePath != relativePath.Trim()
            || Path.IsPathFullyQualified(relativePath)
            || relativePath.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
        {
            throw new InvalidOperationException(
                "ContactAuthority state path must be a clean relative path inside Node:DataDirectory.");
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
                "ContactAuthority state path must resolve to a file inside Node:DataDirectory.");
        }
        return path;
    }
}

internal sealed record ProductionContactAuthorityConfiguration(
    ContactAuthorityHttpSourceOptions Source,
    ContactAuthoritySnapshotPersistenceOptions Persistence);

public sealed class ContactAuthorityHttpSourceOptions
{
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly byte[] directoryLeafKey;

    public ContactAuthorityHttpSourceOptions(
        string registryOrigin,
        XPointNetworkGenesisPin xPointNetworkGenesisPin,
        ReadOnlySpan<byte> directoryLeafKey,
        int maximumResponseBytes,
        TimeSpan requestTimeout)
    {
        Endpoint = ContactAuthorityHttpEndpointPolicy.Create(registryOrigin);
        ArgumentNullException.ThrowIfNull(xPointNetworkGenesisPin);
        genesisPin = new XPointNetworkGenesisPin(
            xPointNetworkGenesisPin.NetworkId.Span,
            xPointNetworkGenesisPin.AuthorityCoreHash.Span);
        if (directoryLeafKey.Length != 32
            || directoryLeafKey.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException(
                "The ContactAuthority directory leaf key must be exactly 32 nonzero bytes.",
                nameof(directoryLeafKey));
        }
        this.directoryLeafKey = directoryLeafKey.ToArray();
        if (maximumResponseBytes is < 256
            or > ContactAuthorityDirectoryCodec.AbsoluteMaximumEnvelopeBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        }
        if (requestTimeout < TimeSpan.FromSeconds(1)
            || requestTimeout > TimeSpan.FromSeconds(120))
        {
            throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        }
        MaximumResponseBytes = maximumResponseBytes;
        RequestTimeout = requestTimeout;
    }

    public Uri Endpoint { get; }
    public XPointNetworkGenesisPin XPointNetworkGenesisPin => new(
        genesisPin.NetworkId.Span,
        genesisPin.AuthorityCoreHash.Span);
    public ReadOnlyMemory<byte> DirectoryLeafKey => directoryLeafKey.ToArray();
    public int MaximumResponseBytes { get; }
    public TimeSpan RequestTimeout { get; }

    internal XPointNetworkGenesisPin CopyGenesisPin() => XPointNetworkGenesisPin;
    internal bool DirectoryLeafKeyMatches(ReadOnlySpan<byte> value) =>
        value.Length == directoryLeafKey.Length
        && CryptographicOperations.FixedTimeEquals(value, directoryLeafKey);
    internal byte[] CopyDirectoryLeafKey() => directoryLeafKey.ToArray();
}

public sealed class ContactAuthorityHttpException : IOException
{
    internal ContactAuthorityHttpException(
        string code,
        string message,
        Exception? inner = null) : base(message, inner) => Code = code;

    public string Code { get; }
}

public sealed class HttpsContactAuthorityArtifactPackageSource
    : IContactAuthorityArtifactPackageSource
{
    private readonly HttpClient httpClient;
    private readonly ContactAuthorityHttpSourceOptions options;
    private readonly XPointNetworkGenesisPin genesisPin;
    private readonly byte[] directoryLeafKey;

    public HttpsContactAuthorityArtifactPackageSource(
        HttpClient httpClient,
        ContactAuthorityHttpSourceOptions options)
    {
        this.httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        genesisPin = options.CopyGenesisPin();
        directoryLeafKey = options.CopyDirectoryLeafKey();
    }

    public XPointNetworkGenesisPin GenesisPin => new(
        genesisPin.NetworkId.Span,
        genesisPin.AuthorityCoreHash.Span);
    public ReadOnlyMemory<byte> DirectoryLeafKey => directoryLeafKey.ToArray();

    public async ValueTask<ContactAuthorityArtifactPackage?> FetchAsync(
        ContactAuthorityArtifactRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (!request.DirectoryLeafKeyMatches(directoryLeafKey))
        {
            throw Fail("request-leaf-mismatch",
                "The Contact authority request does not match the configured directory leaf key.");
        }

        var requestBytes = ContactAuthorityDirectoryCodec.EncodeRequest(genesisPin, request);
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, options.Endpoint);
            message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                ContactAuthorityDirectoryCodec.ResponseMediaType));
            message.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
            message.Content = new ByteArrayContent(requestBytes);
            message.Content.Headers.ContentType = new MediaTypeHeaderValue(
                ContactAuthorityDirectoryCodec.RequestMediaType);
            message.Content.Headers.ContentLength = requestBytes.Length;

            using var response = await httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            EnsureResponseHeaders(response);
            var responseBytes = await ReadExactBoundedAsync(
                response.Content,
                options.MaximumResponseBytes,
                cancellationToken).ConfigureAwait(false);
            try
            {
                return ContactAuthorityDirectoryCodec.DecodeResponse(
                    responseBytes,
                    genesisPin,
                    request,
                    directoryLeafKey);
            }
            catch (FormatException exception)
            {
                throw Fail("invalid-cdr1",
                    "The Contact authority CDR1 response is malformed or not bound to CDQ1.",
                    exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(responseBytes);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
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
            throw Fail("unexpected-status", "The Contact authority endpoint did not return HTTP 200.");
        }
        if (response.RequestMessage?.RequestUri is not { } finalUri
            || Uri.Compare(
                finalUri,
                options.Endpoint,
                UriComponents.AbsoluteUri,
                UriFormat.UriEscaped,
                StringComparison.Ordinal) != 0)
        {
            throw Fail("endpoint-changed",
                "The Contact authority request was redirected or changed endpoint.");
        }
        var contentType = response.Content.Headers.ContentType;
        if (contentType is null
            || !string.Equals(
                contentType.MediaType,
                ContactAuthorityDirectoryCodec.ResponseMediaType,
                StringComparison.OrdinalIgnoreCase)
            || contentType.Parameters.Count != 0)
        {
            throw Fail("unexpected-media-type",
                "The Contact authority response media type is invalid.");
        }
        if (response.Content.Headers.ContentEncoding.Count != 0)
        {
            throw Fail("content-encoding-forbidden",
                "The Contact authority response must not use content encoding.");
        }
        if (response.Headers.CacheControl?.NoStore != true)
        {
            throw Fail("no-store-required",
                "The Contact authority response must declare Cache-Control: no-store.");
        }
        var length = response.Content.Headers.ContentLength;
        if (length is null)
        {
            throw Fail("content-length-required",
                "The Contact authority response requires Content-Length.");
        }
        if (length <= 0
            || length > options.MaximumResponseBytes
            || length > ContactAuthorityDirectoryCodec.AbsoluteMaximumEnvelopeBytes)
        {
            throw Fail("response-too-large",
                "The Contact authority response length is outside its configured bound.");
        }
    }

    private static async Task<byte[]> ReadExactBoundedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        var declared = content.Headers.ContentLength
            ?? throw Fail("content-length-required",
                "The Contact authority response requires Content-Length.");
        if (declared <= 0
            || declared > maximumBytes
            || declared > ContactAuthorityDirectoryCodec.AbsoluteMaximumEnvelopeBytes)
        {
            throw Fail("response-too-large",
                "The Contact authority response length is outside its configured bound.");
        }

        var bytes = new byte[checked((int)declared)];
        var extra = new byte[1];
        try
        {
            await using var stream = await content.ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            var offset = 0;
            while (offset < bytes.Length)
            {
                var read = await stream.ReadAsync(bytes.AsMemory(offset), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw Fail("truncated-response",
                        "The Contact authority response ended before Content-Length.");
                }
                offset += read;
            }
            if (await stream.ReadAsync(extra, cancellationToken).ConfigureAwait(false) != 0)
            {
                throw Fail("trailing-response",
                    "The Contact authority response exceeds Content-Length.");
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

    private static ContactAuthorityHttpException Fail(
        string code,
        string message,
        Exception? inner = null) => new(code, message, inner);
}

internal static class ContactAuthorityHttpEndpointPolicy
{
    internal const string EndpointPath = "/api/v1/directory/contact-resolve-packages";

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
        var endpoint = new UriBuilder(
            Uri.UriSchemeHttps,
            origin.Host,
            origin.IsDefaultPort ? -1 : origin.Port,
            EndpointPath).Uri;
        if (!string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment)
            || endpoint.AbsolutePath != EndpointPath)
        {
            throw new ArgumentException("The Contact authority endpoint is not canonical.", nameof(exactOrigin));
        }
        return endpoint;
    }
}

internal static class ContactAuthorityDirectoryCodec
{
    internal const string RequestMediaType =
        "application/vnd.deep.contact-resolve-directory-request.v1";
    internal const string ResponseMediaType =
        "application/vnd.deep.contact-resolve-directory.v1";
    internal const int AbsoluteMaximumEnvelopeBytes = (68 * 1024 * 1024) + (256 * 1024);
    internal const int MaximumSingleArtifactBytes = 16 * 1024 * 1024;
    internal const int MaximumChainArtifacts = 4_096;
    internal const long MaximumPackageBytes = 68L * 1024 * 1024;

    private const int MinimumRequestBytes = 84;
    private const int DirectoryFloorBytes = 40;
    private const ushort Version = 1;
    private const ushort DirectoryFloorFlag = 0x0001;
    private const ushort ForwardFlag = 0x0001;

    internal static byte[] EncodeRequest(
        XPointNetworkGenesisPin genesisPin,
        ContactAuthorityArtifactRequest request)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        ArgumentNullException.ThrowIfNull(request);
        var hasDirectoryFloor = request.DirectoryTreeSize.HasValue;
        if (hasDirectoryFloor != !request.DirectoryCoreHash.IsEmpty)
        {
            throw new InvalidOperationException(
                "The Contact authority directory floor is incomplete.");
        }
        var requestBytes = hasDirectoryFloor
            ? MinimumRequestBytes + DirectoryFloorBytes
            : MinimumRequestBytes;
        var bytes = new byte[requestBytes];
        "CDQ1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4, 2), Version);
        BinaryPrimitives.WriteUInt16BigEndian(
            bytes.AsSpan(6, 2), hasDirectoryFloor ? DirectoryFloorFlag : (ushort)0);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8, 4), checked((uint)requestBytes));
        genesisPin.NetworkId.Span.CopyTo(bytes.AsSpan(12, 16));
        request.CopyNonceTo(bytes.AsSpan(28, 32));
        request.CopyBootIdTo(bytes.AsSpan(60, 16));
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(76, 8), request.NonceCreatedAt);
        if (hasDirectoryFloor)
        {
            BinaryPrimitives.WriteUInt64BigEndian(
                bytes.AsSpan(MinimumRequestBytes, 8), request.DirectoryTreeSize!.Value);
            request.DirectoryCoreHash.Span.CopyTo(
                bytes.AsSpan(MinimumRequestBytes + 8, 32));
        }
        return bytes;
    }

    internal static ContactAuthorityArtifactPackage DecodeResponse(
        ReadOnlyMemory<byte> encoded,
        XPointNetworkGenesisPin genesisPin,
        ContactAuthorityArtifactRequest request,
        ReadOnlySpan<byte> directoryLeafKey)
    {
        var reader = new Reader(encoded);
        var flags = reader.Header();
        var network = reader.Fixed(16, "network ID");
        var nonce = reader.Fixed(32, "nonce");
        var bootId = reader.Fixed(16, "boot ID");
        var createdAt = reader.U64();
        var leaf = reader.Fixed(32, "directory leaf key");
        RequireExact(network.Span, genesisPin.NetworkId.Span, "network ID");
        if (!request.NonceMatches(nonce.Span)
            || !request.BootIdMatches(bootId.Span)
            || createdAt != request.NonceCreatedAt
            || !request.DirectoryLeafKeyMatches(leaf.Span)
            || directoryLeafKey.Length != 32
            || !CryptographicOperations.FixedTimeEquals(leaf.Span, directoryLeafKey))
        {
            throw new FormatException("The CDR1 response does not exactly echo its CDQ1 request.");
        }

        var xna = reader.Chain(MaximumChainArtifacts, "XNA1");
        var dts = reader.Chain(MaximumChainArtifacts, "DTS1");
        var adh = reader.Artifact("ADH1");
        var dtt = reader.Artifact("DTT1");
        var adp = reader.Artifact("ADP1");
        var xvp = reader.Chain(MaximumChainArtifacts, "XVP1");
        var xnv = reader.Chain(MaximumChainArtifacts, "XNV1");
        var xnh = reader.Chain(MaximumChainArtifacts, "XNH1");
        var xnd = reader.Chain(MaximumChainArtifacts, "XND1");
        var pmt = reader.Chain(MaximumChainArtifacts, "PMT2");
        ContactAuthorityForwardCheckpointPackage? forward = null;
        if ((flags & ForwardFlag) != 0)
        {
            forward = new ContactAuthorityForwardCheckpointPackage(
                xna,
                reader.Chain(64, "XNF1"),
                reader.Artifact("NFP1"),
                reader.Artifact("target XNV1"),
                reader.Artifact("target XNH1"));
        }
        reader.Complete();
        if (reader.ArtifactBytes > MaximumPackageBytes)
        {
            throw new FormatException("The CDR1 package exceeds its aggregate artifact bound.");
        }
        try
        {
            return new ContactAuthorityArtifactPackage(
                xna, dts, adh, dtt, adp, xvp, xnv, xnh, xnd, pmt, forward);
        }
        catch (ArgumentException exception)
        {
            throw new FormatException("The CDR1 package shape is invalid.", exception);
        }
    }

    private static void RequireExact(
        ReadOnlySpan<byte> actual,
        ReadOnlySpan<byte> expected,
        string name)
    {
        if (actual.Length != expected.Length
            || !CryptographicOperations.FixedTimeEquals(actual, expected))
        {
            throw new FormatException($"The CDR1 {name} does not match the request.");
        }
    }

    private ref struct Reader
    {
        private readonly ReadOnlyMemory<byte> value;
        private int offset;

        internal Reader(ReadOnlyMemory<byte> value)
        {
            if (value.Length > AbsoluteMaximumEnvelopeBytes)
            {
                throw new FormatException("The CDR1 envelope exceeds its absolute bound.");
            }
            this.value = value;
            offset = 0;
            ArtifactBytes = 0;
        }

        internal long ArtifactBytes { get; private set; }

        internal ushort Header()
        {
            if (value.Length < 12
                || !Take(4).Span.SequenceEqual("CDR1"u8)
                || BinaryPrimitives.ReadUInt16BigEndian(Take(2).Span) != Version)
            {
                throw new FormatException("The CDR1 header is invalid.");
            }
            var flags = BinaryPrimitives.ReadUInt16BigEndian(Take(2).Span);
            if ((flags & ~ForwardFlag) != 0)
            {
                throw new FormatException("The CDR1 header contains unknown flags.");
            }
            var declared = BinaryPrimitives.ReadUInt32BigEndian(Take(4).Span);
            if (declared != value.Length)
            {
                throw new FormatException("The CDR1 declared length is not canonical.");
            }
            return flags;
        }

        internal ulong U64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8).Span);

        internal ReadOnlyMemory<byte> Fixed(int length, string name)
        {
            var result = Take(length);
            if (result.Span.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new FormatException($"The CDR1 {name} must be nonzero.");
            }
            return result;
        }

        internal ReadOnlyMemory<byte> Artifact(string name)
        {
            var length = BinaryPrimitives.ReadUInt32BigEndian(Take(4).Span);
            if (length is 0 or > MaximumSingleArtifactBytes)
            {
                throw new FormatException($"The CDR1 {name} length is outside its bound.");
            }
            ArtifactBytes = checked(ArtifactBytes + length);
            if (ArtifactBytes > MaximumPackageBytes)
            {
                throw new FormatException("The CDR1 package exceeds its aggregate artifact bound.");
            }
            return Take(checked((int)length));
        }

        internal IReadOnlyList<ReadOnlyMemory<byte>> Chain(int maximum, string name)
        {
            var count = BinaryPrimitives.ReadUInt32BigEndian(Take(4).Span);
            if (count is 0 || count > maximum)
            {
                throw new FormatException($"The CDR1 {name} chain count is outside its bound.");
            }
            var result = new ReadOnlyMemory<byte>[checked((int)count)];
            for (var index = 0; index < result.Length; index++)
            {
                result[index] = Artifact(name);
            }
            return Array.AsReadOnly(result);
        }

        internal void Complete()
        {
            if (offset != value.Length)
            {
                throw new FormatException("The CDR1 envelope contains trailing bytes.");
            }
        }

        private ReadOnlyMemory<byte> Take(int length)
        {
            if (length < 0 || offset > value.Length - length)
            {
                throw new FormatException("The CDR1 envelope is truncated.");
            }
            var result = value.Slice(offset, length);
            offset += length;
            return result;
        }
    }
}

internal sealed class ClosedVerifiedContactRouteClosureSource
    : IVerifiedContactRouteClosureSource
{
    public ValueTask<Deep.Protocol.ContactV1.VerifiedContactRouteClosure?> ReadCurrentAsync(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> locatorHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _ = networkId;
        _ = locatorHash;
        return ValueTask.FromResult<Deep.Protocol.ContactV1.VerifiedContactRouteClosure?>(null);
    }
}

internal static class ProductionContactAuthorityHostComposition
{
    internal static ContactServiceHostCompositionPlan AddProductionContactAuthorityBoundary(
        this IServiceCollection services,
        RouterNodeOptions node,
        ContactServicePersistenceOptions contact,
        ProductionContactAuthorityConfiguration configuration,
        ProductionContactRouteClosureConfiguration? routeClosure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddSingleton(configuration.Source);
        services.AddHttpClient<IContactAuthorityArtifactPackageSource,
                HttpsContactAuthorityArtifactPackageSource>(client =>
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
        if (routeClosure is null)
        {
            services.TryAddSingleton<IVerifiedContactRouteClosureSource,
                ClosedVerifiedContactRouteClosureSource>();
        }
        else
        {
            services.AddProductionContactRouteClosure(routeClosure);
        }

        var keyDirectory = Path.Combine(
            Path.GetFullPath(node.DataDirectory),
            "contact-authority-v1",
            "dataprotection-keys");
        services.AddDataProtection()
            .SetApplicationName("XPoint.XNode.ContactAuthority.v1")
            .PersistKeysToFileSystem(new DirectoryInfo(keyDirectory));
        return services.AddProductionContactServiceBoundary(
            contact,
            configuration.Persistence);
    }
}
