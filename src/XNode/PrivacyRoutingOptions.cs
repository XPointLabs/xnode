using System.Security.Cryptography;
using System.Collections.ObjectModel;
using Sodium;
using XNode.Core;

namespace XNode;

public sealed class PrivacyRoutingOptions
{
    public const string PeerFramePath = "/api/peer/privacy/v1/frame";

    public bool Enabled { get; set; }

    public string X25519PrivateKeyPath { get; set; } = "";

    public string PublicPeerBaseUrl { get; set; } = "";

    public int MaximumConcurrentRequests { get; set; } = 64;

    public int RequestsPerMinute { get; set; } = 600;

    public int RequestTimeoutSeconds { get; set; } = 30;

    public int ReplyPaddingBlockBytes { get; set; } = 1024;

    public int ReplayCapacity { get; set; } = 100_000;

    public int ReplayTtlSeconds { get; set; } = 300;

    public bool AllowInsecureHttpPeerTransport { get; set; }

    public List<PrivacyPeerOptions> Peers { get; set; } = [];

    public PrivacyRoutingConfiguration ValidateAndLoad(
        RouterNodeOptions node,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (!Enabled)
        {
            if (!string.IsNullOrWhiteSpace(X25519PrivateKeyPath)
                || !string.IsNullOrWhiteSpace(PublicPeerBaseUrl)
                || Peers.Count != 0)
            {
                throw new InvalidOperationException(
                    "PrivacyRouting key and peer configuration must be empty when disabled.");
            }

            return PrivacyRoutingConfiguration.Disabled;
        }

        if (!node.IsRelay)
        {
            throw new InvalidOperationException("PrivacyRouting requires Node:IsRelay=true.");
        }


        if (AllowInsecureHttpPeerTransport && !isDevelopment)
        {
            throw new InvalidOperationException(
                "PrivacyRouting insecure peer transport is Development-only.");
        }

        if (MaximumConcurrentRequests is < 1 or > 4096
            || RequestsPerMinute is < 1 or > 1_000_000
            || RequestTimeoutSeconds is < 1 or > 120
            || ReplyPaddingBlockBytes is < 256 or > 65_536
            || (ReplyPaddingBlockBytes & (ReplyPaddingBlockBytes - 1)) != 0
            || ReplayCapacity is < 1_000 or > 10_000_000
            || ReplayTtlSeconds is < 120 or > 3600)
        {
            throw new InvalidOperationException("PrivacyRouting resource bounds are invalid.");
        }

        if (string.IsNullOrWhiteSpace(X25519PrivateKeyPath)
            || !Path.IsPathFullyQualified(X25519PrivateKeyPath)
            || !File.Exists(X25519PrivateKeyPath))
        {
            throw new InvalidOperationException(
                "PrivacyRouting:X25519PrivateKeyPath must name an existing absolute file.");
        }


        if (!Uri.TryCreate(PublicPeerBaseUrl.Trim(), UriKind.Absolute, out var publicPeerBaseUrl)
            || publicPeerBaseUrl.Scheme != Uri.UriSchemeHttps
                && !(isDevelopment && AllowInsecureHttpPeerTransport
                    && publicPeerBaseUrl.Scheme == Uri.UriSchemeHttp)
            || !string.Equals(publicPeerBaseUrl.AbsolutePath, "/", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(publicPeerBaseUrl.Query)
            || !string.IsNullOrEmpty(publicPeerBaseUrl.UserInfo)
            || !string.IsNullOrEmpty(publicPeerBaseUrl.Fragment))
        {
            throw new InvalidOperationException(
                "PrivacyRouting:PublicPeerBaseUrl must be a canonical permitted origin.");
        }

        var privateKey = DecodeHex32(
            File.ReadAllText(X25519PrivateKeyPath).Trim(),
            "PrivacyRouting X25519 private key");
        var ed25519Seed = DecodeHex32(
            node.GetEd25519PrivateKey().Trim(),
            "Node Ed25519 private seed");
        try
        {
            if (CryptographicOperations.FixedTimeEquals(privateKey, ed25519Seed)
                || !string.IsNullOrWhiteSpace(node.Ed25519PrivateKeyPath)
                && string.Equals(
                    Path.GetFullPath(X25519PrivateKeyPath),
                    Path.GetFullPath(node.Ed25519PrivateKeyPath),
                    OperatingSystem.IsWindows()
                        ? StringComparison.OrdinalIgnoreCase
                        : StringComparison.Ordinal))
            {
                CryptographicOperations.ZeroMemory(privateKey);
                throw new InvalidOperationException(
                    "PrivacyRouting X25519 and Node Ed25519 keys must be independent.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ed25519Seed);
        }

        var publicKey = ScalarMult.Base(privateKey);
        if (publicKey.Length != 32 || publicKey.All(static value => value == 0))
        {
            CryptographicOperations.ZeroMemory(privateKey);
            throw new InvalidOperationException("PrivacyRouting X25519 private key is invalid.");
        }

        try
        {
            var localRouterId = node.GetRouterId();
            var peers = new Dictionary<RouterId, PrivacyPeer>();
            foreach (var configured in Peers)
            {
                var peer = configured.Validate(
                    isDevelopment,
                    AllowInsecureHttpPeerTransport);
                if (peer.RouterId == localRouterId || !peers.TryAdd(peer.RouterId, peer))
                {
                    throw new InvalidOperationException(
                        "PrivacyRouting peers must be unique and cannot contain the local router.");
                }
            }

            if (peers.Count == 0)
            {
                throw new InvalidOperationException(
                    "PrivacyRouting requires at least one explicitly pinned peer.");
            }

            return new PrivacyRoutingConfiguration(
                true,
                privateKey,
                publicKey,
                new Uri(publicPeerBaseUrl, PeerFramePath),
                peers,
                MaximumConcurrentRequests,
                RequestsPerMinute,
                TimeSpan.FromSeconds(RequestTimeoutSeconds),
                ReplyPaddingBlockBytes,
                ReplayCapacity,
                TimeSpan.FromSeconds(ReplayTtlSeconds));
        }
        catch
        {
            CryptographicOperations.ZeroMemory(privateKey);
            throw;
        }
    }

    internal static byte[] DecodeHex32(string value, string name)
    {
        if (value.Length != 64 || !value.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f'))
        {
            throw new InvalidOperationException($"{name} must be canonical 32-byte hex.");
        }

        var decoded = Convert.FromHexString(value);
        if (decoded.All(static item => item == 0))
        {
            throw new InvalidOperationException($"{name} cannot be all-zero.");
        }

        return decoded;
    }
}

public sealed class PrivacyPeerOptions
{
    public string RouterId { get; set; } = "";

    public string BaseUrl { get; set; } = "";

    public string CurrentSpkiSha256 { get; set; } = "";

    public string NextSpkiSha256 { get; set; } = "";

    internal PrivacyPeer Validate(
        bool isDevelopment,
        bool allowInsecureHttpPeerTransport)
    {
        if (!XNode.Core.RouterId.TryParse(RouterId, out var routerId)
            || !Uri.TryCreate(BaseUrl.Trim(), UriKind.Absolute, out var baseUrl)
            || baseUrl.Scheme != Uri.UriSchemeHttps
                && !(isDevelopment
                    && allowInsecureHttpPeerTransport
                    && baseUrl.Scheme == Uri.UriSchemeHttp)
            || !string.Equals(baseUrl.AbsolutePath, "/", StringComparison.Ordinal)
            || !string.IsNullOrEmpty(baseUrl.Query)
            || !string.IsNullOrEmpty(baseUrl.UserInfo)
            || !string.IsNullOrEmpty(baseUrl.Fragment))
        {
            throw new InvalidOperationException(
                "PrivacyRouting peer identity and HTTPS endpoint binding are invalid.");
        }

        var insecure = baseUrl.Scheme == Uri.UriSchemeHttp;
        byte[] current;
        byte[] next;
        if (insecure)
        {
            if (!string.IsNullOrWhiteSpace(CurrentSpkiSha256)
                || !string.IsNullOrWhiteSpace(NextSpkiSha256))
            {
                throw new InvalidOperationException(
                    "PrivacyRouting SPKI pins must be empty for Development insecure peers.");
            }

            current = [];
            next = [];
        }
        else
        {
            current = PrivacyRoutingOptions.DecodeHex32(
                CurrentSpkiSha256.Trim(),
                "PrivacyRouting current SPKI SHA-256");
            next = PrivacyRoutingOptions.DecodeHex32(
                NextSpkiSha256.Trim(),
                "PrivacyRouting next SPKI SHA-256");
            if (CryptographicOperations.FixedTimeEquals(current, next))
            {
                throw new InvalidOperationException(
                    "PrivacyRouting current and next SPKI pins must be distinct.");
            }
        }

        return new PrivacyPeer(
            routerId,
            new Uri(baseUrl, PrivacyRoutingOptions.PeerFramePath),
            current,
            next,
            isDevelopment);
    }
}

public sealed class PrivacyRoutingConfiguration : IDisposable
{
    public static PrivacyRoutingConfiguration Disabled { get; } = new(
        false, [], [], new Uri("https://disabled.invalid/"),
        new Dictionary<RouterId, PrivacyPeer>(), 1, 1,
        TimeSpan.FromSeconds(1), 1024, 1, TimeSpan.FromSeconds(1));

    public PrivacyRoutingConfiguration(
        bool enabled,
        byte[] privateKey,
        byte[] publicKey,
        Uri publicPeerEndpoint,
        IReadOnlyDictionary<RouterId, PrivacyPeer> peers,
        int maximumConcurrentRequests,
        int requestsPerMinute,
        TimeSpan requestTimeout,
        int replyPaddingBlockBytes,
        int replayCapacity,
        TimeSpan replayTtl)
    {
        Enabled = enabled;
        PrivateKey = privateKey;
        _publicKey = publicKey.ToArray();
        PublicPeerEndpoint = publicPeerEndpoint;
        Peers = new ReadOnlyDictionary<RouterId, PrivacyPeer>(
            peers.ToDictionary(static item => item.Key, static item => item.Value));
        MaximumConcurrentRequests = maximumConcurrentRequests;
        RequestsPerMinute = requestsPerMinute;
        RequestTimeout = requestTimeout;
        ReplyPaddingBlockBytes = replyPaddingBlockBytes;
        ReplayCapacity = replayCapacity;
        ReplayTtl = replayTtl;
    }

    public bool Enabled { get; }
    internal ReadOnlySpan<byte> PrivateKeySpan => PrivateKey;
    public byte[] PublicKey => _publicKey.ToArray();
    public Uri PublicPeerEndpoint { get; }
    public IReadOnlyDictionary<RouterId, PrivacyPeer> Peers { get; }
    public int MaximumConcurrentRequests { get; }
    public int RequestsPerMinute { get; }
    public TimeSpan RequestTimeout { get; }
    public int ReplyPaddingBlockBytes { get; }
    public int ReplayCapacity { get; }
    public TimeSpan ReplayTtl { get; }

    public void Dispose()
    {
        if (PrivateKey.Length != 0)
        {
            CryptographicOperations.ZeroMemory(PrivateKey);
        }
    }

    private byte[] PrivateKey { get; }
    private readonly byte[] _publicKey;
}

public sealed class PrivacyPeer
{
    private readonly byte[] _currentSpkiSha256;
    private readonly byte[] _nextSpkiSha256;

    public PrivacyPeer(
        RouterId routerId,
        Uri endpoint,
        ReadOnlySpan<byte> currentSpkiSha256,
        ReadOnlySpan<byte> nextSpkiSha256,
        bool allowPrivateResolvedAddresses)
    {
        RouterId = routerId;
        Endpoint = endpoint;
        _currentSpkiSha256 = currentSpkiSha256.ToArray();
        _nextSpkiSha256 = nextSpkiSha256.ToArray();
        AllowPrivateResolvedAddresses = allowPrivateResolvedAddresses;
    }

    public RouterId RouterId { get; }
    public Uri Endpoint { get; }
    public bool AllowPrivateResolvedAddresses { get; }
    internal ReadOnlySpan<byte> CurrentSpkiSha256 => _currentSpkiSha256;
    internal ReadOnlySpan<byte> NextSpkiSha256 => _nextSpkiSha256;
}
