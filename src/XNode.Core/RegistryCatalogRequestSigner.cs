using System.Security.Cryptography;
using System.Text.Json;
using Rebex.Security.Cryptography;

namespace XNode.Core;

public static class RegistryCatalogRequestSigner
{
    public const string NodeIdHeader = "X-XPoint-Node-Id";
    public const string TimestampHeader = "X-XPoint-Timestamp";
    public const string NonceHeader = "X-XPoint-Nonce";
    public const string SignatureHeader = "X-XPoint-Signature";
    private const string PayloadVersion = "xpoint-registry-catalog-v1";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static void Sign(
        HttpRequestMessage request,
        RouterNodeOptions nodeOptions,
        DateTimeOffset now)
    {
        var signer = new Ed25519();
        signer.FromSeed(DecodeHex(nodeOptions.GetEd25519PrivateKey(), 32));
        var nodeId = Convert.ToHexString(signer.GetPublicKey()).ToLowerInvariant();
        if (!string.Equals(nodeId, nodeOptions.RouterId, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Registry catalog signer does not match the configured router id.");
        }

        var timestampUnixMs = now.ToUnixTimeMilliseconds();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var payload = new CatalogRequestPayload(
            PayloadVersion,
            request.Method.Method.ToUpperInvariant(),
            GetRequestPath(request.RequestUri),
            nodeId,
            timestampUnixMs,
            nonce);
        var signature = signer.SignMessage(JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions));

        request.Headers.Add(NodeIdHeader, nodeId);
        request.Headers.Add(TimestampHeader, timestampUnixMs.ToString(System.Globalization.CultureInfo.InvariantCulture));
        request.Headers.Add(NonceHeader, nonce);
        request.Headers.Add(SignatureHeader, Convert.ToHexString(signature).ToLowerInvariant());
    }

    private static string GetRequestPath(Uri? uri)
    {
        if (uri is null)
        {
            return "/";
        }
        if (uri.IsAbsoluteUri)
        {
            return uri.AbsolutePath;
        }

        var value = uri.OriginalString;
        var queryIndex = value.IndexOf('?');
        return queryIndex >= 0 ? value[..queryIndex] : value;
    }

    private static byte[] DecodeHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.");
        }
        return Convert.FromHexString(normalized);
    }

    private sealed record CatalogRequestPayload(
        string Version,
        string Method,
        string Path,
        string NodeId,
        long TimestampUnixMs,
        string Nonce);
}
