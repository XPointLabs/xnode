using System.Security.Cryptography;
using System.Text.Json;
using Rebex.Security.Cryptography;

namespace XNode.Core.Session;

public static class SessionRpcResponseAuthenticator
{
    public const string Version = "xpoint-rpc-response-v1";
    public const string Algorithm = "ed25519";
    public static readonly TimeSpan MaximumAge = TimeSpan.FromMinutes(2);

    public static SessionRpcResponse Sign(
        SessionRpcRequest request,
        SessionRpcResponse response,
        RouterId responderRouterId,
        string privateKeySeedHex,
        DateTimeOffset issuedAt)
    {
        var signer = new Ed25519();
        signer.FromSeed(DecodeFixedHex(privateKeySeedHex, RouterId.ByteLength));
        if (RouterId.FromBytes(signer.GetPublicKey()) != responderRouterId)
        {
            throw new InvalidOperationException("RPC response signer does not match the responder router id.");
        }

        var signed = response with
        {
            Version = Version,
            ResponderRouterId = responderRouterId.Value,
            Method = request.Method,
            Nonce = request.Nonce ?? "",
            RequestPayloadSha256 = RpcCanonicalJson.Sha256Hex(request.Payload),
            IssuedAtUnixMs = issuedAt.ToUnixTimeMilliseconds(),
            OutcomeSha256 = OutcomeSha256(response),
            SignatureAlgorithm = Algorithm,
            Signature = ""
        };
        var signature = signer.SignMessage(BuildSigningPayload(signed));
        return signed with { Signature = Convert.ToHexString(signature).ToLowerInvariant() };
    }

    public static bool Verify(
        SessionRpcRequest request,
        SessionRpcResponse response,
        DateTimeOffset now,
        TimeSpan? maximumAge = null)
    {
        if (!HasExpectedShape(request, response, now, maximumAge ?? MaximumAge, out var responder))
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(responder.ToBytes());
            return verifier.VerifyMessage(
                BuildSigningPayload(response with { Signature = "" }),
                DecodeFixedHex(response.Signature!, 64));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException)
        {
            return false;
        }
    }

    private static bool HasExpectedShape(
        SessionRpcRequest request,
        SessionRpcResponse response,
        DateTimeOffset now,
        TimeSpan maximumAge,
        out RouterId responder)
    {
        responder = default;
        if (!string.Equals(response.Version, Version, StringComparison.Ordinal)
            || !string.Equals(response.SignatureAlgorithm, Algorithm, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(response.Id, request.Id, StringComparison.Ordinal)
            || !string.Equals(response.Method, request.Method, StringComparison.Ordinal)
            || !string.Equals(response.Nonce, request.Nonce ?? "", StringComparison.Ordinal)
            || !RouterId.TryParse(response.ResponderRouterId, out responder)
            || response.IssuedAtUnixMs is null
            || string.IsNullOrWhiteSpace(response.Signature))
        {
            return false;
        }

        DateTimeOffset issuedAt;
        try
        {
            issuedAt = DateTimeOffset.FromUnixTimeMilliseconds(response.IssuedAtUnixMs.Value);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        return (now - issuedAt).Duration() <= maximumAge
            && FixedTimeHexEquals(response.RequestPayloadSha256, RpcCanonicalJson.Sha256Hex(request.Payload), 32)
            && FixedTimeHexEquals(response.OutcomeSha256, OutcomeSha256(response), 32);
    }

    private static byte[] BuildSigningPayload(SessionRpcResponse response)
    {
        var payload = JsonSerializer.SerializeToElement(new SignaturePayload(
            response.Version!,
            response.ResponderRouterId!,
            response.Id,
            response.Method!,
            response.Nonce!,
            response.RequestPayloadSha256!,
            response.IssuedAtUnixMs!.Value,
            response.Success,
            response.OutcomeSha256!), SessionRpc.JsonOptions);
        return RpcCanonicalJson.Serialize(payload);
    }

    private static string OutcomeSha256(SessionRpcResponse response)
    {
        var outcome = response.Success
            ? ToJsonElement(response.Result)
            : JsonSerializer.SerializeToElement(response.Error, SessionRpc.JsonOptions);
        return RpcCanonicalJson.Sha256Hex(outcome);
    }

    private static JsonElement ToJsonElement(object? value)
    {
        return value is JsonElement element
            ? element
            : JsonSerializer.SerializeToElement(value, SessionRpc.JsonOptions);
    }

    private static bool FixedTimeHexEquals(string? actual, string expected, int expectedBytes)
    {
        try
        {
            var actualBytes = DecodeFixedHex(actual ?? "", expectedBytes);
            var expectedBytesValue = DecodeFixedHex(expected, expectedBytes);
            return CryptographicOperations.FixedTimeEquals(actualBytes, expectedBytesValue);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static byte[] DecodeFixedHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.", nameof(value));
        }

        return Convert.FromHexString(normalized);
    }

    private sealed record SignaturePayload(
        string Version,
        string ResponderRouterId,
        string RequestId,
        string Method,
        string Nonce,
        string RequestPayloadSha256,
        long IssuedAtUnixMs,
        bool Success,
        string OutcomeSha256);
}
