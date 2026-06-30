using System.Text.Json;
using Rebex.Security.Cryptography;

namespace XNode.Core.Onion;

public sealed record SignedOnionPeerRequest(
    string SenderRouterId,
    long TimestampUnixMs,
    string Nonce,
    OnionRequest Request,
    string Signature);

public static class SignedOnionPeerRequestAuthenticator
{
    public const string PayloadVersion = "xpoint-onion-peer-v1";
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(2);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static SignedOnionPeerRequest Sign(
        RouterId sender,
        string privateKeySeedHex,
        OnionRequest request,
        DateTimeOffset timestamp,
        string? nonce = null)
    {
        var normalizedNonce = string.IsNullOrWhiteSpace(nonce)
            ? Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()
            : NormalizeNonce(nonce);
        var unsigned = new SignedOnionPeerRequest(
            sender.Value,
            timestamp.ToUnixTimeMilliseconds(),
            normalizedNonce,
            request,
            "");

        var signer = new Ed25519();
        signer.FromSeed(DecodeFixedHex(privateKeySeedHex, RouterId.ByteLength, nameof(privateKeySeedHex)));
        var derived = RouterId.FromBytes(signer.GetPublicKey());
        if (derived != sender)
        {
            throw new InvalidOperationException("Onion peer signer does not match the sender router id.");
        }

        var signature = signer.SignMessage(BuildSigningPayload(unsigned));
        return unsigned with { Signature = Convert.ToHexString(signature).ToLowerInvariant() };
    }

    public static bool Verify(SignedOnionPeerRequest request, DateTimeOffset now)
    {
        if (!TryValidateShape(request, now, out var sender))
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(sender.ToBytes());
            var signature = DecodeFixedHex(request.Signature, 64, nameof(request.Signature));
            return verifier.VerifyMessage(BuildSigningPayload(request with { Signature = "" }), signature);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static bool TryValidateShape(
        SignedOnionPeerRequest request,
        DateTimeOffset now,
        out RouterId sender)
    {
        sender = default;
        if (!RouterId.TryParse(request.SenderRouterId, out sender)
            || request.Request?.Envelope is null
            || string.IsNullOrWhiteSpace(request.Signature))
        {
            return false;
        }

        try
        {
            _ = NormalizeNonce(request.Nonce);
            var timestamp = DateTimeOffset.FromUnixTimeMilliseconds(request.TimestampUnixMs);
            return (now - timestamp).Duration() <= MaximumClockSkew;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static byte[] BuildSigningPayload(SignedOnionPeerRequest request)
    {
        var envelope = request.Request.Envelope;
        var payload = new SigningPayload(
            PayloadVersion,
            request.SenderRouterId,
            request.TimestampUnixMs,
            request.Nonce,
            envelope.Version,
            envelope.EphemeralPublicKey,
            envelope.Nonce,
            envelope.Ciphertext);
        return JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
    }

    private static string NormalizeNonce(string nonce)
    {
        var normalized = nonce.Trim().ToLowerInvariant();
        if (normalized.Length != 32 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Peer request nonce must be a 16-byte hex value.", nameof(nonce));
        }

        return normalized;
    }

    private static byte[] DecodeFixedHex(string value, int expectedBytes, string argumentName)
    {
        var normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
        }

        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.", argumentName);
        }

        return Convert.FromHexString(normalized);
    }

    private sealed record SigningPayload(
        string Version,
        string SenderRouterId,
        long TimestampUnixMs,
        string Nonce,
        string EnvelopeVersion,
        string EphemeralPublicKey,
        string EnvelopeNonce,
        string Ciphertext);
}
