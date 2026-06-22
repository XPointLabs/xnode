using System.Text.Json;
using Rebex.Security.Cryptography;

namespace XNode.Core;

public static class RelayContactSigner
{
    public const string Algorithm = "ed25519";
    public const string PayloadVersion = "deep-relay-contact-v1";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static RelayContact Sign(RelayContact contact, string privateKeySeedHex)
    {
        var seed = DecodeFixedHex(privateKeySeedHex, RouterId.ByteLength, nameof(privateKeySeedHex));
        var signer = new Ed25519();
        signer.FromSeed(seed);

        var publicKey = signer.GetPublicKey();
        var routerId = RouterId.FromBytes(publicKey);
        if (!string.Equals(contact.RouterId.Value, routerId.Value, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Relay contact router id must match the Ed25519 private key public key.");
        }

        var unsigned = contact with
        {
            RouterId = routerId,
            SignatureAlgorithm = Algorithm,
            Signature = ""
        };
        var signature = signer.SignMessage(BuildSigningPayload(unsigned));
        return unsigned with { Signature = Convert.ToHexString(signature).ToLowerInvariant() };
    }

    public static bool Verify(RelayContact contact)
    {
        if (!string.Equals(contact.SignatureAlgorithm, Algorithm, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(contact.Signature))
        {
            return false;
        }

        byte[] signature;
        try
        {
            signature = DecodeFixedHex(contact.Signature, 64, nameof(contact.Signature));
        }
        catch (ArgumentException)
        {
            return false;
        }

        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(contact.RouterId.ToBytes());
            var unsigned = contact with { Signature = "" };
            return verifier.VerifyMessage(BuildSigningPayload(unsigned), signature);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public static RouterId DeriveRouterId(string privateKeySeedHex)
    {
        var signer = new Ed25519();
        signer.FromSeed(DecodeFixedHex(privateKeySeedHex, RouterId.ByteLength, nameof(privateKeySeedHex)));
        return RouterId.FromBytes(signer.GetPublicKey());
    }

    private static byte[] BuildSigningPayload(RelayContact contact)
    {
        var payload = new RelayContactSigningPayload(
            PayloadVersion,
            contact.RouterId.Value,
            contact.PublicHost,
            contact.PublicIp ?? "",
            contact.PublicPort,
            contact.X25519PublicKey,
            contact.RpcEndpoint,
            contact.SignedAt.ToUnixTimeMilliseconds(),
            contact.ExpiresAt.ToUnixTimeMilliseconds(),
            contact.RouterVersion,
            contact.IsReachable,
            contact.Capabilities
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Order(StringComparer.Ordinal)
                .ToArray());
        return JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
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

    private sealed record RelayContactSigningPayload(
        string Version,
        string RouterId,
        string PublicHost,
        string PublicIp,
        int PublicPort,
        string X25519PublicKey,
        string RpcEndpoint,
        long SignedAtUnixMs,
        long ExpiresAtUnixMs,
        string RouterVersion,
        bool IsReachable,
        IReadOnlyList<string> Capabilities);
}
