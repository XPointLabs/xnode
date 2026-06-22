using System.Text.Json;
using System.Text.Json.Serialization;
using Sodium;

namespace XNode.Core.Onion;

public static class OnionCrypto
{
    public const string EnvelopeVersion = "deep-onion-v1";
    public const string ResponseVersion = "deep-onion-response-v1";
    public const string RelayLayerType = "relay";
    public const string StorageLayerType = "storage";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static OnionEnvelope EncryptForNode(byte[] recipientPublicKey, object plaintext)
    {
        if (recipientPublicKey.Length != 32)
        {
            throw new ArgumentException("X25519 recipient public key must be 32 bytes.", nameof(recipientPublicKey));
        }

        var keyPair = PublicKeyBox.GenerateKeyPair();
        var nonce = PublicKeyBox.GenerateNonce();
        var plaintextBytes = JsonSerializer.SerializeToUtf8Bytes(plaintext, JsonOptions);
        var ciphertext = PublicKeyBox.Create(plaintextBytes, nonce, keyPair.PrivateKey, recipientPublicKey);

        return new OnionEnvelope(
            EnvelopeVersion,
            Convert.ToBase64String(keyPair.PublicKey),
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(ciphertext));
    }

    public static OnionLayer DecryptForNode(OnionEnvelope envelope, byte[] recipientPrivateKey)
    {
        if (!string.Equals(envelope.Version, EnvelopeVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Unsupported onion envelope version.");
        }

        if (recipientPrivateKey.Length != 32)
        {
            throw new ArgumentException("X25519 recipient private key must be 32 bytes.", nameof(recipientPrivateKey));
        }

        var ephemeralPublicKey = Convert.FromBase64String(envelope.EphemeralPublicKey);
        var nonce = Convert.FromBase64String(envelope.Nonce);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var plaintext = PublicKeyBox.Open(ciphertext, nonce, recipientPrivateKey, ephemeralPublicKey);
        var layer = JsonSerializer.Deserialize<OnionLayer>(plaintext, JsonOptions);
        return layer ?? throw new InvalidOperationException("Onion layer plaintext is empty.");
    }

    public static OnionResponseEnvelope EncryptResponse(byte[] responsePublicKey, object payload)
    {
        if (responsePublicKey.Length != 32)
        {
            throw new ArgumentException("X25519 response public key must be 32 bytes.", nameof(responsePublicKey));
        }

        var keyPair = PublicKeyBox.GenerateKeyPair();
        var nonce = PublicKeyBox.GenerateNonce();
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        var ciphertext = PublicKeyBox.Create(payloadBytes, nonce, keyPair.PrivateKey, responsePublicKey);
        return new OnionResponseEnvelope(
            ResponseVersion,
            Convert.ToBase64String(keyPair.PublicKey),
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(ciphertext));
    }

    public static JsonElement DecryptResponse(OnionResponseEnvelope envelope, byte[] responsePrivateKey)
    {
        if (!string.Equals(envelope.Version, ResponseVersion, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Unsupported onion response version.");
        }

        var ephemeralPublicKey = Convert.FromBase64String(envelope.EphemeralPublicKey);
        var nonce = Convert.FromBase64String(envelope.Nonce);
        var ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        var plaintext = PublicKeyBox.Open(ciphertext, nonce, responsePrivateKey, ephemeralPublicKey);
        using var document = JsonDocument.Parse(plaintext);
        return document.RootElement.Clone();
    }

    public static OnionKeyMaterial DeriveNodeKeysFromEd25519Seed(string ed25519SeedHex)
    {
        var seed = DecodeFixedHex(ed25519SeedHex, 32, nameof(ed25519SeedHex));
        var ed25519KeyPair = PublicKeyAuth.GenerateKeyPair(seed);
        var x25519PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(ed25519KeyPair.PublicKey);
        var x25519PrivateKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(ed25519KeyPair.PrivateKey);
        return new OnionKeyMaterial(x25519PublicKey, x25519PrivateKey);
    }

    public static byte[] DecodeHex32(string value, string argumentName) => DecodeFixedHex(value, 32, argumentName);

    public static string Hex(byte[] value) => Convert.ToHexString(value).ToLowerInvariant();

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
}

public sealed record OnionKeyMaterial(byte[] PublicKey, byte[] PrivateKey);

public sealed record OnionEnvelope(
    string Version,
    string EphemeralPublicKey,
    string Nonce,
    string Ciphertext);

public sealed record OnionResponseEnvelope(
    string Version,
    string EphemeralPublicKey,
    string Nonce,
    string Ciphertext);

public sealed record OnionRequest(
    OnionEnvelope Envelope);

public sealed record OnionLayer(
    string Type,
    string? NextRouterId,
    string? NextRpcEndpoint,
    OnionEnvelope? Inner,
    string? StoragePath,
    JsonElement? Body,
    string? ResponsePublicKey);
