using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Rebex.Security.Cryptography;
using XNode.Core;

namespace XNode;

public sealed record PrivacyPeerAuthenticationHeaders(
    string SenderRouterId,
    string RecipientRouterId,
    long TimestampUnixMilliseconds,
    string Nonce,
    string Signature);

public static class PrivacyPeerAuthenticator
{
    public const string SenderHeader = "Deep-Peer-Sender";
    public const string RecipientHeader = "Deep-Peer-Recipient";
    public const string TimestampHeader = "Deep-Peer-Timestamp";
    public const string NonceHeader = "Deep-Peer-Nonce";
    public const string SignatureHeader = "Deep-Peer-Signature";
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(2);

    private static ReadOnlySpan<byte> Magic => "DPA1"u8;

    public static PrivacyPeerAuthenticationHeaders Sign(
        RouterId sender,
        RouterId recipient,
        string senderPrivateKeySeedHex,
        ReadOnlySpan<byte> frame,
        DateTimeOffset now)
    {
        var timestamp = now.ToUnixTimeMilliseconds();
        var nonce = RandomNumberGenerator.GetBytes(16);
        var seed = PrivacyRoutingOptions.DecodeHex32(
            senderPrivateKeySeedHex.Trim(),
            "Node Ed25519 private seed");
        try
        {
            var signer = new Ed25519();
            signer.FromSeed(seed);
            if (RouterId.FromBytes(signer.GetPublicKey()) != sender)
            {
                throw new InvalidOperationException(
                    "Privacy peer signing key does not match the local router identity.");
            }

            var signature = signer.SignMessage(BuildTranscript(
                sender, recipient, timestamp, nonce, frame));
            return new PrivacyPeerAuthenticationHeaders(
                sender.Value,
                recipient.Value,
                timestamp,
                Convert.ToHexString(nonce).ToLowerInvariant(),
                Convert.ToHexString(signature).ToLowerInvariant());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public static bool Verify(
        PrivacyPeerAuthenticationHeaders headers,
        RouterId expectedRecipient,
        ReadOnlySpan<byte> frame,
        DateTimeOffset now,
        out RouterId sender,
        out byte[] nonce)
    {
        sender = default;
        nonce = [];
        if (!RouterId.TryParse(headers.SenderRouterId, out sender)
            || !RouterId.TryParse(headers.RecipientRouterId, out var recipient)
            || !string.Equals(headers.SenderRouterId, sender.Value, StringComparison.Ordinal)
            || !string.Equals(headers.RecipientRouterId, recipient.Value, StringComparison.Ordinal)
            || recipient != expectedRecipient
            || headers.Nonce.Length != 32
            || !headers.Nonce.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f')
            || headers.Signature.Length != 128
            || !headers.Signature.All(static character =>
                character is >= '0' and <= '9' or >= 'a' and <= 'f'))
        {
            return false;
        }

        try
        {
            var signedAt = DateTimeOffset.FromUnixTimeMilliseconds(
                headers.TimestampUnixMilliseconds);
            if ((now - signedAt).Duration() > MaximumClockSkew)
            {
                return false;
            }

            nonce = Convert.FromHexString(headers.Nonce);
            var signature = Convert.FromHexString(headers.Signature);
            var verifier = new Ed25519();
            verifier.FromPublicKey(sender.ToBytes());
            return verifier.VerifyMessage(
                BuildTranscript(
                    sender,
                    recipient,
                    headers.TimestampUnixMilliseconds,
                    nonce,
                    frame),
                signature);
        }
        catch (Exception exception) when (
            exception is ArgumentException or ArgumentOutOfRangeException
                or InvalidOperationException)
        {
            nonce = [];
            return false;
        }
    }

    private static byte[] BuildTranscript(
        RouterId sender,
        RouterId recipient,
        long timestampUnixMilliseconds,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> frame)
    {
        var transcript = new byte[4 + 32 + 32 + 8 + 16 + 32];
        Magic.CopyTo(transcript);
        sender.ToBytes().CopyTo(transcript, 4);
        recipient.ToBytes().CopyTo(transcript, 36);
        BinaryPrimitives.WriteInt64BigEndian(
            transcript.AsSpan(68, 8), timestampUnixMilliseconds);
        nonce.CopyTo(transcript.AsSpan(76, 16));
        SHA256.HashData(frame, transcript.AsSpan(92, 32));
        return transcript;
    }
}

public sealed class PrivacyPeerReplayGuard
{
    private readonly ConcurrentDictionary<string, long> _accepted =
        new(StringComparer.Ordinal);
    private readonly int _maximumEntries;
    private readonly TimeSpan _ttl;
    private long _lastPrunedAtUnixMilliseconds;

    public PrivacyPeerReplayGuard(PrivacyRoutingConfiguration configuration)
    {
        _maximumEntries = configuration.ReplayCapacity;
        _ttl = configuration.ReplayTtl;
    }

    public bool TryAccept(
        RouterId sender,
        ReadOnlySpan<byte> nonce,
        long timestampUnixMilliseconds,
        DateTimeOffset now)
    {
        Prune(now);
        if (_accepted.Count >= _maximumEntries)
        {
            return false;
        }

        var key = string.Concat(
            sender.Value,
            ":",
            Convert.ToHexString(nonce).ToLowerInvariant());
        return _accepted.TryAdd(key, timestampUnixMilliseconds);
    }

    private void Prune(DateTimeOffset now)
    {
        var nowMilliseconds = now.ToUnixTimeMilliseconds();
        var prior = Interlocked.Read(ref _lastPrunedAtUnixMilliseconds);
        if (nowMilliseconds - prior < TimeSpan.FromMinutes(1).TotalMilliseconds
            || Interlocked.CompareExchange(
                ref _lastPrunedAtUnixMilliseconds,
                nowMilliseconds,
                prior) != prior)
        {
            return;
        }

        var cutoff = now.Subtract(_ttl).ToUnixTimeMilliseconds();
        foreach (var item in _accepted)
        {
            if (item.Value < cutoff)
            {
                _accepted.TryRemove(item.Key, out _);
            }
        }
    }
}
