using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Rebex.Security.Cryptography;
using XNode.Core;

namespace XNode;

public sealed record MailboxAuthorityForwardingAuthenticationHeaders(
    string SenderRouterId,
    string RecipientRouterId,
    long TimestampUnixMilliseconds,
    string Nonce,
    string Signature);

public static class MailboxAuthorityForwardingAuthenticator
{
    public const string SenderHeader = "Deep-Mailbox-Authority-Sender";
    public const string RecipientHeader = "Deep-Mailbox-Authority-Recipient";
    public const string TimestampHeader = "Deep-Mailbox-Authority-Timestamp";
    public const string NonceHeader = "Deep-Mailbox-Authority-Nonce";
    public const string SignatureHeader = "Deep-Mailbox-Authority-Signature";
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(2);

    private static ReadOnlySpan<byte> Magic => "MAF1"u8;

    public static MailboxAuthorityForwardingAuthenticationHeaders Sign(
        RouterId sender,
        RouterId recipient,
        string senderPrivateKeySeedHex,
        OnionOperation operation,
        ReadOnlySpan<byte> canonicalMau2,
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
                    "Mailbox authority forwarding key does not match the local router identity.");
            }

            var signature = signer.SignMessage(BuildTranscript(
                sender,
                recipient,
                operation,
                timestamp,
                nonce,
                canonicalMau2));
            return new MailboxAuthorityForwardingAuthenticationHeaders(
                sender.Value,
                recipient.Value,
                timestamp,
                Convert.ToHexStringLower(nonce),
                Convert.ToHexStringLower(signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    public static bool Verify(
        MailboxAuthorityForwardingAuthenticationHeaders headers,
        RouterId expectedRecipient,
        OnionOperation operation,
        ReadOnlySpan<byte> canonicalMau2,
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
            || !headers.Nonce.All(IsLowerHex)
            || headers.Signature.Length != 128
            || !headers.Signature.All(IsLowerHex))
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
                    operation,
                    headers.TimestampUnixMilliseconds,
                    nonce,
                    canonicalMau2),
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
        OnionOperation operation,
        long timestampUnixMilliseconds,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> canonicalMau2)
    {
        var route = Encoding.ASCII.GetBytes(
            MailboxAuthorityForwardingHttpContract.Route(operation));
        var transcript = new byte[4 + 32 + 32 + 1 + 32 + 8 + 16 + 32];
        Magic.CopyTo(transcript);
        sender.ToBytes().CopyTo(transcript, 4);
        recipient.ToBytes().CopyTo(transcript, 36);
        transcript[68] = checked((byte)operation);
        SHA256.HashData(route, transcript.AsSpan(69, 32));
        BinaryPrimitives.WriteInt64BigEndian(
            transcript.AsSpan(101, 8),
            timestampUnixMilliseconds);
        nonce.CopyTo(transcript.AsSpan(109, 16));
        SHA256.HashData(canonicalMau2, transcript.AsSpan(125, 32));
        return transcript;
    }

    private static bool IsLowerHex(char character) =>
        character is >= '0' and <= '9' or >= 'a' and <= 'f';
}

public sealed class MailboxAuthorityForwardingReplayGuard
{
    private readonly ConcurrentDictionary<string, long> _accepted =
        new(StringComparer.Ordinal);
    private readonly int _maximumEntries;
    private readonly TimeSpan _ttl;
    private long _lastPrunedAtUnixMilliseconds;

    public MailboxAuthorityForwardingReplayGuard(PrivacyRoutingConfiguration configuration)
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

        var key = string.Concat(sender.Value, ":", Convert.ToHexStringLower(nonce));
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
