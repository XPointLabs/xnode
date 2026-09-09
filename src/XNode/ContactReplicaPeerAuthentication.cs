using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Rebex.Security.Cryptography;
using XNode.Core;

namespace XNode;

internal sealed record ContactReplicaAuthenticationHeaders(
    string SenderReplicaId,
    string RecipientReplicaId,
    long TimestampUnixMilliseconds,
    string Nonce,
    string Correlation,
    string Signature);

internal static class ContactReplicaPeerAuthenticator
{
    internal const string SenderHeader = "Deep-Contact-Replica-Sender";
    internal const string RecipientHeader = "Deep-Contact-Replica-Recipient";
    internal const string TimestampHeader = "Deep-Contact-Replica-Timestamp";
    internal const string NonceHeader = "Deep-Contact-Replica-Nonce";
    internal const string CorrelationHeader = "Deep-Contact-Replica-Correlation";
    internal const string SignatureHeader = "Deep-Contact-Replica-Signature";
    internal static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(2);
    private static ReadOnlySpan<byte> RequestMagic => "CRA1"u8;
    private static ReadOnlySpan<byte> ResponseMagic => "CRA2"u8;

    internal static ContactReplicaAuthenticationHeaders SignRequest(
        RouterId sender,
        RouterId recipient,
        string localPrivateSeedHex,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now) => Sign(
            RequestMagic,
            sender,
            recipient,
            localPrivateSeedHex,
            correlation32,
            exactBody,
            now);

    internal static ContactReplicaAuthenticationHeaders SignResponse(
        RouterId sender,
        RouterId recipient,
        string localPrivateSeedHex,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now) => Sign(
            ResponseMagic,
            sender,
            recipient,
            localPrivateSeedHex,
            correlation32,
            exactBody,
            now);

    internal static bool VerifyRequest(
        ContactReplicaAuthenticationHeaders headers,
        RouterId expectedRecipient,
        ReadOnlySpan<byte> expectedCorrelation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now,
        out RouterId sender,
        out byte[] nonce) => Verify(
            RequestMagic,
            headers,
            expectedRecipient,
            expectedCorrelation32,
            exactBody,
            now,
            out sender,
            out nonce);

    internal static bool VerifyResponse(
        ContactReplicaAuthenticationHeaders headers,
        RouterId expectedRecipient,
        RouterId expectedSender,
        ReadOnlySpan<byte> expectedCorrelation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now)
    {
        var valid = Verify(
            ResponseMagic,
            headers,
            expectedRecipient,
            expectedCorrelation32,
            exactBody,
            now,
            out var sender,
            out _);
        return valid && sender == expectedSender;
    }

    private static ContactReplicaAuthenticationHeaders Sign(
        ReadOnlySpan<byte> magic,
        RouterId sender,
        RouterId recipient,
        string localPrivateSeedHex,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now)
    {
        if (correlation32.Length != 32)
        {
            throw new ArgumentException("The contact replica correlation must be 32 bytes.", nameof(correlation32));
        }
        var seed = PrivacyRoutingOptions.DecodeHex32(
            localPrivateSeedHex.Trim(),
            "Contact replica local Ed25519 private seed");
        var nonce = RandomNumberGenerator.GetBytes(16);
        try
        {
            var signer = new Ed25519();
            signer.FromSeed(seed);
            if (RouterId.FromBytes(signer.GetPublicKey()) != sender)
            {
                throw new InvalidOperationException(
                    "The contact replica transport key does not match the local node identity.");
            }
            var timestamp = now.ToUnixTimeMilliseconds();
            var signature = signer.SignMessage(BuildTranscript(
                magic,
                sender,
                recipient,
                timestamp,
                nonce,
                correlation32,
                exactBody));
            return new ContactReplicaAuthenticationHeaders(
                sender.Value,
                recipient.Value,
                timestamp,
                Convert.ToHexStringLower(nonce),
                Convert.ToHexStringLower(correlation32),
                Convert.ToHexStringLower(signature));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    private static bool Verify(
        ReadOnlySpan<byte> magic,
        ContactReplicaAuthenticationHeaders headers,
        RouterId expectedRecipient,
        ReadOnlySpan<byte> expectedCorrelation32,
        ReadOnlySpan<byte> exactBody,
        DateTimeOffset now,
        out RouterId sender,
        out byte[] nonce)
    {
        sender = default;
        nonce = [];
        if (expectedCorrelation32.Length != 32
            || !RouterId.TryParse(headers.SenderReplicaId, out sender)
            || !RouterId.TryParse(headers.RecipientReplicaId, out var recipient)
            || sender == recipient
            || recipient != expectedRecipient
            || headers.Nonce.Length != 32
            || headers.Correlation.Length != 64
            || headers.Signature.Length != 128
            || !headers.Nonce.All(IsLowerHex)
            || !headers.Correlation.All(IsLowerHex)
            || !headers.Signature.All(IsLowerHex))
        {
            return false;
        }

        try
        {
            var signedAt = DateTimeOffset.FromUnixTimeMilliseconds(headers.TimestampUnixMilliseconds);
            var correlation = Convert.FromHexString(headers.Correlation);
            if ((now - signedAt).Duration() > MaximumClockSkew
                || !CryptographicOperations.FixedTimeEquals(correlation, expectedCorrelation32))
            {
                return false;
            }
            nonce = Convert.FromHexString(headers.Nonce);
            var signature = Convert.FromHexString(headers.Signature);
            var verifier = new Ed25519();
            verifier.FromPublicKey(sender.ToBytes());
            return verifier.VerifyMessage(
                BuildTranscript(
                    magic,
                    sender,
                    recipient,
                    headers.TimestampUnixMilliseconds,
                    nonce,
                    correlation,
                    exactBody),
                signature);
        }
        catch (Exception exception) when (exception is ArgumentException
            or ArgumentOutOfRangeException
            or CryptographicException
            or InvalidOperationException)
        {
            nonce = [];
            return false;
        }
    }

    private static byte[] BuildTranscript(
        ReadOnlySpan<byte> magic,
        RouterId sender,
        RouterId recipient,
        long timestamp,
        ReadOnlySpan<byte> nonce16,
        ReadOnlySpan<byte> correlation32,
        ReadOnlySpan<byte> exactBody)
    {
        var routeHash = SHA256.HashData(Encoding.ASCII.GetBytes(ContactReplicaHttpContract.Route));
        var bodyHash = SHA256.HashData(exactBody);
        var transcript = new byte[4 + 32 + 32 + 32 + 8 + 16 + 32 + 32];
        magic.CopyTo(transcript);
        sender.ToBytes().CopyTo(transcript, 4);
        recipient.ToBytes().CopyTo(transcript, 36);
        routeHash.CopyTo(transcript, 68);
        BinaryPrimitives.WriteInt64BigEndian(transcript.AsSpan(100), timestamp);
        nonce16.CopyTo(transcript.AsSpan(108));
        correlation32.CopyTo(transcript.AsSpan(124));
        bodyHash.CopyTo(transcript, 156);
        return transcript;
    }

    private static bool IsLowerHex(char value) =>
        value is >= '0' and <= '9' or >= 'a' and <= 'f';
}

internal sealed class ContactReplicaReplayGuard
{
    private readonly ConcurrentDictionary<string, long> accepted = new(StringComparer.Ordinal);
    private readonly object admissionGate = new();
    private readonly int capacity;
    private readonly TimeSpan ttl;
    private long lastPruned;

    public ContactReplicaReplayGuard(ContactServicePersistenceOptions options)
    {
        capacity = options.ReplayCapacity;
        ttl = options.ReplayTtl;
    }

    internal bool TryAccept(
        RouterId sender,
        ReadOnlySpan<byte> nonce,
        long timestamp,
        DateTimeOffset now)
    {
        lock (admissionGate)
        {
            Prune(now);
            if (accepted.Count >= capacity)
            {
                return false;
            }
            return accepted.TryAdd(
                string.Concat(sender.Value, ":", Convert.ToHexStringLower(nonce)),
                timestamp);
        }
    }

    private void Prune(DateTimeOffset now)
    {
        var current = now.ToUnixTimeMilliseconds();
        var prior = Interlocked.Read(ref lastPruned);
        if (current - prior < TimeSpan.FromMinutes(1).TotalMilliseconds
            || Interlocked.CompareExchange(ref lastPruned, current, prior) != prior)
        {
            return;
        }
        var cutoff = now.Subtract(ttl).ToUnixTimeMilliseconds();
        foreach (var item in accepted)
        {
            if (item.Value < cutoff)
            {
                accepted.TryRemove(item.Key, out _);
            }
        }
    }
}
