using System.Text.Json;
using System.Security.Cryptography;
using Rebex.Security.Cryptography;

namespace XNode.Core.Mailbox;

public sealed record SignedMailboxReplicaRequest(
    string SenderRouterId,
    string RecipientRouterId,
    long TimestampUnixMs,
    string Nonce,
    EncryptedMailboxBlob Blob,
    string Signature);

public sealed record MailboxWriteReceipt(
    string StorageRouterId,
    string MailboxId,
    string BlobId,
    long ExpiresAtUnixMs,
    long StoredAtUnixMs,
    string Disposition,
    string Signature);

public static class MailboxReplicationProtocol
{
    public const string RequestVersion = "xpoint-mailbox-replica-v1";
    public const string ReceiptVersion = "xpoint-mailbox-receipt-v1";
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static SignedMailboxReplicaRequest SignRequest(
        RouterId sender,
        RouterId recipient,
        string privateKeySeedHex,
        EncryptedMailboxBlob blob,
        DateTimeOffset timestamp,
        string? nonce = null)
    {
        var unsigned = new SignedMailboxReplicaRequest(
            sender.Value,
            recipient.Value,
            timestamp.ToUnixTimeMilliseconds(),
            NormalizeOrCreateNonce(nonce),
            blob,
            "");
        return unsigned with
        {
            Signature = Sign(sender, privateKeySeedHex, BuildRequestPayload(unsigned))
        };
    }

    public static bool VerifyRequest(SignedMailboxReplicaRequest? request, DateTimeOffset now)
    {
        if (request is null
            || !RouterId.TryParse(request.SenderRouterId, out var sender)
            || !RouterId.TryParse(request.RecipientRouterId, out _)
            || request.Blob is null
            || !IsNonce(request.Nonce)
            || string.IsNullOrWhiteSpace(request.Signature)
            || !IsFresh(request.TimestampUnixMs, now))
        {
            return false;
        }

        return Verify(sender, request.Signature, BuildRequestPayload(request with { Signature = "" }));
    }

    public static string ComputeRequestFingerprint(SignedMailboxReplicaRequest request)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
        return Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
    }

    public static MailboxWriteReceipt SignReceipt(
        RouterId storageRouter,
        string privateKeySeedHex,
        EncryptedMailboxBlob blob,
        DateTimeOffset storedAt,
        MailboxPutDisposition disposition)
    {
        if (disposition is not (MailboxPutDisposition.Stored or MailboxPutDisposition.Duplicate))
        {
            throw new ArgumentOutOfRangeException(nameof(disposition));
        }

        var unsigned = new MailboxWriteReceipt(
            storageRouter.Value,
            blob.MailboxId,
            blob.BlobId,
            blob.ExpiresAtUnixMs,
            storedAt.ToUnixTimeMilliseconds(),
            disposition == MailboxPutDisposition.Stored ? "stored" : "duplicate",
            "");
        return unsigned with
        {
            Signature = Sign(storageRouter, privateKeySeedHex, BuildReceiptPayload(unsigned))
        };
    }

    public static bool VerifyReceipt(
        MailboxWriteReceipt? receipt,
        RouterId expectedStorageRouter,
        EncryptedMailboxBlob expectedBlob,
        DateTimeOffset now)
    {
        if (receipt is null
            || !RouterId.TryParse(receipt.StorageRouterId, out var storageRouter)
            || storageRouter != expectedStorageRouter
            || receipt.MailboxId != expectedBlob.MailboxId
            || receipt.BlobId != expectedBlob.BlobId
            || receipt.ExpiresAtUnixMs != expectedBlob.ExpiresAtUnixMs
            || receipt.Disposition is not ("stored" or "duplicate")
            || !IsFresh(receipt.StoredAtUnixMs, now)
            || string.IsNullOrWhiteSpace(receipt.Signature))
        {
            return false;
        }

        return Verify(storageRouter, receipt.Signature, BuildReceiptPayload(receipt with { Signature = "" }));
    }

    private static byte[] BuildRequestPayload(SignedMailboxReplicaRequest request) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = RequestVersion,
            senderRouterId = request.SenderRouterId,
            recipientRouterId = request.RecipientRouterId,
            timestampUnixMs = request.TimestampUnixMs,
            nonce = request.Nonce,
            mailboxId = request.Blob.MailboxId,
            blobId = request.Blob.BlobId,
            expiresAtUnixMs = request.Blob.ExpiresAtUnixMs,
            ciphertext = request.Blob.Ciphertext
        }, JsonOptions);

    private static byte[] BuildReceiptPayload(MailboxWriteReceipt receipt) =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = ReceiptVersion,
            storageRouterId = receipt.StorageRouterId,
            mailboxId = receipt.MailboxId,
            blobId = receipt.BlobId,
            expiresAtUnixMs = receipt.ExpiresAtUnixMs,
            storedAtUnixMs = receipt.StoredAtUnixMs,
            disposition = receipt.Disposition
        }, JsonOptions);

    private static string Sign(RouterId routerId, string privateKeySeedHex, byte[] payload)
    {
        var signer = new Ed25519();
        signer.FromSeed(DecodeFixedHex(privateKeySeedHex, RouterId.ByteLength));
        if (RouterId.FromBytes(signer.GetPublicKey()) != routerId)
        {
            throw new InvalidOperationException("Mailbox signer does not match the router id.");
        }

        return Convert.ToHexString(signer.SignMessage(payload)).ToLowerInvariant();
    }

    private static bool Verify(RouterId routerId, string signature, byte[] payload)
    {
        try
        {
            var verifier = new Ed25519();
            verifier.FromPublicKey(routerId.ToBytes());
            return verifier.VerifyMessage(payload, DecodeFixedHex(signature, 64));
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static string NormalizeOrCreateNonce(string? nonce)
    {
        var normalized = string.IsNullOrWhiteSpace(nonce)
            ? Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLowerInvariant()
            : nonce.Trim().ToLowerInvariant();
        if (!IsNonce(normalized))
        {
            throw new ArgumentException("Mailbox nonce must be 16-byte lowercase hex.", nameof(nonce));
        }

        return normalized;
    }

    private static bool IsNonce(string? nonce) =>
        nonce is { Length: 32 }
        && nonce.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsFresh(long timestampUnixMs, DateTimeOffset now)
    {
        try
        {
            return (now - DateTimeOffset.FromUnixTimeMilliseconds(timestampUnixMs)).Duration()
                <= MaximumClockSkew;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    private static byte[] DecodeFixedHex(string value, int expectedBytes)
    {
        var normalized = value.Trim();
        if (normalized.Length != expectedBytes * 2 || !normalized.All(Uri.IsHexDigit))
        {
            throw new ArgumentException($"Expected {expectedBytes}-byte hex value.", nameof(value));
        }

        return Convert.FromHexString(normalized);
    }
}
