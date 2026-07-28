using System.Security.Cryptography;

namespace XNode.Core.Mailbox;

public sealed record EncryptedMailboxBlob(
    string MailboxId,
    string BlobId,
    long ExpiresAtUnixMs,
    string Ciphertext);

public static class EncryptedMailboxBlobValidator
{
    public static bool TryValidate(
        EncryptedMailboxBlob? blob,
        DateTimeOffset now,
        ReplicatedMailboxOptions options,
        out byte[] ciphertext,
        out string error,
        TimeSpan? minimumTtlOverride = null)
    {
        ciphertext = [];
        error = "invalid-mailbox-blob";
        if (blob is null
            || !IsCanonicalId(blob.MailboxId)
            || !IsCanonicalId(blob.BlobId)
            || string.IsNullOrWhiteSpace(blob.Ciphertext))
        {
            return false;
        }

        DateTimeOffset expiresAt;
        try
        {
            expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(blob.ExpiresAtUnixMs);
            ciphertext = Convert.FromBase64String(blob.Ciphertext);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentOutOfRangeException)
        {
            ciphertext = [];
            return false;
        }

        var ttl = expiresAt - now;
        if (ciphertext.Length == 0 || ciphertext.Length > options.MaxBlobBytes)
        {
            ciphertext = [];
            error = "mailbox-blob-size-rejected";
            return false;
        }

        if (!string.Equals(Convert.ToBase64String(ciphertext), blob.Ciphertext, StringComparison.Ordinal))
        {
            ciphertext = [];
            error = "mailbox-ciphertext-not-canonical";
            return false;
        }

        if (ttl < (minimumTtlOverride ?? options.MinimumTtl)
            || ttl > options.MaximumTtl)
        {
            ciphertext = [];
            error = "mailbox-blob-ttl-rejected";
            return false;
        }

        var digest = SHA256.HashData(ciphertext);
        if (!CryptographicOperations.FixedTimeEquals(
                digest,
                Convert.FromHexString(blob.BlobId)))
        {
            ciphertext = [];
            error = "mailbox-blob-digest-mismatch";
            return false;
        }

        error = "";
        return true;
    }

    public static bool IsCanonicalId(string? value) =>
        value is { Length: 64 }
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
