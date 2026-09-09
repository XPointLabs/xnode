using System.Buffers.Binary;
using System.Security.Cryptography;
using XNode.Core.Mailbox;

namespace XNode.Core.PrivacyRouting;

internal interface IOnionSecretFileReader
{
    byte[] ReadSecret(string path, int exactBytes);
}

internal sealed class OnionSecretFileReader : IOnionSecretFileReader
{
    public byte[] ReadSecret(string path, int exactBytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1,
            FileOptions.SequentialScan);
        if (stream.Length != exactBytes)
        {
            throw new InvalidDataException("An ONION secret file has an invalid length.");
        }

        var secret = new byte[exactBytes];
        stream.ReadExactly(secret);
        if (IsZero(secret))
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new InvalidDataException("An ONION secret file contains an invalid value.");
        }

        return secret;
    }

    private static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte aggregate = 0;
        foreach (var item in value)
        {
            aggregate |= item;
        }

        return aggregate == 0;
    }
}

internal sealed class OnionDurableFile : IDisposable
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int HeaderBytes = 8 + sizeof(uint) + sizeof(uint) + NonceBytes;
    private readonly string path;
    private readonly byte[] magic;
    private readonly int maximumPlaintextBytes;
    private readonly IMailboxStorageSecurity security;
    private readonly IMailboxDurabilityBarrier durability;
    private readonly byte[] protectionKey;
    private readonly FileStream lifetimeLease;
    private bool disposed;

    internal OnionDurableFile(
        string statePath,
        string protectionKeyPath,
        ReadOnlySpan<byte> formatMagic8,
        int maximumPlaintextBytes,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null,
        IOnionSecretFileReader? secretReader = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(protectionKeyPath);
        if (formatMagic8.Length != 8 || maximumPlaintextBytes < 16)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumPlaintextBytes));
        }

        path = Path.GetFullPath(statePath);
        var keyPath = Path.GetFullPath(protectionKeyPath);
        if (string.Equals(
                path,
                keyPath,
                OperatingSystem.IsWindows()
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal))
        {
            throw new ArgumentException("ONION state and protection key paths must be distinct.");
        }

        magic = formatMagic8.ToArray();
        this.maximumPlaintextBytes = maximumPlaintextBytes;
        this.security = security ?? new MailboxStorageSecurity();
        this.durability = durability ?? new MailboxDurabilityBarrier();
        secretReader ??= new OnionSecretFileReader();

        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("The ONION state path has no parent directory.", nameof(statePath));
        this.security.SecureDirectory(directory);
        if (!File.Exists(keyPath))
        {
            throw new FileNotFoundException("The ONION state protection key is unavailable.");
        }

        this.security.SecureFile(keyPath);
        var loadedKey = secretReader.ReadSecret(keyPath, 32);
        try
        {
            protectionKey = loadedKey.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(loadedKey);
        }

        try
        {
            var lockPath = path + ".lock";
            lifetimeLease = new FileStream(
                lockPath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None,
                1,
                FileOptions.WriteThrough);
            this.security.SecureFile(lockPath);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(protectionKey);
            throw;
        }
    }

    internal bool Exists
    {
        get
        {
            ThrowIfDisposed();
            return File.Exists(path);
        }
    }

    internal byte[] Read()
    {
        ThrowIfDisposed();
        var maximumEnvelopeBytes = checked(HeaderBytes + maximumPlaintextBytes + TagBytes);
        byte[] envelope;
        using (var stream = new FileStream(
                   path,
                   FileMode.Open,
                   FileAccess.Read,
                   FileShare.Read,
                   4096,
                   FileOptions.SequentialScan))
        {
            if (stream.Length < HeaderBytes + TagBytes || stream.Length > maximumEnvelopeBytes)
            {
                throw new InvalidDataException("The protected ONION state has an invalid length.");
            }

            envelope = new byte[checked((int)stream.Length)];
            stream.ReadExactly(envelope);
        }

        try
        {
            if (!envelope.AsSpan(0, 8).SequenceEqual(magic)
                || BinaryPrimitives.ReadUInt32BigEndian(envelope.AsSpan(8, 4)) != 1)
            {
                throw new InvalidDataException("The protected ONION state format is invalid.");
            }

            var plaintextLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                envelope.AsSpan(12, 4)));
            if (plaintextLength < 0
                || plaintextLength > maximumPlaintextBytes
                || envelope.Length != HeaderBytes + plaintextLength + TagBytes)
            {
                throw new InvalidDataException("The protected ONION state bounds are invalid.");
            }

            var plaintext = new byte[plaintextLength];
            try
            {
                using var aes = new AesGcm(protectionKey, TagBytes);
                aes.Decrypt(
                    envelope.AsSpan(16, NonceBytes),
                    envelope.AsSpan(HeaderBytes, plaintextLength),
                    envelope.AsSpan(HeaderBytes + plaintextLength, TagBytes),
                    plaintext,
                    envelope.AsSpan(0, HeaderBytes));
                return plaintext;
            }
            catch (CryptographicException exception)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new InvalidDataException(
                    "The protected ONION state failed authentication.",
                    exception);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    internal void Write(ReadOnlySpan<byte> plaintext)
    {
        ThrowIfDisposed();
        if (plaintext.Length > maximumPlaintextBytes)
        {
            throw new InvalidOperationException("The protected ONION state exceeds its configured bound.");
        }

        var envelope = new byte[checked(HeaderBytes + plaintext.Length + TagBytes)];
        magic.CopyTo(envelope, 0);
        BinaryPrimitives.WriteUInt32BigEndian(envelope.AsSpan(8, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(envelope.AsSpan(12, 4), checked((uint)plaintext.Length));
        RandomNumberGenerator.Fill(envelope.AsSpan(16, NonceBytes));
        try
        {
            using (var aes = new AesGcm(protectionKey, TagBytes))
            {
                aes.Encrypt(
                    envelope.AsSpan(16, NonceBytes),
                    plaintext,
                    envelope.AsSpan(HeaderBytes, plaintext.Length),
                    envelope.AsSpan(HeaderBytes + plaintext.Length, TagBytes),
                    envelope.AsSpan(0, HeaderBytes));
            }

            var temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var stream = new FileStream(
                           temporaryPath,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           4096,
                           FileOptions.WriteThrough))
                {
                    stream.Write(envelope);
                    stream.Flush(flushToDisk: true);
                }

                security.SecureFile(temporaryPath);
                durability.FlushFileAndParentDirectory(temporaryPath);
                durability.ReplaceFile(temporaryPath, path);
                security.SecureFile(path);
                durability.FlushFileAndParentDirectory(path);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    CryptographicOperations.ZeroMemory(envelope);
                    try
                    {
                        durability.DeleteFile(temporaryPath);
                    }
                    catch
                    {
                        // The primary persistence failure remains authoritative. The random,
                        // authenticated temporary file contains no plaintext state.
                    }
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        lifetimeLease.Dispose();
        CryptographicOperations.ZeroMemory(protectionKey);
    }

    internal ReadOnlySpan<byte> ProtectionKeyForTests => protectionKey;

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(disposed, this);
}
