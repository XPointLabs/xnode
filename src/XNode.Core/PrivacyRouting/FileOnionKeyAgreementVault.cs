using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;
using XNode.Core.Mailbox;

namespace XNode.Core.PrivacyRouting;

public sealed class FileOnionKeyAgreementVaultOptions
{
    public int MaximumKeySlots { get; init; } = 4_096;

    internal void Validate()
    {
        if (MaximumKeySlots is < 1 or > 65_536)
        {
            throw new InvalidOperationException("ONION key-vault bounds are invalid.");
        }
    }
}

/// <summary>
/// Opaque-handle X25519 adapter backed by authenticated encrypted key slots.
/// The public surface accepts only paths, opaque handles and peer public keys;
/// private scalars never enter options, configuration, logs or return values.
/// </summary>
public sealed class FileOnionKeyAgreementVault : IOnionKeyAgreementVault, IDisposable
{
    private const int HandleBytes = 32;
    private const int ScalarBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int HeaderBytes = 8 + sizeof(uint) + NonceBytes;
    private const int PlaintextBytes = HandleBytes + ScalarBytes;
    private const int SlotBytes = HeaderBytes + PlaintextBytes + TagBytes;
    private static ReadOnlySpan<byte> Magic => "XONKEY01"u8;
    private readonly string slotDirectory;
    private readonly int maximumKeySlots;
    private readonly IMailboxStorageSecurity security;
    private readonly byte[] wrappingKey;
    private int disposed;

    public FileOnionKeyAgreementVault(
        string slotDirectory,
        string wrappingKeyPath,
        FileOnionKeyAgreementVaultOptions? options = null)
        : this(slotDirectory, wrappingKeyPath, options, null, null)
    {
    }

    internal FileOnionKeyAgreementVault(
        string slotDirectory,
        string wrappingKeyPath,
        FileOnionKeyAgreementVaultOptions? options,
        IMailboxStorageSecurity? security,
        IOnionSecretFileReader? secretReader)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slotDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(wrappingKeyPath);
        options ??= new FileOnionKeyAgreementVaultOptions();
        options.Validate();
        this.slotDirectory = Path.GetFullPath(slotDirectory);
        maximumKeySlots = options.MaximumKeySlots;
        this.security = security ?? new MailboxStorageSecurity();
        secretReader ??= new OnionSecretFileReader();
        this.security.SecureDirectory(this.slotDirectory);

        var keyPath = Path.GetFullPath(wrappingKeyPath);
        if (!File.Exists(keyPath))
        {
            throw new FileNotFoundException("The ONION key-vault wrapping key is unavailable.");
        }

        this.security.ValidateSecureFile(keyPath);
        var loaded = secretReader.ReadSecret(keyPath, 32);
        try
        {
            wrappingKey = loaded.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(loaded);
        }

        try
        {
            ValidateSlotInventory();
        }
        catch
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
            throw;
        }
    }

    public ValueTask<byte[]> DeriveX25519SharedSecretAsync(
        OnionKeyHandle keyHandle,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(keyHandle);
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();

        var handle = keyHandle.Id.ToArray();
        var peer = peerPublicKey.ToArray();
        byte[]? envelope = null;
        byte[]? plaintext = null;
        byte[]? scalar = null;
        try
        {
            ValidateNonZero32(handle, "opaque key handle");
            ValidateNonZero32(peer, "X25519 peer public key");
            var slotPath = Path.Combine(slotDirectory, Convert.ToHexString(handle).ToLowerInvariant() + ".slot");
            envelope = ReadSlot(slotPath);
            plaintext = DecryptSlot(envelope, handle, wrappingKey);
            if (!CryptographicOperations.FixedTimeEquals(plaintext.AsSpan(0, HandleBytes), handle))
            {
                throw new CryptographicException("The ONION key slot does not match its opaque handle.");
            }

            scalar = plaintext.AsSpan(HandleBytes, ScalarBytes).ToArray();
            ValidateNonZero32(scalar, "X25519 private scalar");
            cancellationToken.ThrowIfCancellationRequested();
            byte[] shared;
            try
            {
                shared = ScalarMult.Mult(scalar, peer);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                throw new CryptographicException("The ONION key agreement failed closed.", exception);
            }

            if (shared.Length != 32 || IsZero(shared))
            {
                CryptographicOperations.ZeroMemory(shared);
                throw new CryptographicException("The ONION key agreement produced an invalid result.");
            }

            return ValueTask.FromResult(shared);
        }
        catch (FileNotFoundException exception)
        {
            throw new CryptographicException("The requested ONION opaque key handle is unavailable.", exception);
        }
        catch (InvalidDataException exception)
        {
            throw new CryptographicException("The requested ONION key slot is invalid.", exception);
        }
        catch (CryptographicException exception)
        {
            throw new CryptographicException("The requested ONION key slot could not be used.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(handle);
            CryptographicOperations.ZeroMemory(peer);
            if (envelope is not null) CryptographicOperations.ZeroMemory(envelope);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (scalar is not null) CryptographicOperations.ZeroMemory(scalar);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }
    }

    internal ReadOnlySpan<byte> WrappingKeyForTests => wrappingKey;

    internal static void EnsureSlot(
        string slotDirectory,
        ReadOnlySpan<byte> handle,
        ReadOnlySpan<byte> privateScalar,
        string wrappingKeyPath,
        IMailboxStorageSecurity? security = null,
        IMailboxDurabilityBarrier? durability = null,
        IOnionSecretFileReader? secretReader = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(slotDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(wrappingKeyPath);
        ValidateNonZero32(handle, nameof(handle));
        ValidateNonZero32(privateScalar, nameof(privateScalar));
        security ??= new MailboxStorageSecurity();
        durability ??= new MailboxDurabilityBarrier();
        secretReader ??= new OnionSecretFileReader();

        var directory = Path.GetFullPath(slotDirectory);
        var keyPath = Path.GetFullPath(wrappingKeyPath);
        security.SecureDirectory(directory);
        if (!File.Exists(keyPath))
        {
            throw new FileNotFoundException("The ONION key-vault wrapping key is unavailable.");
        }
        security.ValidateSecureFile(keyPath);
        var wrappingKey = secretReader.ReadSecret(keyPath, 32);
        byte[]? envelope = null;
        byte[]? plaintext = null;
        try
        {
            var finalPath = Path.Combine(
                directory,
                Convert.ToHexString(handle).ToLowerInvariant() + ".slot");
            if (File.Exists(finalPath))
            {
                security.SecureFile(finalPath);
                envelope = File.ReadAllBytes(finalPath);
                plaintext = DecryptSlot(envelope, handle, wrappingKey);
                if (!CryptographicOperations.FixedTimeEquals(
                        plaintext.AsSpan(0, HandleBytes),
                        handle)
                    || !CryptographicOperations.FixedTimeEquals(
                        plaintext.AsSpan(HandleBytes, ScalarBytes),
                        privateScalar))
                {
                    throw new CryptographicException(
                        "The existing ONION key slot does not match the configured key capability.");
                }
                return;
            }

            envelope = CreateSlotEnvelope(handle, privateScalar, wrappingKey);
            var temporaryPath = finalPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
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
                durability.ReplaceFile(temporaryPath, finalPath);
                security.SecureFile(finalPath);
                durability.FlushFileAndParentDirectory(finalPath);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    durability.DeleteFile(temporaryPath);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
            if (envelope is not null) CryptographicOperations.ZeroMemory(envelope);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal static void WriteSlotForTests(
        string slotDirectory,
        ReadOnlySpan<byte> fileHandle,
        ReadOnlySpan<byte> embeddedHandle,
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> wrappingKey)
    {
        ValidateNonZero32(fileHandle, nameof(fileHandle));
        ValidateNonZero32(embeddedHandle, nameof(embeddedHandle));
        ValidateNonZero32(privateScalar, nameof(privateScalar));
        ValidateNonZero32(wrappingKey, nameof(wrappingKey));
        Directory.CreateDirectory(slotDirectory);
        var envelope = CreateSlotEnvelope(fileHandle, privateScalar, wrappingKey, embeddedHandle);
        try
        {
            File.WriteAllBytes(
                Path.Combine(slotDirectory, Convert.ToHexString(fileHandle).ToLowerInvariant() + ".slot"),
                envelope);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(envelope);
        }
    }

    private static byte[] CreateSlotEnvelope(
        ReadOnlySpan<byte> fileHandle,
        ReadOnlySpan<byte> privateScalar,
        ReadOnlySpan<byte> wrappingKey,
        ReadOnlySpan<byte> embeddedHandle = default)
    {
        if (embeddedHandle.IsEmpty)
        {
            embeddedHandle = fileHandle;
        }
        var plaintext = new byte[PlaintextBytes];
        var envelope = new byte[SlotBytes];
        try
        {
            embeddedHandle.CopyTo(plaintext);
            privateScalar.CopyTo(plaintext.AsSpan(HandleBytes));
            Magic.CopyTo(envelope);
            BinaryPrimitives.WriteUInt32BigEndian(envelope.AsSpan(8, 4), 1);
            RandomNumberGenerator.Fill(envelope.AsSpan(12, NonceBytes));
            using var aes = new AesGcm(wrappingKey, TagBytes);
            aes.Encrypt(
                envelope.AsSpan(12, NonceBytes),
                plaintext,
                envelope.AsSpan(HeaderBytes, PlaintextBytes),
                envelope.AsSpan(HeaderBytes + PlaintextBytes, TagBytes),
                fileHandle);
            return envelope;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(envelope);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private byte[] ReadSlot(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128,
            FileOptions.SequentialScan);
        if (stream.Length != SlotBytes)
        {
            throw new InvalidDataException("The ONION key slot has an invalid length.");
        }

        security.SecureFile(path);
        var bytes = new byte[SlotBytes];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static byte[] DecryptSlot(
        ReadOnlySpan<byte> envelope,
        ReadOnlySpan<byte> expectedHandle,
        ReadOnlySpan<byte> key)
    {
        if (envelope.Length != SlotBytes
            || !envelope[..8].SequenceEqual(Magic)
            || BinaryPrimitives.ReadUInt32BigEndian(envelope.Slice(8, 4)) != 1)
        {
            throw new InvalidDataException("The ONION key slot format is invalid.");
        }

        var plaintext = new byte[PlaintextBytes];
        try
        {
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(
                envelope.Slice(12, NonceBytes),
                envelope.Slice(HeaderBytes, PlaintextBytes),
                envelope.Slice(HeaderBytes + PlaintextBytes, TagBytes),
                plaintext,
                expectedHandle);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
    }

    private void ValidateSlotInventory()
    {
        var slots = Directory.EnumerateFiles(slotDirectory, "*.slot", SearchOption.TopDirectoryOnly)
            .Take(maximumKeySlots + 1)
            .ToArray();
        if (slots.Length > maximumKeySlots)
        {
            throw new InvalidDataException("The ONION key-vault slot bound is exceeded.");
        }

        foreach (var slot in slots)
        {
            var name = Path.GetFileNameWithoutExtension(slot);
            if (name.Length != 64 || !name.All(static item => item is >= '0' and <= '9' or >= 'a' and <= 'f'))
            {
                throw new InvalidDataException("The ONION key-vault contains a non-canonical slot name.");
            }

            if (new FileInfo(slot).Length != SlotBytes)
            {
                throw new InvalidDataException("The ONION key-vault contains an invalid slot.");
            }
        }
    }

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

    private static void ValidateNonZero32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || IsZero(value))
        {
            throw new ArgumentException("A nonzero 32-byte value is required.", name);
        }
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
