using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.Mailbox;

namespace XNode.Core.PrivacyRouting;

public sealed class DurableOnionReplayStoreOptions
{
    public int MaximumEntries { get; init; } = 1_000_000;

    internal void Validate()
    {
        if (MaximumEntries is < 1 or > 5_000_000)
        {
            throw new InvalidOperationException("ONION replay store bounds are invalid.");
        }
    }
}

/// <summary>
/// Restart-safe replay admission. Begin is side-effect free; Commit atomically persists the
/// exact (network, owner, key, key-handle, boot, epoch, position, frame, replay-id) digest.
/// No TTL eviction is performed without a verified key-retirement capability.
/// </summary>
public sealed class DurableOnionReplayStore : IOnionDurableReplayStore, IDisposable
{
    private const int HeaderBytes = sizeof(uint) + sizeof(ulong) + sizeof(uint);
    private static readonly byte[] ScopeDomain = Encoding.UTF8.GetBytes("Deep/XPoint/V1/xnode-replay-scope\0");
    private static readonly byte[] EntryDomain = Encoding.UTF8.GetBytes("Deep/XPoint/V1/xnode-replay-entry\0");
    private static ReadOnlySpan<byte> Magic => "XONRPL01"u8;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly int maximumEntries;
    private readonly OnionDurableFile file;
    private readonly HashSet<OnionHash32> entries;
    private ulong generation;
    private int faulted;
    private int disposed;

    public DurableOnionReplayStore(
        string statePath,
        string protectionKeyPath,
        DurableOnionReplayStoreOptions? options = null)
        : this(statePath, protectionKeyPath, options, null, null, null)
    {
    }

    internal DurableOnionReplayStore(
        string statePath,
        string protectionKeyPath,
        DurableOnionReplayStoreOptions? options,
        IMailboxStorageSecurity? security,
        IMailboxDurabilityBarrier? durability,
        IOnionSecretFileReader? secretReader)
    {
        options ??= new DurableOnionReplayStoreOptions();
        options.Validate();
        maximumEntries = options.MaximumEntries;
        file = new OnionDurableFile(
            statePath,
            protectionKeyPath,
            Magic,
            checked(HeaderBytes + maximumEntries * 32),
            security,
            durability,
            secretReader);
        try
        {
            (generation, entries) = Load();
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    public ValueTask<IOnionDurableReplayTransaction> BeginAsync(
        OnionReplayScope scope,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();
        var scopeDigest = ComputeScopeDigest(scope);
        return ValueTask.FromResult<IOnionDurableReplayTransaction>(new Transaction(this, scopeDigest));
    }

    internal ValueTask<IOnionDurableReplayTransaction> BeginDigestForTestsAsync(
        ReadOnlyMemory<byte> scopeDigest,
        CancellationToken cancellationToken = default)
    {
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();
        _ = new OnionHash32(scopeDigest.Span);
        return ValueTask.FromResult<IOnionDurableReplayTransaction>(
            new Transaction(this, scopeDigest.ToArray()));
    }

    internal static byte[] ComputeScopeDigestForTests(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> owner,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> keyHandle,
        ReadOnlySpan<byte> bootId,
        ulong epoch,
        OnionReceivePosition position,
        ReadOnlySpan<byte> frameHash) =>
        ComputeScopeDigest(network, owner, key, keyHandle, bootId, epoch, position, frameHash);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        file.Dispose();
        gate.Dispose();
        entries.Clear();
    }

    private async ValueTask<OnionReplayCommitOutcome> CommitAsync(
        ReadOnlyMemory<byte> scopeDigest,
        ReadOnlyMemory<byte> replayId,
        CancellationToken cancellationToken)
    {
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();
        OnionHash32 entry;
        try
        {
            _ = new OnionHash32(scopeDigest.Span);
            _ = new OnionHash32(replayId.Span);
            entry = ComputeEntryDigest(scopeDigest.Span, replayId.Span);
        }
        catch (ArgumentException)
        {
            return OnionReplayCommitOutcome.Rejected;
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfUnavailable();
            cancellationToken.ThrowIfCancellationRequested();
            if (entries.Contains(entry))
            {
                return OnionReplayCommitOutcome.Replayed;
            }

            if (entries.Count >= maximumEntries || generation == ulong.MaxValue)
            {
                return OnionReplayCommitOutcome.Saturated;
            }

            entries.Add(entry);
            generation++;
            try
            {
                Save();
                return OnionReplayCommitOutcome.Committed;
            }
            catch
            {
                Volatile.Write(ref faulted, 1);
                return OnionReplayCommitOutcome.Ambiguous;
            }
        }
        finally
        {
            gate.Release();
        }
    }

    private static byte[] ComputeScopeDigest(OnionReplayScope scope)
    {
        var network = scope.NetworkId.ToArray();
        var owner = scope.RouterOwnerId.ToArray();
        var key = scope.KeyId.ToArray();
        var keyHandle = scope.KeyHandleId.ToArray();
        var bootId = scope.BootId.ToArray();
        var frame = scope.ExactFrameHash.ToArray();
        try
        {
            return ComputeScopeDigest(
                network,
                owner,
                key,
                keyHandle,
                bootId,
                scope.Epoch,
                scope.Position,
                frame);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(network);
            CryptographicOperations.ZeroMemory(owner);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(keyHandle);
            CryptographicOperations.ZeroMemory(bootId);
            CryptographicOperations.ZeroMemory(frame);
        }
    }

    private static byte[] ComputeScopeDigest(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> owner,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> keyHandle,
        ReadOnlySpan<byte> bootId,
        ulong epoch,
        OnionReceivePosition position,
        ReadOnlySpan<byte> frameHash)
    {
        _ = new OnionHash32(network);
        _ = new OnionHash32(owner);
        _ = new OnionHash32(key);
        _ = new OnionHash32(keyHandle);
        _ = new OnionHash32(bootId);
        _ = new OnionHash32(frameHash);
        if (position is < OnionReceivePosition.Ingress or > OnionReceivePosition.Exit)
        {
            throw new ArgumentOutOfRangeException(nameof(position));
        }

        Span<byte> numeric = stackalloc byte[9];
        BinaryPrimitives.WriteUInt64BigEndian(numeric, epoch);
        numeric[8] = (byte)position;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(ScopeDomain);
        hash.AppendData(network);
        hash.AppendData(owner);
        hash.AppendData(key);
        hash.AppendData(keyHandle);
        hash.AppendData(bootId);
        hash.AppendData(numeric);
        hash.AppendData(frameHash);
        CryptographicOperations.ZeroMemory(numeric);
        return hash.GetHashAndReset();
    }

    private static OnionHash32 ComputeEntryDigest(
        ReadOnlySpan<byte> scopeDigest,
        ReadOnlySpan<byte> replayId)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(EntryDomain);
        hash.AppendData(scopeDigest);
        hash.AppendData(replayId);
        var digest = hash.GetHashAndReset();
        try
        {
            return new OnionHash32(digest);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private (ulong Generation, HashSet<OnionHash32> Values) Load()
    {
        if (!file.Exists)
        {
            return (0, []);
        }

        var plaintext = file.Read();
        try
        {
            if (plaintext.Length < HeaderBytes
                || BinaryPrimitives.ReadUInt32BigEndian(plaintext) != 1)
            {
                throw new InvalidDataException("The ONION replay store format is invalid.");
            }

            var loadedGeneration = BinaryPrimitives.ReadUInt64BigEndian(plaintext.AsSpan(4, 8));
            var count = checked((int)BinaryPrimitives.ReadUInt32BigEndian(plaintext.AsSpan(12, 4)));
            if (count < 0
                || count > maximumEntries
                || plaintext.Length != HeaderBytes + count * 32
                || (count == 0) != (loadedGeneration == 0))
            {
                throw new InvalidDataException("The ONION replay store bounds are invalid.");
            }

            var loaded = new HashSet<OnionHash32>();
            OnionHash32? previous = null;
            for (var index = 0; index < count; index++)
            {
                OnionHash32 value;
                try
                {
                    value = new OnionHash32(plaintext.AsSpan(HeaderBytes + index * 32, 32));
                }
                catch (ArgumentException exception)
                {
                    throw new InvalidDataException("The ONION replay store contains an invalid entry.", exception);
                }

                if ((previous is { } prior && prior.CompareTo(value) >= 0) || !loaded.Add(value))
                {
                    throw new InvalidDataException("The ONION replay store is not canonical.");
                }

                previous = value;
            }

            return (loadedGeneration, loaded);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void Save()
    {
        var ordered = entries.Order().ToArray();
        var plaintext = new byte[checked(HeaderBytes + ordered.Length * 32)];
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(plaintext, 1);
            BinaryPrimitives.WriteUInt64BigEndian(plaintext.AsSpan(4, 8), generation);
            BinaryPrimitives.WriteUInt32BigEndian(plaintext.AsSpan(12, 4), checked((uint)ordered.Length));
            for (var index = 0; index < ordered.Length; index++)
            {
                ordered[index].Write(plaintext.AsSpan(HeaderBytes + index * 32, 32));
            }

            file.Write(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            Array.Clear(ordered);
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);
        if (Volatile.Read(ref faulted) != 0)
        {
            throw new InvalidOperationException("The ONION replay store is faulted after an ambiguous durability failure.");
        }
    }

    private sealed class Transaction : IOnionDurableReplayTransaction
    {
        private DurableOnionReplayStore? owner;
        private byte[]? scopeDigest;
        private int consumed;

        internal Transaction(DurableOnionReplayStore owner, byte[] scopeDigest)
        {
            this.owner = owner;
            this.scopeDigest = scopeDigest;
        }

        public async ValueTask<OnionReplayCommitOutcome> CommitAsync(
            ReadOnlyMemory<byte> replayId,
            CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref consumed, 1) != 0)
            {
                return OnionReplayCommitOutcome.Rejected;
            }

            var currentOwner = Interlocked.Exchange(ref owner, null);
            var currentScope = Interlocked.Exchange(ref scopeDigest, null);
            if (currentOwner is null || currentScope is null)
            {
                if (currentScope is not null)
                {
                    CryptographicOperations.ZeroMemory(currentScope);
                }

                return OnionReplayCommitOutcome.Rejected;
            }

            try
            {
                return await currentOwner.CommitAsync(currentScope, replayId, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(currentScope);
            }
        }

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref owner, null);
            var currentScope = Interlocked.Exchange(ref scopeDigest, null);
            if (currentScope is not null)
            {
                CryptographicOperations.ZeroMemory(currentScope);
            }

            return ValueTask.CompletedTask;
        }
    }
}
