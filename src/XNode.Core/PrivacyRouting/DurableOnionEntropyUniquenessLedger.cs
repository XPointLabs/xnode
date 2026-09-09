using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using XNode.Core.Mailbox;

namespace XNode.Core.PrivacyRouting;

public sealed class DurableOnionEntropyLedgerOptions
{
    public int MaximumCommitments { get; init; } = 1_000_000;
    public int MaximumBatchCommitments { get; init; } = 16;

    internal void Validate()
    {
        if (MaximumCommitments is < 1 or > 5_000_000
            || MaximumBatchCommitments is < 1 or > 64
            || MaximumBatchCommitments > MaximumCommitments)
        {
            throw new InvalidOperationException("ONION entropy ledger bounds are invalid.");
        }
    }
}

/// <summary>
/// Durable all-or-nothing reservation of protocol-produced entropy commitments.
/// Entries are deliberately never time-evicted: the boundary supplies no proof that every
/// key which could make an old commitment relevant has been retired. Capacity exhaustion
/// therefore fails closed and requires an operator-managed, verified key-epoch cutover.
/// </summary>
public sealed class DurableOnionEntropyUniquenessLedger
    : IOnionEntropyUniquenessLedger, IDisposable
{
    private const int HeaderBytes = sizeof(uint) + sizeof(ulong) + sizeof(uint);
    private static ReadOnlySpan<byte> Magic => "XONENT01"u8;
    private readonly SemaphoreSlim gate = new(1, 1);
    private readonly int maximumCommitments;
    private readonly int maximumBatchCommitments;
    private readonly OnionDurableFile file;
    private readonly HashSet<OnionHash32> commitments;
    private ulong generation;
    private int faulted;
    private int disposed;

    public DurableOnionEntropyUniquenessLedger(
        string statePath,
        string protectionKeyPath,
        DurableOnionEntropyLedgerOptions? options = null)
        : this(statePath, protectionKeyPath, options, null, null, null)
    {
    }

    internal DurableOnionEntropyUniquenessLedger(
        string statePath,
        string protectionKeyPath,
        DurableOnionEntropyLedgerOptions? options,
        IMailboxStorageSecurity? security,
        IMailboxDurabilityBarrier? durability,
        IOnionSecretFileReader? secretReader)
    {
        options ??= new DurableOnionEntropyLedgerOptions();
        options.Validate();
        maximumCommitments = options.MaximumCommitments;
        maximumBatchCommitments = options.MaximumBatchCommitments;
        file = new OnionDurableFile(
            statePath,
            protectionKeyPath,
            Magic,
            checked(HeaderBytes + maximumCommitments * 32),
            security,
            durability,
            secretReader);
        try
        {
            (generation, commitments) = Load();
        }
        catch
        {
            file.Dispose();
            throw;
        }
    }

    public async ValueTask<OnionEntropyCommitOutcome> CommitAsync(
        OnionEntropyCommitmentBatch batch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(batch);
        ThrowIfUnavailable();
        cancellationToken.ThrowIfCancellationRequested();

        var values = batch.Commitments;
        if (values.Count is < 1 || values.Count > maximumBatchCommitments)
        {
            return OnionEntropyCommitOutcome.Rejected;
        }

        var candidate = new OnionHash32[values.Count];
        try
        {
            var unique = new HashSet<OnionHash32>();
            for (var index = 0; index < values.Count; index++)
            {
                try
                {
                    candidate[index] = new OnionHash32(values[index].Span);
                }
                catch (ArgumentException)
                {
                    return OnionEntropyCommitOutcome.Rejected;
                }

                if (!unique.Add(candidate[index]))
                {
                    return OnionEntropyCommitOutcome.Duplicate;
                }
            }

            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfUnavailable();
                cancellationToken.ThrowIfCancellationRequested();
                if (candidate.Any(commitments.Contains))
                {
                    return OnionEntropyCommitOutcome.Duplicate;
                }

                if (commitments.Count > maximumCommitments - candidate.Length
                    || generation == ulong.MaxValue)
                {
                    return OnionEntropyCommitOutcome.Rejected;
                }

                foreach (var value in candidate)
                {
                    commitments.Add(value);
                }

                generation++;
                try
                {
                    Save();
                    return OnionEntropyCommitOutcome.Committed;
                }
                catch
                {
                    Volatile.Write(ref faulted, 1);
                    return OnionEntropyCommitOutcome.Ambiguous;
                }
            }
            finally
            {
                gate.Release();
            }
        }
        finally
        {
            Array.Clear(candidate);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        file.Dispose();
        gate.Dispose();
        commitments.Clear();
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
                throw new InvalidDataException("The ONION entropy ledger format is invalid.");
            }

            var loadedGeneration = BinaryPrimitives.ReadUInt64BigEndian(plaintext.AsSpan(4, 8));
            var count = checked((int)BinaryPrimitives.ReadUInt32BigEndian(plaintext.AsSpan(12, 4)));
            if (count < 0
                || count > maximumCommitments
                || plaintext.Length != HeaderBytes + count * 32
                || (count == 0) != (loadedGeneration == 0))
            {
                throw new InvalidDataException("The ONION entropy ledger bounds are invalid.");
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
                    throw new InvalidDataException("The ONION entropy ledger contains an invalid commitment.", exception);
                }

                if (previous is { } prior && prior.CompareTo(value) >= 0 || !loaded.Add(value))
                {
                    throw new InvalidDataException("The ONION entropy ledger is not canonical.");
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
        var ordered = commitments.Order().ToArray();
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
            throw new InvalidOperationException("The ONION entropy ledger is faulted after an ambiguous durability failure.");
        }
    }
}
