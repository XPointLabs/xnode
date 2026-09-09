using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;
using XNode.Core.Mailbox;
using XNode.Core.PrivacyRouting;

namespace XNode.Tests.Core;

public sealed class OnionDurableAdaptersTests
{
    [Fact]
    public async Task EntropyLedger_RestartRejectsDuplicate_AndBatchIsAtomic()
    {
        using var fixture = new Fixture();
        var first = Batch(Bytes(0x11), Bytes(0x12));
        using (var ledger = fixture.EntropyLedger())
        {
            Assert.Equal(OnionEntropyCommitOutcome.Committed, await ledger.CommitAsync(first, default));
        }

        using var restarted = fixture.EntropyLedger();
        Assert.Equal(OnionEntropyCommitOutcome.Duplicate, await restarted.CommitAsync(first, default));
        Assert.Equal(
            OnionEntropyCommitOutcome.Duplicate,
            await restarted.CommitAsync(Batch(Bytes(0x13), Bytes(0x12)), default));
        Assert.Equal(
            OnionEntropyCommitOutcome.Committed,
            await restarted.CommitAsync(Batch(Bytes(0x13)), default));
    }

    [Fact]
    public async Task EntropyLedger_ConcurrentReservationHasSingleWinner()
    {
        using var fixture = new Fixture();
        using var ledger = fixture.EntropyLedger();
        var batch = Batch(Bytes(0x21));
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 24).Select(
            _ => ledger.CommitAsync(batch, default).AsTask()));
        Assert.Single(outcomes, item => item == OnionEntropyCommitOutcome.Committed);
        Assert.Equal(23, outcomes.Count(item => item == OnionEntropyCommitOutcome.Duplicate));
    }

    [Fact]
    public async Task EntropyLedger_DiskFailureIsAmbiguousAndFaultsInstance()
    {
        using var fixture = new Fixture();
        using var ledger = fixture.EntropyLedger(new FailingDurability());
        Assert.Equal(
            OnionEntropyCommitOutcome.Ambiguous,
            await ledger.CommitAsync(Batch(Bytes(0x31)), default));
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await ledger.CommitAsync(Batch(Bytes(0x32)), default));
    }

    [Fact]
    public async Task EntropyAndReplayCapacityExhaustionFailsClosed()
    {
        using var fixture = new Fixture();
        using (var entropy = new DurableOnionEntropyUniquenessLedger(
                   fixture.EntropyPath,
                   fixture.ProtectionKeyPath,
                   new DurableOnionEntropyLedgerOptions
                   {
                       MaximumCommitments = 1,
                       MaximumBatchCommitments = 1
                   },
                   new NoOpSecurity(),
                   null,
                   null))
        {
            Assert.Equal(
                OnionEntropyCommitOutcome.Committed,
                await entropy.CommitAsync(Batch(Bytes(0x33)), default));
            Assert.Equal(
                OnionEntropyCommitOutcome.Rejected,
                await entropy.CommitAsync(Batch(Bytes(0x34)), default));
        }

        using var replay = new DurableOnionReplayStore(
            fixture.ReplayPath,
            fixture.ProtectionKeyPath,
            new DurableOnionReplayStoreOptions { MaximumEntries = 1 },
            new NoOpSecurity(),
            null,
            null);
        await using (var first = await replay.BeginDigestForTestsAsync(Bytes(0x35)))
        {
            Assert.Equal(
                OnionReplayCommitOutcome.Committed,
                await first.CommitAsync(Bytes(0x36), default));
        }
        await using (var second = await replay.BeginDigestForTestsAsync(Bytes(0x37)))
        {
            Assert.Equal(
                OnionReplayCommitOutcome.Saturated,
                await second.CommitAsync(Bytes(0x38), default));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EntropyLedger_CorruptOrWrongProtectionKeyFailsClosed(bool wrongKey)
    {
        using var fixture = new Fixture();
        using (var ledger = fixture.EntropyLedger())
        {
            Assert.Equal(
                OnionEntropyCommitOutcome.Committed,
                await ledger.CommitAsync(Batch(Bytes(0x41)), default));
        }

        if (wrongKey)
        {
            File.WriteAllBytes(fixture.ProtectionKeyPath, Bytes(0xee));
        }
        else
        {
            var state = File.ReadAllBytes(fixture.EntropyPath);
            state[^1] ^= 0x80;
            File.WriteAllBytes(fixture.EntropyPath, state);
        }

        Assert.Throws<InvalidDataException>(() => fixture.EntropyLedger());
    }

    [Fact]
    public async Task ReplayStore_RestartRejectsReplay_AndConcurrentCommitIsAtomic()
    {
        using var fixture = new Fixture();
        var scope = Bytes(0x51);
        var replay = Bytes(0x52);
        using (var store = fixture.ReplayStore())
        {
            await using var transaction = await store.BeginDigestForTestsAsync(scope);
            Assert.Equal(OnionReplayCommitOutcome.Committed, await transaction.CommitAsync(replay, default));
        }

        using var restarted = fixture.ReplayStore();
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 16).Select(async _ =>
        {
            await using var transaction = await restarted.BeginDigestForTestsAsync(scope);
            return await transaction.CommitAsync(replay, default);
        }));
        Assert.All(outcomes, item => Assert.Equal(OnionReplayCommitOutcome.Replayed, item));

        var freshReplay = Bytes(0x53);
        outcomes = await Task.WhenAll(Enumerable.Range(0, 16).Select(async _ =>
        {
            await using var transaction = await restarted.BeginDigestForTestsAsync(scope);
            return await transaction.CommitAsync(freshReplay, default);
        }));
        Assert.Single(outcomes, item => item == OnionReplayCommitOutcome.Committed);
        Assert.Equal(15, outcomes.Count(item => item == OnionReplayCommitOutcome.Replayed));
    }

    [Fact]
    public async Task ReplayStore_SeparatesEveryExposedReceiveScopeDimension()
    {
        using var fixture = new Fixture();
        using var store = fixture.ReplayStore();
        var baseline = new ScopeParts(
            Bytes(0x61), Bytes(0x62), Bytes(0x63), Bytes(0x64), Bytes(0x67), 7,
            OnionReceivePosition.Core, Bytes(0x65));
        var scopes = new[]
        {
            baseline,
            baseline with { Network = Bytes(0x71) },
            baseline with { Owner = Bytes(0x72) },
            baseline with { Key = Bytes(0x73) },
            baseline with { KeyHandle = Bytes(0x74) },
            baseline with { BootId = Bytes(0x76) },
            baseline with { Epoch = 8 },
            baseline with { Position = OnionReceivePosition.Exit },
            baseline with { Frame = Bytes(0x75) }
        };

        var replay = Bytes(0x66);
        foreach (var item in scopes)
        {
            var digest = DurableOnionReplayStore.ComputeScopeDigestForTests(
                item.Network,
                item.Owner,
                item.Key,
                item.KeyHandle,
                item.BootId,
                item.Epoch,
                item.Position,
                item.Frame);
            await using var transaction = await store.BeginDigestForTestsAsync(digest);
            Assert.Equal(OnionReplayCommitOutcome.Committed, await transaction.CommitAsync(replay, default));
        }
    }

    [Fact]
    public async Task ReplayStore_DiskFailureIsAmbiguousAndFaultsInstance()
    {
        using var fixture = new Fixture();
        using var store = fixture.ReplayStore(new FailingDurability());
        await using var transaction = await store.BeginDigestForTestsAsync(Bytes(0x81));
        Assert.Equal(
            OnionReplayCommitOutcome.Ambiguous,
            await transaction.CommitAsync(Bytes(0x82), default));
        Assert.Throws<InvalidOperationException>(() =>
            store.BeginDigestForTestsAsync(Bytes(0x83)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReplayStore_CorruptOrWrongProtectionKeyFailsClosed(bool wrongKey)
    {
        using var fixture = new Fixture();
        using (var store = fixture.ReplayStore())
        {
            await using var transaction = await store.BeginDigestForTestsAsync(Bytes(0x91));
            Assert.Equal(
                OnionReplayCommitOutcome.Committed,
                await transaction.CommitAsync(Bytes(0x92), default));
        }

        if (wrongKey)
        {
            File.WriteAllBytes(fixture.ProtectionKeyPath, Bytes(0xdd));
        }
        else
        {
            var state = File.ReadAllBytes(fixture.ReplayPath);
            state[20] ^= 0x40;
            File.WriteAllBytes(fixture.ReplayPath, state);
        }

        Assert.Throws<InvalidDataException>(() => fixture.ReplayStore());
    }

    [Fact]
    public async Task KeyVault_DerivesByOpaqueHandle_AndRejectsHandleMismatch()
    {
        using var fixture = new Fixture();
        var handle = Bytes(0xa1);
        var scalar = Bytes(0xa2);
        var peerScalar = Bytes(0xa3);
        var peerPublic = ScalarMult.Base(peerScalar);
        var wrappingKey = File.ReadAllBytes(fixture.WrappingKeyPath);
        try
        {
            FileOnionKeyAgreementVault.WriteSlotForTests(
                fixture.SlotDirectory, handle, handle, scalar, wrappingKey);
            using var vault = fixture.KeyVault();
            var authority = new OnionKeyAgreementAuthority(vault);
            var shared = await vault.DeriveX25519SharedSecretAsync(
                authority.BindKeyHandle(handle), peerPublic, default);
            var expected = ScalarMult.Mult(scalar, peerPublic);
            try
            {
                Assert.True(CryptographicOperations.FixedTimeEquals(expected, shared));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(expected);
                CryptographicOperations.ZeroMemory(shared);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(peerScalar);
            CryptographicOperations.ZeroMemory(peerPublic);
            CryptographicOperations.ZeroMemory(scalar);
        }

        var mismatchedFileHandle = Bytes(0xa4);
        wrappingKey = File.ReadAllBytes(fixture.WrappingKeyPath);
        try
        {
            FileOnionKeyAgreementVault.WriteSlotForTests(
                fixture.SlotDirectory, mismatchedFileHandle, handle, Bytes(0xa5), wrappingKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        using var mismatchVault = fixture.KeyVault();
        var mismatchAuthority = new OnionKeyAgreementAuthority(mismatchVault);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await mismatchVault.DeriveX25519SharedSecretAsync(
                mismatchAuthority.BindKeyHandle(mismatchedFileHandle), Bytes(0xa6), default));
    }

    [Fact]
    public async Task KeyVault_ProductionSlotProvisioningIsIdempotentAndRejectsKeyMismatch()
    {
        using var fixture = new Fixture();
        var handle = Bytes(0xa7);
        var scalar = Bytes(0xa8);
        FileOnionKeyAgreementVault.EnsureSlot(
            fixture.SlotDirectory,
            handle,
            scalar,
            fixture.WrappingKeyPath,
            new NoOpSecurity());
        FileOnionKeyAgreementVault.EnsureSlot(
            fixture.SlotDirectory,
            handle,
            scalar,
            fixture.WrappingKeyPath,
            new NoOpSecurity());

        using var vault = fixture.KeyVault();
        var authority = new OnionKeyAgreementAuthority(vault);
        var peerScalar = Bytes(0xa9);
        var peerPublic = ScalarMult.Base(peerScalar);
        var actual = await vault.DeriveX25519SharedSecretAsync(
            authority.BindKeyHandle(handle), peerPublic, default);
        var expected = ScalarMult.Mult(scalar, peerPublic);
        try
        {
            Assert.True(CryptographicOperations.FixedTimeEquals(expected, actual));
            Assert.Throws<CryptographicException>(() =>
                FileOnionKeyAgreementVault.EnsureSlot(
                    fixture.SlotDirectory,
                    handle,
                    Bytes(0xaa),
                    fixture.WrappingKeyPath,
                    new NoOpSecurity()));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(peerScalar);
            CryptographicOperations.ZeroMemory(peerPublic);
            CryptographicOperations.ZeroMemory(actual);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(scalar);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task KeyVault_CorruptOrWrongWrappingKeyFailsClosed(bool wrongKey)
    {
        using var fixture = new Fixture();
        var handle = Bytes(0xb1);
        var wrappingKey = File.ReadAllBytes(fixture.WrappingKeyPath);
        try
        {
            FileOnionKeyAgreementVault.WriteSlotForTests(
                fixture.SlotDirectory, handle, handle, Bytes(0xb2), wrappingKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
        }

        if (wrongKey)
        {
            File.WriteAllBytes(fixture.WrappingKeyPath, Bytes(0xbf));
        }
        else
        {
            var slot = Directory.GetFiles(fixture.SlotDirectory, "*.slot").Single();
            var bytes = File.ReadAllBytes(slot);
            bytes[^1] ^= 1;
            File.WriteAllBytes(slot, bytes);
        }

        using var vault = fixture.KeyVault();
        var authority = new OnionKeyAgreementAuthority(vault);
        await Assert.ThrowsAsync<CryptographicException>(async () =>
            await vault.DeriveX25519SharedSecretAsync(
                authority.BindKeyHandle(handle), Bytes(0xb3), default));
    }

    [Fact]
    public void SecretReaderBuffersAndVaultResidentWrappingKeyAreZeroized()
    {
        using var fixture = new Fixture();
        var reader = new TrackingSecretReader(Bytes(0xc1));
        var vault = new FileOnionKeyAgreementVault(
            fixture.SlotDirectory,
            fixture.WrappingKeyPath,
            null,
            new NoOpSecurity(),
            reader);
        Assert.All(reader.LastReturned!, item => Assert.Equal(0, item));
        Assert.Contains(vault.WrappingKeyForTests.ToArray(), item => item != 0);
        vault.Dispose();
        Assert.All(vault.WrappingKeyForTests.ToArray(), item => Assert.Equal(0, item));
    }

    private static OnionEntropyCommitmentBatch Batch(params byte[][] commitments)
    {
        var constructor = typeof(OnionEntropyCommitmentBatch).GetConstructors(
                BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(item => item.GetParameters().Length == 2);
        return (OnionEntropyCommitmentBatch)constructor.Invoke([false, commitments]);
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();

    private sealed record ScopeParts(
        byte[] Network,
        byte[] Owner,
        byte[] Key,
        byte[] KeyHandle,
        byte[] BootId,
        ulong Epoch,
        OnionReceivePosition Position,
        byte[] Frame);

    private sealed class Fixture : IDisposable
    {
        private readonly string root = Path.Combine(
            Path.GetTempPath(), "xnode-onion-adapters-" + Guid.NewGuid().ToString("N"));

        internal Fixture()
        {
            Directory.CreateDirectory(root);
            File.WriteAllBytes(ProtectionKeyPath, Bytes(0xd1));
            File.WriteAllBytes(WrappingKeyPath, Bytes(0xd2));
        }

        internal string ProtectionKeyPath => Path.Combine(root, "state.key");
        internal string WrappingKeyPath => Path.Combine(root, "vault.key");
        internal string EntropyPath => Path.Combine(root, "entropy.state");
        internal string ReplayPath => Path.Combine(root, "replay.state");
        internal string SlotDirectory => Path.Combine(root, "slots");

        internal DurableOnionEntropyUniquenessLedger EntropyLedger(
            IMailboxDurabilityBarrier? durability = null) => new(
                EntropyPath,
                ProtectionKeyPath,
                new DurableOnionEntropyLedgerOptions { MaximumCommitments = 1_000 },
                new NoOpSecurity(),
                durability,
                null);

        internal DurableOnionReplayStore ReplayStore(
            IMailboxDurabilityBarrier? durability = null) => new(
                ReplayPath,
                ProtectionKeyPath,
                new DurableOnionReplayStoreOptions { MaximumEntries = 1_000 },
                new NoOpSecurity(),
                durability,
                null);

        internal FileOnionKeyAgreementVault KeyVault() => new(
            SlotDirectory,
            WrappingKeyPath,
            null,
            new NoOpSecurity(),
            null);

        public void Dispose()
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    private sealed class NoOpSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }

    private sealed class FailingDurability : IMailboxDurabilityBarrier
    {
        public void FlushFileAndParentDirectory(string path) { }
        public void FlushParentDirectory(string deletedPath) { }
        public void ReplaceFile(string temporaryPath, string finalPath) =>
            throw new IOException("Injected atomic replace failure.");
    }

    private sealed class TrackingSecretReader(byte[] value) : IOnionSecretFileReader
    {
        internal byte[]? LastReturned { get; private set; }

        public byte[] ReadSecret(string path, int exactBytes)
        {
            LastReturned = value.ToArray();
            return LastReturned;
        }
    }
}
