using Deep.Protocol.DeepExtension.MailboxCapabilities;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.Tests.Core;

public sealed class MailboxClientCanonicalOutcomeStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"xnode-mailbox-client-outcomes-{Guid.NewGuid():N}");

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public void Restart_ReturnsDefensiveExactCanonicalSuccess(
        MailboxAuthenticatedOperation operation)
    {
        var key = Key(0x11, 7, 0x21);
        var canonical = CanonicalSuccess(
            operation,
            retrieveLength: 70 * 1024);
        using (var store = Store())
        using (var reservation = store.Reserve(
                   key,
                   operation,
                   retainUntilUnixSeconds: 2_000,
                   maximumCanonicalBytes: canonical.Length))
        {
            var written = store.PutSuccess(reservation, canonical);
            Assert.Equal(canonical, written.CanonicalBytes.ToArray());

            var callerCopy = written.CanonicalBytes.ToArray();
            callerCopy[^1] ^= 0xff;
            Assert.Equal(canonical, store.ReadRequired(key, operation).CanonicalBytes.ToArray());
        }

        using var restarted = Store();
        var recovered = restarted.ReadRequired(key, operation);
        Assert.Equal(MailboxClientCanonicalOutcomeKind.Success, recovered.Kind);
        Assert.Equal(operation, recovered.Operation);
        Assert.Equal(2_000UL, recovered.RetainUntilUnixSeconds);
        Assert.Equal(canonical, recovered.CanonicalBytes.ToArray());
        Assert.Equal(1, restarted.Diagnostics.EntryCount);
        Assert.Equal(canonical.Length, restarted.Diagnostics.CanonicalBytes);
    }

    [Fact]
    public void ExactOneMiBSuccessIsAllowed_AndLargerOutcomeIsRejectedBeforeWrite()
    {
        var maximum = CanonicalRetrievePage(MailboxClientLimits.MaximumPageBytes);
        using var store = Store(maximumBytes: MailboxClientLimits.MaximumPageBytes + 4096L);
        using (var reservation = store.Reserve(
                   Key(0x12, 1, 0x22),
                   MailboxAuthenticatedOperation.Retrieve,
                   2_000,
                   maximum.Length))
        {
            Assert.Equal(
                maximum,
                store.PutSuccess(reservation, maximum).CanonicalBytes.ToArray());
        }

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            store.Reserve(
                Key(0x13, 1, 0x23),
                MailboxAuthenticatedOperation.Retrieve,
                2_000,
                MailboxClientLimits.MaximumPageBytes + 1));
    }

    [Fact]
    public void TaggedTerminalOutcome_IsFixedCoarseAndRestartSafe()
    {
        var key = Key(0x14, 2, 0x24);
        byte[] canonical;
        using (var store = Store())
        using (var reservation = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   maximumCanonicalBytes: 64))
        {
            var written = store.PutTerminal(
                reservation,
                MailboxClientTerminalOutcome.AuthorizationRejected);
            canonical = written.CanonicalBytes.ToArray();
            Assert.Equal(MailboxClientCanonicalOutcomeKind.Terminal, written.Kind);
            Assert.Equal(
                MailboxClientTerminalOutcome.AuthorizationRejected,
                written.Terminal);
            Assert.Equal("MTO1", System.Text.Encoding.ASCII.GetString(canonical, 0, 4));
            Assert.Equal(16, canonical.Length);
        }

        using var restarted = Store();
        var recovered = restarted.ReadRequired(
            key,
            MailboxAuthenticatedOperation.Store);
        Assert.Equal(canonical, recovered.CanonicalBytes.ToArray());
        Assert.Equal(
            MailboxClientTerminalOutcome.AuthorizationRejected,
            recovered.Terminal);
    }

    [Fact]
    public void IdempotentPutAllowsExactBytes_AndRejectsEveryConflict()
    {
        var key = Key(0x15, 3, 0x25);
        var canonical = CanonicalQuorum();
        using var store = Store();
        using (var first = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   canonical.Length))
        {
            _ = store.PutSuccess(first, canonical);
        }

        using (var retry = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   canonical.Length))
        {
            Assert.Equal(
                canonical,
                store.PutSuccess(retry, canonical).CanonicalBytes.ToArray());
        }

        var changed = canonical.ToArray();
        changed[^1] ^= 0xff;
        using (var conflict = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   changed.Length))
        {
            Assert.Throws<MailboxClientCanonicalOutcomeConflictException>(() =>
                store.PutSuccess(conflict, changed));
        }

        Assert.Throws<MailboxClientCanonicalOutcomeConflictException>(() =>
            store.Reserve(
                key,
                MailboxAuthenticatedOperation.Retrieve,
                2_000,
                canonical.Length));
        Assert.Throws<MailboxClientCanonicalOutcomeConflictException>(() =>
            store.Reserve(
                key,
                MailboxAuthenticatedOperation.Store,
                2_001,
                canonical.Length));
    }

    [Fact]
    public void MissingIndexedFileCannotBeReplacedByConflictingOutcome()
    {
        var key = Key(0x35, 13, 0x45);
        var original = CanonicalQuorum();
        var conflicting = original.ToArray();
        conflicting[^1] ^= 0xff;
        using (var store = Store())
        {
            using (var first = store.Reserve(
                       key,
                       MailboxAuthenticatedOperation.Store,
                       2_000,
                       original.Length))
            {
                _ = store.PutSuccess(first, original);
            }

            File.Delete(Assert.Single(Directory.EnumerateFiles(
                OutcomeDirectory(),
                "*.outcome")));
            using var retry = store.Reserve(
                key,
                MailboxAuthenticatedOperation.Store,
                2_000,
                conflicting.Length);
            Assert.Throws<MailboxClientCanonicalOutcomeConflictException>(() =>
                store.PutSuccess(retry, conflicting));
            Assert.Empty(Directory.EnumerateFiles(
                OutcomeDirectory(),
                "*.outcome"));
        }

        using var restarted = Store();
        Assert.Throws<MailboxClientCanonicalOutcomeMissingException>(() =>
            restarted.ReadRequired(
                key,
                MailboxAuthenticatedOperation.Store));
    }

    [Fact]
    public void MissingCorruptDigestAndOperationMismatch_FailClosed()
    {
        var key = Key(0x16, 4, 0x26);
        var canonical = CanonicalRetrievePage(1024);
        using (var store = Store())
        using (var reservation = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Retrieve,
                   2_000,
                   canonical.Length))
        {
            _ = store.PutSuccess(reservation, canonical);
            Assert.Throws<MailboxClientCanonicalOutcomeConflictException>(() =>
                store.ReadRequired(key, MailboxAuthenticatedOperation.Store));

            var persisted = Assert.Single(Directory.EnumerateFiles(
                OutcomeDirectory(),
                "*.outcome"));
            File.Delete(persisted);
            Assert.Throws<MailboxClientCanonicalOutcomeMissingException>(() =>
                store.ReadRequired(key, MailboxAuthenticatedOperation.Retrieve));
        }

        using (var replacement = Store())
        using (var reservation = replacement.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Retrieve,
                   2_000,
                   canonical.Length))
        {
            _ = replacement.PutSuccess(reservation, canonical);
        }

        var path = Assert.Single(Directory.EnumerateFiles(
            OutcomeDirectory(),
            "*.outcome"));
        var original = File.ReadAllBytes(path);
        var metadataTampered = original.ToArray();
        metadataTampered[15] ^= 0x01;
        File.WriteAllBytes(path, metadataTampered);
        Assert.Throws<InvalidDataException>(() => Store());

        var payloadTampered = original.ToArray();
        payloadTampered[^1] ^= 0xff;
        File.WriteAllBytes(path, payloadTampered);
        Assert.Throws<InvalidDataException>(() => Store());
    }

    [Fact]
    public void EntryAndByteReservations_AreChargedBeforeWriteAndReleasedExactly()
    {
        var canonical = CanonicalQuorum();
        var payloadBytes = canonical.Length;
        var options = new MailboxClientCanonicalOutcomeStoreOptions
        {
            MaximumEntries = 1,
            MaximumBytes = MailboxClientCanonicalOutcomeStore.HeaderLength + payloadBytes
        };
        using var store = Store(options);
        using (var held = store.Reserve(
                   Key(0x17, 5, 0x27),
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   payloadBytes))
        {
            Assert.Equal(1, store.Diagnostics.ReservedEntries);
            Assert.Throws<MailboxClientCanonicalOutcomeCapacityException>(() =>
                store.Reserve(
                    Key(0x18, 5, 0x28),
                    MailboxAuthenticatedOperation.Store,
                    2_000,
                    16));
        }

        Assert.Equal(0, store.Diagnostics.ReservedEntries);
        var key = Key(0x19, 5, 0x29);
        using (var reservation = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   payloadBytes))
        {
            _ = store.PutSuccess(reservation, canonical);
        }

        Assert.Equal(1, store.Diagnostics.EntryCount);
        Assert.Throws<MailboxClientCanonicalOutcomeCapacityException>(() =>
            store.Reserve(
                Key(0x1a, 5, 0x2a),
                MailboxAuthenticatedOperation.Store,
                2_000,
                16));
    }

    [Theory]
    [InlineData(MailboxAuthenticatedOperation.Store)]
    [InlineData(MailboxAuthenticatedOperation.Retrieve)]
    [InlineData(MailboxAuthenticatedOperation.Ack)]
    public void MalformedOrNonCanonicalSuccessIsRejectedAndReservationIsReleased(
        MailboxAuthenticatedOperation operation)
    {
        var canonical = CanonicalSuccess(operation, retrieveLength: 1024);
        var malformed = canonical.ToArray();
        malformed[operation == MailboxAuthenticatedOperation.Retrieve ? 6 : 5] = 1;
        var options = new MailboxClientCanonicalOutcomeStoreOptions
        {
            MaximumEntries = 1,
            MaximumBytes = MailboxClientCanonicalOutcomeStore.HeaderLength
                           + canonical.Length
        };
        using var store = Store(options);
        using (var reservation = store.Reserve(
                   Key(0x20, 10, 0x30),
                   operation,
                   2_000,
                   canonical.Length))
        {
            Assert.Throws<ArgumentException>(() =>
                store.PutSuccess(reservation, malformed));
        }

        Assert.Equal(0, store.Diagnostics.ReservedEntries);
        using var replacement = store.Reserve(
            Key(0x21, 10, 0x31),
            operation,
            2_000,
            canonical.Length);
        Assert.Equal(
            canonical,
            store.PutSuccess(replacement, canonical).CanonicalBytes.ToArray());
    }

    [Fact]
    public void StartupRejectsCumulativeByteQuotaBeforeAcceptingIndex()
    {
        var canonical = CanonicalQuorum();
        using (var store = Store())
        {
            for (var index = 0; index < 2; index++)
            {
                using var reservation = store.Reserve(
                    Key((byte)(0x22 + index), 11, (byte)(0x32 + index)),
                    MailboxAuthenticatedOperation.Store,
                    2_000,
                    canonical.Length);
                _ = store.PutSuccess(reservation, canonical);
            }
        }

        var persistedBytes = Directory
            .EnumerateFiles(OutcomeDirectory(), "*.outcome")
            .Sum(static path => new FileInfo(path).Length);
        var constrained = new MailboxClientCanonicalOutcomeStoreOptions
        {
            MaximumEntries = 2,
            MaximumBytes = persistedBytes - 1
        };
        Assert.Throws<InvalidDataException>(() => Store(constrained));
    }

    [Fact]
    public void CollectionNeverRemovesBeforeRetainUntil_AndReleasesBothQuotasAtBoundary()
    {
        var key = Key(0x1b, 6, 0x2b);
        var canonical = CanonicalQuorum();
        using var store = Store();
        using (var reservation = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   canonical.Length))
        {
            _ = store.PutSuccess(reservation, canonical);
        }

        Assert.Equal(0, store.CollectExpiredForTestsOnly(1_999, 10));
        Assert.True(store.TryRead(key, MailboxAuthenticatedOperation.Store, out _));
        Assert.Equal(0, store.CollectExpiredForTestsOnly(2_000, 10));
        Assert.True(store.TryRead(key, MailboxAuthenticatedOperation.Store, out _));
        Assert.Equal(1, store.CollectExpiredForTestsOnly(2_001, 10));
        Assert.False(store.TryRead(key, MailboxAuthenticatedOperation.Store, out _));
        Assert.Equal(0, store.Diagnostics.EntryCount);
        Assert.Equal(0, store.Diagnostics.CanonicalBytes);
    }

    [Fact]
    public void DirectoryLeaseIsExclusiveAndCleanBreakSchemaRejectsUnknownFiles()
    {
        using (var owner = Store())
        {
            Assert.Throws<InvalidOperationException>(() => Store());
        }

        Directory.CreateDirectory(OutcomeDirectory());
        File.WriteAllBytes(
            Path.Combine(OutcomeDirectory(), $"{new string('a', 64)}.outcome"),
            "MCO0"u8.ToArray());
        Assert.Throws<InvalidDataException>(() => Store());
    }

    [Fact]
    public void WriteFaultsRespectTheDurableCommitBoundary()
    {
        var beforeKey = Key(0x1c, 7, 0x2c);
        var canonical = CanonicalRetrievePage(70 * 1024);
        Assert.Throws<MailboxClientCanonicalOutcomePersistenceException>(() =>
        {
            using var store = Store(faults: new ThrowOnceFaults(
                MailboxClientCanonicalOutcomeFaultPoint.BeforeReplace));
            using var reservation = store.Reserve(
                beforeKey,
                MailboxAuthenticatedOperation.Retrieve,
                2_000,
                canonical.Length);
            _ = store.PutSuccess(reservation, canonical);
        });
        using (var recovered = Store())
        {
            Assert.False(recovered.TryRead(
                beforeKey,
                MailboxAuthenticatedOperation.Retrieve,
                out _));
        }

        var afterKey = Key(0x1d, 8, 0x2d);
        Assert.Throws<MailboxClientCanonicalOutcomePersistenceException>(() =>
        {
            using var store = Store(faults: new ThrowOnceFaults(
                MailboxClientCanonicalOutcomeFaultPoint.AfterReplaceBeforeDurability));
            using var reservation = store.Reserve(
                afterKey,
                MailboxAuthenticatedOperation.Retrieve,
                2_000,
                canonical.Length);
            _ = store.PutSuccess(reservation, canonical);
        });
        using var afterRestart = Store();
        Assert.Equal(
            canonical,
            afterRestart.ReadRequired(
                afterKey,
                MailboxAuthenticatedOperation.Retrieve).CanonicalBytes.ToArray());

        afterRestart.Dispose();
        var committedKey = Key(0x1e, 9, 0x2e);
        var durability = new RecordingDurabilityBarrier();
        Assert.Throws<MailboxClientCanonicalOutcomePersistenceException>(() =>
        {
            using var store = Store(
                durability: durability,
                faults: new ThrowOnceFaults(
                    MailboxClientCanonicalOutcomeFaultPoint.AfterCommit));
            using var reservation = store.Reserve(
                committedKey,
                MailboxAuthenticatedOperation.Retrieve,
                2_000,
                canonical.Length);
            _ = store.PutSuccess(reservation, canonical);
        });
        Assert.Equal(["replace", "flush"], durability.Events);
        using var committedRestart = Store();
        Assert.Equal(
            canonical,
            committedRestart.ReadRequired(
                committedKey,
                MailboxAuthenticatedOperation.Retrieve).CanonicalBytes.ToArray());
    }

    [Fact]
    public void FilenamesAndExceptionsNeverExposeReplayInputs()
    {
        var scope = Bytes(0x6a, 32);
        var claim = Bytes(0x7b, 32);
        var key = MailboxClientCanonicalOutcomeKey.Create(scope, 9, claim);
        var canonical = CanonicalQuorum();
        using var store = Store();
        using (var reservation = store.Reserve(
                   key,
                   MailboxAuthenticatedOperation.Store,
                   2_000,
                   canonical.Length))
        {
            _ = store.PutSuccess(reservation, canonical);
        }

        var filename = Path.GetFileName(Assert.Single(
            Directory.EnumerateFiles(OutcomeDirectory(), "*.outcome")));
        var scopeHex = Convert.ToHexString(scope).ToLowerInvariant();
        var claimHex = Convert.ToHexString(claim).ToLowerInvariant();
        Assert.DoesNotContain(scopeHex, filename, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(claimHex, filename, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("[opaque-mailbox-outcome-key]", key.ToString());

        var missing = Assert.Throws<MailboxClientCanonicalOutcomeMissingException>(() =>
            store.ReadRequired(
                Key(0x1f, 9, 0x2f),
                MailboxAuthenticatedOperation.Store));
        Assert.DoesNotContain(scopeHex, missing.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(claimHex, missing.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(_directory, missing.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PersistenceFailuresDoNotExposeFilesystemOrReplayMaterial()
    {
        var scope = Bytes(0x7c, 32);
        var claim = Bytes(0x8d, 32);
        var key = MailboxClientCanonicalOutcomeKey.Create(scope, 12, claim);
        var canonical = CanonicalQuorum();
        var durability = new SensitiveFailureDurabilityBarrier(_directory);
        using var store = Store(durability: durability);
        using var reservation = store.Reserve(
            key,
            MailboxAuthenticatedOperation.Store,
            2_000,
            canonical.Length);
        var failure =
            Assert.Throws<MailboxClientCanonicalOutcomePersistenceException>(() =>
                store.PutSuccess(reservation, canonical));
        Assert.DoesNotContain(_directory, failure.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            Convert.ToHexString(scope),
            failure.ToString(),
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            Convert.ToHexString(claim),
            failure.ToString(),
            StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private MailboxClientCanonicalOutcomeStore Store(
        MailboxClientCanonicalOutcomeStoreOptions? options = null,
        long? maximumBytes = null,
        IMailboxDurabilityBarrier? durability = null,
        IMailboxClientCanonicalOutcomeFaultInjector? faults = null)
    {
        options ??= new MailboxClientCanonicalOutcomeStoreOptions
        {
            MaximumEntries = 32,
            MaximumBytes = maximumBytes ?? 4L * MailboxClientLimits.MaximumPageBytes
        };
        return new(_directory, options, null, durability, faults);
    }

    private string OutcomeDirectory() =>
        Path.Combine(
            _directory,
            new MailboxClientCanonicalOutcomeStoreOptions().DirectoryName);

    private static MailboxClientCanonicalOutcomeKey Key(
        byte scope,
        ulong counter,
        byte claim) =>
        MailboxClientCanonicalOutcomeKey.Create(
            Bytes(scope, 32),
            counter,
            Bytes(claim, 32));

    private static byte[] CanonicalSuccess(
        MailboxAuthenticatedOperation operation,
        int retrieveLength)
        => operation switch
        {
            MailboxAuthenticatedOperation.Store => CanonicalQuorum(),
            MailboxAuthenticatedOperation.Retrieve =>
                CanonicalRetrievePage(retrieveLength),
            MailboxAuthenticatedOperation.Ack => CanonicalAggregateAck(),
            _ => throw new ArgumentOutOfRangeException(nameof(operation))
        };

    private static byte[] CanonicalQuorum(
        MailboxReplicaDisposition disposition = MailboxReplicaDisposition.Stored)
    {
        var operationId = Bytes(0x41, MailboxClientLimits.OperationIdLength);
        MailboxReplicaReceiptV2 Replica(byte replicaId) => new()
        {
            Status = MailboxReceiptStatus.Durable,
            Disposition = disposition,
            ReplicaId = Bytes(replicaId, MailboxReceiptV2Limits.ReplicaIdLength),
            OperationId = operationId,
            Epoch = 7,
            Cursor = 1,
            AcceptedAtUnixSeconds = 1_000,
            DurableAtUnixSeconds = 1_001,
            ExpiresAtUnixSeconds = 1_080,
            BlindedMailboxId = Bytes(0x42, MailboxClientLimits.BlindedIdentifierLength),
            PlacementCommitment = Bytes(0x43, MailboxReceiptV2Limits.DigestLength),
            MembershipCommitment = Bytes(0x44, MailboxReceiptV2Limits.DigestLength),
            EnvelopeDigest = Bytes(0x45, MailboxReceiptV2Limits.DigestLength),
            Signature = Bytes((byte)(replicaId + 2), 64)
        };

        return MailboxReceiptV3Codec.EncodeDurableQuorum(
            new MailboxDurableQuorumReceiptV3
            {
                CoordinatorId = Bytes(0x50, MailboxReceiptV2Limits.ReplicaIdLength),
                CoordinatorSequence = 1,
                FirstReplica = Replica(0x11),
                SecondReplica = Replica(0x22),
                Signature = Bytes(0x51, 64)
            });
    }

    private static byte[] CanonicalAggregateAck() =>
        MailboxAggregateAckCodec.EncodeMqr3(
            new MailboxAggregateAckResponse
            {
                Epoch = 7,
                OperationId = Bytes(0x41, MailboxClientLimits.OperationIdLength),
                TombstoneQuorums =
                [
                    CanonicalQuorum(MailboxReplicaDisposition.Tombstone)
                ]
            });

    private static byte[] CanonicalRetrievePage(int exactLength)
    {
        const int pageHeaderLength = 48;
        const int itemHeaderLength = 12;
        if (exactLength < pageHeaderLength
                          + itemHeaderLength
                          + MailboxClientLimits.EncryptedEnvelopeHeaderLength
                          + MailboxClientLimits.MinimumCiphertextLength
            || exactLength > MailboxClientLimits.MaximumPageBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(exactLength));
        }

        var items = new List<MailboxRetrievedEnvelope>();
        var currentLength = pageHeaderLength;
        ulong cursor = 0;
        while (exactLength - currentLength
               > itemHeaderLength + MailboxClientLimits.MaximumEncryptedEnvelopeLength)
        {
            cursor++;
            items.Add(RetrieveItem(
                cursor,
                MailboxClientLimits.MaximumCiphertextLength));
            currentLength += itemHeaderLength
                             + MailboxClientLimits.MaximumEncryptedEnvelopeLength;
        }

        var finalEnvelopeLength = exactLength - currentLength - itemHeaderLength;
        var finalCiphertextLength =
            finalEnvelopeLength - MailboxClientLimits.EncryptedEnvelopeHeaderLength;
        if (finalCiphertextLength is
            < MailboxClientLimits.MinimumCiphertextLength
            or > MailboxClientLimits.MaximumCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(nameof(exactLength));
        }

        cursor++;
        items.Add(RetrieveItem(cursor, finalCiphertextLength));
        return MailboxClientCodec.EncodeRetrievePage(
            new MailboxRetrievePage
            {
                Epoch = 7,
                OperationId = Bytes(0x61, MailboxClientLimits.OperationIdLength),
                NextCursor = cursor,
                HasMore = false,
                ContinuationToken = ReadOnlyMemory<byte>.Empty,
                Items = items
            });
    }

    private static MailboxRetrievedEnvelope RetrieveItem(
        ulong cursor,
        int ciphertextLength) =>
        new()
        {
            Cursor = cursor,
            Envelope = new MailboxEncryptedEnvelope
            {
                Epoch = 7,
                MailboxId = new BlindedMailboxId(
                    Bytes(0x62, MailboxClientLimits.BlindedIdentifierLength)),
                PlacementId = new BlindedPlacementId(
                    Bytes(0x63, MailboxClientLimits.BlindedIdentifierLength)),
                OperationId = Bytes(
                    checked((byte)(0x64 + cursor)),
                    MailboxClientLimits.OperationIdLength),
                DeduplicationDigest = Bytes(
                    checked((byte)(0x74 + cursor)),
                    MailboxClientLimits.DigestLength),
                CreatedAtUnixSeconds = 1_000,
                ExpiresAtUnixSeconds = 1_080,
                Ciphertext = Bytes(
                    checked((byte)(0x84 + cursor)),
                    ciphertextLength)
            }
        };

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).Select(static item => (byte)item).ToArray();

    private sealed class ThrowOnceFaults(MailboxClientCanonicalOutcomeFaultPoint point)
        : IMailboxClientCanonicalOutcomeFaultInjector
    {
        private int _thrown;

        public void Inject(MailboxClientCanonicalOutcomeFaultPoint observed)
        {
            if (observed == point && Interlocked.Exchange(ref _thrown, 1) == 0)
            {
                throw new IOException("Synthetic canonical outcome persistence fault.");
            }
        }
    }

    private sealed class RecordingDurabilityBarrier : IMailboxDurabilityBarrier
    {
        private readonly MailboxDurabilityBarrier _inner = new();

        public List<string> Events { get; } = [];

        public void FlushFileAndParentDirectory(string path)
        {
            Events.Add("flush");
            _inner.FlushFileAndParentDirectory(path);
        }

        public void FlushParentDirectory(string deletedPath) =>
            _inner.FlushParentDirectory(deletedPath);

        public void ReplaceFile(string temporaryPath, string finalPath)
        {
            Events.Add("replace");
            _inner.ReplaceFile(temporaryPath, finalPath);
        }

        public void DeleteFile(string path) => _inner.DeleteFile(path);
    }

    private sealed class SensitiveFailureDurabilityBarrier(string sensitivePath)
        : IMailboxDurabilityBarrier
    {
        public void FlushFileAndParentDirectory(string path) =>
            throw new IOException($"Synthetic failure at {sensitivePath}.");

        public void FlushParentDirectory(string deletedPath)
        {
        }

        public void ReplaceFile(string temporaryPath, string finalPath) =>
            File.Move(temporaryPath, finalPath, overwrite: true);
    }
}
