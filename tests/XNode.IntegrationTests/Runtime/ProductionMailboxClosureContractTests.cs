using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Sodium;
using System.Security.Cryptography;

namespace XNode.IntegrationTests.Runtime;

public sealed class ProductionMailboxClosureContractTests
{
    [Fact]
    public void FetchRequest_IsFixedSizeOwnerAuthenticatedAndMutationRejected()
    {
        var owner = PublicKeyAuth.GenerateKeyPair(Bytes(0x31, 32));
        var unsigned = new ProductionMailboxClosureRequest(
            2_000_000_000, Bytes(0x41, 32), Bytes(0x51, 32), Bytes(0x61, 32),
            Bytes(0x71, 32), Bytes(0x81, 32), owner.PublicKey, new byte[64]);
        var signed = unsigned with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(unsigned),
                owner.PrivateKey)
        };
        var encoded = ProductionMailboxClosureRequestCodec.Encode(signed);

        Assert.Equal(ProductionMailboxClosureRequestCodec.EncodedLength, encoded.Length);
        Assert.Equal("PMQ2"u8.ToArray(), encoded[..4]);
        Assert.Equal(2, encoded[4]);
        Assert.True(ProductionMailboxClosureRequestCodec.VerifyOwner(
            ProductionMailboxClosureRequestCodec.Decode(encoded)));

        encoded[48] ^= 0x01;
        Assert.False(ProductionMailboxClosureRequestCodec.VerifyOwner(
            ProductionMailboxClosureRequestCodec.Decode(encoded)));
        encoded[48] ^= 0x01;
        encoded[80] ^= 0x01;
        Assert.False(ProductionMailboxClosureRequestCodec.VerifyOwner(
            ProductionMailboxClosureRequestCodec.Decode(encoded)));
        encoded[80] ^= 0x01;
        encoded[112] ^= 0x01;
        Assert.False(ProductionMailboxClosureRequestCodec.VerifyOwner(
            ProductionMailboxClosureRequestCodec.Decode(encoded)));
        encoded[112] ^= 0x01;
        encoded[144] ^= 0x01;
        Assert.False(ProductionMailboxClosureRequestCodec.VerifyOwner(
            ProductionMailboxClosureRequestCodec.Decode(encoded)));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureRequestCodec.Decode(encoded[..^1]));

        var terminal = signed with { TimestampUnixSeconds = ulong.MaxValue };
        terminal = terminal with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(terminal),
                owner.PrivateKey)
        };
        Assert.True(ProductionMailboxClosureRequestCodec.VerifyOwner(terminal));
        Assert.False(ProductionMailboxClosureRequestCodec.IsFresh(
            terminal, 2_000_000_000));
    }


    [Fact]
    public void PrepositionCommand_MaximumUnsignedLengthFailsAsCoarseInvalidData()
    {
        var malformed = new byte[ProductionMailboxPrepositionCommandCodec.HeaderLength];
        "PMP2"u8.CopyTo(malformed);
        malformed[4] = 2;
        BinaryPrimitives.WriteUInt32BigEndian(malformed.AsSpan(272), uint.MaxValue);

        var failure = Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxPrepositionCommandCodec.Decode(malformed));

        Assert.DoesNotContain(nameof(OverflowException), failure.ToString(),
            StringComparison.Ordinal);
    }

    [Fact]
    public void Pmc2Header_PreflightsLateEightMiBAndInvalidTagBeforeArtifactCopies()
    {
        var hostile = new byte[ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes];
        "PMC2"u8.CopyTo(hostile);
        hostile[4] = 2;
        hostile[5] = (byte)ProductionMailboxRouteAuthorizationKind.OwnerPRA2;
        hostile.AsSpan(8, 64).Fill(0xA5);
        // Exact ten-length table begins at 72; the late aggregate mismatch is detected before
        // any of the hostile body can be cloned or passed to Protocol.
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(72), 1);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(76), 1);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(80), 1);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(84), 1);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(88), 1);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(92), 1);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(96),
            ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(100),
            ProductionMailboxRouteAuthorizationConstants.CanonicalTransitionContextLength);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(104), 0);
        BinaryPrimitives.WriteUInt32BigEndian(hostile.AsSpan(108),
            ProductionMailboxRouteAuthorizationConstants.CanonicalAdvertisementV2Length);

        var before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureEnvelopeCodec.Decode(hostile));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 128 * 1024,
            $"PMC2 allocated {allocated} bytes before late aggregate rejection.");

        hostile[5] = byte.MaxValue;
        before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureEnvelopeCodec.Decode(hostile));
        allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 128 * 1024,
            $"PMC2 allocated {allocated} bytes before authorization-tag rejection.");
    }

    [Fact]
    public void CapacityCommandAndReceipt_AreCanonicalTargetBoundAndAuthenticated()
    {
        var publisher = PublicKeyAuth.GenerateKeyPair(Bytes(0x71, 32));
        var node = PublicKeyAuth.GenerateKeyPair(Bytes(0x72, 32));
        var unsigned = new ProductionMailboxCapacityCommand(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            2_000_000_000, 2_000_003_600, Bytes(0x73, 32), Bytes(0x74, 32),
            node.PublicKey, 12, 1_048_576, 1, new byte[64]);
        var command = unsigned with
        {
            PublisherSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityCommandCodec.GetSigningBytes(unsigned),
                publisher.PrivateKey)
        };
        var canonicalCommand = ProductionMailboxCapacityCommandCodec.Encode(command);
        var decodedCommand = ProductionMailboxCapacityCommandCodec.Decode(canonicalCommand);
        Assert.Equal(ProductionMailboxCapacityCommandCodec.EncodedLength,
            canonicalCommand.Length);
        Assert.True(ProductionMailboxCapacityCommandCodec.VerifyPublisher(
            decodedCommand, publisher.PublicKey));
        Assert.False(ProductionMailboxCapacityCommandCodec.VerifyPublisher(
            decodedCommand with { ReservedBytes = decodedCommand.ReservedBytes + 1 },
            publisher.PublicKey));

        var unsignedReceipt = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            2_000_000_001, 2_000_003_600, command.CohortId, command.TargetReplicaId,
            12, 1_048_576, 3, 262_144, 1, SHA256.HashData(canonicalCommand),
            new byte[64]);
        var receipt = unsignedReceipt with
        {
            NodeSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityReceiptCodec.GetSigningBytes(unsignedReceipt),
                node.PrivateKey)
        };
        var canonicalReceipt = ProductionMailboxCapacityReceiptCodec.Encode(receipt);
        var decodedReceipt = ProductionMailboxCapacityReceiptCodec.Decode(canonicalReceipt);
        Assert.Equal(ProductionMailboxCapacityReceiptCodec.EncodedLength,
            canonicalReceipt.Length);
        Assert.True(ProductionMailboxCapacityReceiptCodec.VerifyNode(
            decodedReceipt, node.PublicKey));
        Assert.False(ProductionMailboxCapacityReceiptCodec.VerifyNode(
            decodedReceipt with { ConsumedBytes = decodedReceipt.ConsumedBytes + 1 },
            node.PublicKey));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxCapacityCommandCodec.Decode(canonicalCommand[..^1]));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxCapacityReceiptCodec.Decode(canonicalReceipt[..^1]));
    }

    [Fact]
    public void CapacityCodecs_PreflightFixedFieldsBeforeCopyingHostileMemory()
    {
        var oversized = new byte[8 * 1024 * 1024];
        var command = new ProductionMailboxCapacityCommand(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            2_000_000_000, 2_000_003_600, oversized, Bytes(0x73, 32),
            Bytes(0x74, 32), 1, 65_536, 1, new byte[64]);
        var before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxCapacityCommandCodec.GetSigningBytes(command));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 128 * 1024,
            $"PMB1 allocated {allocated} bytes before fixed-field rejection.");

        var receipt = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.ReserveOrRenew,
            2_000_000_000, 2_000_003_600, oversized, Bytes(0x75, 32),
            1, 65_536, 0, 0, 1, Bytes(0x76, 32), new byte[64]);
        before = GC.GetAllocatedBytesForCurrentThread();
        Assert.False(ProductionMailboxCapacityReceiptCodec.VerifyNode(
            receipt, Bytes(0x77, 32)));
        allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 128 * 1024,
            $"PMB2 allocated {allocated} bytes before fixed-field rejection.");
    }

    [Fact]
    public void CapacityReconciliationCodecs_BindExactPriorReceiptAndNodeStatus()
    {
        var publisher = PublicKeyAuth.GenerateKeyPair(Bytes(0x81, 32));
        var node = PublicKeyAuth.GenerateKeyPair(Bytes(0x82, 32));
        var priorUnsigned = new ProductionMailboxCapacityReceipt(
            ProductionMailboxCapacityOperation.Release, 2_000_000_000,
            2_000_003_600, Bytes(0x83, 32), node.PublicKey, 2, 65_536,
            2, 65_536, 3, Bytes(0x84, 32), new byte[64]);
        var prior = ProductionMailboxCapacityReceiptCodec.Encode(priorUnsigned with
        {
            NodeSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxCapacityReceiptCodec.GetSigningBytes(priorUnsigned),
                node.PrivateKey)
        });
        var commandUnsigned = new ProductionMailboxCapacityReconciliationCommand(
            2_000_010_000, 2_000_010_060, Bytes(0x85, 32), Bytes(0x83, 32),
            node.PublicKey, 3, prior, SHA256.HashData(prior), Bytes(0x84, 32),
            new byte[64]);
        var command = ProductionMailboxCapacityReconciliationCommandCodec.Encode(
            commandUnsigned with
            {
                PublisherSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReconciliationCommandCodec.GetSigningBytes(
                        commandUnsigned), publisher.PrivateKey)
            });
        var decodedCommand = ProductionMailboxCapacityReconciliationCommandCodec.Decode(command);
        Assert.True(ProductionMailboxCapacityReconciliationCommandCodec.VerifyPublisher(
            decodedCommand, publisher.PublicKey));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxCapacityReconciliationCommandCodec.Decode(command[..^1]));

        var responseUnsigned = new ProductionMailboxCapacityReconciliationReceipt(
            ProductionMailboxCapacityReconciliationStatus.AbsentTerminal,
            2_000_010_001, 2_000_010_060, Bytes(0x83, 32), node.PublicKey, 3,
            SHA256.HashData(prior), Bytes(0x84, 32), 2, 65_536,
            Bytes(0x86, 32), new byte[64]);
        var response = ProductionMailboxCapacityReconciliationReceiptCodec.Encode(
            responseUnsigned with
            {
                NodeSignature = PublicKeyAuth.SignDetached(
                    ProductionMailboxCapacityReconciliationReceiptCodec.GetSigningBytes(
                        responseUnsigned), node.PrivateKey)
            });
        var decodedResponse = ProductionMailboxCapacityReconciliationReceiptCodec.Decode(response);
        Assert.True(ProductionMailboxCapacityReconciliationReceiptCodec.VerifyNode(
            decodedResponse, node.PublicKey));
        Assert.False(ProductionMailboxCapacityReconciliationReceiptCodec.VerifyNode(
            decodedResponse with { AccountedBytes = 65_537 }, node.PublicKey));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxCapacityReconciliationReceiptCodec.Decode(response[..^1]));
    }


    [Theory]
    [InlineData(7443, 7443, true)]
    [InlineData(7080, 7443, false)]
    [InlineData(null, 7443, false)]
    public void PrepositionListener_IsExactPeerPortOnly(
        int? localPort, int peerPort, bool expected) =>
        Assert.Equal(expected,
            ProductionMailboxClosureHttpContract.IsPrepositionListener(localPort, peerPort));

    [Fact]
    public void HttpSurface_UsesConstantPostPathsAndContainsNoRouteIdentifier()
    {
        Assert.Equal("/api/production-mailbox/closure",
            ProductionMailboxClosureHttpContract.FetchRoute);
        Assert.Equal("/api/peer/production-mailbox/closure",
            ProductionMailboxClosureHttpContract.PrepositionRoute);
        Assert.Equal("/api/peer/production-mailbox/closure-capacity",
            ProductionMailboxClosureHttpContract.CapacityRoute);
        Assert.DoesNotContain("{", ProductionMailboxClosureHttpContract.FetchRoute,
            StringComparison.Ordinal);
        Assert.DoesNotContain("?", ProductionMailboxClosureHttpContract.FetchRoute,
            StringComparison.Ordinal);
        Assert.DoesNotContain("selection", ProductionMailboxClosureHttpContract.FetchRoute,
            StringComparison.OrdinalIgnoreCase);
        var root = FindRepositoryRoot();
        var program = File.ReadAllText(Path.Combine(root, "src", "XNode", "Program.cs"));
        Assert.DoesNotContain("UseHttpLogging", program, StringComparison.Ordinal);
        Assert.DoesNotContain("Request.EnableBuffering", program, StringComparison.Ordinal);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !Directory.Exists(Path.Combine(current.FullName, ".git")))
            current = current.Parent;
        return current?.FullName ?? throw new DirectoryNotFoundException("Repository root is unavailable.");
    }

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private sealed class OversizedNodeList : IReadOnlyList<ReadOnlyMemory<byte>>
    {
        public int Count => int.MaxValue;
        public ReadOnlyMemory<byte> this[int index] => throw new InvalidOperationException();
        public IEnumerator<ReadOnlyMemory<byte>> GetEnumerator() =>
            throw new InvalidOperationException();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            GetEnumerator();
    }

    private sealed class UnstableNodeList : IReadOnlyList<ReadOnlyMemory<byte>>
    {
        private int _countReads;
        public int Count => Interlocked.Increment(ref _countReads) == 1 ? 2 : 1;
        public ReadOnlyMemory<byte> this[int index] => Bytes((byte)(0x20 + index), 32);
        public IEnumerator<ReadOnlyMemory<byte>> GetEnumerator() =>
            throw new InvalidOperationException();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
            GetEnumerator();
    }
}
