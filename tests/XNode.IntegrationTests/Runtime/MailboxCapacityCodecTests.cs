using Sodium;
using System.Security.Cryptography;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxCapacityCodecTests
{
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

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();
}
