using System.Buffers.Binary;
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
            2_000_000_000, Bytes(0x41, 32), Bytes(0x51, 32), owner.PublicKey,
            new byte[64]);
        var signed = unsigned with
        {
            OwnerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxClosureRequestCodec.GetSigningBytes(unsigned),
                owner.PrivateKey)
        };
        var encoded = ProductionMailboxClosureRequestCodec.Encode(signed);

        Assert.Equal(ProductionMailboxClosureRequestCodec.EncodedLength, encoded.Length);
        Assert.True(ProductionMailboxClosureRequestCodec.VerifyOwner(
            ProductionMailboxClosureRequestCodec.Decode(encoded)));

        encoded[48] ^= 0x01;
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
    public void ClosureEnvelope_IsCanonicalBoundedAndRequiresSuccessor()
    {
        var value = new ProductionMailboxClosureEnvelope(
            Bytes(1, 3), Bytes(2, 5), Bytes(3, 7), Bytes(4, 11), Bytes(5, 13));
        var canonical = ProductionMailboxClosureEnvelopeCodec.Encode(value);
        var decoded = ProductionMailboxClosureEnvelopeCodec.Decode(canonical);

        Assert.Equal(canonical, ProductionMailboxClosureEnvelopeCodec.Encode(decoded));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureEnvelopeCodec.Encode(value with { Successor = Array.Empty<byte>() }));
        Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxClosureEnvelopeCodec.Decode(
                new byte[ProductionMailboxClosureEnvelopeCodec.MaximumEnvelopeBytes + 1]));
    }

    [Fact]
    public void PrepositionCommand_BindsEnvelopeTargetNonceAndTimestamp()
    {
        var publisher = PublicKeyAuth.GenerateKeyPair(Bytes(0x61, 32));
        var envelope = ProductionMailboxClosureEnvelopeCodec.Encode(new(
            Bytes(1, 3), Bytes(2, 5), Bytes(3, 7), Bytes(4, 11), Bytes(5, 13)));
        var unsigned = new ProductionMailboxPrepositionCommand(
            2_000_000_000, Bytes(0x62, 32), SHA256.HashData(envelope),
            Bytes(0x63, 32), new byte[64], envelope);
        var signed = unsigned with
        {
            PublisherSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxPrepositionCommandCodec.GetSigningBytes(unsigned),
                publisher.PrivateKey)
        };
        var canonical = ProductionMailboxPrepositionCommandCodec.Encode(signed);
        var decoded = ProductionMailboxPrepositionCommandCodec.Decode(canonical);

        Assert.True(ProductionMailboxPrepositionCommandCodec.VerifyPublisher(
            decoded, publisher.PublicKey));
        Assert.True(ProductionMailboxPrepositionCommandCodec.IsFresh(
            decoded, 2_000_000_300));
        Assert.False(ProductionMailboxPrepositionCommandCodec.IsFresh(
            decoded, 2_000_000_301));
        Assert.False(ProductionMailboxPrepositionCommandCodec.VerifyPublisher(
            decoded with { TargetReplicaId = Bytes(0x64, 32) }, publisher.PublicKey));
    }

    [Fact]
    public void PrepositionCommand_MaximumUnsignedLengthFailsAsCoarseInvalidData()
    {
        var malformed = new byte[ProductionMailboxPrepositionCommandCodec.HeaderLength];
        "PMP1"u8.CopyTo(malformed);
        malformed[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(malformed.AsSpan(176), uint.MaxValue);

        var failure = Assert.Throws<InvalidDataException>(() =>
            ProductionMailboxPrepositionCommandCodec.Decode(malformed));

        Assert.DoesNotContain(nameof(OverflowException), failure.ToString(),
            StringComparison.Ordinal);
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
}
