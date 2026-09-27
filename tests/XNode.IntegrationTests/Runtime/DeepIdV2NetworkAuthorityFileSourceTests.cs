using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace XNode.IntegrationTests.Runtime;

public sealed class DeepIdV2NetworkAuthorityFileSourceTests
{
    [Fact]
    public async Task IndependentGenesisPin_VerifiesExactFilesAndRejectsSubstitution()
    {
        var directory = Path.Combine(Path.GetTempPath(),
            "xnode-did2-xna-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var network = Bytes(16, 0x20);
        var rootPairs = Enumerable.Range(0, 3).Select(index =>
            PublicKeyAuth.GenerateKeyPair(
                Bytes(32, checked((byte)(0x30 + index))))).ToArray();
        var witnessPairs = Enumerable.Range(0, 3).Select(index =>
            PublicKeyAuth.GenerateKeyPair(
                Bytes(32, checked((byte)(0x50 + index))))).ToArray();
        try
        {
            var roots = rootPairs.Select((pair, index) =>
                new XPointNetworkBootstrapRootKey(
                    Bytes(32, checked((byte)(0x40 + index))), 0,
                    pair.PublicKey,
                    Bytes(32, checked((byte)(0xb0 + index))))).ToArray();
            var witnesses = witnessPairs.Select((pair, index) =>
                new XPointNetworkBootstrapWitnessKey(
                    Bytes(32, checked((byte)(0x60 + index))), 0,
                    pair.PublicKey,
                    Bytes(32, checked((byte)(0x70 + index))))).ToArray();
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x80),
                    Bytes(32, 0x90), 1, "time-a.example", 4460,
                    Bytes(32, 0xa0), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x81),
                    Bytes(32, 0x91), 1, "time-b.example", 4460,
                    Bytes(32, 0xa1), 5)
            };
            var request = new XPointNetworkGenesisAuthoringRequest(
                Bytes(32, 0x01), network, roots, 2, witnesses, 2,
                sources, 10, 10, 100, 100, 34_000_000, 100,
                2_592_000, 1, 1);
            var authored = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                request,
                roots.Take(2).Select((root, index) =>
                    (IXPointNetworkBootstrapRootSigner)new TestRootSigner(
                        root, rootPairs[index])).ToArray());
            var xnaPath = Path.Combine(directory, "current.xna1");
            var dtsPath = Path.Combine(directory, "current.dts1");
            File.WriteAllBytes(xnaPath, authored.ExactXna1.ToArray());
            File.WriteAllBytes(dtsPath, authored.ExactDts1.ToArray());
            var source = new DeepIdV2NetworkAuthorityFileSource(
                authored.GenesisPin, [xnaPath], [dtsPath]);
            var verified = source.ReadCurrent();
            Assert.Equal(authored.Authority.AuthorityCoreHash.ToArray(),
                verified.AuthorityCoreHash.ToArray());
            Assert.Equal(network, verified.NetworkId.ToArray());

            var wrongPin = new DeepIdV2NetworkAuthorityFileSource(
                new XPointNetworkGenesisPin(network, Bytes(32, 0x88)),
                [xnaPath], [dtsPath]);
            Assert.Throws<XPointNetworkAuthorityVerificationException>(
                wrongPin.ReadCurrent);
            var tampered = authored.ExactXna1.ToArray();
            tampered[^1] ^= 1;
            File.WriteAllBytes(xnaPath, tampered);
            Assert.Throws<XPointNetworkAuthorityVerificationException>(
                source.ReadCurrent);
            Assert.Throws<ArgumentException>(() =>
                new DeepIdV2NetworkAuthorityFileSource(authored.GenesisPin,
                    [xnaPath], [xnaPath]));
        }
        finally
        {
            foreach (var pair in rootPairs.Concat(witnessPairs))
                CryptographicOperations.ZeroMemory(pair.PrivateKey);
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class TestRootSigner(
        XPointNetworkBootstrapRootKey root, KeyPair pair)
        : IXPointNetworkBootstrapRootSigner
    {
        public ReadOnlyMemory<byte> RootKeyId => root.RootKeyId;
        public ulong KeyGeneration => root.KeyGeneration;
        public ReadOnlyMemory<byte> Ed25519PublicKey => root.Ed25519PublicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => root.CustodyDomainHash;

        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = PublicKeyAuth.SignDetached(
                request.SigningInput.ToArray(), pair.PrivateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
    }

    private static byte[] Bytes(int count, byte value) =>
        Enumerable.Repeat(value, count).ToArray();
}
