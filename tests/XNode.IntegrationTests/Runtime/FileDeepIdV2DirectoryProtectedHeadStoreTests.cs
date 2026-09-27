using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.XPointNetworkV1;
using Microsoft.AspNetCore.DataProtection;
using Sodium;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class FileDeepIdV2DirectoryProtectedHeadStoreTests
{
    [Fact]
    public async Task SignedGenesisSurvivesRestartWithIndependentAnchor()
    {
        using var fixture = await Fixture.CreateAsync();
        using (var first = fixture.Open())
        {
            var genesis = await first.RestoreAsync(fixture.Authority, default);
            Assert.Equal(fixture.ExactGenesis, genesis.ExactAdh1.ToArray());
        }

        using var restarted = fixture.Open();
        var restored = await restarted.RestoreAsync(fixture.Authority, default);
        Assert.Equal(fixture.ExactGenesis, restored.ExactAdh1.ToArray());
        Assert.True(File.Exists(fixture.AnchorPath));
        Assert.True(File.Exists(fixture.TipPath));
    }

    [Fact]
    public async Task LostIndexIsRecoveredOnlyFromAuthenticatedJournalAndAnchor()
    {
        using var fixture = await Fixture.CreateAsync();
        using (var first = fixture.Open())
            await first.RestoreAsync(fixture.Authority, default);
        File.Delete(fixture.LatestPath);

        using var restarted = fixture.Open();
        var restored = await restarted.RestoreAsync(fixture.Authority, default);
        Assert.Equal(fixture.ExactGenesis, restored.ExactAdh1.ToArray());
        Assert.True(File.Exists(fixture.LatestPath));
    }

    [Fact]
    public async Task MissingOrCorruptedIndependentAnchorFailsClosed()
    {
        using var fixture = await Fixture.CreateAsync();
        using (var first = fixture.Open())
            await first.RestoreAsync(fixture.Authority, default);
        var authenticatedAnchor = File.ReadAllBytes(fixture.AnchorPath);
        File.Delete(fixture.AnchorPath);
        using (var missing = fixture.Open())
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await missing.RestoreAsync(fixture.Authority, default));

        authenticatedAnchor[^1] ^= 0x01;
        File.WriteAllBytes(fixture.AnchorPath, authenticatedAnchor);
        new MailboxStorageSecurity().SecureFile(fixture.AnchorPath);
        using var corrupt = fixture.Open();
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await corrupt.RestoreAsync(fixture.Authority, default));
    }

    [Fact]
    public async Task MissingJournalCannotBeRecreatedWhileIndexExists()
    {
        using var fixture = await Fixture.CreateAsync();
        using (var first = fixture.Open())
            await first.RestoreAsync(fixture.Authority, default);
        File.Delete(fixture.TipPath);

        using var restarted = fixture.Open();
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.RestoreAsync(fixture.Authority, default));
    }

    [Fact]
    public async Task WrongGenesisPinCannotInitializeState()
    {
        using var fixture = await Fixture.CreateAsync();
        var wrong = fixture.GenesisHash.ToArray();
        wrong[0] ^= 0x01;
        using var store = fixture.Open(wrong);
        await Assert.ThrowsAsync<AccountDirectoryFreshnessVerificationException>(async () =>
            await store.RestoreAsync(fixture.Authority, default));
        Assert.False(File.Exists(fixture.AnchorPath));
        Assert.False(File.Exists(fixture.TipPath));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string root;
        private readonly byte[][] privateKeys;

        private Fixture(string root, VerifiedXPointNetworkAuthority authority,
            byte[] exactGenesis, byte[] genesisHash, byte[][] privateKeys)
        {
            this.root = root;
            Authority = authority;
            ExactGenesis = exactGenesis;
            GenesisHash = genesisHash;
            this.privateKeys = privateKeys;
        }

        internal VerifiedXPointNetworkAuthority Authority { get; }
        internal byte[] ExactGenesis { get; }
        internal byte[] GenesisHash { get; }
        internal string AnchorPath => Path.Combine(root, "did2-head-anchor", "anchor.floor");
        internal string TipPath => Path.Combine(root, "did2-head-journal", "tip-0000000000000000.floor");
        internal string LatestPath => Path.Combine(root, "did2-head-journal", "latest.floor");

        internal FileDeepIdV2DirectoryProtectedHeadStore Open(byte[]? hash = null)
        {
            var keys = Path.Combine(root, "dp-keys");
            Directory.CreateDirectory(keys);
            var provider = DataProtectionProvider.Create(new DirectoryInfo(keys),
                builder => builder.SetApplicationName("XNode.DID2.HeadFloor.Test"));
            return new FileDeepIdV2DirectoryProtectedHeadStore(
                Path.Combine(root, "did2-head-journal"), root,
                ExactGenesis, hash ?? GenesisHash, provider,
                new MailboxStorageSecurity(), new MailboxDurabilityBarrier());
        }

        internal static async Task<Fixture> CreateAsync()
        {
            var root = Path.Combine(Path.GetTempPath(),
                "xnode-did2-floor-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            var rootKeys = Enumerable.Range(0, 2).Select(index =>
                PublicKeyAuth.GenerateKeyPair(Bytes(32, (byte)(0x30 + index))))
                .ToArray();
            var witnessKeys = Enumerable.Range(0, 3).Select(index =>
                PublicKeyAuth.GenerateKeyPair(Bytes(32, (byte)(0x50 + index))))
                .ToArray();
            var roots = rootKeys.Select((pair, index) =>
                new XPointNetworkBootstrapRootKey(
                    Bytes(32, (byte)(0x40 + index)), 0, pair.PublicKey,
                    Bytes(32, (byte)(0xb0 + index)))).ToArray();
            var witnesses = witnessKeys.Select((pair, index) =>
                new XPointNetworkBootstrapWitnessKey(
                    Bytes(32, (byte)(0x60 + index)), 0, pair.PublicKey,
                    Bytes(32, (byte)(0x70 + index)))).ToArray();
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
                Bytes(32, 0x01), Bytes(16, 0x20), roots, 2, witnesses, 2,
                sources, 10, 10, 100, 100, 34_000_000, 100, 2_592_000,
                1, 1);
            var rootSigners = roots.Select((entry, index) =>
                (IXPointNetworkBootstrapRootSigner)new RootSigner(
                    entry.RootKeyId.ToArray(), rootKeys[index].PrivateKey,
                    entry.CustodyDomainHash.ToArray(), rootKeys[index].PublicKey))
                .ToArray();
            var network = await XPointNetworkBootstrapAuthor.AuthorGenesisAsync(
                request, rootSigners);
            var witnessSigners = witnesses.Take(2).Select((entry, index) =>
                (IAccountDirectoryAdh1WitnessSigner)new WitnessSigner(
                    entry.WitnessId.ToArray(), witnessKeys[index].PrivateKey))
                .ToArray();
            var head = await DeepIdV2DirectoryHeadAuthor.AuthorGenesisAsync(
                network.Authority, 1_000, 2_000, witnessSigners);
            return new Fixture(root, network.Authority, head.ExactAdh1.ToArray(),
                head.ProtectedHead.CoreHash.ToArray(),
                rootKeys.Concat(witnessKeys).Select(pair => pair.PrivateKey)
                    .ToArray());
        }

        public void Dispose()
        {
            foreach (var key in privateKeys)
                CryptographicOperations.ZeroMemory(key);
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private sealed class RootSigner(byte[] id, byte[] privateKey,
        byte[] custody, byte[] publicKey) : IXPointNetworkBootstrapRootSigner
    {
        public ReadOnlyMemory<byte> RootKeyId => id;
        public ulong KeyGeneration => 0;
        public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey;
        public ReadOnlyMemory<byte> CustodyDomainHash => custody;

        public ValueTask<int> SignAsync(XPointNetworkRootSigningRequest request,
            Memory<byte> signature64, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = PublicKeyAuth.SignDetached(
                request.SigningInput.ToArray(), privateKey);
            signature.CopyTo(signature64);
            return ValueTask.FromResult(signature.Length);
        }
    }

    private sealed class WitnessSigner(byte[] id, byte[] privateKey) :
        IAccountDirectoryAdh1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => id;

        public ValueTask<ReadOnlyMemory<byte>> SignAdh1Async(
            ReadOnlyMemory<byte> signingInput, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), privateKey));
        }
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index =>
            unchecked((byte)(seed + index))).ToArray();
}
