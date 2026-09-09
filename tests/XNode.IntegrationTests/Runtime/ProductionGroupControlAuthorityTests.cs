using System.Security.Cryptography;
using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.GroupV1;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Rebex.Security.Cryptography;
using Sodium;
using XNode.Core;
using XNode.Core.Mailbox;

namespace XNode.IntegrationTests.Runtime;

public sealed class ProductionGroupControlAuthorityTests : IDisposable
{
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "xnode-group-control-authority-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void DefaultConfigurationRemainsDormant()
    {
        var service = new GroupControlServiceOptions();
        var options = new ProductionGroupControlAuthorityOptions();

        var configuration = options.ValidateAndLoad(Node(), service, false);
        var services = new ServiceCollection();
        var plan = services.AddGroupControlServiceBoundary(service);
        using var provider = services.BuildServiceProvider();

        Assert.Null(configuration);
        Assert.False(plan.RuntimeActivation);
        Assert.False(plan.MapReplicaEndpoint);
        Assert.IsType<UnavailableGroupControlTerminalDispatcher>(
            provider.GetRequiredService<IGroupControlTerminalDispatcher>());
    }

    [Theory]
    [InlineData(true, "artifacts", "state/gcl1.bin", 0, 65536, 64)]
    [InlineData(true, "", "state/gcl1.bin", 65536, 65536, 64)]
    [InlineData(false, "artifacts", "", 0, 0, 0)]
    public void PartialConfigurationFailsBeforeHostBuild(
        bool enabled,
        string artifacts,
        string state,
        int dcrBytes,
        int stateBytes,
        int depth)
    {
        var options = new ProductionGroupControlAuthorityOptions
        {
            Enabled = enabled,
            ArtifactDirectoryRelativePath = artifacts,
            StateRelativePath = state,
            MaximumDcr1Bytes = dcrBytes,
            MaximumProtectedStateBytes = stateBytes,
            MaximumLineageDepth = depth
        };

        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(
            Node(),
            new GroupControlServiceOptions
            {
                RuntimeActivation = enabled,
                MapReplicaEndpoint = enabled
            },
            verifiedNetworkAuthorityConfigured: true));
    }

    [Fact]
    public void ActivationWithoutVerifiedNetworkAuthorityFailsClosed()
    {
        var options = CompleteOptions();

        Assert.Throws<InvalidOperationException>(() => options.ValidateAndLoad(
            Node(),
            ActiveService(),
            verifiedNetworkAuthorityConfigured: false));
    }

    [Fact]
    public void ExplicitProductionCompositionRegistersAuthorityDurabilityAndTwoReplicaRuntime()
    {
        var node = Node();
        var service = ActiveService();
        var configuration = CompleteOptions().ValidateAndLoad(node, service, true)!;
        Directory.CreateDirectory(configuration.ArtifactDirectory);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(node);
        services.AddSingleton<IClock>(new FixedClock(DateTimeOffset.FromUnixTimeSeconds(100)));
        services.AddSingleton<IOnionMonotonicClock>(new FixedMonotonicClock());
        services.AddSingleton<IContactVerifiedAuthoritySnapshotSource,
            UnavailableSnapshotSource>();
        services.AddSingleton<IMailboxStorageSecurity, TestStorageSecurity>();
        services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
        services.AddSingleton<IDataProtectionProvider>(
            DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(root, "keys"))));
        services.AddSingleton(new PrivacyRoutingConfiguration(
            false,
            Hash("private"),
            Hash("public"),
            new Uri("https://local.example/api/peer/privacy/v1/frame"),
            new Dictionary<RouterId, PrivacyPeer>(),
            64,
            600,
            TimeSpan.FromSeconds(30),
            4096,
            100000,
            TimeSpan.FromMinutes(5)));

        var plan = services.AddProductionGroupControlAuthorityBoundary(
            node,
            service,
            configuration);
        using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        Assert.True(plan.RuntimeActivation);
        Assert.True(plan.MapReplicaEndpoint);
        Assert.IsType<ProductionGroupControlAuthoritySource>(
            provider.GetRequiredService<IGroupControlAuthoritySource>());
        Assert.IsType<FileGroupControlAuthorityLineageStore>(
            provider.GetRequiredService<IGroupControlAuthorityLineageStore>());
        Assert.IsType<ProductionGroupControlTerminalDispatcher>(
            provider.GetRequiredService<IGroupControlTerminalDispatcher>());
        Assert.NotNull(provider.GetRequiredService<GroupControlReplicaRequestReceiver>());
        Assert.IsType<ProductionGroupControlAuthorityHostedService>(
            Assert.Single(provider.GetServices<IHostedService>()));
    }

    [Fact]
    public async Task DurableLineageRejectsWrongGenerationAndRollback()
    {
        var store = Store("rollback");
        var rootHash = Hash("root");
        var nextHash = Hash("next");
        await store.ObserveAsync(Observation(rootHash), default);
        await store.ObserveAsync(Observation(rootHash, nextHash), default);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.ObserveAsync(Observation(rootHash), default));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await store.ObserveAsync(new GroupControlLineageObservation(
                rootHash,
                4,
                nextHash,
                [rootHash, nextHash]), default));
    }

    [Fact]
    public async Task ForkLatchSurvivesRestartAndRejectsBothBranches()
    {
        var configuration = Configuration("fork");
        var protection = DataProtectionProvider.Create(
            new DirectoryInfo(Path.Combine(root, "fork-keys")));
        var first = Store(configuration, protection);
        var rootHash = Hash("fork-root");
        var headA = Hash("fork-a");
        var headB = Hash("fork-b");
        await first.ObserveAsync(Observation(rootHash, headA), default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await first.ObserveAsync(Observation(rootHash, headB), default));

        var restarted = Store(configuration, protection);
        await restarted.InitializeAsync(default);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ObserveAsync(Observation(rootHash, headA), default));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await restarted.ObserveAsync(Observation(rootHash, headB), default));
    }

    [Fact]
    public async Task ProtectedStateTamperingFailsStartupInsteadOfResettingAuthority()
    {
        var configuration = Configuration("tamper");
        var protection = DataProtectionProvider.Create(
            new DirectoryInfo(Path.Combine(root, "tamper-keys")));
        var store = Store(configuration, protection);
        await store.ObserveAsync(Observation(Hash("tamper-root")), default);
        var bytes = File.ReadAllBytes(configuration.StatePath);
        bytes[^1] ^= 0x80;
        File.WriteAllBytes(configuration.StatePath, bytes);

        var restarted = Store(configuration, protection);
        await Assert.ThrowsAnyAsync<CryptographicException>(async () =>
            await restarted.InitializeAsync(default));
    }

    [Fact]
    public void ExactGsr1RejectsWrongNetworkAndExpiredAuthorityWindow()
    {
        var key = PublicKeyAuth.GenerateKeyPair(Hash("gsr-network-key"));
        var network = Hash("gsr-network")[..16];
        var gsr = Gsr(network, key.PrivateKey, issuedAt: 20, expiresAt: 90);

        ProductionGroupControlAuthoritySource.EnsureRendezvousBindings(
            gsr,
            network,
            trustedLowerUnixSeconds: 30,
            trustedUpperUnixSeconds: 60);
        Assert.Throws<GroupControlAuthorityUnavailableException>(() =>
            ProductionGroupControlAuthoritySource.EnsureRendezvousBindings(
                gsr,
                Hash("wrong-network")[..16],
                30,
                60));
        Assert.Throws<GroupControlAuthorityUnavailableException>(() =>
            ProductionGroupControlAuthoritySource.EnsureRendezvousBindings(
                gsr,
                network,
                30,
                90));
    }

    [Fact]
    public void ExactGsr1RejectsWrongSignature()
    {
        var key = PublicKeyAuth.GenerateKeyPair(Hash("gsr-signature-key"));
        var gsr = Gsr(Hash("gsr-signature-network")[..16], key.PrivateKey, 20, 90);
        ProductionGroupControlAuthoritySource.EnsureRendezvousSignature(
            gsr,
            key.PublicKey);

        var other = PublicKeyAuth.GenerateKeyPair(Hash("other-signature-key"));
        Assert.Throws<CryptographicException>(() =>
            ProductionGroupControlAuthoritySource.EnsureRendezvousSignature(
                gsr,
                other.PublicKey));
    }

    [Fact]
    public void VerifiedPlacementRejectsWrongRoleAndMissingLocalReplica()
    {
        ReadOnlyMemory<byte>[] replicas = [Hash("replica-a"), Hash("replica-b")];
        var roles = replicas.ToDictionary(
            static value => Convert.ToHexString(value.Span),
            static _ => (ushort)(1 << 2),
            StringComparer.Ordinal);
        ProductionGroupControlAuthoritySource.EnsureProductionReplicaSet(
            roles,
            replicas,
            replicas[0].Span);

        roles[Convert.ToHexString(replicas[1].Span)] = 1 << 1;
        Assert.Throws<GroupControlAuthorityUnavailableException>(() =>
            ProductionGroupControlAuthoritySource.EnsureProductionReplicaSet(
                roles,
                replicas,
                replicas[0].Span));
        roles[Convert.ToHexString(replicas[1].Span)] = 1 << 2;
        Assert.Throws<GroupControlAuthorityUnavailableException>(() =>
            ProductionGroupControlAuthoritySource.EnsureProductionReplicaSet(
                roles,
                replicas,
                Hash("not-a-replica")));
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private ProductionGroupControlAuthorityOptions CompleteOptions() => new()
    {
        Enabled = true,
        ArtifactDirectoryRelativePath = "group-authority/artifacts",
        StateRelativePath = "group-authority/state/gcl1.bin",
        MaximumDcr1Bytes = 1024 * 1024,
        MaximumProtectedStateBytes = 1024 * 1024,
        MaximumLineageDepth = 64
    };

    private RouterNodeOptions Node()
    {
        Directory.CreateDirectory(root);
        var seed = Enumerable.Repeat((byte)0x71, 32).ToArray();
        var signer = new Ed25519();
        signer.FromSeed(seed);
        return new RouterNodeOptions
        {
            DataDirectory = root,
            RouterId = Convert.ToHexStringLower(signer.GetPublicKey()),
            Ed25519PrivateKey = Convert.ToHexStringLower(seed)
        };
    }

    private static GroupControlServiceOptions ActiveService() => new()
    {
        RuntimeActivation = true,
        MapReplicaEndpoint = true
    };

    private ProductionGroupControlAuthorityConfiguration Configuration(string name)
    {
        var directory = Path.Combine(root, name, "artifacts");
        Directory.CreateDirectory(directory);
        return new ProductionGroupControlAuthorityConfiguration(
            directory,
            Path.Combine(root, name, "state.bin"),
            1024 * 1024,
            1024 * 1024,
            64);
    }

    private FileGroupControlAuthorityLineageStore Store(string name)
    {
        var configuration = Configuration(name);
        return Store(
            configuration,
            DataProtectionProvider.Create(new DirectoryInfo(Path.Combine(root, name, "keys"))));
    }

    private static FileGroupControlAuthorityLineageStore Store(
        ProductionGroupControlAuthorityConfiguration configuration,
        IDataProtectionProvider protection) => new(
            configuration,
            protection,
            new TestStorageSecurity(),
            new MailboxDurabilityBarrier());

    private static GroupControlLineageObservation Observation(params byte[][] hashes) => new(
        hashes[0],
        checked((ulong)hashes.Length - 1),
        hashes[^1],
        hashes.Select(static value => (ReadOnlyMemory<byte>)value).ToArray());

    private static byte[] Hash(string value) =>
        SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value));

    private static GroupControlRendezvousRecord Gsr(
        byte[] network,
        byte[] privateKey,
        ulong issuedAt,
        ulong expiresAt)
    {
        ReadOnlyMemory<byte>[] fields =
        [
            network,
            Hash("service-capability"),
            Hash("direction"),
            Be((ulong)0),
            new byte[32],
            Reference("PMT2", Hash("pmt")),
            Hash("placement-input"),
            Hash("sealing-key-id"),
            Hash("sealing-public-key"),
            Hash("owner-device"),
            Reference("DPD1", Hash("owner-dpd")),
            Be(issuedAt),
            Be(expiresAt),
            Enumerable.Repeat((byte)1, 64).ToArray()
        ];
        var unsigned = (GroupControlRendezvousRecord)GroupCodec.Decode(
            EncodeGroup("GSR1", fields));
        fields[13] = PublicKeyAuth.SignDetached(
            unsigned.SignatureInput.ToArray(),
            privateKey);
        return (GroupControlRendezvousRecord)GroupCodec.Decode(
            EncodeGroup("GSR1", fields));
    }

    private static byte[] EncodeGroup(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        var bytes = new byte[12 + fields.Sum(static value => 8 + value.Length)];
        Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].Span.CopyTo(bytes.AsSpan(offset));
            offset += fields[index].Length;
        }
        return bytes;
    }

    private static byte[] Reference(string magic, byte[] hash)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[5] = 1;
        hash.CopyTo(value, 6);
        return value;
    }

    private static byte[] Be(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
    }

    private sealed class FixedMonotonicClock : IOnionMonotonicClock
    {
        public ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new OnionMonotonicReading(
                Enumerable.Repeat((byte)0x45, 16).ToArray(),
                100));
        }
    }

    private sealed class UnavailableSnapshotSource : IContactVerifiedAuthoritySnapshotSource
    {
        public ValueTask<ContactVerifiedAuthoritySnapshot> ReadCurrentAsync(
            CancellationToken cancellationToken) =>
            ValueTask.FromException<ContactVerifiedAuthoritySnapshot>(
                new IOException("not used during composition"));
    }

    private sealed class TestStorageSecurity : IMailboxStorageSecurity
    {
        public void SecureDirectory(string path) => Directory.CreateDirectory(path);
        public void SecureFile(string path) { }
    }
}
