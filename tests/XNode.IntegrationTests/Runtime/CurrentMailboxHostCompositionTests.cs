using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;
using static XNode.IntegrationTests.Runtime.MailboxGrantRevocationStoreTests;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace XNode.IntegrationTests.Runtime;

public sealed class CurrentMailboxHostCompositionTests
{
    [Fact]
    public void DisabledCompositionDoesNotRegisterOwnersOrCreateCustody()
    {
        var services = new ServiceCollection();
        var node = new RouterNodeOptions();
        var mailbox = new ReplicatedMailboxOptions();
        Assert.Null(new CurrentMailboxCustodyOptions().Validate(node, mailbox));
        Assert.Same(services, services.AddCurrentMailboxHost(null, node, mailbox));
        Assert.Empty(services);
        Assert.Throws<InvalidOperationException>(() => new CurrentMailboxCustodyOptions
        { NetworkIdHex = new string('1', 32) }.Validate(node, mailbox));
    }

    [Theory]
    [InlineData("network-zero")]
    [InlineData("network-upper")]
    [InlineData("policy-width")]
    [InlineData("relative")]
    [InlineData("root")]
    [InlineData("nested")]
    [InlineData("equal")]
    [InlineData("insecure")]
    public void InvalidLocalBindingsRejectBeforeFilesystemAccess(string fault)
    {
        var root = Path.Combine(Path.GetTempPath(), "deep-composition-" + Guid.NewGuid().ToString("N"));
        var node = new RouterNodeOptions { DataDirectory = Path.Combine(root, "data") };
        var options = Options(root);
        var mailbox = new ReplicatedMailboxOptions { Enabled = true };
        switch (fault)
        {
            case "network-zero": options.NetworkIdHex = new string('0', 32); break;
            case "network-upper": options.NetworkIdHex = new string('A', 32); break;
            case "policy-width": options.MailboxAuthorityCoreHashHex = "11"; break;
            case "relative": options.IndependentCustodyDirectory = "custody"; break;
            case "root": options.IndependentCustodyDirectory = Path.GetPathRoot(root)!; break;
            case "nested": options.IndependentCustodyDirectory = Path.Combine(node.DataDirectory, "nested"); break;
            case "equal": options.DataProtectionKeysDirectory = options.IndependentCustodyDirectory; break;
            case "insecure": mailbox.AllowInsecureHttpPeerTransport = true; break;
        }
        Assert.Throws<InvalidOperationException>(() => options.Validate(node, mailbox));
        Assert.False(Directory.Exists(root));
    }

    [Theory]
    [InlineData("ContactAuthority")]
    [InlineData("GroupControlAuthority")]
    [InlineData("MailboxPeerAuthority")]
    [InlineData("MailboxClient")]
    [InlineData("MailboxClientAdapter")]
    [InlineData("MailboxClientProductionAuthority")]
    [InlineData("MailboxAuthorityForwarding")]
    public void RetiredConfigurationRejectsEvenAnEmptySection(string section)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { [section] = "" }).Build();
        Assert.Throws<InvalidOperationException>(() => RetiredAuthorityConfiguration.RequireAbsent(configuration));
        using var json = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("{\"" + section + "\":{}}"));
        var emptyObject = new ConfigurationBuilder().AddJsonStream(json).Build();
        Assert.Throws<InvalidOperationException>(() => RetiredAuthorityConfiguration.RequireAbsent(emptyObject));
    }

    [Fact]
    public void MissingCurrentSourceOrSplitNativeOwnersRejectBeforeRegistration()
    {
        var services = new ServiceCollection();
        var configuration = Options(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")))
            .Validate(new RouterNodeOptions { DataDirectory = Path.Combine(Path.GetTempPath(), "deep-data") },
                new ReplicatedMailboxOptions { Enabled = true });
        Assert.Throws<InvalidOperationException>(() => services.AddCurrentMailboxHost(configuration,
            new RouterNodeOptions(), new ReplicatedMailboxOptions { Enabled = true }));
        Assert.Empty(services);
        services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(_ => throw new Exception("Must not resolve."));
        services.AddSingleton<IOnionMonotonicClock>(_ => throw new Exception("Must not resolve."));
        services.AddSingleton<MailboxPeerMutationStore>(_ => throw new Exception("Must not resolve."));
        var count = services.Count;
        Assert.Throws<InvalidOperationException>(() => services.AddCurrentMailboxHost(configuration,
            new RouterNodeOptions(), new ReplicatedMailboxOptions { Enabled = true }));
        Assert.Equal(count, services.Count);
    }

    [Theory]
    [InlineData("valid")]
    [InlineData("retrieve-role")]
    [InlineData("retrieve-signature")]
    [InlineData("existing-operation")]
    [InlineData("interrupted-operation")]
    [InlineData("interrupted-custody")]
    [InlineData("unknown-custody")]
    [InlineData("signing-key")]
    [InlineData("cancelled")]
    public async Task ActualFactoryOwnsBothRolesAndOperationsAcrossColdReopenWithoutReaderEnrollment(string scenario)
    {
        using var signed = await DeepIdV2PublicationAuthorityFixture.CreateAsync(distinctNodeIdentities: true);
        var host = await Host(signed);
        var nodeId = signed.NodeIds[0];
        var root = Path.Combine(Path.GetTempPath(), "deep-composition-" + Guid.NewGuid().ToString("N"));
        var options = Options(root);
        options.NetworkIdHex = Convert.ToHexString(host.NetworkId.Span).ToLowerInvariant();
        options.MailboxAuthorityCoreHashHex = Convert.ToHexString(ContactCodec.Decode(ProtocolMagic.PMA2, signed.MailboxAuthority.Span).CoreHash.Span).ToLowerInvariant();
        var node = new RouterNodeOptions { DataDirectory = Path.Combine(root, "data"),
            RouterId = Convert.ToHexString(nodeId.Span), Ed25519PrivateKey = Convert.ToHexString(signed.Node(nodeId.Span).Seed) };
        var mailbox = new ReplicatedMailboxOptions { Enabled = true };
        var configuration = options.Validate(node, mailbox)!;
        ServiceProvider Open()
        {
            var services = new ServiceCollection();
            services.AddSingleton<IDeepIdV2ContactStoreAuthoritySource>(signed);
            services.AddSingleton<IOnionMonotonicClock>(signed);
            services.AddSingleton<IMailboxStorageSecurity, MailboxStorageSecurity>();
            services.AddSingleton<IMailboxDurabilityBarrier, MailboxDurabilityBarrier>();
            services.AddSingleton(mailbox);
            services.AddCurrentMailboxHost(configuration, node, mailbox);
            return services.BuildServiceProvider();
        }
        try
        {
            // No key ring: resolving a reader must neither generate keys nor enroll custody.
            await using (var missingKeys = Open())
                Assert.Throws<InvalidDataException>(() => missingKeys.GetRequiredService<CurrentMailboxReplicaReceiver>());
            Assert.False(Directory.Exists(root));
            var security = new MailboxStorageSecurity();
            security.SecureDirectory(options.DataProtectionKeysDirectory);
            var provisionServices = new ServiceCollection();
            provisionServices.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(options.DataProtectionKeysDirectory))
                .SetApplicationName(CurrentMailboxHostComposition.ProtectionApplication).DisableAutomaticKeyGeneration();
            using (var provision = provisionServices.BuildServiceProvider())
                provision.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(90));
            foreach (var key in Directory.GetFiles(options.DataProtectionKeysDirectory)) security.SecureFile(key);
            if (scenario == "signing-key") node.Ed25519PrivateKey = Convert.ToHexString(Enumerable.Repeat((byte)0x77, 32).ToArray());
            var keyHashes = Directory.GetFiles(options.DataProtectionKeysDirectory).ToDictionary(path => Path.GetFileName(path)!,
                path => SHA256.HashData(File.ReadAllBytes(path)));
            await using (var first = Open())
            {
                var receiver = first.GetRequiredService<CurrentMailboxReplicaReceiver>();
                first.GetRequiredService<CurrentMailboxReplicationCoordinator>().RequireReceiver(receiver);
                Assert.NotNull(await Record.ExceptionAsync(() => receiver.InitializeHostAsync().AsTask()));
                Assert.Empty(Directory.GetFiles(options.IndependentCustodyDirectory, "enrollment.bin", SearchOption.AllDirectories));
                var deposit = Snapshot(signed);
                var retrieve = Snapshot(signed, MailboxCapabilityDomain.Retrieve);
                if (scenario == "retrieve-role") retrieve = deposit;
                if (scenario == "retrieve-signature") retrieve[^1] ^= 1;
                string? interrupted = null;
                if (scenario is "existing-operation" or "interrupted-operation")
                {
                    interrupted = Path.Combine(node.DataDirectory, CurrentMailboxHostComposition.OperationDirectory,
                        scenario == "existing-operation" ? "operations.json" : "operations.json." + new string('1', 32) + ".tmp");
                    using (var file = new FileStream(interrupted, FileMode.CreateNew)) file.WriteByte(0x55);
                    security.SecureFile(interrupted);
                }
                if (scenario is "interrupted-custody" or "unknown-custody")
                {
                    var scope = Convert.ToHexString(SHA256.HashData([.. nodeId.Span, .. host.NetworkId.Span]));
                    interrupted = Path.Combine(options.IndependentCustodyDirectory, scope,
                        scenario == "interrupted-custody" ? "checkpoint.bin" : "unknown.bin");
                    using (var file = new FileStream(interrupted, FileMode.CreateNew)) file.WriteByte(0x55);
                    security.SecureFile(interrupted);
                }
                using var cancellation = new CancellationTokenSource();
                if (scenario == "cancelled") cancellation.Cancel();
                if (scenario != "valid")
                {
                    Assert.NotNull(await Record.ExceptionAsync(() => receiver.EnrollNewHostAsync(deposit, retrieve, cancellation.Token).AsTask()));
                    Assert.Empty(Directory.GetFiles(options.IndependentCustodyDirectory, "enrollment.bin", SearchOption.AllDirectories));
                    Assert.Empty(Directory.GetFiles(options.IndependentCustodyDirectory, "floor.bin", SearchOption.AllDirectories));
                    Assert.Equal(scenario == "interrupted-custody" ? 1 : 0,
                        Directory.GetFiles(options.IndependentCustodyDirectory, "checkpoint.bin", SearchOption.AllDirectories).Length);
                    if (interrupted is not null) Assert.Equal(new byte[] { 0x55 }, File.ReadAllBytes(interrupted));
                    Assert.NotNull(await Record.ExceptionAsync(() => receiver.InitializeHostAsync().AsTask()));
                    Assert.Equal(keyHashes.Count, Directory.GetFiles(options.DataProtectionKeysDirectory).Length);
                    foreach (var key in Directory.GetFiles(options.DataProtectionKeysDirectory))
                        Assert.Equal(keyHashes[Path.GetFileName(key)], SHA256.HashData(File.ReadAllBytes(key)));
                    return;
                }
                await receiver.EnrollNewHostAsync(deposit, retrieve);
                Assert.NotNull(await Record.ExceptionAsync(() => receiver.EnrollNewHostAsync(deposit, retrieve).AsTask()));
                await receiver.InitializeHostAsync();
                Assert.Equal(0, first.GetRequiredService<DurableMailboxCapabilityReplayJournal>().Diagnostics.ScopeCount);
            }
            await using (var reopened = Open())
            {
                await reopened.GetRequiredService<CurrentMailboxReplicaReceiver>().InitializeHostAsync();
                Assert.Equal(0, reopened.GetRequiredService<DurableMailboxCapabilityReplayJournal>().Diagnostics.ScopeCount);
            }
            Assert.Equal(keyHashes.Count, Directory.GetFiles(options.DataProtectionKeysDirectory).Length);
            foreach (var key in Directory.GetFiles(options.DataProtectionKeysDirectory))
                Assert.Equal(keyHashes[Path.GetFileName(key)], SHA256.HashData(File.ReadAllBytes(key)));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static CurrentMailboxCustodyOptions Options(string root) => new()
    {
        NetworkIdHex = new string('1', 32), MailboxAuthorityCoreHashHex = new string('2', 64),
        IndependentCustodyDirectory = Path.Combine(root, "custody"), DataProtectionKeysDirectory = Path.Combine(root, "keys")
    };
}
