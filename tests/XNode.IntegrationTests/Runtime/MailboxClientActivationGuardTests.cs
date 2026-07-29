using System.Text.Json;
using System.Text.RegularExpressions;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.Configuration;
using XNode;
using XNode.Core;
using XNode.Core.Mailbox;
using XNode.Core.Mailbox.Client;

namespace XNode.IntegrationTests.Runtime;

public sealed class MailboxClientActivationGuardTests
{
    [Fact]
    public void DefaultStatus_IsExplicitlyDormantAndNotReadyPerOperation()
    {
        var status = MailboxClientActivationGuard.EnsureDormant(
            new MailboxClientActivationOptions());

        Assert.False(status.Enabled);
        Assert.False(status.ClientRoutesMapped);
        Assert.False(status.LegacyV1TranslationEnabled);
        Assert.Equal("p10b3-internal-reject-all", status.CapabilityVerifier);
        Assert.Equal("disabled", status.StoreFanout);
        Assert.Equal("disabled", status.TombstoneFanout);
        Assert.Equal("not-ready", status.Store);
        Assert.Equal("not-ready", status.Retrieve);
        Assert.Equal("not-ready", status.Acknowledge);
        Assert.Equal(MailboxClientActivationGuard.BlockedReason, status.Reason);
        Assert.True(status.StrictMau2DecoderRegistered);
        Assert.True(status.Ed25519CapabilityVerifierRegistered);
        Assert.True(status.DurableReplayJournalRegistered);
        Assert.Equal("dormant-reject-all", status.IssuerAuthority);
        Assert.Equal("dormant-reject-all", status.RevocationPolicy);
        Assert.True(status.PeerRuntimeReady);
        Assert.Equal("prq2-mrr2-mqr3", status.PeerWire);
        Assert.Equal("client-dormant-reject-all", status.PlacementAuthority);
        Assert.Equal("dormant-unmapped", status.ClientIngress);

        var verifier = new RejectAllMailboxClientCapabilityVerifier();
        Assert.False(verifier.IsConfigured);
        Assert.False(verifier.ProvidesDurableAtomicReplay);
        Assert.False(new RejectAllMailboxClientReplicaAuthorizer().IsConfigured);
        Assert.False(new DisabledMailboxClientReplicaFanout().IsConfigured);
        Assert.False(new DisabledMailboxClientTombstoneFanout().IsConfigured);
    }

    [Fact]
    public void ConfigurationOrEnvironmentCannotActivateBlockedRuntime()
    {
        const string prefix = "XNODE_ACTIVATION_GUARD_TEST_";
        var variable = $"{prefix}MailboxClient__Enabled";
        Environment.SetEnvironmentVariable(variable, "true");
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddEnvironmentVariables(prefix)
                .Build();
            var options = configuration.GetSection("MailboxClient")
                .Get<MailboxClientActivationOptions>();

            Assert.NotNull(options);
            Assert.True(options.Enabled);
            Assert.Throws<InvalidOperationException>(() =>
                MailboxClientActivationGuard.EnsureDormant(options));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [Fact]
    public void ProgramMapsCanonicalClientRoutesOnlyBehindDisabledByDefaultComposition()
    {
        var root = FindRepositoryRoot();
        var hostDirectory = Path.Combine(root, "src", "XNode");
        var hostSource = string.Join(
            "\n",
            Directory.GetFiles(hostDirectory, "*.cs", SearchOption.AllDirectories)
                .Order(StringComparer.Ordinal)
                .Select(File.ReadAllText));
        Assert.DoesNotContain(
            "/api/peer/mailbox/replica",
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxWireHttpContract.PeerStoreRoute),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxWireHttpContract.PeerTombstoneRoute),
            hostSource,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "SignedMailboxReplicaRequest",
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxClientStoreAdapter),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxWireHttpContract.StoreRoute),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxWireHttpContract.RetrieveRoute),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxWireHttpContract.AcknowledgeRoute),
            hostSource,
            StringComparison.Ordinal);

        using var appSettings = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(hostDirectory, "appsettings.json")));
        Assert.False(appSettings.RootElement
            .GetProperty("MailboxClient")
            .GetProperty("enabled")
            .GetBoolean());
        Assert.Contains(
            nameof(MailboxClientComposition.Validate),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(MailboxAuthenticatedCapabilityRuntime),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            nameof(DurableMailboxCapabilityReplayJournal),
            hostSource,
            StringComparison.Ordinal);
        Assert.Contains(
            "onionPeerReplay = \"volatile-explicit-debt\"",
            hostSource,
            StringComparison.Ordinal);
    }

    [Fact]
    public void DevelopmentFanoutUsesActualPeerTransportAndOwnsNoRemotePrivateKey()
    {
        var hostTypes = typeof(Program).Assembly.GetTypes()
            .Where(static type => type is { IsAbstract: false, IsInterface: false })
            .ToArray();
        Assert.Contains(hostTypes, type =>
            type == typeof(DevelopmentMailboxReplicaFanout)
            && typeof(IMailboxClientReplicaFanout).IsAssignableFrom(type)
            && typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(type));
        var constructor = Assert.Single(
            typeof(DevelopmentMailboxReplicaFanout).GetConstructors());
        Assert.Contains(
            constructor.GetParameters(),
            parameter => parameter.ParameterType == typeof(IMailboxReplicaPeerClient));
        Assert.DoesNotContain(
            typeof(MailboxClientDevelopmentFixtureOptions).GetProperties(),
            property => property.Name.Contains("Private", StringComparison.OrdinalIgnoreCase));
        Assert.False(typeof(IMailboxClientReplicaFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.False(typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.DoesNotContain(
            typeof(HttpMailboxReplicaPeerClient).GetMethods(),
            method => method.ReturnType == typeof(MailboxReplicaReceiptV2));
        Assert.DoesNotContain(
            typeof(MailboxClientStoreAdapter).GetConstructors()
                .SelectMany(static constructor => constructor.GetParameters()),
            parameter => parameter.ParameterType.Name.Contains(
                "Observer",
                StringComparison.Ordinal));
        Assert.DoesNotContain(
            typeof(MailboxClientStoreAdapter).GetProperties(),
            property => property.Name.Contains("Observer", StringComparison.Ordinal));
    }

    [Fact]
    public void EnabledReleaseAndIncompleteDevelopmentActivationFailAtStartup()
    {
        var enabled = new MailboxClientActivationOptions { Enabled = true };
        var adapter = new MailboxClientAdapterOptions { Enabled = true };
        var node = new RouterNodeOptions();
        var mailbox = new ReplicatedMailboxOptions { Enabled = true };

        Assert.Throws<InvalidOperationException>(() =>
            MailboxClientComposition.Validate(
                enabled,
                adapter,
                node,
                mailbox,
                isDevelopment: false));
        Assert.Throws<InvalidOperationException>(() =>
            MailboxClientComposition.Validate(
                enabled,
                adapter,
                node,
                mailbox,
                isDevelopment: true));
    }

    [Fact]
    public void DevelopmentActivation_AcceptsDockerAdvertisedOriginThenRejectsKeyReuseAndBadOrigins()
    {
        var crypto = new SodiumMailboxPeerReplicationCrypto();
        var localSeed = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var remoteSeed = Enumerable.Range(65, 32).Select(static value => (byte)value).ToArray();
        var issuerSeed = Enumerable.Range(201, 32)
            .Select(static value => unchecked((byte)value))
            .ToArray();
        var localId = crypto.GetPublicKey(localSeed);
        var remoteId = crypto.GetPublicKey(remoteSeed);
        var distinctIssuer = crypto.GetPublicKey(issuerSeed);
        var currentPlacementId =
            Enumerable.Range(101, 32).Select(static value => unchecked((byte)value)).ToArray();
        var nextPlacementId =
            Enumerable.Range(151, 32).Select(static value => unchecked((byte)value)).ToArray();
        var now = checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var activation = new MailboxClientActivationOptions
        {
            Enabled = true,
            DevelopmentFixture = new()
            {
                Enabled = true,
                NetworkId = new string('1', 32),
                IssuerPublicKey = Convert.ToHexString(localId).ToLowerInvariant(),
                MinimumGeneration = 7,
                MaximumGeneration = 8,
                IssuerValidFromUnixSeconds = now - 60,
                IssuerValidUntilUnixSeconds = now + 3600,
                CoordinatorUrl = "http://192.168.1.44:41801/",
                CurrentPlacementId =
                    Convert.ToHexString(currentPlacementId).ToLowerInvariant(),
                CurrentPlacementCommitment = Convert.ToHexString(
                    MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(currentPlacementId))).ToLowerInvariant(),
                NextPlacementId =
                    Convert.ToHexString(nextPlacementId).ToLowerInvariant(),
                NextPlacementCommitment = Convert.ToHexString(
                    MailboxPlacementCommitment.Compute(
                        new BlindedPlacementId(nextPlacementId))).ToLowerInvariant(),
                ReplicaIds =
                [
                    Convert.ToHexString(localId).ToLowerInvariant(),
                    Convert.ToHexString(remoteId).ToLowerInvariant()
                ],
                ReplicaSigningPublicKeys =
                [
                    Convert.ToHexString(localId).ToLowerInvariant(),
                    Convert.ToHexString(remoteId).ToLowerInvariant()
                ]
            }
        };
        var adapter = new MailboxClientAdapterOptions
        {
            Enabled = true,
            CurrentEpoch = 7,
            NextEpoch = 8,
            CurrentMembershipCommitment = new string('4', 64),
            NextMembershipCommitment = new string('5', 64),
            CurrentNotBeforeUnixSeconds = now - 60,
            NextNotBeforeUnixSeconds = now,
            CurrentExpiresAtUnixSeconds = now + 3600,
            NextExpiresAtUnixSeconds = now + 7200
        };
        var node = new RouterNodeOptions
        {
            RouterId = Convert.ToHexString(localId).ToLowerInvariant(),
            Ed25519PrivateKey = Convert.ToHexString(localSeed).ToLowerInvariant(),
            ApiListenUrl = "http://0.0.0.0:8080",
            PublicHost = "192.168.1.44",
            PublicPort = 41801
        };

        var error = Assert.Throws<InvalidOperationException>(() =>
            MailboxClientComposition.Validate(
                activation,
                adapter,
                node,
                new ReplicatedMailboxOptions { Enabled = true },
                isDevelopment: true));
        Assert.Contains("must be distinct", error.Message, StringComparison.Ordinal);

        activation.DevelopmentFixture.IssuerPublicKey =
            Convert.ToHexString(distinctIssuer).ToLowerInvariant();
        foreach (var invalidCoordinator in new[]
                 {
                     "http://user@192.168.1.44:41801/",
                     "http://192.168.1.44:41801/unexpected",
                     "http://192.168.1.44:41802/"
                 })
        {
            activation.DevelopmentFixture.CoordinatorUrl = invalidCoordinator;
            var coordinatorError = Assert.Throws<InvalidOperationException>(() =>
                MailboxClientComposition.Validate(
                    activation,
                    adapter,
                    node,
                    new ReplicatedMailboxOptions { Enabled = true },
                    isDevelopment: true));
            Assert.Contains(
                "authority window is invalid",
                coordinatorError.Message,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ClientIngressLimiter_EvictsIdlePartitionsAfterAdversarialChurn()
    {
        var limiter = new MailboxClientIngressLimiter();
        ulong now = 1;
        for (var index = 0; index < 4097; index++)
        {
            Assert.True(limiter.TryEnter(
                $"198.51.{index / 256}.{index % 256}",
                MailboxWireHttpContract.Store,
                now,
                out var lease));
            lease.Dispose();
            now += 61;
        }

        Assert.True(limiter.TryEnter(
            "203.0.113.250",
            MailboxWireHttpContract.Store,
            now,
            out var recovered));
        recovered.Dispose();
    }

    [Fact]
    public void ClientIngressLimiter_ConcurrencyRejectionDoesNotConsumeRateQuota()
    {
        var limiter = new MailboxClientIngressLimiter();
        var contract = MailboxWireHttpContract.Store with
        {
            MaximumConcurrentRequests = 1,
            RequestsPerMinute = 2
        };
        Assert.True(limiter.TryEnter("192.0.2.1", contract, 100, out var first));
        Assert.False(limiter.TryEnter("192.0.2.1", contract, 100, out var rejected));
        rejected.Dispose();
        first.Dispose();
        Assert.True(limiter.TryEnter("192.0.2.1", contract, 100, out var second));
        second.Dispose();
        Assert.False(limiter.TryEnter("192.0.2.1", contract, 100, out var exhausted));
        exhausted.Dispose();
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "XNode.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("XNode repository root was not found.");
    }
}
