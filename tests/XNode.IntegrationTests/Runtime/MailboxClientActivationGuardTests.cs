using System.Text.Json;
using System.Text.RegularExpressions;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Microsoft.Extensions.Configuration;
using XNode;
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
    public void ProgramMapsOnlyCanonicalPeerMailboxRoutesAndCannotComposeClientAdapter()
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
        Assert.DoesNotContain(
            nameof(MailboxClientStoreAdapter),
            hostSource,
            StringComparison.Ordinal);

        using var appSettings = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(hostDirectory, "appsettings.json")));
        Assert.False(appSettings.RootElement
            .GetProperty("MailboxClient")
            .GetProperty("enabled")
            .GetBoolean());
        Assert.Contains(
            nameof(MailboxClientActivationGuard.EnsureDormant),
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
    public void CanonicalPeerClientDoesNotActivateDormantPublicClientFanout()
    {
        var hostTypes = typeof(Program).Assembly.GetTypes()
            .Where(static type => type is { IsAbstract: false, IsInterface: false })
            .ToArray();
        Assert.DoesNotContain(hostTypes, type =>
            typeof(IMailboxClientReplicaFanout).IsAssignableFrom(type));
        Assert.DoesNotContain(hostTypes, type =>
            typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(type));
        Assert.False(typeof(IMailboxClientReplicaFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.False(typeof(IMailboxClientTombstoneFanout).IsAssignableFrom(
            typeof(HttpMailboxReplicaPeerClient)));
        Assert.DoesNotContain(
            typeof(HttpMailboxReplicaPeerClient).GetMethods(),
            method => method.ReturnType == typeof(MailboxReplicaReceiptV2));
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
